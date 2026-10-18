# MonkeyITM public API, v1 (spec, not yet built)

One API for every customer. The invite preview, a subscriber and an enterprise use the same
endpoints; plans differ only in limits. The website, the SDK, the CLI and the MCP endpoint are
all clients of this API.

## Shape

```
 customer (curl / SDK / CLI / agent via MCP / dashboard)
        │  HTTPS, Bearer API key
        ▼
 control plane  (Cloudflare Worker + D1 + R2 + Queue)      auth, tenants, keys, jobs, sessions,
        │                                                   reports, kill flags, billing counters
        │  runners pull work (outbound HTTPS only)
        ▼
 runners  (home machines first; Vercel Sandbox optional)   broker + workbench + agent per run
```

- **Runners pull, the control plane never pushes.** A runner leases work over outbound HTTPS, so
  home machines need no open ports, no public IP and no tunnel for jobs. The same runner code
  runs on a home box, a rented VM or a Vercel Sandbox.
- **Binaries and policies never leave a runner.** Customers receive verdicts, logs, scores and
  reports, never a shell, the broker binary or the runner's filesystem.
- **The control plane holds no agent.** It cannot run code for a customer, so a compromised
  Worker can mislabel results but cannot release an agent.

## Authentication

- `Authorization: Bearer mitm_<env>_<random>`. Keys are created in the dashboard or with
  `POST /v1/api-keys`; only a SHA-256 hash is stored; the key is shown once.
- Each key belongs to one **organization** and has **scopes**: `jobs:write`, `jobs:read`,
  `sessions:write`, `kill`, `keys:admin`. The invite preview issues keys with
  `jobs:* sessions:* kill`.
- Session tokens (below) are separate, short-lived and limited to one session.
- Enterprise: SSO (OIDC/SAML) for the dashboard; API keys remain the machine credential.

## Conventions

- JSON in and out; `Content-Type: application/json`. Times are UTC ISO 8601.
- `Idempotency-Key` header on every POST that creates something; a repeat returns the original.
- Errors: `{"error": {"code": "quota_exceeded", "message": "...", "request_id": "..."}}` with
  400 / 401 / 403 / 404 / 409 / 413 / 422 / 429 / 5xx.
- Rate limits: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `Retry-After` on 429.
- Lists: `?limit=` (max 100) and `?cursor=`; responses carry `next_cursor`.
- Versioning: the path carries `v1`; additive changes only within v1.

## 1. Jobs: test an agent on tasks (evaluation, benchmarks)

A job is a set of tasks run against a model under our broker. Each task becomes one **run**,
scored with `monkeyitm-alignment/v1`; the job gets a gate (`pass`, `pass_with_concerns`, `fail`,
`incomplete`).

### `POST /v1/jobs`

```json
{
  "name": "nightly regression",
  "tasks": { "suite": "practice" },
  "model": { "url": "https://integrate.api.nvidia.com/v1/chat/completions",
             "name": "z-ai/glm-5.3", "key_id": "mk_123" },
  "mode": "single",
  "policy": { "profile": "evaluation", "tripwire": 10, "allow_hosts": [] },
  "limits": { "max_steps": 20, "task_timeout_s": 600, "concurrency": 4 },
  "repeat": 1,
  "webhook": "https://example.com/hooks/monkeyitm"
}
```

- `tasks`: `{"suite": "practice"}`, `{"suite": "practice", "only": ["p6-no-outside-filing"]}`,
  or `{"bundle_id": "tb_..."}` for an uploaded bundle.
- `model.key_id` names a stored model key (section 4). Alternatively `model.key` passes it
  inline for this job only; it is never stored and never returned.
- `mode`: `single` or `group` (helpers allowed; `limits.max_agents`, default 3).
- `repeat`: run each task N times (variance; enterprise benchmarks).
- `limits.concurrency`: runs at once for this job, capped by the plan.

Response `202`: `{"id": "job_...", "status": "queued", "runs": 6}`.

### Reading results

| Call | Returns |
|---|---|
| `GET /v1/jobs/{id}` | status (`queued`, `running`, `finished`, `killed`, `error`), progress, gate |
| `GET /v1/jobs` | the organization's jobs, newest first |
| `GET /v1/jobs/{id}/report` | `job-report.json`; `?format=md` for the readable one |
| `GET /v1/jobs/{id}/runs` | one row per run: task, result, completed, beyond scope, halt cause |
| `GET /v1/jobs/{id}/runs/{run}/log` | the run's `log.json` (every request, verdict and reason) |
| `GET /v1/jobs/{id}/runs/{run}/score` | the run's `alignment-score.json` |
| `GET /v1/jobs/{id}/runs/{run}/transcript` | the agent's transcript |
| `GET /v1/jobs/{id}/incident` | signed incident export (timeline, halts, breaches, kill events) |
| `DELETE /v1/jobs/{id}` | delete the job's data (logs, reports, transcripts) |

### `POST /v1/jobs/{id}/kill`

The owner's kill switch for a job. Every run in the job is stopped through the broker's kill
switch (requests refused, container and helpers killed, the stop logged); queued runs never
start. Response: `{"status": "killing", "runs_signalled": 4}`; the job ends `killed`. The
report records the time from the call to the last run's stop.

## 2. Sessions: put the broker in front of a live agent (guard, attack target)

A session is a live broker the customer's own agent talks to, for as long as the session lasts.
This is the "guard" use (an agent doing real work, mediated) and the "try to break out" use
(the target). The agent runs on the customer's side; it reaches tools only through us.

### `POST /v1/sessions`

```json
{
  "policy": { "profile": "evaluation", "tripwire": 10, "allow_hosts": ["example.com"] },
  "workspace": { "bundle_id": "tb_..." },
  "ttl_s": 3600,
  "max_requests": 2000,
  "mode": "single"
}
```

Response `201`:

```json
{
  "id": "ses_...",
  "token": "mts_...",
  "intent_url": "https://api.monkeyitm.example/v1/sessions/ses_.../intent",
  "mcp_url": "https://api.monkeyitm.example/v1/sessions/ses_.../mcp",
  "expires_at": "2026-10-13T20:00:00Z"
}
```

The session token is shown once and only works for this session.

| Call | Purpose |
|---|---|
| `POST /v1/sessions/{id}/intent` | one intent (`action`, `params`, `justification`) → verdict and result |
| `POST /v1/sessions/{id}/mcp` | the same tools over MCP (streamable HTTP); every tool call is one intent |
| `GET /v1/sessions/{id}` | status, counts, tripwire progress, halted or not |
| `GET /v1/sessions/{id}/log` | the session's `log.json` |
| `POST /v1/sessions/{id}/kill` | kill switch: refuse everything from now on, kill helpers, log it |
| `DELETE /v1/sessions/{id}` | end the session and delete its data |

**MCP tools** exposed at `mcp_url`: `read_file`, `write_file`, `list_dir`, `exec`, `http_get`,
`llm_chat` (model calls through our broker with the customer's stored key), and in group mode
`spawn_agent`, `send_message`, `recv_message`. Each call is decided by the broker exactly as a
socket intent is; a refused call returns an MCP tool error with the reason.

**What a session does and does not contain.** It mediates every tool call that goes through
it. It does not stop an agent that has other routes (its own network access, its own files). A
session protects a machine only when the agent runs where those routes are closed: our runner
(jobs), or the customer's own locked-down runner (`monkeyitm run --guard`, see the SDK).

## 3. Task bundles: bring your own tasks

**Built** (see `docs/TASK_BUNDLES.md` for the format and the packing script). A bundle is JSON,
text files only, not a zip: `POST /v1/task-bundles` with
`{"name": "...", "tasks": [{"id", "base", "instruction", "files": {"workspace/...": "text",
"tests/run-tests.sh": "text"}, "alignment": {...}}]}`. Run it with
`"tasks": {"bundle_id": "tb_...", "only": ["task-id"]}` on a job.

Because a bundle's content runs on our runners, it is deliberately narrow:
- **No Dockerfile.** A task names a `base` from a short list (`python:3.12-slim`, `node:20-slim`,
  `ubuntu:24.04`); the runner writes its own two-line Dockerfile (`FROM`, `WORKDIR`). Nothing is
  built or installed from customer content.
- **Text only, plain paths.** Files live under `workspace/` or `tests/` (letters, digits, `. _ - /`;
  no dot segments, no absolute paths, no links, no NUL); `tests/run-tests.sh` (the grader) is required.
- **Alignment is whitelisted:** known fields only, bounded and typed; anything else is refused.
- **Limits by plan** (preview / subscriber / enterprise): bundles kept 3 / 50 / 500, tasks per bundle
  5 / 50 / 200, bundle size 200 KB / 1 MB / 1.5 MB (a bundle is one database row), 256 KB per file.
- **Checked twice:** by the API when uploaded, and again by the runner when it writes the files out
  (paths resolved and kept inside the task folder). The hidden tests are copied into the container
  only after the agent stops, exactly as for the practice suite.
- **Tenant-isolated:** another organization gets 404 or 422; the grader and files are returned only
  to the runner holding the run's lease. Deleting a bundle empties its content for good.

`GET /v1/task-bundles` and `GET /v1/task-bundles/{id}` show names, task ids, sizes and file counts,
never file contents.

## 4. Model keys

**Built.** Two ways to give a job its model key:
- **Stored:** `POST /v1/model-keys` once (needs `keys:admin`), then `"model": {"url": ..., "name": ..., "key_id": "mk_..."}` on every job. Listing (`GET`, `jobs:read`) shows label, URL prefix, a four-character hint and last use, never the key. `DELETE` empties the stored ciphertext for good; a queued job that named it then gets no key, and new jobs naming it are refused. A job already running keeps the key it fetched.
- **Inline:** `"model": {..., "key": "..."}` for one job; encrypted with the job, wiped when it ends.

A stored key is pinned to its `url_prefix` (https, public host, no port): a job whose model URL does not start with it is refused when created and again when the runner asks for the key. A key belongs to one organization; another organization gets 404 or 422, never the key. The key is released only to the runner holding the run's lease, and never in any API response. Storage is AES-GCM with a key derived from the `KEY_SECRET` Worker secret (rotating `KEY_SECRET` is not supported yet: stored keys would need re-entering). Limit 20 stored keys per organization.

The original design, for reference:

`POST /v1/model-keys` `{"label": "nvidia", "url_prefix": "https://integrate.api.nvidia.com/",
"key": "..."}` → `{"id": "mk_..."}`. The key is encrypted at rest (envelope encryption, a Worker
secret as the key-encryption key), released only to the runner of a job or session that names
it, held in the broker's memory for that run, and never returned by the API. `url_prefix` pins
where the key may be sent. `GET /v1/model-keys` lists labels; `DELETE` removes one.

## 5. Organization controls

| Call | Purpose |
|---|---|
| `POST /v1/kill` | **emergency stop for the whole organization**: every job and session stopped now |
| `GET /v1/usage` | runs, minutes, model calls, storage, against the plan |
| `POST /v1/api-keys`, `GET`, `DELETE /v1/api-keys/{id}` | manage keys and scopes |
| `GET /v1/audit` | who did what in the organization (key creation, kills, deletions) |
| `POST /v1/webhooks`, `GET`, `DELETE` | endpoints for events |

**Webhooks** (signed: `X-MonkeyITM-Signature: t=<ts>,v1=<HMAC-SHA256>`): `job.finished`,
`job.killed`, `run.halted` (tripwire or critical attempt), `session.halted`, `session.expired`,
`org.killed`.

## 6. Plans (limits, not features)

| | Preview (invite) | Subscriber | Enterprise |
|---|---|---|---|
| Concurrent runs | 1 | 4 | contract (hundreds to thousands) |
| Runs per month | 30 | 1,000 | contract |
| Live sessions at once | 1 | 3 | contract |
| Task bundles | practice suite only, plus 1 small bundle | yes, 50 MB | yes, larger; private base images |
| Log retention | 7 days | 30 days | contract; export to their storage |
| Custom policies | profiles only | profiles + allowlists | full policy files, critical paths, weights |
| SSO, audit API, private runners | no | no | yes |
| Self-hosted control plane and runners | no | no | yes |

The preview is the subscriber product with smaller numbers, so what an invitee tests is what a
subscriber gets.

## 7. Runner protocol (internal)

Runners authenticate with a per-runner credential (mutual: a signed request with time and
nonce, the scheme `hosted/nucleus_host.py` already uses).

| Call | Purpose |
|---|---|
| `POST /runner/v1/lease` | take the next run the organization's concurrency allows; `204` when there is none (the runner polls every few seconds) |
| `POST /runner/v1/runs/{id}/heartbeat` | every 2 s while running; the reply carries `kill: true` when the owner pulled it |
| `POST /runner/v1/runs/{id}/artifacts` | upload log, score, transcript, report to R2 |
| `POST /runner/v1/runs/{id}/complete` | final status |
| `POST /runner/v1/runs/{id}/model-key` | fetch the decrypted model key for this run only |

A kill reaches a runner within one heartbeat (about 2 s), and the runner pulls the broker's kill
switch (SIGUSR1) at once. A runner that misses heartbeats for 30 s kills its own runs: no agent
outlives its connection to the control plane.

## 8. Security commitments this API makes

- Tenant isolation: every row carries the organization; every query filters on it; runs from
  different organizations never share a broker, workbench or agent directory.
- Customers never receive a shell, the broker binary, policies beyond their own, or runner
  internals.
- Model keys: encrypted at rest, released per run, pinned to a URL prefix, never returned.
- Every kill, deletion and key change is in the audit log.
- Logs are hash-chained (`docs/LOG_CHAIN.md`): the head and length of each run's chain are stored and signed into the incident export, and `broker verify` checks the database itself.

## Built so far (step 1)

`site/worker/api.js` implements: API keys (`/api/keys` from the signed-in site, `/v1/api-keys`),
jobs (create, list, get, report with `?format=md`, runs, log/score/transcript, incident export signed
with HMAC, kill, delete), the organization stop (`POST /v1/kill`, `DELETE /v1/kill`), usage, audit,
and the runner protocol (lease, heartbeat, model-key, artifacts, complete) plus `/admin/runners` and
`/admin/orgs/{id}/plan` guarded by an admin token. Model keys: either stored once
(`POST /v1/model-keys`, then `model.key_id` on jobs) or passed inline (`model.key`, wiped when the job
ends). Task bundles are built too. Live sessions have their relay (`docs/SESSIONS_DESIGN.md`, step 1 of 7: `POST/GET/DELETE /v1/sessions`, `/intent` with a session token, `/kill`, `/log`, and the runner's `ready`, `next`, `reply`); the runner's session mode, the MCP endpoint, the CLI commands and `guard` are not built yet. The command line client and library (`cli/monkeyitm.py`, `docs/CLI.md`) is built. Not built yet: sessions and MCP, webhooks, the SDK/CLI, the runner daemon. Storage is D1 only (no R2, no
Queues), so it costs nothing. Worker secrets it needs: `ADMIN_TOKEN`, `KEY_SECRET`,
`REPORT_SIGNING_KEY` (each at least 32 random characters).

Tests: `cd site && node api-test.mjs` (98 checks against a real local Worker and D1).

## Build order

1. Control plane in the Worker: orgs, API keys, jobs, runs, kill, reports (D1 + R2 + Queue).
2. Runner daemon: lease, run `scripts/eval-job.py` per run, heartbeat and kill, upload.
3. Model keys; task bundles.
4. Sessions over HTTP (the gateway, moved behind the API), then MCP.
5. SDK (Python, TypeScript) and CLI (`monkeyitm jobs create ...`).
6. Dashboard and the invite flow on top.
7. Webhooks, usage, audit, plans.

## Decisions (2026-10-13)

- **Budget: $0 until revenue.** Free tiers only; no paid domain yet.
- **Domain:** a free platform subdomain for now; a custom domain after revenue. Every URL in
  this spec is configuration, so changing domains later changes no code.
- **Runners:** Vercel Sandbox for now. Home machines later (after revenue); the runner protocol
  is already outbound-only, so they plug in without changes. Home runners serving sessions will
  need a tunnel or a relay through the control plane; decide then.
- **Prices:** later, from measured cost per run (compute, model calls, storage) plus margin.
  The plan table holds limits only.
