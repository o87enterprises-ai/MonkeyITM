# Sessions: a live guard in front of the customer's own agent (design proposal)

**Status: approved 2026-10-15. Steps 1 (the relay) and 2 (the runner's session mode) are built, tested and proven live on real Docker (docs/FIELD_TESTS.md); step 3 (the MCP endpoint, docs/MCP.md) is built and tested, including against the official MCP SDK client; steps 4 to 7 are not.**
The relay is `site/worker/relay.js` (the Durable Object) plus the session endpoints in `site/worker/api.js`;
the table is `live_sessions` (migration 0010; `sessions` was already the site's login table); 58 of the
API suite's 243 checks cover it, with a fake runner that takes intents and answers like a broker. The runner's side
(`runner/runner.py`, `scripts/run-session.sh`, see `docs/RUNNER.md`) is covered by 113 runner checks, some against the real broker.

## 1. What a session is, and why it matters

A **job** tests an agent we run, on tasks. A **session** is the other product: the customer's own
agent, running on their side doing real work, sends every tool call (read a file, run a command, fetch
a page, call a model) to a MonkeyITM broker, which decides, executes inside containment, logs (hash-
chained) and can be killed instantly. It serves three uses with one mechanism:

- **The daily guard** for people running an agent on their own business or machine.
- **The attack target** ("try to break out from the inside", the shape-B use in the original plan).
- **A live evaluation** of an agent that cannot be handed to us as a job.

What it does and does not do must be said plainly everywhere: **a session mediates the tool calls that
go through it.** It does not contain an agent that has other routes (its own network, its own files).
It protects a machine only when the agent runs where those routes are closed. Section 6 (`guard`)
is how we close them.

## 2. The problem to solve

Everything else in the API is *pull*: runners poll the control plane over outbound HTTPS, so a runner
needs no open port and works from a laptop or a sandbox. A session is *push*: the customer's agent
sends a request now and wants an answer in about a second, but the broker is on a runner we cannot
reach. Something must sit between them and hold the request until the runner takes it.

## 3. Options considered

| Option | How | Verdict |
|---|---|---|
| **A. Durable Object per session as a relay** (recommended) | The customer's request reaches a Worker, which hands it to that session's Durable Object. The runner, holding an outbound request open (long-poll), receives it, asks its broker, posts the reply; the object answers the customer. | Works from behind NAT, no open ports, state per session, free-tier eligible. |
| B. Mailbox in D1, runner polls | Intents are rows; the runner polls for them. | D1 free writes (100,000 a day) would be gone in a day; latency 1 to 5 s. Rejected. |
| C. Customer connects straight to the runner (tunnel) | Cloudflare Tunnel to each runner. | Exposes the runner (our whole attack surface); needs a tunnel per machine; no. |
| D. Run the decision logic inside the Worker | Compile the policy crate to WebAssembly, execute on the runner only. | Interesting later (cuts latency, removes the relay for refusals), but it splits the broker in two and is a large change. Not now. |

**Recommendation: A, with HTTP long-poll from the runner first, and WebSocket later if volume demands.**
Long-poll keeps the runner standard-library-only and testable with a fake server (as the runner is today).
It costs about three object requests per intent against a free allowance of 100,000 a day (a
1,000-intent session is about 3,000); the tighter free-plan limit is active duration (section 8). A
WebSocket from the runner cuts that about tenfold; the relay interface does not change, so it can be
swapped in later.

## 4. Architecture

```
 customer's agent ──HTTPS──► Worker ──► Durable Object (one per session)  ◄──long-poll── runner ──► broker ──► workbench
   (session token)           /v1/sessions/{id}/intent | /mcp               next / reply            (one per session)
```

**A session is a job with one long run.** It reuses the pieces already built and tested: the runner's
lease, heartbeat (with the kill flag), artifacts, completion, the org-wide kill, usage and the incident
export. New tables: only `sessions (id, org_id, job_id, run_id, token_hash, status, expires_at,
max_requests)`. The runner learns one new mode: instead of `eval-job.py`, it starts a broker and a
**bridge** that carries intents between the relay and the broker's socket.

### Lifecycle

1. **Create.** `POST /v1/sessions` (scope `sessions:write`) with the policy (evaluation profile, tripwire,
   allowed hosts), an optional workspace (a task bundle's `workspace/` files), the model key (stored `key_id`
   or inline) and limits (`ttl_s`, `max_requests`). Response, once: `{id, token: "mts_...", intent_url, mcp_url,
   expires_at}`. The **session token** is separate from API keys and works on this session only.
2. **Lease.** A runner leases it as it would a run, starts the broker (its own socket path), seeds the
   workspace, opens the long-poll to the relay and reports ready. Until then intents get `503 not_ready`.
3. **Use.** The agent calls `POST /v1/sessions/{id}/intent` (the intent protocol) or the MCP endpoint
   (section 5). The relay checks the token, expiry and caps, forwards the intent, waits up to 120 s for the
   runner's reply and returns it.
4. **Stop.** Any of: the tripwire halts it (the broker says so and the relay refuses everything after),
   the owner kills it (`POST .../kill`, `DELETE`, or the org-wide kill), the TTL or request cap runs out, or
   the runner goes silent for 30 s (`lost`: the relay refuses, the runner's own watchdog kills the broker).
   The runner uploads the log (with its chain head), score and transcript as for a job and completes the run.

### Endpoints (customer side)

| Call | Auth | Purpose |
|---|---|---|
| `POST /v1/sessions` | API key, `sessions:write` | create; returns the token once |
| `GET /v1/sessions/{id}` | API key `jobs:read`, or the session token | status, counts, tripwire progress |
| `POST /v1/sessions/{id}/intent` | **session token only** | one intent in, one verdict and result out |
| `POST /v1/sessions/{id}/mcp` | **session token only** | MCP (section 5) |
| `POST /v1/sessions/{id}/kill` | API key, `kill` | stop at once (kill switch through the broker) |
| `DELETE /v1/sessions/{id}` | API key, `sessions:write` | end now, collect the log |
| `GET /v1/sessions/{id}/log` | API key, `jobs:read` | the chained log, when the session has ended |

Keys never go to the agent: the agent holds only the session token, which cannot create jobs, read other
data or kill anything but is revoked the moment the session ends.

### Endpoints (runner side)

`POST /runner/v1/sessions/{id}/ready`, `GET /runner/v1/sessions/{id}/next?wait=25` (holds until an intent
arrives or 25 s pass; `204` when idle), `POST /runner/v1/sessions/{id}/reply`. Heartbeat, artifacts and
completion are the existing run endpoints. The runner authenticates as it does today; only the runner that
holds the lease can use them.

## 5. MCP

Agent frameworks speak MCP, so the MCP endpoint is the easiest way to put the broker in front of an
existing agent. `POST /v1/sessions/{id}/mcp` implements the streamable-HTTP transport in its simple form
(JSON in, JSON out; no server-sent events): `initialize`, `notifications/initialized`, `ping`, `tools/list`,
`tools/call`. Tools: `read_file{path}`, `write_file{path, content}`, `exec{argv, cwd?, timeout_s?}`,
`http_get{url}`, `llm_chat{messages}`. Each call becomes one intent. An allowed call returns the result as
tool content; a refused one returns `isError` with the broker's reason (and says so if the run was halted).
Tools the policy never allows are still listed, so a refusal teaches the agent what is out of scope rather
than the tool silently being absent.

Reading the broker's log live (to watch a session as it runs) is a follow-up: the runner would push event
batches; for the first version the log is available when the session ends.

## 6. The `guard` wrapper (closing the other routes)

Mediation alone does not contain anything. For a Linux agent process, `monkeyitm guard` closes the other
routes: it runs the customer's command in a bubblewrap sandbox with **no network, no home directory, no
secrets**, and gives it only one way out: a loopback bridge inside the sandbox forwarding to a Unix socket
that a process outside the sandbox owns. That outside process holds the session token and relays to the
cloud session. So:

```
 guard (outside, holds the token) ◄─unix socket─► bridge (inside the sandbox, 127.0.0.1:PORT) ◄── the agent speaks MCP/HTTP to localhost
```

- The agent cannot reach the internet or the API directly, cannot read the token, and cannot touch the
  host's files; its only capability is what the broker lets through, exactly the property our own agent
  already has.
- Works for anything that speaks MCP or the intent protocol over HTTP to a local address.
- Linux first (the same bubblewrap path the project already ships). Windows and macOS need a small Linux VM
  (see `docs/research/PERSONAL_DEVICE_HARNESS.md`).

Without `guard`, a session is evidence and mediation for tools the agent chooses to route through us, which
is useful for evaluation and still logs and stops those calls, but is not containment, and the documentation
and the dashboard must say that.

## 7. Threats and what answers them

| Threat | Answer |
|---|---|
| Stolen session token | scoped to one session, short TTL, revoked at end, shown once, stored only as a hash; kill with the owner key |
| One tenant reaching another's session | the object is addressed by session id *and* checks the token hash; the creating organization is recorded; API-key calls filter on `org_id` |
| Using sessions as free compute or a proxy | `exec` only inside a no-network container; `http_get` only to allowed hosts, https, never internal addresses; request, TTL and concurrency caps by plan; the model key is the customer's |
| A flood of intents | per-session rate and size limits in the relay (4 MiB per request as elsewhere), the request cap, the tripwire, the relay refuses after a halt |
| The relay or a runner lying | the chain proves the log was not changed after its head was recorded (`docs/LOG_CHAIN.md`); it does not prove a hostile runner honest. Same trust boundary as jobs; self-hosted runners are the enterprise answer |
| A compromised runner | holds a session's data while it runs, nothing else; no inbound port; one broker per session in its own sandbox and socket |
| Customer data in our systems | intents and results pass through the relay and are in the log; the terms must say so (a counsel item, listed in section 10) |
| Replay of an old request | each intent has an id, the relay rejects reuse, and tokens die with the session |

## 8. Costs and limits (free tier)

- Durable Objects (SQLite-backed) are on the free Workers plan. **Verified 2026-10-15** (Cloudflare's
  Durable Objects pricing page), free plan, per day: **100,000 requests**, **13,000 GB-s of active
  duration**, 5 GB of stored data in all, 5 million rows read and **100,000 rows written**. All reset at
  00:00 UTC; past a limit, that kind of operation fails until the reset. An incoming WebSocket message
  counts as 1/20 of a request.
- **The binding limit is duration, not requests.** An object with a runner's long-poll open is active for
  the whole session, billed as 128 MB for the wall-clock time: a 30-minute session is about 1,800 s x
  0.125 GB = **225 GB-s, so about 57 such sessions a day** (the request count, about 3 per intent, would
  allow about 66 at 500 intents). Rows written: the relay writes only on a state change and every 20
  requests, so it stays well inside 100,000. Measure real sessions in step 6 and revisit these figures.
- D1 is touched only at create and end (a few writes per session), not per intent.
- Plan limits to start: **preview** 1 session at a time, 30 minutes, 500 intents; **subscriber** 3, 4 hours,
  20,000; **enterprise** by contract.
- Runner capacity: today one run per machine because the broker's socket path is fixed. A session script
  sets `BROKER_SOCKET` per session, so one machine can host several; that also helps job throughput later
  and matters for the cost model.

## 9. Build order (each step ships and is tested)

1. **Relay**: the Durable Object, the session endpoints and the runner endpoints, with a fake runner in
   `site/api-test.mjs` (token, caps, timeouts, kill, org-wide kill, lost runner, tenant isolation).
2. **Runner session mode**: `scripts/run-session.sh` (workbench, broker on its own socket, workspace) and
   the bridge (`runner/session_bridge.py`); test with the real broker as in `scripts/broker-live-tests.py`.
3. **MCP endpoint**, tested with a small MCP client in the test suite.
4. **CLI**: `monkeyitm sessions create | show | kill | end | log`.
5. **`guard`** for Linux, with tests that an agent in it cannot reach the network or the token.
6. **Live test**: a real model driving a session through MCP on a sandbox, then the "break out from the
   inside" run (our scripted rogue agent through the relay).
7. Dashboard pages and the invite flow's "start a session" step.

## 10. Decisions I need from you

1. **Approve option A (Durable Object relay)?** It adds one Cloudflare feature to the project (still free).
2. **Long-poll first, WebSocket later?** (My recommendation.)
3. **Include one 30-minute session in the invite preview plan?** It lets an invitee try "put the guard in front of
   my agent" as well as "test my agent", which the earlier market discussion said is probably the bigger use.
4. **`guard` Linux-only at first?** (My recommendation; Windows and macOS later via a small VM.)
5. **Terms and counsel:** sessions pass customer tool-call content through our systems and hold it in the log.
   The terms must say so, and counsel should review the "guard" wording (no claim to stop outside attackers,
   no claim to meet a statute) before any public offer. I will draft the terms change when you approve.

## 11. What could make this wrong or hard

- **Latency.** Customer, Worker, object, runner, broker and back is a few hundred milliseconds when idle.
  Fine for agent loops, noticeable for chatty ones; WebSocket and the WebAssembly option reduce it.
- **Long-poll holds** consume runner and object time; the numbers in section 8 are estimates to be measured
  in step 1.
- **`exec` needs the workbench** (Docker), as for jobs. A session without Docker would offer file and web
  tools only.
- **Agents that do not speak MCP or the intent protocol** need a small adapter; the Python client in
  `cli/monkeyitm.py` and `gateway/monkeyitm_client.py` are the starting points.
- **It is only as strong as the layer it runs on** (bubblewrap, the kernel, the broker); the outside
  penetration test planned before launch must include sessions.
