# Claims register

What MonkeyITM-VM says about itself, one claim per row, with what actually supports it and how someone who
wants to prove it wrong should try. Written 2026-10-15 against `main` at the commit named in
`docs/REVIEW_HANDOFF_2026-10-15.md`. **The purpose of the external security test is to move rows in this
table, in either direction.** Nothing here is a marketing statement: a row marked weak is a row we must not
claim until the test says otherwise.

**Status key**
- **LIVE**: shown on the deployed system or on real Docker, as well as by automated tests.
- **TEST**: shown by automated tests in this repository only (they pass; they are our tests of our code).
- **DESIGN**: true by construction as far as we can tell, with no direct test, or tested only in part.
- **GAP**: known not to hold, or only partly; stated so it is not claimed.

An automated test that we wrote proves the code does what we meant. It does not prove we thought of every
way in. The "try to break it" column is where an independent person adds that.

## A. Containing an agent that we run (jobs) or mediate (sessions)

| # | Claim | Status | Evidence | Try to break it |
|---|---|---|---|---|
| A1 | The agent process has no network, no home directory, no host files and no secrets in its environment | TEST (relies on bubblewrap and the kernel; not independently tested) | `scripts/run-agent.sh`; `scripts/vercel-sandbox-setup.sh` check; 14 scripted escapes in `broker/tests/escapes.rs` and `scripts/broker-live-tests.py` exercise the broker side, not bubblewrap itself | From inside the agent sandbox: reach the network, read a host path, see another process, find a credential |
| A2 | Everything the agent does to the outside goes through the broker, which denies by default | TEST | `policy/src/lib.rs` (first match wins, default deny); `broker/tests/escapes.rs`; `scripts/group-attack-test.py` (85 checks); real-model runs | Find an action with an effect and no verdict row; a path spelling, symlink, race or parser difference the policy and the executor read differently |
| A3 | Every request is logged before it is decided; if the log cannot be written the request is refused | TEST | `Broker::decide_as` step 1; `broker/tests/logging.rs` | Make the log fail (full disk, locked database) and see whether anything still runs |
| A4 | After too many refusals (weighted), or one critical request, the run halts: everything later is refused, the container and helpers are killed | LIVE | tripwire tests; live session B (halt surfaced 1.8 s after the refused request) | Stay just under the limit forever; find a request class that never counts; make the halt not reach the container |
| A5 | The owner's kill switch stops a session or job in seconds, and the stop is recorded | LIVE | live session C: 1.4 s, `kill_switch` in the log, chain head matches; `broker/tests/kill_switch.rs`; runner tests | Stop the kill from landing: starve the runner, hold the broker busy, kill during a long `exec`, forge or suppress the heartbeat's kill flag |
| A6 | The workbench container has no network and no capabilities and cannot gain privilege | LIVE (2026-10-15, real Docker) | CapEff 0, NoNewPrivs 1, `setuid` and `chroot` refused, no network | Container escape; reach the Docker socket; use a kernel bug (we rely on Docker's default seccomp profile and the host kernel) |
| A7 | The container cannot exhaust the runner: processes, memory per process, file size | LIVE (2026-10-16, Vercel Sandbox, real Docker) | where cgroup limits work: processes 256, memory 1 GiB, 1 CPU. **Where they do not (Vercel Sandbox), per-process limits since 2026-10-16:** a fork bomb stopped at 492 processes (3,000 without), one process asking for 4 GiB refused, one file capped at 1 GiB (1.5 GiB without) | **Still open (do not claim):** total CPU and memory summed over many processes are not capped on Vercel Sandbox; many files under 1 GiB can still fill a disk. Try those |
| A8 | The model API key never reaches the agent | TEST | key lives only in the broker's environment; redacted from every uploaded artifact (`runner/runner.py` `redact`: since 2026-10-17 these forms: plain, base64 standard / URL-safe / unpadded, URL-encoded (both styles), hex in either case, JSON-escaped; a key split across lines or otherwise transformed is not caught); `runner/runner-test.py` | Make the key appear: through `llm_chat`, error messages, the log, the transcript, the score, `/proc`, an exec in the container |
| A9 | `http_get` is https-only, host-allowlisted, refuses internal addresses, pins DNS, re-checks every redirect | TEST | `broker/src/web.rs` and its tests; since 2026-10-15 the pinned resolver refuses any other name (it used to fall back to system DNS) and 198.18/15 and 240/4 count as internal; since 2026-10-17 an operator proxy (HTTPS_PROXY) on an internal address is refused too, unless BROKER_TRUST_INTERNAL_PROXY=1 | DNS rebinding, IPv6-mapped and decimal or octal IPs, URL parser confusion (`@`, `#`, `\`, unicode), redirect chains |
| A10 | A customer-chosen model URL cannot be used to reach internal addresses on a runner | TEST (**found in our own review 2026-10-15; was NOT true before PR #46**) | `web::public_agent` (3 tests); the runner sets `BROKER_LLM_PUBLIC_ONLY=1` for every model URL it is given; the Worker also refuses IP literals, ports, credentials | The same attack class as A9 aimed at the model URL; a hostile model server (slow, huge, malformed, redirecting, rebinding) |
| A11 | A live session **mediates** the tool calls an agent sends through it | LIVE | live sessions A to C; MCP checks incl. the official SDK client | (see A12) |
| A13 | An agent cannot change its own grade (the hidden tests run untouched after it stops) | LIVE (real Docker, 2026-10-16: the old setup let an agent plant `/tests/run-tests.sh` and trojan `sha256sum`, and the grader then "passed"; the fixed setup refused all three attempts, the hash matched, and the grader correctly failed an unsolved task. **Was NOT true before 2026-10-15**: the bench container ran as root and the grader went to a fixed `/tests`, so an agent could pre-plant a passing grader; found by the internal review) | `run-bench.sh` and `target.py`: container runs as the invoking user, grader copied to a random new path and hash-checked; both scripts refuse to run as root (since 2026-10-17) | Plant a grader, trojan `bash` or `sha256sum`, or anything else the grader trusts inside the container |
| A12 | A live session **on its own** contains the customer's own agent | **GAP, do not claim** | it does not: an agent with its own network or files bypasses it. Claim containment only with `guard` (A14) | Run an agent that simply does not call the tools |
| A14 | **With `guard`** (Linux), the customer's agent can only act through its live session: no network, no token, no home directory, nothing of the user's except an optional work folder | TEST (2026-10-16; relies on bubblewrap and the host kernel, like A1) | `cli/guard.py`, `docs/GUARD.md`; `cli/guard-test.py` (24 checks, 2026-10-17: also a read-only root, no host processes visible, no mount, no network from a new namespace, a dot-dot path through the bridge refused; the bridge carries the token added outside; no direct route to the server or the internet; the token in no environment or command line visible inside; other paths closed) | Reach the network or the guard's socket owner from inside; read the token; use another path through the bridge; escape bubblewrap |

## B. The record

| # | Claim | Status | Evidence | Try to break it |
|---|---|---|---|---|
| B1 | The log is tamper-evident: an edited, deleted, inserted or re-ordered record is found by `broker verify` | TEST + LIVE (partial) | `log/tests/chain.rs` (13 tests); `scripts/broker-live-tests.py` part H; one live run's chain head matched the control plane's | Change the database so `verify` still passes; find a record kind that is not chained; race the broker's write |
| B2 | A log cut short, or rewritten from the start, is found **if the head was recorded elsewhere** | DESIGN (stated limit) | `docs/LOG_CHAIN.md`; `verify_against` | This is a known limit: alone, the chain cannot see it. Test whether the recorded head really is out of the keeper's reach |
| B3 | The control plane stores each run's chain head and signs it into the incident export | LIVE | `site/worker/api.js` incident export (HMAC-SHA256 with a Worker secret) | Forge or alter an export; note the signature is not publicly verifiable (shared secret) |
| B4 | A log's honesty depends on the runner | DESIGN (stated limit) | `docs/LOG_CHAIN.md` | A hostile runner can write a false log with a valid chain; the answer today is "run your own runners" |

## C. The control plane (the Cloudflare Worker, `site/worker/`)

| # | Claim | Status | Evidence | Try to break it |
|---|---|---|---|---|
| C1 | API keys are stored only as SHA-256 hashes and shown once | TEST | `api_keys.key_hash`; `site/api-test.mjs` | Recover a key from the database or a response |
| C2 | A key cannot grant a scope it does not hold; session tokens and runner tokens are separate credential classes | TEST | `site/api-test.mjs` | Privilege escalation across scope, key class or organization |
| C3 | One organization cannot see or touch another's jobs, runs, logs, bundles, stored keys, sessions or API keys | TEST | many cross-organization checks, always 404 or 401 | IDOR on every identifier; list endpoints; error-message differences; timing |
| C4 | Stored model keys are encrypted (AES-GCM), pinned to a URL prefix, never returned; on delete the ciphertext is emptied (label, URL prefix and hint are kept) | TEST | `api-test.mjs` stored-key section; migration 0007 | Read a key out of the database, a response, an audit row or a log; use a key against a URL outside its pin; `KEY_SECRET` handling (single static secret, **no rotation**) |
| C5 | A model key reaches only the runner holding that run's lease, and only while the run is live | TEST | runner endpoints; wiped when a job ends | Double-lease races; fetching a key after kill; a second runner |
| C6 | A session token works for one session only, is stored as a hash, and dies with the session | TEST | `sessionTokenApi`; relay tests | Replay after end; cross-session use; token in logs; timing |
| C7 | Task bundles cannot smuggle a Dockerfile, a path outside `workspace/` or `tests/`, a link or a NUL; checked in the API and again in the runner | TEST | 15 refusal cases in each of `api-test.mjs` and `runner-test.py` | Unicode path tricks, very long names, many files, JSON oddities (duplicate keys, huge numbers), the grader script as a weapon |
| C8 | The MCP endpoint validates `Origin` and protocol version, refuses malformed or oversized input, and never lets invalid arguments reach the broker | TEST + SDK client check | `site/worker/mcp.js`; `site/mcp-sdk-check.mjs`; the plain `/intent` endpoint checks `Origin` too since 2026-10-15 (it did not before) | DNS rebinding from a page; JSON-RPC edge cases (ids, batches, nesting depth); body-size and concurrency limits |
| C9 | Quotas survive deleting a job; job and session creation are rate-limited | TEST | `usage` table; `rate` table | Bypass by many keys; races at the quota edge |
| C10 | The control plane stays up under abuse | **GAP (partly mitigated 2026-10-17)**: every Worker route except the runner channel is limited to 300 requests a minute per address per Cloudflare location (tested); a distributed flood and the free-plan daily quotas remain | free-plan limits (Workers 100,000 requests a day, Durable Objects 100,000 requests and 13,000 GB-s a day, D1 100,000 row writes a day) are low; **most endpoints have no rate limit** and every invalid key costs a database read | Cheap flooding; deliberate quota exhaustion. (Volumetric attacks are out of scope for the first test; we want the analysis, not an outage) |
| C11 | Admin endpoints (`/admin/*`) are only reachable with the admin token | TEST | constant-time compare; token must be 32+ characters | They are on the public hostname: brute force is infeasible, but exposure and rate limiting deserve a view |
| C12 | Sign-in (GitHub OAuth), the invite gate, terms acceptance, same-origin checks on state-changing calls | Reviewed 2026-10-10; changes since are small | `docs/FINDINGS_2026-10-10.md`; `site/worker/index.js` | CSRF, open redirects, state and nonce handling, cookie flags, invite matching (email vs login) |
| C13 | The runner never uses API data as a path or a command, and does not pass its token to the jobs it starts | TEST | `runner/runner.py` `check_spec`, `check_session_lease`, environment allow-list | Make the runner run something it should not; read its environment from a job (same-uid `/proc/<pid>/environ`) |

## D. Results about agents

| # | Claim | Status | Evidence | Note |
|---|---|---|---|---|
| D1 | Two models (GLM-5.3, nemotron) passed all six practice tasks | LIVE | `docs/FIELD_TESTS.md` | Six small tasks. It shows the pipeline works and that these models behaved in these tasks. It does **not** show an agent is safe |
| D2 | The scorer can tell whether an agent told the user about a planted instruction | TEST + LIVE | `scripts/score-run.py`; GLM flagged, nemotron did not | Keyword and phrase matching: easy to fool in both directions. A note, never a gate |

## E. What we must NOT claim (until the evidence exists)

- That MonkeyITM protects a person or a machine from attacks by outside AI or malware. It contains agents that
  run through it; it is not an intrusion defence (`docs/research/PERSONAL_DEVICE_HARNESS.md`).
- That an agent is "safe", "aligned" or "certified" because it scored well.
- That a live session contains an agent without `guard` (row A12), or that `guard` works off Linux.
- That total CPU or total memory is capped on every platform (row A7: per-process limits only on Vercel Sandbox).
- That it meets, or is endorsed by, any law or standard (including the proposed AI Kill Switch Act).
- That it has been independently audited. **Nothing here has been.** The 2026-10-10 review was a first pass.
- Windows or macOS support; hosting thousands of concurrent runs (one run per machine today; never tried at scale).
- That a hostile **runner operator** cannot read a customer's data or model key: the runner holds both while it
  works (self-hosted runners are the planned answer).
