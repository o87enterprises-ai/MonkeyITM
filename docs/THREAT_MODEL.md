# Threat Model

Honest map of what we've thought about. Empty rows are open.

| Threat | Status |
|---|---|
| Agent reads credential from env | Mitigated (no env in sandbox) |
| Agent opens socket to internet | Mitigated (no net in sandbox) |
| Agent writes to filesystem | Mitigated (no fs in sandbox) |
| Agent forges capability token | Mitigated (never sees signing key) |
| Agent replays token | Mitigated (executor records every nonce; a token runs once; 60s TTL). Note: nonce set is in memory, resets on broker restart |
| Path traversal (`/tmp/safe/../../etc/shadow`) | Mitigated (paths normalized before policy match; relative paths denied) |
| Symlink escape (`/tmp/safe/link -> /etc/passwd`) | Mitigated (executor re-checks canonical path against policy) |
| Symlink swapped between check and read (TOCTOU) | OPEN |
| Agent reads model API key | Mitigated (model reached only via broker `llm_chat`; key lives in broker env) |
| Agent code bypasses broker and acts directly | Mitigated on Linux (bubblewrap: no net ns, no /etc, no home, empty env, read-only /usr) |
| Signing key persists across restarts | OPEN (fresh keypair per start; old tokens die on restart, which is safe but not durable) |
| Agent persists across sessions | OPEN |
| Agent social-engineers the human approver | OPEN |
| Broker itself is compromised | OPEN |
| Policy file is world-writable | OPEN |
| Side-channel via timing / resource use | OPEN |
| Prompt injection redirects intent content | PARTIAL (injected actions still pass policy; see `run-agent.sh --task` demo. Injected *allowed* actions are not caught) |
| Model weights leak via outputs | OPEN |
| Data smuggled out through DNS lookups (DNS tunneling) | Mitigated: the agent has no network namespace, so no resolver; web access only via broker `http_get` to allowlisted hosts |
| Allowlisted host used to reach an internal service (SSRF, cloud metadata) | Mitigated: broker refuses hosts resolving to private/loopback/link-local addresses and pins the connection to the checked address |
| Allowed site redirects the request elsewhere | Mitigated: each redirect hop is re-checked against the policy |
| Escape attempts detected but the run keeps going | Mitigated: `BROKER_TRIPWIRE` halts the run after N denials, refuses everything after, kills the workbench |
| **Benchmark runs** (`scripts/run-bench.sh`, see `docs/BROKERED_EXEC.md`) | |
| Agent reads or edits the hidden tests | Mitigated (tests are copied into the workbench only after the agent stops) |
| Agent looks up solutions online | Mitigated (workbench has `--network none`; `http_get` denied) |
| Agent file access escapes `/workspace` (traversal, symlinks) | Mitigated (paths resolved on the host and re-checked; writes never follow symlinks) |
| Command escapes the workbench container | Relies on the container runtime's isolation, which is not a hypervisor |
| Command rules bypassed with `bash -c` | Accepted: command rules are for reporting and coarse limits; the container is the boundary |
| Agent plants files that change how the grader behaves | OPEN (grader runs against the state the agent left) |
| Run bundle edited after the fact | PARTIAL (SHA-256 manifest; no hash chain or durable signature yet) |
| Socket trust is filesystem permissions, not peer credentials | OPEN; sockets are now always mode 0600 whatever the umask (any process running as the broker's user can connect to any agent's socket and speak as that agent; `SO_PEERCRED` is not checked. Out of scope: same-user code execution is game-over) |
| Log write fails after the action has started | Mitigated (the action stands; the verdict row is still written as a deny and the tripwire still counts it; the log no longer shows a clean allow) |
| Malformed or oversized intent line | Mitigated (refused, logged as a `malformed_request` run event under the sending agent, and counted toward the tripwire; `MAX_INTENT_BYTES` bounds each line) |
| FIFO or device file under an allowed read prefix | Mitigated (the open is `O_NONBLOCK` and a non-regular file is refused after `fstat`) |
| Broker shutdown races its own exit events | Mitigated for SIGINT, SIGTERM and SIGHUP (every child is killed and its exit row awaited for up to 5 s). A `kill -9` records nothing, but helpers do not outlive it (bubblewrap `--die-with-parent`, `PR_SET_PDEATHSIG` for other launchers) |

**Hosted real test** (`docs/HOSTED_REAL_TEST.md`, `hosted/nucleus_host.py`) | |
| Anyone but the site's Worker calls the host | Mitigated in code (HMAC-signed requests with time and nonce; stale, replayed and unsigned requests refused; listens on 127.0.0.1 only). The reverse proxy or tunnel and the VM firewall are not built |
| An invitee reads another invitee's run or log | Mitigated in code (every read is scoped to the user id the Worker signs; tested). The Worker must pass the right id: not built |
| The owner's model key leaks to an invitee | Mitigated in tests (key only in the broker's environment; absent from run files, logs, responses and the service's output) |
| An invitee runs the host out of budget or capacity | PARTIAL (per-user concurrency, host cap, daily cap, 12 turns, 10-minute limit, bounded inputs, halt switch; the model provider's own limits are not controlled) |
| An invitee's agent escapes the sandbox on the VM | Relies on bubblewrap and the broker, which are the thing under test; the VM must hold nothing else of value and run runs as an unprivileged user |
| Runs of different invitees share one Unix user | OPEN (same-user socket trust, as above; each agent sees only its own socket) |
| Retention and deletion | Built (30-day sweep, delete on request); backups and the log of who accessed what are not |

Add yours.
