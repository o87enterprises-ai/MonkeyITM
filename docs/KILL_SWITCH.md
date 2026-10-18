# The owner's kill switch

One action stops everything an agent can do, at once, and does not depend on the agent, the
model or the network.

**What it does.** Every later request is refused (and still logged, with the reason "run stopped
by the owner (kill switch)"); the task container is killed; every helper agent is killed. The
broker stays up to write the log, so the stop is on record: one `kill_switch` run event, and
`summary.killed_by_owner: true` in the exported log. The scorer reports the halt cause as
"stopped by the owner" and does not hold the unfinished work against the agent.

**How to pull it** (locally or in a sandbox):

| Way | Command |
|---|---|
| Signal | `scripts/kill-switch.sh` (newest broker) or `scripts/kill-switch.sh <PID>` (SIGUSR1) |
| File | `scripts/kill-switch.sh --file <path>`, or `touch <BROKER_KILL_FILE>`; default path is the log path plus `.KILL`, checked every 100 ms |
| Whole host | `hosted/halt.py` (signed request; kills every run on the nucleus host) |
| Stop and exit | Ctrl-C or SIGTERM: kills children, logs `shutdown`, and exits |

A kill file left over from an earlier run is deleted at startup, so it cannot stop a new run.
Nothing an agent sends can reach any of these: the signal and the file belong to the broker's
user, outside the agent's sandbox.

**Tested.** `broker/tests/kill_switch.rs` (stops with zero denials, second pull is a no-op, a pull
after the tripwire records nothing twice) and part G of `scripts/broker-live-tests.py` (signal,
file, stale file, against the real process).

The stop is a chained, verifiable record (`docs/LOG_CHAIN.md`). **Not built yet.** A button for the invitee on the hosted site (the Worker will call the same
stop on the job's sandbox); a time-to-stop measurement in the report.