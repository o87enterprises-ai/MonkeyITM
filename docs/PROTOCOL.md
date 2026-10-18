# The MonkeyITM Intent Protocol (v1)

Status: v1, 2026-10-17. This is the contract between an AI agent and a broker that mediates everything the agent
does. It is written so that anyone can implement a compatible agent or broker without reading this repository's
code; the Rust crate `intent/` is the machine-readable form. Words in capitals (MUST, SHOULD, MAY) are used as in
RFC 2119.

**The idea in one paragraph.** The agent holds no ambient authority: no network, no files, no credentials. To do
anything it sends an **intent** to a broker. The broker logs the intent, decides it against a policy, performs it
itself if allowed, logs the verdict and returns the result. The agent can ask for anything; it can do nothing.

## Transports

| Transport | Framing | Used by |
|---|---|---|
| Unix domain socket | one JSON object per line (UTF-8, `\n`-terminated), one verdict line per intent, in order | an agent in a local sandbox (`BROKER_SOCKET`, default `/tmp/broker.sock`) |
| HTTP | `POST <session>/intent`, body = one intent, response = one verdict; bearer token for the session | a remote agent through a hosted session (`docs/API_V1.md`) |
| MCP (streamable HTTP) | each action is an MCP tool; a tool call becomes an intent, the verdict becomes the tool result, a refusal is a tool error carrying the reason | agent frameworks that speak MCP (`docs/MCP.md`) |

Agent -> Broker: one JSON object per line over a Unix domain socket.

## Intent
{
  "id": "<uuid v4>",
  "action": "read_file | http_get | write_file | exec | ...",
  "params": { ... },
  "justification": "<free text, logged but never trusted>"
}

## Verdict
{
  "id": "<echo of intent id>",
  "verdict": "allow | deny | approve_required | transform | dry_run",
  "result": <any | null>,
  "reason": "<policy path or human decision>",
  "token": "<ed25519 signed capability token, only if allow>"
}

## Action params

| action | params | notes |
|---|---|---|
| `read_file` | `{"path": "/abs/path"}` | paths under `/workspace/` are read inside the benchmark workbench |
| `write_file` | `{"path": "/workspace/...", "content": "...", "mode": "overwrite" \| "append"}` | workbench only; 1 MB cap; never through a symlink |
| `exec` | `{"argv": ["prog", "arg"], "cwd": "/workspace", "timeout_s": 60}` | workbench only; `argv` is a list, use `["bash", "-c", "..."]` for shell syntax; result has `exit_code`, `stdout`, `stderr` (64 KB each, with SHA-256 of the full output), `duration_ms`, `timed_out` |
| `http_get` | `{"url": "https://..."}` | fetched by the broker, never the agent, only for hosts a policy allows (`url_hosts`, where `.example.org` covers subdomains). HTTPS only; hosts resolving to private, loopback or link-local addresses refused and the connection pinned to the checked address; every redirect re-checked against the policy; 15 s timeout, 64 KB body cap. The shipped policies deny it. |
| `llm_chat` | `{"messages": [{"role": "...", "content": "..."}]}` | the broker holds the endpoint, model and key |
| `send_message` | `{"to": "a2", "body": "..."}` | multi-agent groups (`docs/MULTI_AGENT.md`); routed by the broker, which knows the sender from the socket. Only between an agent and its parent or its own children; body at most 64 KB; refused when the recipient has 100 unread messages or has exited. Result `{"queued": true, "to": "a2"}`. The shipped policies deny it. |
| `spawn_agent` | `{"task": "...", "max_steps": 8}` | multi-agent groups. Only the root agent (`a1`) may spawn, and only when the broker was started with `BROKER_MAX_AGENTS` above 1; the group is capped at that many agents. `task` at most 16 KB, `max_steps` 1 to 50 (default 8). The child runs `scripts/run-child.sh` in its own sandbox with its own socket. Result `{"agent": "a2"}`. The shipped policies deny it. |
| `recv_message` | `{}` | returns up to 20 waiting messages, oldest first, as `{"messages": [{"from": "a1", "body": "..."}], "remaining": 0}`; a poll, there is no push. The shipped policies deny it. |

## Unattended runs

With `BROKER_UNATTENDED=1` no human is asked: every `approve_required`
verdict becomes `deny` with reason `"no human approver (unattended run)"`,
and the escalation is recorded as `unattended`.

## Tripwire

With `BROKER_TRIPWIRE=N` the broker halts the run after N denied requests.
Every later request is refused with reason `"run halted by tripwire: too many
denied requests"` (and still logged), a `tripwire` run event is recorded, and
a benchmark workbench is killed. `scripts/run-bench.sh` arms it at 10.

## Human approval

An `approve_required` decision asks a human. A broker MUST NOT take answers from a source that cannot be matched
to the question: this implementation refuses answers on a non-terminal stdin unless the operator sets
`BROKER_ALLOW_PIPED_APPROVAL=1`, and denies the escalation (recorded as `unattended`) otherwise.

## Kill switch

The owner MUST be able to stop a run at any moment without the agent's cooperation. In this implementation:
`SIGUSR1` to the broker, or a kill file (`docs/KILL_SWITCH.md`); every later intent is refused, the workbench and
helpers are killed, and a `kill_switch` event is logged. A hosted control plane carries the owner's kill to the
runner on its next heartbeat.

## The log

Every intent and every verdict is written to an append-only log, and each record is chained:
`hash = SHA-256(previous hash, kind, record content)`, written in the same transaction as the record. `broker verify`
recomputes the chain; an edited, deleted, inserted or reordered record breaks it. A log cut short or rewritten from
the start is only detectable if the head (latest hash and count) was recorded elsewhere, so a deployment SHOULD send
the head to a party the log keeper does not control. Details: `docs/LOG_CHAIN.md`.

## Rules (normative)

A conforming **broker** MUST:

1. Deny by default: an intent that no policy rule allows is refused.
2. Log every intent **before** acting on it, and refuse the intent if the log cannot be written.
3. Return exactly one verdict per intent, echoing its `id`.
4. Perform allowed actions itself; never give the agent the means (credentials, file handles, network access) to
   perform them directly.
5. Treat `justification` as data only: log it, never use it to decide.
6. Support an owner kill switch that does not depend on the agent.
7. Keep model and service credentials out of every result returned to the agent.

A conforming broker SHOULD: halt a run after repeated refusals (tripwire); chain the log; refuse internal addresses
for any URL the agent or a customer chooses; bound result sizes.

A conforming **agent** MUST: generate a fresh `id` per intent; send nothing but intents to the broker; treat a
`deny` as final for that intent.

## Versioning

This is v1. Additive changes (new actions, new optional fields) keep v1; a broker MUST refuse an unknown action with
`deny`, so older brokers stay safe with newer agents (this implementation answers any intent it cannot parse, including an
unknown action, with `deny`, `id` `"<unparseable>"` and the parse error as the reason, and logs it). Breaking changes will be v2. Implementations SHOULD state the
version they follow.

## Other rules
- The agent never sees the broker's signing key.
- Capability tokens, when a broker issues them, are assignee-locked, resource-scoped, time-bound, single-use by default.
- Escalation to a human is itself a verdict (`approve_required`), not a side channel.

Not in v1: streaming results, multi-step transactions, delegation.

"MonkeyITM" is a trademark (`TRADEMARKS.md`). You may say an implementation "implements the MonkeyITM Intent
Protocol v1" truthfully; you may not call it MonkeyITM.

See `docs/BROKERED_EXEC.md` for the benchmark workbench design.
