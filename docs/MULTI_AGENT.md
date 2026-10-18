# Design: parallel agents (roadmap phase 5)

**Status: built; awaiting independent review.** Written 2026-10-10. Decisions taken by the owner:
agents talk only through the broker; the first test is one parent starting two children,
all three stopped by one kill switch.

## Build progress

1. Agent identity: **done.** Every logged request carries the agent the broker assigned
   (`a1` for the root); older logs gain the column on open. A request cannot set its own
   agent.
2. Messages between agents (`send_message`, `recv_message`): **done.** Routed and logged
   by the broker; parent and child only; 64 KB per message; 100 unread per agent; 20
   returned per poll. A refused message counts toward the tripwire like any other denial,
   so an agent probing its siblings trips it.
3. Starting children (`spawn_agent`) and the group-wide kill: **done.** Two locks: the
   broker must be started with `BROKER_MAX_AGENTS` above 1 (default 1, off) and the policy
   must allow `spawn_agent`. Children start through `scripts/run-child.sh` (same sandbox as
   `run-agent.sh`) in their own process group; the tripwire and broker shutdown kill every
   group. Children's `approve_required` requests are denied without asking anyone. The
   export lists each child with its parent, task and how it ended, and the text report names
   the agent on every line. Checked with the real sandbox and the scripted model: the child
   ran, its 5 attack attempts were refused, and the log attributed all 13 of its requests
   to it.
4. Live test with the scripted stand-in model: **done.** `scripts/multi-agent-test.py`
   (policy `policies/multi-agent-test.yaml`, `MOCK_SCRIPT=group`). The parent starts a
   well-behaved helper and a rogue one; 16 checks cover the report reaching the parent,
   the rogue's three refusals, the tripwire stopping it, the parent being refused after
   the halt, and no socket or process left behind. The root agent joins a group with
   `agent.py --group`; helpers learn their id from `AGENT_ID`. The group tools appear in
   the prompt only in a group, so single-agent runs and benchmarks are unchanged.

## Goal

A parent agent can start child agents that run at the same time, each in its own
sandbox, and exchange messages with them. Nothing new may bypass the broker: starting
a child and every message are requests that policy checks and the log records, the same
as a file read.

## Shape: one broker per group

One broker process hosts the whole group (the parent and its children).

- **Identity comes from the socket, not from anything the agent says.** The broker gives
  each agent its own Unix socket and binds only that socket into that agent's sandbox.
  A request arriving on a socket is from that agent; an `agent` field in the request
  body, if sent, is ignored.
- **One kill switch for free.** The denial counter and the halt flag already live in the
  broker process. With one broker per group they are group-wide without any
  cross-process coordination.
- **One log.** Every row gets the agent that made the request, so the run bundle shows who
  did what, who started whom, and every message.

Rejected: one broker per child, linked by authenticated channels. It needs a shared
halt across processes and a network protocol between brokers, which adds attack surface
for no benefit while every agent runs on one machine. It returns as an option only when
a group must span machines.

## New actions

All three are denied by `policies/default.yaml` (its `default-deny` rule matches any
action), so existing deployments are unchanged until a policy allows them.

| Action | Params | Result |
|---|---|---|
| `spawn_agent` | `task` (text), `max_steps` (optional) | `{ "agent": "a2" }` |
| `send_message` | `to` (an agent id), `body` (text, at most 64 KB) | `{ "queued": true }` |
| `recv_message` | none | `{ "messages": [ { "from": "a1", "body": "..." } ] }`, possibly empty |

`recv_message` is a poll because the protocol is one reply per request; there is no push.

## Limits in the first version

- **Depth 1.** Only the root agent may spawn. A child's `spawn_agent` is refused by the
  broker whatever the policy says.
- **Parent and child only.** A child may message its parent and the parent may message
  any child. Children cannot message each other.
- **Group size.** At most `BROKER_MAX_AGENTS` agents including the root. The default is
  1, which turns spawning off; 3 is the intended setting for the first tests.
- **Same policy for every agent.** Per-child policies come later.
- **Mailbox caps.** At most 100 undelivered messages per agent; beyond that a send is
  refused and logged.
- Children run unattended: anything needing a human is denied.

## Starting a child

The broker creates the child's socket in a private directory (mode 0700), then starts
the child sandbox with the same bubblewrap settings as `scripts/run-agent.sh`: no
network, read-only `/usr`, empty `/tmp`, no environment, and only its own socket at
`/run/broker.sock`. The model key stays in the broker; the child reaches the model only
through `llm_chat`, like the root. The broker keeps each child's process handle.

## Kill switch

When the tripwire fires, or the broker stops, the broker:
1. sets the halt flag, so every later request from any agent is refused;
2. kills every child sandbox it started, and the workbench container if there is one;
3. records one `tripwire` event and one `agent_exited` event per child.

The halt is also re-checked after the policy decision and before anything executes, so a
request that was already being decided when the halt fired cannot run.

## Known limits of what is built

- If the broker process is killed outright, its children still die: each child's
  bubblewrap is started with `--die-with-parent`, and the broker is that parent.
- A child's process group is killed with the system `kill` command; if that command is
  missing the kill silently does nothing. [Later: send the signal directly.]
- A request whose execution has already started when the halt fires still finishes.
- Every agent follows the same policy file.

## Protection from the outside in

- Child sockets live in a directory only the broker's user can open.
- No sandbox has a network, so nothing outside can reach an agent except through its
  broker socket, and each sandbox can see only its own socket.
- Agents cannot address each other directly; the broker routes every message.

## Log changes

- An `agent` column on intents (`a1` for the root, `a2`, `a3`... for children), added to
  existing databases on open.
- Run events `agent_spawned` (with parent) and `agent_exited` (with reason).
- The export gains an `agents` list (id, parent, task, start, end, exit reason).

## Tests

Rust (in CI): spawning is denied by the default policy; the group size limit holds; a
message from parent to child arrives and is logged; a child cannot message a sibling
or spawn; the `agent` value in a request body is ignored; after a halt, every agent is
refused, including a request already in progress.

Live (on a test host): `scripts/multi-agent-test.py` with the scripted stand-in model.
The parent starts two children, the children do allowed and denied work, the tripwire
fires, and the test checks that all three sandboxes are gone and that the log shows the
whole sequence.

## Later

Per-child policies, spawn depth above 1, token and time budgets per child, groups across
machines with authenticated broker-to-broker channels.
