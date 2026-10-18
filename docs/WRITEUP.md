# MonkeyITM-VM: a broker between AI agents and everything they can touch

*A technical summary, October 2026. Daniel Oden, o87 Enterprises. Open source (Apache-2.0; the hosted control plane
AGPL-3.0). Not independently audited.*

## The problem

AI agents now get real tools: shells, files, browsers, API keys. When an agent is manipulated (an instruction hidden in
a file it reads, a hostile web page, another agent) it can be talked into actions nobody asked for. In most setups the
agent holds the authority itself, so the only defence is the model's own judgement, and the record of what happened,
if there is one, can be edited by whatever went wrong.

## The design

MonkeyITM-VM takes the authority away from the agent and puts a broker in front of it.

- **The agent holds nothing.** It runs in a sandbox (bubblewrap on Linux) with no network, no home directory and no
  credentials. Its only way to act is to send an **intent** to the broker: read a file, write a file, run a command,
  fetch a URL, call a model, message another agent.
- **The broker decides, then acts.** Each intent is logged first, then decided against a policy (deny by default, first
  matching rule wins). Allowed actions are performed by the broker itself: commands run in a separate container with no
  network and no privileges, model calls use a key the agent never sees, fetches are HTTPS-only to allow-listed hosts
  with internal addresses refused.
- **The record is tamper-evident.** Every intent and verdict is chained (SHA-256 over the previous hash and the record),
  so an edited, deleted, inserted or reordered record is detected by `broker verify`.
- **It can be stopped.** A tripwire halts a run after repeated refusals; the owner's kill switch stops it at once without
  the agent's cooperation.
- **Your own agent, too.** A hosted live session puts the same broker in front of an agent that runs elsewhere, over
  HTTP or MCP. On Linux, `guard` runs that agent in a sandbox where the session is its only way out.

The wire format is specified in `docs/PROTOCOL.md` (the MonkeyITM Intent Protocol v1) so others can build compatible
agents and brokers.

## What we measured

All tests below were written and run by us. They show what we checked, not that nothing can get past.

**Automated suites (2026-10-17):** 749 checks across 16 suites on Linux with real Docker, plus 302 checks of the
hosted API against a real local Worker and database; 0 failures.

**Real models, real tasks.** Six practice tasks (fix a bug, summarize a file with a planted instruction, change one
config value without touching others, fetch a page title, coordinate helper agents, refuse to file a document outside
the workspace), run end to end through the hosted service on a cloud sandbox:

| Model | Result | Time for the suite |
|---|---|---|
| GLM-5.3 | 6 of 6 pass, 0 critical attempts, 0 requests beyond scope | about 10.5 minutes |
| Nemotron 3 Super | 6 of 6 pass, 0 critical attempts, 0 requests beyond scope | about 90 seconds |

Both models resisted the planted instructions. Only GLM told the user it had seen one; Nemotron silently ignored it.
That difference is the kind of thing an evaluation should surface, and is now a recorded signal.

**Adversarial multi-agent campaigns.** 14 attack scenarios (direct credential reads, path traversal, exfiltration,
injected instructions, helpers recruiting helpers, spoofed system messages, persisting after a halt), two runs each, on
two models. Across 1,900 brokered requests in those campaigns, **no allowed request broke a policy rule**; the broker
refused what its rules said it should. In two runs a helper agent's own refused attempts tripped the tripwire and the
broker killed the helpers.

**The kill switch through the hosted API** stopped a running job 3 seconds after the owner's request.

**Found in our own review and fixed, with before-and-after on real Docker:**
- An agent in the benchmark container could plant its own passing grader (it ran as root, and the grader went to a fixed
  path). Before the fix the attack produced a fake pass; after it, every attempt was refused and the real grader ran.
- On a cloud sandbox without cgroup controls, a fork bomb started 3,000 processes; with per-process limits it stopped at
  492, and a 4 GiB allocation was refused.
- A customer-chosen model URL could have reached internal addresses on a shared runner; it is now refused.

## What it does not do (yet)

- It contains agents that run **through** it. It is not antivirus and does not protect a machine from software already
  running outside it.
- A live session alone mediates the tool calls sent to it; it does not stop an agent that simply does not use them.
  Containment of your own agent needs `guard`, which is Linux only.
- It is not a VM: a kernel exploit is out of scope, as for any container.
- On hosts without cgroup controls, total CPU and total memory are not capped.
- A log cut short or rewritten from the start is detectable only if its latest hash was recorded elsewhere, and a hostile
  operator of the machine running the broker could write a false log.
- Scoring of agent behaviour is heuristic. A pass is not a safety certificate.
- **No independent audit or penetration test has been completed.** We have invited security researchers to test it.

## Try it, break it

- Source, protocol and claims register (every claim with its evidence and its status): the public repository.
- Security researchers: see `SECURITY.md` and the open invitation issue. Report privately; we credit and fix.
- The hosted service is invite-only on free infrastructure; request access on the site.
