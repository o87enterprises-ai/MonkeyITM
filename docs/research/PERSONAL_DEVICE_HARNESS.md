# Research note: a harness for personal computers and servers

**Status: idea for later, not designed or built.** Written 2026-10-10 at the owner's
request. Nothing here is tested. Platform details marked [VERIFY] are from general
knowledge and must be checked before any design work.

## The idea

Use the same containment on an ordinary laptop, desktop or server, so that a person who
runs an AI agent on their own machine is protected from what that agent might do, even
if no large company ever adopts the product.

## Two different problems

They are easy to blur and they need different answers.

1. **Containing an agent the person runs.** The person starts an agent (a coding
   assistant, a browser agent, an automation script). The harness runs it in a sandbox
   and makes every file, network and command request go through the broker, which checks
   rules the person controls, asks them about anything sensitive, and keeps a log.
   **This is what MonkeyITM-VM already does**, and it is feasible on a personal machine.
2. **Stopping a rogue agent that attacks the machine from outside.** For example, malware
   that uses an AI model, or a hostile agent probing the person's network. This is
   general computer security, the job of antivirus, firewalls and system updates. A
   harness only controls programs started inside it; it cannot see or stop software that
   arrives another way. Claiming it does would be wrong.

The honest pitch is problem 1: "agents you choose to run can only touch what you allow,
and you can see everything they tried."

## Why problem 1 is feasible

- Nothing in the design needs a virtual machine. The test host was a virtual machine
  only because it was convenient; bubblewrap and the broker run on any ordinary Linux
  computer.
- On a personal machine the broker would sit between the agent and the person's real
  files: rules such as "this folder read-only, this folder writable, nothing in my home
  folder's key and password stores", with a prompt for anything else.
- The parallel-agents design (`docs/MULTI_AGENT.md`) carries over unchanged: every agent
  in its own sandbox, all of them behind one broker and one kill switch.

## Platform by platform

| Platform | Likely sandbox | Notes |
|---|---|---|
| Linux (desktop or server) | bubblewrap, as today | Closest to working now. Needs unprivileged user namespaces, which some distributions restrict [VERIFY per distribution]. |
| Windows | A small Linux virtual machine (WSL2), or Windows' own isolation features (AppContainer, Windows Sandbox) | WSL2 would reuse the Linux code [VERIFY that files outside the VM can be kept out]. |
| macOS | A small Linux virtual machine through Apple's virtualization framework, or Apple's own sandbox profiles | Apple's command-line sandbox tool is deprecated [VERIFY current status]. A virtual machine is the more predictable path. |

A small virtual machine on Windows and macOS is the same approach container desktop
apps already take, which suggests it is practical for ordinary users [VERIFY].

## What would be hard

- **Approval fatigue.** If the person is asked about everything, they start clicking
  "yes" without reading. Rules need sensible defaults and the prompts need to be rare and
  clear.
- **The broker becomes the most sensitive program on the machine.** It holds the model
  key and can touch whatever the rules allow. It must run with the fewest rights it can,
  update safely, and fail closed.
- **Agents that are not started through the harness are not protected.** Browser
  extensions, apps with built-in agents, and agents in the cloud acting on the person's
  accounts are outside its reach. The product must say so plainly.
- **Ease of installation.** It has to install in one step and explain itself without
  jargon, or ordinary people will not use it.
- **Support and liability.** Software that guards personal machines carries a duty of
  care. Counsel should review before any public release.

## Possible first step, later

A Linux-only, command-line version for technical users: wrap one agent program (for
example a coding assistant) so that its file and network access go through the broker,
with a per-folder rule file. That would test whether the approach is usable day to day
before any Windows or macOS work.
