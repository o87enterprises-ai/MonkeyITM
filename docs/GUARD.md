# guard: put a live session in front of your own agent, and close every other route (Linux)

A live session mediates the tool calls an agent sends through it. It does not stop an agent that simply uses its
own network, files or keys instead. `guard` closes those routes: it runs your agent in a bubblewrap sandbox where the
session is the **only** way out.

```bash
export MONKEYITM_SESSION_TOKEN=mts_...        # from creating the session; or guard asks for it, hidden
python3 cli/guard.py --session-url https://monkeyitm-vm.o87enterprises.workers.dev/v1/sessions/ses_... \
  --workdir ./my-project -- python3 my_agent.py
```

Inside the sandbox the agent sees:

- **no network**: no internet, no DNS, not even the API itself. Only `127.0.0.1:8765` (change with `--port`).
- `MONKEYITM_MCP_URL=http://127.0.0.1:8765/mcp` and `MONKEYITM_INTENT_URL=http://127.0.0.1:8765/intent`: point the
  agent's MCP client (or plain HTTP) there. No token is needed inside; guard adds it outside.
- **no environment from you** (so no API keys, no token), **no home directory**, a read-only `/usr`, `/bin`, `/lib`,
  the few `/etc` files programs need, an empty `/tmp`.
- `--workdir` mounted read-write at `/work` (optional). Nothing else of yours is visible.

How it works: a small bridge inside the sandbox listens on `127.0.0.1:<port>` and passes bytes to a Unix socket.
guard, outside, owns that socket, accepts only `/mcp` and `/intent`, adds `Authorization: Bearer <session token>`,
and relays to the session URL over HTTPS. The token never enters the sandbox.

**Safe use:**

- Use a session URL from **your own** session only: guard sends the token to whatever host that URL names.
- `--workdir` must be a project folder; `/`, a whole home directory, and system directories are refused.
- The agent can delete the bridge's socket inside its sandbox; that only cuts off its own access (it cannot
  reach anything else that way).
- The agent can read `/etc/passwd` and `/etc/group` (read-only; programs need them for user names).

**What it does not do:** it is not a VM. The agent shares the host kernel (a kernel exploit is out of scope, as for any
container). It needs Linux and `bubblewrap`; Windows and macOS need a Linux VM. The agent's model calls must go through
the session (`llm_chat`) or the agent cannot reach a model at all, by design.

Tests: `python3 cli/guard-test.py` (16 checks: the bridge works and carries the token; the agent cannot reach the
network, the session server directly, the token in any environment or command line, or home directories; other paths
are closed).
