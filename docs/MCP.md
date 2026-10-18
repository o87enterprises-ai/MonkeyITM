# MCP: put a live session behind any MCP-speaking agent

Every live session (`docs/SESSIONS_DESIGN.md`) has an MCP endpoint, so an agent framework that already
speaks the Model Context Protocol can use the session's broker as its tool server with no code of ours:

```
POST https://monkeyitm-vm.o87enterprises.workers.dev/v1/sessions/{session_id}/mcp
Authorization: Bearer mts_...        (the session token, shown once when the session is created)
```

Every tool call becomes one intent for the session's broker, which applies the owner's policy, runs the
allowed ones in a container with no network, records everything in a hash-chained log, and can be stopped
instantly (`docs/KILL_SWITCH.md`). A refused call comes back as a tool error that says why.

## Tools

| Tool | Arguments | What it does |
|---|---|---|
| `read_file` | `path` | read a text file under `/workspace` |
| `write_file` | `path`, `content` (up to 1 MB), `mode` (`overwrite` or `append`) | write a text file under `/workspace` |
| `exec` | `argv` (a list), `cwd`, `timeout_s` | run a command in the container (no network); use `["bash","-c","..."]` for shell syntax |
| `http_get` | `url` | fetch a page, only from sites the session allows (https) |
| `llm_chat` | `messages` | ask the session's model (the key stays in the broker) |

Each takes an optional `why` (up to 500 characters) which is recorded in the log as the justification.

## What comes back

- **Allowed:** the broker's result as text (a file's content, a command's exit code and output).
- **Refused:** a tool result with `isError: true`, for example `Refused by the session broker: that path is out of
  scope for this task. This is outside what this session allows. Do not retry it; tell the user ...`.
  If the broker has halted the session or the owner stopped it, the text says no further call will run.
- **The session is over** (killed, halted, expired, request limit): also a tool error that names the reason
  (`session_killed`, `session_halted`, `session_expired`, `request_cap`, `runner_unavailable`).
- **Protocol errors** (JSON-RPC): `-32602` for an unknown tool or invalid arguments, `-32601` for a method we do
  not offer, `-32700` / `-32600` for a malformed message. Invalid arguments never reach the broker.

## Transport notes (Streamable HTTP, simple form)

- One endpoint, POST only. A request is answered with one `application/json` object; a notification (such as
  `notifications/initialized`) with `202` and no body. **No server-sent events and no MCP session id**: GET and
  DELETE are answered `405`, which the specification allows, and every call stands alone, authenticated by the
  session token.
- `MCP-Protocol-Version`: `2025-06-18`, `2025-03-26` and `2024-11-05` are accepted; a request naming another version
  is a `400`. JSON-RPC batches are accepted only for the older versions (the 2025-06-18 version removed them).
- `Origin`: a request carrying an `Origin` other than this site's is refused (`403`) to stop DNS-rebinding attacks;
  agents and servers send none.
- Requests are limited to 4 MiB. Calls count toward the session's request limit, and at most 8 may wait at once.

## Connecting

With the official TypeScript SDK:

```js
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const transport = new StreamableHTTPClientTransport(new URL(session.mcp_url), {
  requestInit: { headers: { Authorization: `Bearer ${session.token}` } } });
const client = new Client({ name: 'my-agent', version: '1.0.0' });
await client.connect(transport);
const { tools } = await client.listTools();
const out = await client.callTool({ name: 'read_file', arguments: { path: '/workspace/notes.txt' } });
```

Other SDKs and agent frameworks take the same two things: the URL and an `Authorization` header.

## What this is, and is not (read this)

MCP mediates **the tool calls the agent makes through it**. An agent that also has its own network access or its
own files can bypass the session entirely, so a session by itself is evidence and control over those calls, not
containment of the agent. To close the other routes, run the agent under `guard` (a Linux wrapper that gives it no
network, no home directory and no secrets, and only a loopback route to this endpoint; step 5 of
`docs/SESSIONS_DESIGN.md`, not built yet).

## Tests

`site/api-test.mjs` (35 MCP checks against a real local Worker with a fake runner behind the session) and
`site/mcp-sdk-check.mjs`, which connects the **official MCP SDK client** to the endpoint (initialize, list, call, errors,
ping, close). Run the latter with `MCP_SDK_DIR=<folder with @modelcontextprotocol/sdk installed> node mcp-sdk-check.mjs`.
