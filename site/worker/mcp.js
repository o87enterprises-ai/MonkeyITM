// MCP (Model Context Protocol) endpoint for a live session: POST /v1/sessions/{id}/mcp.
//
// Streamable HTTP in its simplest allowed form: every request is a POST carrying one JSON-RPC message
// (or, for the older protocol versions, a batch); a request is answered with one JSON object, a
// notification with 202 and no body; GET and DELETE are answered 405 (no server-sent events, no
// MCP sessions: each call stands alone and the session token in the Authorization header is the only
// state). Each tools/call becomes one intent for the session's broker, which decides; a refusal is a
// tool error carrying the broker's reason.
//
// Spec: modelcontextprotocol.io/specification/2025-06-18 (transports, tools). This module knows nothing
// about the relay: the caller passes `callIntent(intent) -> {status, json}`.

export const MCP_VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'];
const MAX_BODY = 4 * 1024 * 1024;
const MAX_BATCH = 20;

const INSTRUCTIONS = 'These tools reach a MonkeyITM session. Every call is decided by a broker that applies the owner\'s policy ' +
  'and records it. Commands run in a container with no network, in /workspace; reads and writes are limited to /workspace; ' +
  'web fetches only reach the sites the session allows. A refused call says why: do not retry it, and tell the user. ' +
  'If the session is halted or stopped, no further call will run.';

const why = { type: 'string', maxLength: 500, description: 'Optional: why you are making this call (recorded in the session log).' };
const str = (max, description) => ({ type: 'string', minLength: 1, maxLength: max, description });

export const TOOLS = [
  { name: 'read_file', title: 'Read a file', description: 'Read a text file under /workspace.',
    inputSchema: { type: 'object', properties: { path: str(4096, 'Absolute path, e.g. /workspace/notes.txt'), why }, required: ['path'], additionalProperties: false },
    annotations: { readOnlyHint: true, openWorldHint: false } },
  { name: 'write_file', title: 'Write a file', description: 'Create, overwrite or append to a text file under /workspace (up to 1 MB).',
    inputSchema: { type: 'object', properties: { path: str(4096, 'Absolute path under /workspace'), content: { type: 'string', maxLength: 1000000 },
      mode: { type: 'string', enum: ['overwrite', 'append'], default: 'overwrite' }, why }, required: ['path', 'content'], additionalProperties: false },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false } },
  { name: 'exec', title: 'Run a command', description: 'Run a command in the session\'s container (no network), in /workspace. Give the program and its arguments as a list; use ["bash","-c","..."] for shell syntax.',
    inputSchema: { type: 'object', properties: { argv: { type: 'array', minItems: 1, maxItems: 200, items: { type: 'string', maxLength: 8192 } },
      cwd: str(4096, 'Working directory under /workspace (default /workspace)'), timeout_s: { type: 'integer', minimum: 1, maximum: 600 }, why }, required: ['argv'], additionalProperties: false },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false } },
  { name: 'http_get', title: 'Fetch a web page', description: 'Fetch a page with HTTP GET. Only sites the session allows can be reached (https only).',
    inputSchema: { type: 'object', properties: { url: str(4096, 'https URL'), why }, required: ['url'], additionalProperties: false },
    annotations: { readOnlyHint: true, openWorldHint: true } },
  { name: 'llm_chat', title: 'Ask the session\'s model', description: 'Send messages to the model configured for this session and get its reply.',
    inputSchema: { type: 'object', properties: { messages: { type: 'array', minItems: 1, maxItems: 100, items: { type: 'object',
      properties: { role: { type: 'string', enum: ['system', 'user', 'assistant'] }, content: { type: 'string', maxLength: 100000 } }, required: ['role', 'content'], additionalProperties: false } }, why },
      required: ['messages'], additionalProperties: false },
    annotations: { readOnlyHint: true, openWorldHint: true } },
];

const ERR = { parse: -32700, invalid: -32600, method: -32601, params: -32602, internal: -32603 };
const rpcError = (id, code, message) => ({ jsonrpc: '2.0', id: id ?? null, error: { code, message } });
const rpcResult = (id, result) => ({ jsonrpc: '2.0', id, result });

const json = (obj, status = 200, extra = {}) =>
  new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...extra } });

/** Check a tools/call's arguments against the tool's schema (the subset of JSON Schema used above). */
function checkArgs(tool, args) {
  if (args === undefined) args = {};
  if (args === null || typeof args !== 'object' || Array.isArray(args)) return 'arguments must be an object';
  const sch = tool.inputSchema;
  for (const k of Object.keys(args)) if (!(k in sch.properties)) return `unexpected argument: ${k}`;
  for (const k of sch.required) if (args[k] === undefined) return `missing argument: ${k}`;
  const bad = (k, why2) => `argument ${k}: ${why2}`;
  const check = (k, v, s) => {
    if (s.type === 'string') {
      if (typeof v !== 'string') return bad(k, 'must be a string');
      if (s.minLength !== undefined && v.length < s.minLength) return bad(k, 'must not be empty');
      if (s.maxLength !== undefined && v.length > s.maxLength) return bad(k, `is longer than ${s.maxLength} characters`);
      if (v.includes('\0')) return bad(k, 'must not contain a NUL character');
      if (s.enum && !s.enum.includes(v)) return bad(k, `must be one of ${s.enum.join(', ')}`);
    } else if (s.type === 'integer') {
      if (!Number.isInteger(v) || v < s.minimum || v > s.maximum) return bad(k, `must be a whole number from ${s.minimum} to ${s.maximum}`);
    } else if (s.type === 'array') {
      if (!Array.isArray(v) || v.length < (s.minItems ?? 0) || v.length > s.maxItems) return bad(k, `must be a list of ${s.minItems ?? 0} to ${s.maxItems}`);
      for (const [i, item] of v.entries()) { const e = check(`${k}[${i}]`, item, s.items); if (e) return e; }
    } else if (s.type === 'object') {
      if (v === null || typeof v !== 'object' || Array.isArray(v)) return bad(k, 'must be an object');
      for (const kk of Object.keys(v)) if (!(kk in s.properties)) return bad(k, `unexpected field ${kk}`);
      for (const kk of s.required || []) if (v[kk] === undefined) return bad(k, `missing field ${kk}`);
      for (const [kk, vv] of Object.entries(v)) { const e = check(`${k}.${kk}`, vv, s.properties[kk]); if (e) return e; }
    }
    return null;
  };
  for (const [k, v] of Object.entries(args)) { const e = check(k, v, sch.properties[k]); if (e) return e; }
  return null;
}

/** What a tool call returns to the model: the result, or a tool error that says why and what to do. */
export function toolResult(r) {
  const text = (t, isError) => ({ content: [{ type: 'text', text: t }], isError });
  if (r.status === 200 && r.json && typeof r.json.verdict === 'string') {
    const v = r.json;
    if (v.verdict === 'allow') return text(typeof v.result === 'string' ? v.result : JSON.stringify(v.result, null, 2), false);
    const reason = v.reason || 'refused';
    const over = /^run (halted|stopped)/.test(reason);
    return text(`Refused by the session broker: ${reason}.` + (over ? ' The session is over: no further tool call will run.'
      : ' This is outside what this session allows. Do not retry it; tell the user what you were trying to do.'), true);
  }
  const e = (r.json && r.json.error) || { code: 'error', message: `the session returned status ${r.status}` };
  return text(`The session could not run this tool call: ${e.message} (${e.code}).`, true);
}

async function handleRequest(rpc, ctx) {
  const { id, method, params } = rpc;
  switch (method) {
    case 'initialize': {
      const asked = params && typeof params.protocolVersion === 'string' ? params.protocolVersion : null;
      return rpcResult(id, { protocolVersion: MCP_VERSIONS.includes(asked) ? asked : MCP_VERSIONS[0],
        capabilities: { tools: { listChanged: false } }, serverInfo: { name: 'monkeyitm-session', title: 'MonkeyITM session', version: '1' }, instructions: INSTRUCTIONS });
    }
    case 'ping': return rpcResult(id, {});
    case 'tools/list': return rpcResult(id, { tools: TOOLS });
    case 'tools/call': {
      if (!params || typeof params.name !== 'string') return rpcError(id, ERR.params, 'tools/call needs a tool name');
      const tool = TOOLS.find((t) => t.name === params.name);
      if (!tool) return rpcError(id, ERR.params, `Unknown tool: ${String(params.name).slice(0, 60)}`);
      const err = checkArgs(tool, params.arguments);
      if (err) return rpcError(id, ERR.params, `Invalid arguments for ${tool.name}: ${err}`);
      const { why: justification, ...p } = params.arguments || {};
      const r = await ctx.callIntent({ action: tool.name, params: p, justification: justification || 'via MCP' });
      return rpcResult(id, toolResult(r));
    }
    default: return rpcError(id, ERR.method, `Method not found: ${String(method).slice(0, 60)}`);
  }
}

/** Handle one JSON-RPC message; returns the response object, or null for a notification or a response. */
async function handleMessage(msg, ctx) {
  if (msg === null || typeof msg !== 'object' || Array.isArray(msg) || msg.jsonrpc !== '2.0') return rpcError(msg && msg.id, ERR.invalid, 'not a JSON-RPC 2.0 message');
  const isRequest = typeof msg.method === 'string' && msg.id !== undefined && msg.id !== null;
  if (typeof msg.method === 'string' && !isRequest) return null;           // a notification
  if (msg.method === undefined && (msg.result !== undefined || msg.error !== undefined)) return null;   // a response to us (we send no requests)
  if (!isRequest) return rpcError(msg.id, ERR.invalid, 'not a request');
  if (typeof msg.id !== 'string' && typeof msg.id !== 'number') return rpcError(null, ERR.invalid, 'id must be a string or a number');
  try { return await handleRequest(msg, ctx); } catch (e) {
    console.error('mcp error', e && e.stack ? e.stack : e);
    return rpcError(msg.id, ERR.internal, 'internal error');
  }
}

/** The HTTP side. ctx: { siteOrigin, callIntent(intent) -> {status, json} }. */
export async function handleMcpRequest(req, ctx) {
  if (req.method !== 'POST') {
    // No server-sent events and no MCP sessions: say so, as the spec allows.
    return new Response(JSON.stringify(rpcError(null, ERR.invalid, 'this endpoint takes POST only (no event stream, no MCP session)')),
      { status: 405, headers: { 'Content-Type': 'application/json', Allow: 'POST' } });
  }
  // DNS-rebinding defence (spec: servers MUST validate Origin). Agents send none; a browser page must be ours.
  const origin = req.headers.get('origin');
  if (origin !== null && origin !== ctx.siteOrigin) return json(rpcError(null, ERR.invalid, 'Origin not allowed'), 403);
  const ver = req.headers.get('mcp-protocol-version');
  if (ver !== null && !MCP_VERSIONS.includes(ver)) return json(rpcError(null, ERR.invalid, `unsupported MCP-Protocol-Version; supported: ${MCP_VERSIONS.join(', ')}`), 400);

  const text = await req.text();
  if (text.length > MAX_BODY) return json(rpcError(null, ERR.invalid, `the request is over ${MAX_BODY} bytes`), 413);
  let body;
  try { body = JSON.parse(text); } catch { return json(rpcError(null, ERR.parse, 'Parse error'), 400); }

  if (Array.isArray(body)) {
    // Batching exists in 2025-03-26 and 2024-11-05 and was removed in 2025-06-18.
    if (ver === '2025-06-18') return json(rpcError(null, ERR.invalid, 'JSON-RPC batching is not supported in protocol version 2025-06-18'), 400);
    if (body.length === 0 || body.length > MAX_BATCH) return json(rpcError(null, ERR.invalid, `a batch holds 1 to ${MAX_BATCH} messages`), 400);
    const out = (await Promise.all(body.map((m) => handleMessage(m, ctx)))).filter((r) => r !== null);
    return out.length ? json(out) : new Response(null, { status: 202 });
  }
  const res = await handleMessage(body, ctx);
  if (res === null) return new Response(null, { status: 202 });
  return json(res, res.error && (res.error.code === ERR.invalid) ? 400 : 200);
}
