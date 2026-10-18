// Check the session MCP endpoint (worker/mcp.js) against the OFFICIAL MCP SDK client, so it is tested
// against an independent implementation of the protocol and not only against our own test client.
//
//     mkdir <dir> && cd <dir> && npm init -y && npm install @modelcontextprotocol/sdk
//     cd site && MCP_SDK_DIR=<dir> node mcp-sdk-check.mjs
//
// Starts `wrangler dev --local` with a throwaway database, opens a session with a fake runner behind it,
// and connects with the SDK's StreamableHTTPClientTransport: initialize, list the tools, call them.
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { execSync } from 'node:child_process';

const SDK = process.env.MCP_SDK_DIR;
if (!SDK) { console.log('set MCP_SDK_DIR to a folder where @modelcontextprotocol/sdk is installed'); process.exit(2); }
const sdkFile = (p) => pathToFileURL(join(SDK, 'node_modules', '@modelcontextprotocol', 'sdk', 'dist', 'esm', p)).href;
const { Client } = await import(sdkFile('client/index.js'));
const { StreamableHTTPClientTransport } = await import(sdkFile('client/streamableHttp.js'));

const WRANGLER = (() => {
  const local = join(process.cwd(), 'node_modules', 'wrangler', 'bin', 'wrangler.js');
  if (existsSync(local)) return local;
  return join(execSync('npm root -g', { encoding: 'utf8' }).trim(), 'wrangler', 'bin', 'wrangler.js');
})();
const PORT = 8797, BASE = `http://127.0.0.1:${PORT}`, ADMIN = 'a'.repeat(40);
const dir = mkdtempSync(join(tmpdir(), 'mitm-mcp-'));
const sha = (s) => createHash('sha256').update(s).digest('hex');
let pass = 0, failed = 0;
const check = (name, ok, detail = '') => { ok ? pass++ : failed++; console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && detail ? '   [' + String(detail).slice(0, 300) + ']' : ''}`); };
const wr = (args) => { const r = spawnSync(process.execPath, [WRANGLER, ...args], { encoding: 'utf8' }); if (r.status !== 0) throw new Error(r.stdout + r.stderr); return r.stdout; };
const sql = (q) => wr(['d1', 'execute', 'monkeyitm-vm', '--local', '--persist-to', dir, '--json', '--command', q]);
async function call(method, path, { key, body, headers = {} } = {}) {
  const h = { ...headers };
  if (key) h.authorization = `Bearer ${key}`;
  if (body !== undefined) h['content-type'] = 'application/json';
  const res = await fetch(BASE + path, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text();
  let json = null; try { json = JSON.parse(text); } catch { /* not json */ }
  return { status: res.status, json, text };
}

let server;
try {
  wr(['d1', 'migrations', 'apply', 'monkeyitm-vm', '--local', '--persist-to', dir]);
  const t = Math.floor(Date.now() / 1000);
  for (const q of [
    `INSERT INTO users (id, github_id, login, email, created_at, last_login, terms_version, terms_accepted_at) VALUES (1, 100, 'alice', 'alice@example.com', ${t}, ${t}, '2026-10-02-v1', ${t})`,
    `INSERT INTO invites (email, created_at) VALUES ('alice@example.com', ${t})`,
    `INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ('${sha('1'.repeat(64))}', 1, ${t + 3600})`]) sql(q);
  server = spawn(process.execPath, [WRANGLER, 'dev', '--local', '--compatibility-date', '2026-06-01', '--port', String(PORT), '--persist-to', dir,
    '--var', `ADMIN_TOKEN:${ADMIN}`, '--var', 'KEY_SECRET:' + 'k'.repeat(40), '--var', 'REPORT_SIGNING_KEY:sign-sign-sign-sign-sign-sign'], { stdio: 'ignore' });
  for (let i = 0; i < 120; i++) { try { if ((await fetch(BASE + '/v1/healthz')).ok) break; } catch { /* not up */ } await new Promise((r) => setTimeout(r, 500)); }

  console.log('\nSetup');
  const cookie = { cookie: `mitm_s=${'1'.repeat(64)}`, origin: BASE };
  const SK = (await call('POST', '/api/keys', { body: { label: 's', scopes: ['sessions:write', 'jobs:read', 'kill'] }, headers: cookie })).json.key;
  const rn = (await call('POST', '/admin/runners', { body: { label: 'r' }, headers: { 'x-admin-token': ADMIN } })).json;
  const s = (await call('POST', '/v1/sessions', { key: SK, body: { name: 'mcp', ttl_s: 600, model: { url: 'https://integrate.api.nvidia.com/v1/chat/completions', name: 'm', key: 'dummy-key-0000' } } })).json;
  sql(`UPDATE runs SET status = 'leased', runner_id = '${rn.id}', lease_expires_at = ${t + 600} WHERE id = '${s.run_id}'`);
  await call('POST', `/runner/v1/sessions/${s.id}/ready`, { key: rn.token });
  check('a session is open with a runner behind it', !!s.id && !!s.token);
  let stop = false;
  const runner = (async () => {   // answers like a broker: allows reads, refuses the rest
    while (!stop) {
      const r = await call('GET', `/runner/v1/sessions/${s.id}/next?wait=2`, { key: rn.token });
      if (r.status !== 200 || !r.json.intent) { if (r.json && (r.json.kill || r.json.end)) break; continue; }
      const a = r.json.intent.action;
      const reply = a === 'read_file' ? { id: r.json.id, verdict: 'allow', result: { content: 'hello from the broker' }, reason: 'ok' } : { id: r.json.id, verdict: 'deny', result: null, reason: 'not allowed here' };
      await call('POST', `/runner/v1/sessions/${s.id}/reply`, { key: rn.token, body: { id: r.json.id, reply } });
    }
  })();
  await new Promise((r) => setTimeout(r, 300));

  console.log('\nThe official SDK client');
  const transport = new StreamableHTTPClientTransport(new URL(`${BASE}/v1/sessions/${s.id}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${s.token}` } } });
  const client = new Client({ name: 'sdk-check', version: '1.0.0' });
  await client.connect(transport);
  check('the SDK connects (initialize, then the initialized notification)', true);
  check('it reads our server info and the tools capability', client.getServerVersion()?.name === 'monkeyitm-session' && !!client.getServerCapabilities()?.tools, JSON.stringify(client.getServerVersion()));
  const listed = await client.listTools();
  check('listTools returns the five tools with schemas', listed.tools.length === 5 && listed.tools.every((t) => t.inputSchema?.type === 'object'), JSON.stringify(listed.tools.map((t) => t.name)));
  const ok = await client.callTool({ name: 'read_file', arguments: { path: '/workspace/a.txt', why: 'sdk check' } });
  check('callTool returns an allowed read as text', !ok.isError && ok.content[0].type === 'text' && ok.content[0].text.includes('hello from the broker'), JSON.stringify(ok));
  const no = await client.callTool({ name: 'exec', arguments: { argv: ['ls'] } });
  check('a refused call comes back as a tool error with the broker\'s reason', no.isError === true && no.content[0].text.includes('Refused by the session broker: not allowed here'), JSON.stringify(no));
  let threw = null;
  try { await client.callTool({ name: 'read_file', arguments: {} }); } catch (e) { threw = e; }
  check('invalid arguments surface as an MCP protocol error (-32602)', threw && threw.code === -32602, threw && String(threw.message));
  let threw2 = null;
  try { await client.callTool({ name: 'no_such_tool', arguments: {} }); } catch (e) { threw2 = e; }
  check('an unknown tool is a protocol error too', threw2 && threw2.code === -32602, threw2 && String(threw2.message));
  await client.ping();
  check('ping works', true);
  await client.close();
  check('the client closes cleanly (DELETE is answered 405, which the spec allows)', true);
  stop = true;
  await call('POST', `/v1/sessions/${s.id}/kill`, { key: SK });
  await Promise.race([runner, new Promise((r) => setTimeout(r, 8000))]);
} catch (e) {
  failed++;
  console.log('\nERROR', e.stack || e);
} finally {
  if (server) { if (process.platform === 'win32') spawnSync('taskkill', ['/pid', String(server.pid), '/T', '/F'], { stdio: 'ignore' }); else server.kill('SIGKILL'); }
  await new Promise((r) => setTimeout(r, 500));
  try { rmSync(dir, { recursive: true, force: true }); } catch { /* in use */ }
  console.log(`\n${pass} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
}
