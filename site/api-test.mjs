// Tests of the public API (worker/api.js) against a real local Worker + D1.
//
//     cd site && node api-test.mjs
//
// Starts `wrangler dev --local` with a throwaway database, seeds two invited users, and drives
// the API over HTTP: customer calls with API keys, runner calls with a runner token.
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { existsSync } from 'node:fs';
import { execSync } from 'node:child_process';

// Run wrangler's own script with node: no shell, so SQL and arguments are passed untouched.
const WRANGLER = (() => {
  const local = join(process.cwd(), 'node_modules', 'wrangler', 'bin', 'wrangler.js');
  if (existsSync(local)) return local;
  const g = join(execSync('npm root -g', { encoding: 'utf8' }).trim(), 'wrangler', 'bin', 'wrangler.js');
  if (existsSync(g)) return g;
  throw new Error('wrangler is not installed');
})();

const PORT = 8799;
const BASE = `http://127.0.0.1:${PORT}`;
const ADMIN = 'a'.repeat(40);
const KEY_SECRET = 'k'.repeat(40);
const TERMS = '2026-10-17-v2';
const dir = mkdtempSync(join(tmpdir(), 'mitm-api-'));
const sha = (s) => createHash('sha256').update(s).digest('hex');
const sh = process.platform === 'win32';

let pass = 0, failed = 0;
function check(name, ok, detail = '') {
  if (ok) pass++; else failed++;
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && detail ? '   [' + String(detail).slice(0, 300) + ']' : ''}`);
}
function wr(args) {
  const r = spawnSync(process.execPath, [WRANGLER, ...args], { encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`wrangler ${args.join(' ')} failed:\n${r.stdout}\n${r.stderr}`);
  return r.stdout;
}
const sql = (q) => wr(['d1', 'execute', 'monkeyitm-vm', '--local', '--persist-to', dir, '--json', '--command', q]);
const rows = (q) => JSON.parse(sql(q))[0].results;

async function call(method, path, { key, body, headers = {}, raw } = {}) {
  const h = { ...headers };
  if (key) h.authorization = `Bearer ${key}`;
  let payload = raw;
  if (body !== undefined) { h['content-type'] = 'application/json'; payload = JSON.stringify(body); }
  const res = await fetch(BASE + path, { method, headers: h, body: payload });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* not json */ }
  return { status: res.status, json, text, headers: res.headers };
}

const MODEL_KEY = 'sk-test-0123456789abcdef';
const jobBody = (extra = {}) => ({
  name: 't', tasks: { suite: 'practice', only: ['p1-fix-bug'] },
  model: { url: 'https://integrate.api.nvidia.com/v1/chat/completions', name: 'z-ai/glm-5.3', key: MODEL_KEY },
  ...extra,
});

let server;
async function main() {
  console.log('\nSetup');
  wr(['d1', 'migrations', 'apply', 'monkeyitm-vm', '--local', '--persist-to', dir]);
  const t = Math.floor(Date.now() / 1000);
  const seed = [];
  for (const [id, login] of [[1, 'alice'], [2, 'bob']]) {
    seed.push(`INSERT INTO users (id, github_id, login, email, created_at, last_login, terms_version, terms_accepted_at) VALUES (${id}, ${id}00, '${login}', '${login}@example.com', ${t}, ${t}, '${TERMS}', ${t})`);
    seed.push(`INSERT INTO invites (email, created_at) VALUES ('${login}@example.com', ${t})`);
    seed.push(`INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ('${sha(String(id).repeat(64).slice(0, 64))}', ${id}, ${t + 3600})`);
  }
  // A third user who is signed in but not invited.
  seed.push(`INSERT INTO users (id, github_id, login, email, created_at, last_login, terms_version, terms_accepted_at) VALUES (3, 300, 'carol', 'carol@example.com', ${t}, ${t}, '${TERMS}', ${t})`);
  seed.push(`INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ('${sha('3'.repeat(64))}', 3, ${t + 3600})`);
  // A fourth user invited as a security tester (by GitHub login), who has not signed the testing agreement.
  seed.push(`INSERT INTO users (id, github_id, login, email, created_at, last_login, terms_version, terms_accepted_at) VALUES (4, 400, 'dave', 'dave@example.com', ${t}, ${t}, '${TERMS}', ${t})`);
  seed.push(`INSERT INTO invites (email, github_login, tester, created_at) VALUES ('other@example.com', 'Dave', 1, ${t})`);
  seed.push(`INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ('${sha('4'.repeat(64))}', 4, ${t + 3600})`);
  for (const s of seed) sql(s);

  server = spawn(process.execPath, [WRANGLER, 'dev', '--local', '--compatibility-date', '2026-06-01', '--port', String(PORT), '--persist-to', dir,
    '--var', `ADMIN_TOKEN:${ADMIN}`, '--var', `KEY_SECRET:${KEY_SECRET}`, '--var', 'REPORT_SIGNING_KEY:sign-sign-sign-sign-sign-sign',
    // No real-test host here, whatever a developer's site/.dev.vars says.
    '--var', 'NUCLEUS_URL:', '--var', 'NUCLEUS_SECRET:'],
  { stdio: 'ignore' });
  for (let i = 0; i < 120; i++) {
    try { if ((await fetch(BASE + '/v1/healthz')).ok) break; } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 500));
  }
  const up = await call('GET', '/v1/healthz');
  check('the Worker is up', up.status === 200, up.text);

  const cookie = (n) => ({ cookie: `mitm_s=${String(n).repeat(64).slice(0, 64)}`, origin: BASE });

  console.log('\nAuthentication');
  check('no key is refused', (await call('GET', '/v1/jobs')).status === 401);
  check('a malformed key is refused', (await call('GET', '/v1/jobs', { key: 'mitm_live_nope' })).status === 401);
  check('a well-formed but unknown key is refused', (await call('GET', '/v1/jobs', { key: 'mitm_live_' + '0'.repeat(32) })).status === 401);
  check('the site cannot make keys without a session', (await call('POST', '/api/keys', { body: {}, headers: { origin: BASE } })).status === 401);
  check('a signed-in user who is not invited gets no key', (await call('POST', '/api/keys', { body: {}, headers: cookie(3) })).status === 403);

  console.log('\nLaunch funnel');
  const reqBody = (extra) => ({ name: 'Pat', email: `pat${Math.random().toString(36).slice(2, 8)}@example.com`, organization: 'Org', role: 'Eng', use_case: 'agents', no_confidential: true, ...extra });
  const ra = await call('POST', '/api/request-access', { body: reqBody({ source: 'reddit-netsec', interest: 'tester' }), headers: { origin: BASE } });
  check('an access request is accepted', ra.status === 200, ra.text);
  check('it records where the visitor came from and what they want', rows("SELECT source, interest FROM access_requests WHERE source = 'reddit-netsec'").some((r) => r.interest === 'tester'));
  await call('POST', '/api/request-access', { body: reqBody({ source: 'Bad Tag!<x>', interest: 'admin' }), headers: { origin: BASE } });
  check('a malformed source or interest is dropped, not stored', rows("SELECT id FROM access_requests WHERE source LIKE 'Bad%' OR interest = 'admin'").length === 0);
  check('the challenge page is off until it is switched on', (await call('GET', '/challenge')).status === 404);

  console.log('\nRate limit per address');
  const flood = { 'cf-connecting-ip': '203.0.113.77' };
  let first429 = 0;
  for (let i = 1; i <= 320 && !first429; i++) {
    if ((await call('GET', '/v1/healthz', { headers: flood })).status === 429) first429 = i;
  }
  check('one address is cut off after about 300 requests a minute (429)', first429 > 250 && first429 <= 320, first429);
  check('other addresses are not affected', (await call('GET', '/v1/healthz', { headers: { 'cf-connecting-ip': '203.0.113.78' } })).status === 200);
  check('the runner channel is exempt', (await call('GET', '/runner/v1/lease', { headers: flood })).status !== 429);

  console.log('\nSecurity testers');
  const noManual = { ...cookie(4) };
  check('an unsigned tester gets no API key', (await call('POST', '/api/keys', { body: {}, headers: noManual })).status === 403);
  const toDemo = await fetch(BASE + '/demo', { headers: noManual, redirect: 'manual' });
  check('an unsigned tester is sent to the agreement', toDemo.status === 302 && (toDemo.headers.get('location') || '').endsWith('/security-agreement'), toDemo.status);
  const agr = await call('GET', '/security-agreement', { headers: noManual });
  check('the agreement page shows the agreement', agr.status === 200 && agr.text.includes('Confidential Information'), agr.status);
  check('a non-tester cannot open the agreement', (await call('GET', '/security-agreement', { headers: cookie(1) })).status === 403);
  check('a non-tester cannot sign it', (await call('POST', '/api/tester-accept', { body: { accept: true, name: 'Alice A', version: 'x' }, headers: cookie(1) })).status === 403);
  const ver = (agr.text.match(/version (\d{4}-\d\d-\d\d-tester-v\d+)/) || [])[1];
  check('signing needs a typed name', (await call('POST', '/api/tester-accept', { body: { accept: true, name: '', version: ver }, headers: noManual })).status === 400);
  check('signing needs the current version', (await call('POST', '/api/tester-accept', { body: { accept: true, name: 'Dave Tester', version: 'old' }, headers: noManual })).status === 400);
  check('a cross-origin signature is refused', (await call('POST', '/api/tester-accept', { body: { accept: true, name: 'Dave Tester', version: ver }, headers: { ...noManual, origin: 'https://evil.example' } })).status === 403);
  check('the tester signs', (await call('POST', '/api/tester-accept', { body: { accept: true, name: 'Dave Tester', version: ver }, headers: noManual })).status === 200);
  const dk = await call('POST', '/api/keys', { body: { label: 'dave' }, headers: noManual });
  check('a signed tester gets an API key', dk.status === 201 && /^mitm_live_/.test(dk.json?.key || ''), dk.text);
  const acct = await call('GET', '/account', { headers: noManual });
  check('the account page shows the signature', acct.text.includes('signed by Dave Tester'), acct.status);
  check('the signature is recorded permanently', rows("SELECT signed_name FROM tester_signatures WHERE login = 'dave'").length === 1);
  const del = await call('POST', '/api/delete', { body: {}, headers: noManual });
  check('the tester can delete their account', del.status === 200, `${del.status} ${del.text}`);
  check('the signature record survives the account deletion', rows("SELECT signed_name FROM tester_signatures WHERE login = 'dave'")[0]?.signed_name === 'Dave Tester'
    && rows("SELECT id FROM users WHERE login = 'dave'").length === 0);
  check('a cross-origin key request is refused', (await call('POST', '/api/keys', { body: {}, headers: { ...cookie(1), origin: 'https://evil.example' } })).status === 403);

  const a = await call('POST', '/api/keys', { body: { label: 'alice-all', scopes: ['jobs:write', 'jobs:read', 'kill', 'keys:admin'] }, headers: cookie(1) });
  check('an invited user creates a key', a.status === 201 && /^mitm_live_[0-9a-f]{32}$/.test(a.json?.key || ''), a.text);
  const KA = a.json.key;
  const b = await call('POST', '/api/keys', { body: { label: 'bob' }, headers: cookie(2) });
  const KB = b.json.key;
  const listed = await call('GET', '/api/keys', { headers: cookie(1) });
  check('listing keys never shows the secret', listed.status === 200 && !listed.text.includes(KA) && listed.json.keys.length === 1);
  check('the key is stored only as a hash', rows('SELECT key_hash FROM api_keys').every((r) => r.key_hash === sha(KA) || r.key_hash === sha(KB) || r.key_hash === sha(dk.json.key)));

  const ro = await call('POST', '/v1/api-keys', { key: KA, body: { label: 'ro', scopes: ['jobs:read'] } });
  check('a key makes a narrower key', ro.status === 201, ro.text);
  const KRO = ro.json.key;
  const wide = await call('POST', '/v1/api-keys', { key: KRO, body: { scopes: ['jobs:read'] } });
  check('a key without keys:admin cannot manage keys', wide.status === 403);
  const grow = await call('POST', '/v1/api-keys', { key: KA, body: { label: 'x', scopes: ['jobs:read'] } });
  const tryWider = await call('POST', '/v1/api-keys', { key: grow.json.key, body: { scopes: ['jobs:read', 'kill'] } });
  check('a key cannot grant scopes it does not hold', tryWider.status === 403 || tryWider.status === 400);
  check('a read-only key cannot create jobs', (await call('POST', '/v1/jobs', { key: KRO, body: jobBody() })).status === 403);
  check('a read-only key cannot kill', (await call('POST', '/v1/kill', { key: KRO })).status === 403);

  console.log('\nCreating jobs');
  const bad = async (extra, why) => {
    const r = await call('POST', '/v1/jobs', { key: KA, body: jobBody(extra) });
    check(`refused: ${why}`, r.status === 422, r.text);
  };
  await bad({ model: { url: 'http://integrate.api.nvidia.com/x', name: 'm', key: MODEL_KEY } }, 'a plain http model URL');
  await bad({ model: { url: 'https://169.254.169.254/latest', name: 'm', key: MODEL_KEY } }, 'an IP address as the model host');
  await bad({ model: { url: 'https://localhost/x', name: 'm', key: MODEL_KEY } }, 'localhost as the model host');
  await bad({ model: { url: 'https://user:pw@example.com/x', name: 'm', key: MODEL_KEY } }, 'credentials in the model URL');
  await bad({ model: { url: 'https://example.com:8443/x', name: 'm', key: MODEL_KEY } }, 'a port in the model URL');
  await bad({ model: { url: 'https://example.com/x', name: 'm' } }, 'neither model.key nor model.key_id');
  await bad({ model: { url: 'https://example.com/x', name: 'm', key: MODEL_KEY, key_id: 'mk_000000000000' } }, 'both model.key and model.key_id');
  await bad({ model: { url: 'https://example.com/x', name: 'm', key_id: 'nope' } }, 'a malformed model.key_id');
  await bad({ model: { url: 'https://example.com/x', name: 'm', key_id: 'mk_000000000000' } }, 'a stored key that does not exist');
  await bad({ tasks: { suite: 'practice', only: ['nope'] } }, 'an unknown task id');
  await bad({ tasks: { bundle_id: 'tb_x' } }, 'a task bundle (not built yet)');
  await bad({ mode: 'swarm' }, 'an unknown mode');
  await bad({ policy: { tripwire: 0 } }, 'a tripwire of zero');
  await bad({ policy: { allow_hosts: ['not a host'] } }, 'a malformed allow-listed host');
  await bad({ limits: { concurrency: 50 } }, 'concurrency above the plan');
  await bad({ repeat: 9 }, 'repeat above the plan');
  await bad({ webhook: 'https://example.com/h' }, 'a webhook (not built yet)');
  check('a body over the size limit is refused', (await call('POST', '/v1/jobs', { key: KA, raw: 'x'.repeat(70 * 1024), headers: { 'content-type': 'application/json' } })).status === 413);
  check('a non-JSON body is refused', (await call('POST', '/v1/jobs', { key: KA, raw: 'not json', headers: { 'content-type': 'application/json' } })).status === 400);

  const j1 = await call('POST', '/v1/jobs', { key: KA, body: jobBody(), headers: { 'idempotency-key': 'one' } });
  check('a valid job is accepted', j1.status === 202 && j1.json.runs === 1, j1.text);
  const j1b = await call('POST', '/v1/jobs', { key: KA, body: jobBody(), headers: { 'idempotency-key': 'one' } });
  check('the same Idempotency-Key returns the same job', j1b.json?.id === j1.json.id && j1b.json.repeated === true);
  const stored = rows(`SELECT model_key_enc, spec FROM jobs WHERE id = '${j1.json.id}'`)[0];
  check('the model key is encrypted at rest', stored.model_key_enc && !stored.model_key_enc.includes(MODEL_KEY) && !stored.spec.includes(MODEL_KEY));
  check('the job response and the job never carry the model key',
    !j1.text.includes(MODEL_KEY) && !(await call('GET', `/v1/jobs/${j1.json.id}`, { key: KA })).text.includes(MODEL_KEY));

  console.log('\nTenant isolation');
  check("another organization cannot read the job", (await call('GET', `/v1/jobs/${j1.json.id}`, { key: KB })).status === 404);
  check("another organization cannot kill the job", (await call('POST', `/v1/jobs/${j1.json.id}/kill`, { key: KB })).status === 404);
  check("another organization cannot delete the job", (await call('DELETE', `/v1/jobs/${j1.json.id}`, { key: KB })).status === 404);
  check("another organization's job list is empty", (await call('GET', '/v1/jobs', { key: KB })).json.jobs.length === 0);
  check('the owner sees the job in the list', (await call('GET', '/v1/jobs', { key: KA })).json.jobs.some((j) => j.id === j1.json.id));

  console.log('\nThe runner protocol');
  check('runner endpoints refuse a customer key', (await call('POST', '/runner/v1/lease', { key: KA })).status === 401);
  check('runner endpoints refuse no token', (await call('POST', '/runner/v1/lease')).status === 401);
  check('creating a runner needs the admin token', (await call('POST', '/admin/runners', { body: { label: 'x' } })).status === 401);
  check('a wrong admin token is refused', (await call('POST', '/admin/runners', { body: {}, headers: { 'x-admin-token': 'b'.repeat(40) } })).status === 401);
  const rn = await call('POST', '/admin/runners', { body: { label: 'test' }, headers: { 'x-admin-token': ADMIN } });
  check('the admin creates a runner', rn.status === 201 && /^mitr_[0-9a-f]{32}$/.test(rn.json?.token || ''), rn.text);
  const KR = rn.json.token;
  check('customer endpoints refuse a runner token', (await call('GET', '/v1/jobs', { key: KR })).status === 401);

  const lease = await call('POST', '/runner/v1/lease', { key: KR });
  check('the runner leases the queued run', lease.status === 200 && lease.json.task === 'p1-fix-bug' && lease.json.job_id === j1.json.id, lease.text);
  check('the lease carries the task spec but not the model key', !lease.text.includes(MODEL_KEY) && lease.json.model.name === 'z-ai/glm-5.3');
  const RUN = lease.json.run_id;
  check('the job is now running', (await call('GET', `/v1/jobs/${j1.json.id}`, { key: KA })).json.status === 'running');
  const mk = await call('POST', `/runner/v1/runs/${RUN}/model-key`, { key: KR });
  check('the runner holding the lease gets the model key', mk.status === 200 && mk.json.key === MODEL_KEY);
  const other = (await call('POST', '/admin/runners', { body: { label: 'other' }, headers: { 'x-admin-token': ADMIN } })).json.token;
  check('another runner cannot fetch that key', (await call('POST', `/runner/v1/runs/${RUN}/model-key`, { key: other })).status === 404);
  check('another runner cannot heartbeat that run', (await call('POST', `/runner/v1/runs/${RUN}/heartbeat`, { key: other })).status === 404);

  // Preview plan: one run at a time.
  const j2 = await call('POST', '/v1/jobs', { key: KA, body: jobBody({ tasks: { suite: 'practice', only: ['p2-summarize-injected'] } }) });
  check('a second run waits while the first is active (preview concurrency 1)', (await call('POST', '/runner/v1/lease', { key: KR })).status === 204);

  const hb = await call('POST', `/runner/v1/runs/${RUN}/heartbeat`, { key: KR });
  check('a heartbeat says keep going', hb.status === 200 && hb.json.kill === false, hb.text);
  const up1 = await call('POST', `/runner/v1/runs/${RUN}/artifacts`, { key: KR, body: { kind: 'log', body: '{"events":[]}' } });
  check('the runner uploads the log', up1.status === 200);
  await call('POST', `/runner/v1/runs/${RUN}/artifacts`, { key: KR, body: { kind: 'score', body: '{"result":{"overall":"pass"}}' } });
  await call('POST', `/runner/v1/runs/${RUN}/artifacts`, { key: KR, body: { kind: 'transcript', body: 'hello' } });
  check('an unknown artifact kind is refused', (await call('POST', `/runner/v1/runs/${RUN}/artifacts`, { key: KR, body: { kind: 'binary', body: 'x' } })).status === 400);
  check('an oversized artifact is refused', (await call('POST', `/runner/v1/runs/${RUN}/artifacts`, { key: KR, body: { kind: 'log', body: 'x'.repeat(901 * 1024) }, raw: undefined })).status === 413);

  const done = await call('POST', `/runner/v1/runs/${RUN}/complete`, { key: KR, body: { status: 'finished', result: { overall: 'pass', completed: true, beyond_scope: 0, critical: 0, halted: false, flagged_injection: true, log_chain: { head: 'ab'.repeat(32), rows: 9 } } } });
  check('the run completes', done.status === 200 && done.json.status === 'finished', done.text);
  const jv = (await call('GET', `/v1/jobs/${j1.json.id}`, { key: KA })).json;
  check('the job finishes with a pass gate', jv.status === 'finished' && jv.gate === 'pass', JSON.stringify(jv));
  check('the model key is wiped when the job ends', rows(`SELECT model_key_enc FROM jobs WHERE id = '${j1.json.id}'`)[0].model_key_enc === null);
  check('a finished run no longer releases a key', (await call('POST', `/runner/v1/runs/${RUN}/model-key`, { key: KR })).status === 409);
  check('the customer reads the log', (await call('GET', `/v1/jobs/${j1.json.id}/runs/${RUN}/log`, { key: KA })).text === '{"events":[]}');
  check('the customer reads the score', (await call('GET', `/v1/jobs/${j1.json.id}/runs/${RUN}/score`, { key: KA })).json?.result?.overall === 'pass');
  check('the customer reads the transcript', (await call('GET', `/v1/jobs/${j1.json.id}/runs/${RUN}/transcript`, { key: KA })).text === 'hello');
  check("another organization cannot read the log", (await call('GET', `/v1/jobs/${j1.json.id}/runs/${RUN}/log`, { key: KB })).status === 404);
  const rep = await call('GET', `/v1/jobs/${j1.json.id}/report`, { key: KA });
  check('the report names the gate and counts', rep.json?.tier_gate === 'pass' && rep.json.counts.pass === 1, rep.text);
  check('the markdown report reads well', (await call('GET', `/v1/jobs/${j1.json.id}/report?format=md`, { key: KA })).text.includes('Gate: PASS'));
  check('the report counts the planted instruction the agent told the user about',
    rep.json.counts.injection_tasks === 1 && rep.json.counts.injection_flagged === 1 && rep.json.runs[0].flagged_injection === true, rep.text);
  check('the run records the head and length of its log chain', rep.json.runs[0].log_chain.head === 'ab'.repeat(32) && rep.json.runs[0].log_chain.rows === 9, rep.text);
  check('the signed incident export includes the chain head', JSON.stringify((await call('GET', `/v1/jobs/${j1.json.id}/incident`, { key: KA })).json.document.runs[0].log_chain).includes('ab'.repeat(32)));
  check('a malformed chain head is not stored', await (async () => {
    const jx = await call('POST', '/v1/jobs', { key: KA, body: jobBody() });
    const rx = rows(`SELECT id FROM runs WHERE job_id = '${jx.json.id}'`)[0].id;
    sql(`UPDATE runs SET status = 'leased', runner_id = '${rn.json.id}', lease_expires_at = ${Math.floor(Date.now() / 1000) + 600} WHERE id = '${rx}'`);
    await call('POST', `/runner/v1/runs/${rx}/complete`, { key: KR, body: { status: 'finished', result: { overall: 'pass', completed: true, log_chain: { head: 'not-a-hash', rows: 3 } } } });
    return rows(`SELECT log_chain_head FROM runs WHERE id = '${rx}'`)[0].log_chain_head === null;
  })());
  check('the markdown report says so, as a note', (await call('GET', `/v1/jobs/${j1.json.id}/report?format=md`, { key: KA })).text.includes('Planted instructions the agent told the user about: 1 of 1'));
  check('a run that is not an injection task carries no such flag', (await call('GET', `/v1/jobs/${j2.json.id}/runs`, { key: KA })).json.runs[0].flagged_injection === null);
  const inc = await call('GET', `/v1/jobs/${j1.json.id}/incident`, { key: KA });
  check('the incident export is signed', inc.status === 200 && /^[0-9a-f]{64}$/.test(inc.json?.signature || ''), inc.text);
  check('a job that is over can be deleted', (await call('DELETE', `/v1/jobs/${j1.json.id}`, { key: KA })).status === 200);
  check('its artifacts are gone with it', rows(`SELECT COUNT(*) AS n FROM artifacts WHERE run_id = '${RUN}'`)[0].n === 0);

  console.log('\nThe kill switch');
  check('an active job cannot be deleted', (await call('DELETE', `/v1/jobs/${j2.json.id}`, { key: KA })).status === 409);
  const j3 = await call('POST', '/v1/jobs', { key: KA, body: jobBody({ tasks: { suite: 'practice', only: ['p3-fix-config-scope', 'p4-fetch-title'] } }) });
  const l2 = await call('POST', '/runner/v1/lease', { key: KR });
  check('the runner leases the next run (oldest first)', l2.status === 200 && l2.json.job_id === j2.json.id, l2.text);
  const killed = await call('POST', `/v1/jobs/${j2.json.id}/kill`, { key: KA });
  check('killing a job signals its active run', killed.status === 202 && killed.json.runs_signalled === 1, killed.text);
  const hb2 = await call('POST', `/runner/v1/runs/${l2.json.run_id}/heartbeat`, { key: KR });
  check('the next heartbeat says kill', hb2.json?.kill === true, hb2.text);
  check('a runner told to stop gets no model key', (await call('POST', `/runner/v1/runs/${l2.json.run_id}/model-key`, { key: KR })).status === 409);
  const d2 = await call('POST', `/runner/v1/runs/${l2.json.run_id}/complete`, { key: KR, body: { status: 'finished', result: { overall: 'pass', completed: false } } });
  check('a run the owner stopped is recorded as killed whatever the runner says', d2.json?.status === 'killed', d2.text);
  const kj = (await call('GET', `/v1/jobs/${j2.json.id}`, { key: KA })).json;
  check('the job is killed, with the time to stop', kj.status === 'killed' && typeof kj.seconds_to_stop === 'number', JSON.stringify(kj));
  check('the model key is wiped on a killed job', rows(`SELECT model_key_enc FROM jobs WHERE id = '${j2.json.id}'`)[0].model_key_enc === null);
  check('the report says the owner stopped it', (await call('GET', `/v1/jobs/${j2.json.id}/report?format=md`, { key: KA })).text.includes('Stopped by the owner'));

  const l3 = await call('POST', '/runner/v1/lease', { key: KR });
  check('another job continues after a single-job kill', l3.status === 200 && l3.json.job_id === j3.json.id);

  console.log('\nOrganization stop');
  const ko = await call('POST', '/v1/kill', { key: KA });
  check('the organization stop signals active runs', ko.status === 202 && ko.json.runs_signalled === 1, ko.text);
  check('queued runs are killed before they start', rows(`SELECT COUNT(*) AS n FROM runs WHERE job_id = '${j3.json.id}' AND status = 'killed'`)[0].n === 1);
  check('no run is leased while the organization is stopped', (await call('POST', '/runner/v1/lease', { key: KR })).status === 204);
  check('no job can be created while it is stopped', (await call('POST', '/v1/jobs', { key: KA, body: jobBody() })).status === 409);
  check("another organization is not affected", (await call('POST', '/v1/jobs', { key: KB, body: jobBody() })).status === 202);
  check('clearing the stop needs keys:admin', (await call('DELETE', '/v1/kill', { key: (await call('POST', '/v1/api-keys', { key: KA, body: { scopes: ['kill'] } })).json.key })).status === 403);
  check('the owner clears the stop', (await call('DELETE', '/v1/kill', { key: KA })).json?.org_killed === false);
  check('jobs can be created again', (await call('POST', '/v1/jobs', { key: KA, body: jobBody() })).status === 202);

  console.log('\nLost runners, limits, audit');
  const jl = await call('POST', '/v1/jobs', { key: KB, body: jobBody({ tasks: { suite: 'practice', only: ['p4-fetch-title'] } }) });
  // Bob's first job is still queued; lease the oldest queued run, then let its lease lapse.
  const lb = await call('POST', '/runner/v1/lease', { key: KR });
  check('a run is leased for the lapse test', lb.status === 200, lb.text);
  sql(`UPDATE runs SET lease_expires_at = ${t - 100} WHERE id = '${lb.json.run_id}'`);
  const lostJob = (await call('GET', `/v1/jobs/${lb.json.job_id}`, { key: KB })).json;
  check('a run whose runner went silent is ended, not retried',
    rows(`SELECT status, note FROM runs WHERE id = '${lb.json.run_id}'`)[0].status === 'error', JSON.stringify(lostJob));
  check('its job is incomplete', ['incomplete'].includes((await call('GET', `/v1/jobs/${lb.json.job_id}`, { key: KB })).json.gate) || (await call('GET', `/v1/jobs/${lb.json.job_id}`, { key: KB })).json.status === 'running');

  const us = await call('GET', '/v1/usage', { key: KA });
  check('deleting a job does not give its runs back to the quota (usage counts the deleted job)', us.json?.plan === 'preview' && us.json.runs_this_month >= 4 && us.json.limits.concurrency === 1, us.text);
  // Monthly quota: preview allows 30 runs a month.
  sql(`UPDATE orgs SET plan = 'preview' WHERE id = (SELECT org_id FROM api_keys WHERE key_hash = '${sha(KB)}')`);
  const full = await call('POST', '/v1/jobs', { key: KB, body: jobBody({ tasks: { suite: 'practice' } }) });
  check('a job within the monthly quota is accepted', full.status === 202, full.text);
  const over = [];
  for (let i = 0; i < 6; i++) over.push((await call('POST', '/v1/jobs', { key: KB, body: jobBody({ tasks: { suite: 'practice' } }) })).status);
  check('past the monthly quota a job is refused with 429', over.includes(429), over.join(','));
  check('a bigger plan lifts the limit (set by the admin)', (await call('POST', `/admin/orgs/${rows(`SELECT org_id FROM api_keys WHERE key_hash = '${sha(KB)}'`)[0].org_id}/plan`, { body: { plan: 'subscriber' }, headers: { 'x-admin-token': ADMIN } })).status === 200);
  const au = await call('GET', '/v1/audit', { key: KA });
  check('the audit log records key, job and kill actions',
    ['api_key.create', 'job.create', 'job.kill', 'org.kill', 'org.kill.clear'].every((x) => au.json?.audit.some((e) => e.action === x)), au.text);
  check('the audit log needs keys:admin', (await call('GET', '/v1/audit', { key: KRO })).status === 403);
  console.log('\nStored model keys');
  const NV = 'https://integrate.api.nvidia.com/';
  const STORED = 'nvapi-stored-0123456789abcdef-WXYZ';
  check('creating a stored key needs keys:admin', (await call('POST', '/v1/model-keys', { key: KRO, body: { label: 'x', url_prefix: NV, key: STORED } })).status === 403);
  for (const [why, b] of [['no label', { url_prefix: NV, key: STORED }], ['a plain http prefix', { label: 'x', url_prefix: 'http://integrate.api.nvidia.com/', key: STORED }],
    ['an IP address prefix', { label: 'x', url_prefix: 'https://10.0.0.1/', key: STORED }], ['a prefix with a port', { label: 'x', url_prefix: 'https://example.com:8443/', key: STORED }],
    ['a prefix with a query', { label: 'x', url_prefix: 'https://example.com/?a=1', key: STORED }], ['a short key', { label: 'x', url_prefix: NV, key: 'abc' }]]) {
    check(`refused: ${why}`, (await call('POST', '/v1/model-keys', { key: KA, body: b })).status === 422);
  }
  const mkc = await call('POST', '/v1/model-keys', { key: KA, body: { label: 'nvidia', url_prefix: NV, key: STORED } });
  check('a stored key is created', mkc.status === 201 && /^mk_[0-9a-f]{12}$/.test(mkc.json?.id || '') && mkc.json.hint === 'WXYZ', mkc.text);
  check('the response does not contain the key', !mkc.text.includes(STORED));
  const MK = mkc.json.id;
  const mkl = await call('GET', '/v1/model-keys', { key: KRO });
  check('a read-only key lists labels, never the key', mkl.status === 200 && mkl.json.model_keys.length === 1 && !mkl.text.includes(STORED), mkl.text);
  check('the stored key is encrypted in the database', rows(`SELECT key_enc FROM model_keys WHERE id = '${MK}'`)[0].key_enc.length > 20 && !rows(`SELECT key_enc FROM model_keys WHERE id = '${MK}'`)[0].key_enc.includes('WXYZ'));
  check("another organization cannot see it", (await call('GET', '/v1/model-keys', { key: KB })).json.model_keys.length === 0);
  check("another organization cannot use it", (await call('POST', '/v1/jobs', { key: KB, body: jobBody({ model: { url: NV + 'v1/chat/completions', name: 'm', key_id: MK } }) })).status === 422);
  const bobAdmin = (await call('POST', '/api/keys', { body: { label: 'bob-admin', scopes: ['keys:admin', 'jobs:read'] }, headers: cookie(2) })).json.key;
  check("another organization, even with keys:admin, cannot delete it", (await call('DELETE', `/v1/model-keys/${MK}`, { key: bobAdmin })).status === 404);
  check("a key without keys:admin cannot delete it either", (await call('DELETE', `/v1/model-keys/${MK}`, { key: KB })).status === 403);
  check('a job cannot send the stored key to a URL outside its pin',
    (await call('POST', '/v1/jobs', { key: KA, body: jobBody({ model: { url: 'https://evil.example.com/v1/chat/completions', name: 'm', key_id: MK } }) })).status === 422);
  check('a look-alike host does not match the pin',
    (await call('POST', '/v1/jobs', { key: KA, body: jobBody({ model: { url: 'https://integrate.api.nvidia.com.evil.example/x', name: 'm', key_id: MK } }) })).status === 422);
  const js = await call('POST', '/v1/jobs', { key: KA, body: jobBody({ model: { url: NV + 'v1/chat/completions', name: 'z-ai/glm-5.3', key_id: MK } }) });
  check('a job names the stored key by id', js.status === 202, js.text);
  const jrow = rows(`SELECT model_key_enc, model_key_id, spec FROM jobs WHERE id = '${js.json.id}'`)[0];
  check('the job holds the key id, not a copy of the key', jrow.model_key_enc === null && jrow.model_key_id === MK && !jrow.spec.includes(STORED));
  check('the job response does not carry the key', !js.text.includes(STORED) && !(await call('GET', `/v1/jobs/${js.json.id}`, { key: KA })).text.includes(STORED));
  const rsun = rows(`SELECT id FROM runs WHERE job_id = '${js.json.id}'`)[0].id;
  sql(`UPDATE runs SET status = 'leased', runner_id = '${rn.json.id}', lease_expires_at = ${Math.floor(Date.now() / 1000) + 600} WHERE id = '${rsun}'`);
  const got = await call('POST', `/runner/v1/runs/${rsun}/model-key`, { key: KR });
  check('the runner holding the lease gets the stored key', got.status === 200 && got.json.key === STORED, got.text);
  check('using the key is recorded', rows(`SELECT last_used_at FROM model_keys WHERE id = '${MK}'`)[0].last_used_at !== null);
  const fin = await call('POST', `/runner/v1/runs/${rsun}/complete`, { key: KR, body: { status: 'finished', result: { overall: 'pass', completed: true } } });
  check('the stored key is NOT wiped when a job ends (it is meant to be reused)', fin.status === 200 && rows(`SELECT revoked_at FROM model_keys WHERE id = '${MK}'`)[0].revoked_at === null);
  const js2 = await call('POST', '/v1/jobs', { key: KA, body: jobBody({ model: { url: NV + 'v1/chat/completions', name: 'z-ai/glm-5.3', key_id: MK } }) });
  const rsun2 = rows(`SELECT id FROM runs WHERE job_id = '${js2.json.id}'`)[0].id;
  check('a second job reuses the same stored key', js2.status === 202);
  check('deleting the stored key works', (await call('DELETE', `/v1/model-keys/${MK}`, { key: KA })).status === 200);
  check('the deleted key is really gone from the database', rows(`SELECT key_enc, revoked_at FROM model_keys WHERE id = '${MK}'`)[0].key_enc === '' && rows(`SELECT revoked_at FROM model_keys WHERE id = '${MK}'`)[0].revoked_at !== null);
  sql(`UPDATE runs SET status = 'leased', runner_id = '${rn.json.id}', lease_expires_at = ${Math.floor(Date.now() / 1000) + 600} WHERE id = '${rsun2}'`);
  check('a queued job whose stored key was deleted gets no key', (await call('POST', `/runner/v1/runs/${rsun2}/model-key`, { key: KR })).status === 409);
  check('a deleted key cannot be used for a new job', (await call('POST', '/v1/jobs', { key: KA, body: jobBody({ model: { url: NV + 'v1/chat/completions', name: 'm', key_id: MK } }) })).status === 422);
  check('the audit log records stored-key creation and deletion',
    ['model_key.create', 'model_key.delete'].every((x) => rows(`SELECT action FROM audit WHERE action = '${x}'`).length > 0));
  console.log('\nTask bundles');
  const GOOD = { id: 'my-task', base: 'python:3.12-slim', instruction: 'Fix it.', files: { 'workspace/a.py': 'x = 1\n', 'tests/run-tests.sh': '#!/bin/bash\necho ok\n' },
    alignment: { pressure: 'injection', critical_paths: ['/workspace/.secrets/'], injection_terms: ['evil'], limits: { http_get: 2 } } };
  const mkB = (tasks, name = 'b') => call('POST', '/v1/task-bundles', { key: KA, body: { name, tasks } });
  const badB = async (why, tasks, name) => check(`refused: ${why}`, (await mkB(tasks, name)).status === 422, (await mkB(tasks, name)).text);
  check('a read-only key cannot upload a bundle', (await call('POST', '/v1/task-bundles', { key: KRO, body: { name: 'x', tasks: [GOOD] } })).status === 403);
  await badB('no name', [GOOD], '');
  await badB('no tasks', []);
  await badB('a Dockerfile', [{ ...GOOD, dockerfile: 'FROM evil' }]);
  await badB('an unknown field', [{ ...GOOD, run: 'rm -rf /' }]);
  await badB('a base image that is not allowed', [{ ...GOOD, base: 'evil:latest' }]);
  await badB('an upper-case task id', [{ ...GOOD, id: 'My-Task' }]);
  await badB('a task id used twice', [GOOD, GOOD]);
  await badB('no grader', [{ ...GOOD, files: { 'workspace/a.py': 'x' } }]);
  await badB('a file path that climbs out', [{ ...GOOD, files: { ...GOOD.files, 'workspace/../../etc/passwd': 'x' } }]);
  await badB('a file outside workspace and tests', [{ ...GOOD, files: { ...GOOD.files, 'Dockerfile': 'FROM evil' } }]);
  await badB('an absolute file path', [{ ...GOOD, files: { ...GOOD.files, '/etc/cron.d/x': 'x' } }]);
  await badB('a backslash in a path', [{ ...GOOD, files: { ...GOOD.files, 'workspace\\x': 'x' } }]);
  await badB('a NUL in a file', [{ ...GOOD, files: { ...GOOD.files, 'workspace/n': 'a\u0000b' } }]);
  await badB('a file over 256 KB', [{ ...GOOD, files: { ...GOOD.files, 'workspace/big': 'x'.repeat(257 * 1024) } }]);
  await badB('an unknown alignment field', [{ ...GOOD, alignment: { run: 'x' } }]);
  await badB('an unknown pressure', [{ ...GOOD, alignment: { pressure: 'nuclear' } }]);
  await badB('a critical path outside /workspace', [{ ...GOOD, alignment: { critical_paths: ['/etc/'] } }]);
  await badB('an allowed host that is not a host', [{ ...GOOD, alignment: { allow_hosts: ['not a host'] } }]);
  await badB('more tasks than the plan allows (5)', Array.from({ length: 6 }, (_, i) => ({ ...GOOD, id: `t${i}` })));
  const half = 'x'.repeat(250 * 1024);
  check('a bundle over the plan size (200 KB) is refused', (await mkB([{ ...GOOD, files: { ...GOOD.files, 'workspace/a': half } }])).status === 422);
  check('a request far over the plan size is refused unread', (await call('POST', '/v1/task-bundles', { key: KA, raw: 'x'.repeat(400 * 1024), headers: { 'content-type': 'application/json' } })).status === 413);
  const tb = await mkB([GOOD, { ...GOOD, id: 'second', files: { ...GOOD.files, 'workspace/.secrets/k': 'canary' } }], 'my bundle');
  check('a valid bundle is created', tb.status === 201 && /^tb_[0-9a-f]{12}$/.test(tb.json?.id || '') && tb.json.tasks.join() === 'my-task,second', tb.text);
  const TB = tb.json.id;
  const tl = await call('GET', '/v1/task-bundles', { key: KRO });
  check('a read-only key lists bundles (no file contents)', tl.status === 200 && tl.json.task_bundles.length >= 1 && !tl.text.includes('canary'));
  const tg = await call('GET', `/v1/task-bundles/${TB}`, { key: KA });
  check('a bundle shows its tasks and sizes, not their files', tg.status === 200 && tg.json.tasks.length === 2 && tg.json.tasks[0].files === 2 && !tg.text.includes('x = 1'), tg.text);
  check('another organization cannot see the bundle', (await call('GET', `/v1/task-bundles/${TB}`, { key: KB })).status === 404);
  check('another organization cannot delete the bundle', (await call('DELETE', `/v1/task-bundles/${TB}`, { key: KB })).status === 404);
  check("another organization's bundle list is empty", (await call('GET', '/v1/task-bundles', { key: KB })).json.task_bundles.length === 0);
  const tj = (tasks) => jobBody({ tasks });
  check('another organization cannot run the bundle', (await call('POST', '/v1/jobs', { key: KB, body: tj({ bundle_id: TB }) })).status === 422);
  check('a job cannot name both a suite and a bundle', (await call('POST', '/v1/jobs', { key: KA, body: tj({ suite: 'practice', bundle_id: TB }) })).status === 422);
  check('a job cannot name a task that is not in the bundle', (await call('POST', '/v1/jobs', { key: KA, body: tj({ bundle_id: TB, only: ['nope'] }) })).status === 422);
  check('a job cannot name a bundle that does not exist', (await call('POST', '/v1/jobs', { key: KA, body: tj({ bundle_id: 'tb_000000000000' }) })).status === 422);
  const bj = await call('POST', '/v1/jobs', { key: KA, body: tj({ bundle_id: TB }) });
  check('a job runs every task in the bundle', bj.status === 202 && bj.json.runs === 2, bj.text);
  const bj1 = await call('POST', '/v1/jobs', { key: KA, body: tj({ bundle_id: TB, only: ['second'] }) });
  check('a job can run just some of the tasks', bj1.status === 202 && bj1.json.runs === 1, bj1.text);
  const brun = rows(`SELECT id, task FROM runs WHERE job_id = '${bj1.json.id}'`)[0];
  check('the run is for the named task', brun.task === 'second');
  check('a runner that does not hold the lease cannot get the task', (await call('POST', `/runner/v1/runs/${brun.id}/bundle`, { key: KR })).status === 404);
  sql(`UPDATE runs SET status = 'leased', runner_id = '${rn.json.id}', lease_expires_at = ${Math.floor(Date.now() / 1000) + 600} WHERE id = '${brun.id}'`);
  const bt = await call('POST', `/runner/v1/runs/${brun.id}/bundle`, { key: KR });
  check('the runner holding the lease gets that task, files and all', bt.status === 200 && bt.json.task.id === 'second' && bt.json.task.files['workspace/.secrets/k'] === 'canary', bt.text);
  check('a customer key cannot fetch it this way', (await call('POST', `/runner/v1/runs/${brun.id}/bundle`, { key: KA })).status === 401);
  const prun = rows(`SELECT id FROM runs WHERE job_id = '${(await call('POST', '/v1/jobs', { key: KA, body: jobBody() })).json.id}'`)[0].id;
  sql(`UPDATE runs SET status = 'leased', runner_id = '${rn.json.id}', lease_expires_at = ${Math.floor(Date.now() / 1000) + 600} WHERE id = '${prun}'`);
  check('a run from the practice suite has no bundle', (await call('POST', `/runner/v1/runs/${prun}/bundle`, { key: KR })).status === 409);
  const brun2 = rows(`SELECT id FROM runs WHERE job_id = '${bj.json.id}' ORDER BY task LIMIT 1`)[0].id;
  sql(`UPDATE runs SET status = 'leased', runner_id = '${rn.json.id}', lease_expires_at = ${Math.floor(Date.now() / 1000) + 600} WHERE id = '${brun2}'`);
  check('deleting a bundle works', (await call('DELETE', `/v1/task-bundles/${TB}`, { key: KA })).status === 200);
  check('the deleted bundle is emptied in the database', rows(`SELECT body, deleted_at FROM task_bundles WHERE id = '${TB}'`)[0].body === '{"tasks":[]}');
  check('a run whose bundle was deleted gets no task', (await call('POST', `/runner/v1/runs/${brun2}/bundle`, { key: KR })).status === 409);
  check('a deleted bundle cannot start a new job', (await call('POST', '/v1/jobs', { key: KA, body: tj({ bundle_id: TB }) })).status === 422);
  const many = [];
  for (let i = 0; i < 4; i++) many.push((await mkB([{ ...GOOD, id: `m${i}` }], `m${i}`)).status);
  check('a plan limits how many bundles are kept (preview: 3)', many.filter((s) => s === 201).length === 3 && many.includes(409), many.join());
  check('the audit log records bundle creation and deletion', ['task_bundle.create', 'task_bundle.delete'].every((x) => rows(`SELECT action FROM audit WHERE action = '${x}'`).length > 0));

  console.log('\nLive sessions (the relay)');
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  // An organization may hold 10 live keys; the tests above used most of them. Retire the spent ones.
  sql(`UPDATE api_keys SET revoked_at = 1 WHERE org_id = (SELECT org_id FROM api_keys WHERE key_hash = '${sha(KA)}') AND id NOT IN ('${a.json.id}', '${ro.json.id}') AND revoked_at IS NULL`);
  check('a key cannot grant a scope it does not hold (KA has no sessions:write)',
    (await call('POST', '/v1/api-keys', { key: KA, body: { label: 'sess', scopes: ['sessions:write', 'jobs:read'] } })).status === 400);
  const SK = (await call('POST', '/api/keys', { body: { label: 'sess', scopes: ['sessions:write', 'jobs:read', 'kill'] }, headers: cookie(1) })).json.key;
  const sbody = (extra = {}) => ({ name: 'live', model: { url: 'https://integrate.api.nvidia.com/v1/chat/completions', name: 'z-ai/glm-5.3', key: MODEL_KEY }, ...extra });
  const mkSession = async (extra = {}) => {
    const r = await call('POST', '/v1/sessions', { key: SK, body: sbody(extra) });
    return { r, id: r.json?.id, token: r.json?.token, runId: r.json?.run_id };
  };
  const leaseNow = (s) => sql(`UPDATE runs SET status = 'leased', runner_id = '${rn.json.id}', lease_expires_at = ${Math.floor(Date.now() / 1000) + 600} WHERE id = '${s.runId}'`);
  const goReady = async (s) => { leaseNow(s); return call('POST', `/runner/v1/sessions/${s.id}/ready`, { key: KR }); };
  const intent = (s, body, token = s.token) => call('POST', `/v1/sessions/${s.id}/intent`, { key: token, body });
  const endSession = async (s) => call('DELETE', `/v1/sessions/${s.id}`, { key: SK });
  // A fake runner: takes intents from the relay and answers like a broker (allow reads, refuse the rest).
  const fakeRunner = (s, { haltOn, silent } = {}) => {
    const st = { stop: false, notices: [], seen: [] };
    st.done = (async () => {
      while (!st.stop) {
        const r = await call('GET', `/runner/v1/sessions/${s.id}/next?wait=2`, { key: KR });
        if (r.status !== 200) continue;
        if (r.json.kill || r.json.end) { st.notices.push(r.json); if (r.json.kill || r.json.end) break; }
        if (!r.json.intent) continue;
        st.seen.push(r.json.intent);
        if (silent) continue;
        const a = r.json.intent.action;
        const rep = a === 'read_file' ? { id: r.json.id, verdict: 'allow', result: { content: 'hello' }, reason: 'ok' }
          : { id: r.json.id, verdict: 'deny', result: null, reason: haltOn ? 'run halted by tripwire: too many denied requests' : 'not allowed here' };
        await call('POST', `/runner/v1/sessions/${s.id}/reply`, { key: KR, body: { id: r.json.id, reply: rep } });
      }
    })();
    return st;
  };
  const READ = { action: 'read_file', params: { path: '/workspace/a' }, justification: 'test' };

  check('creating a session needs sessions:write', (await call('POST', '/v1/sessions', { key: KRO, body: sbody() })).status === 403);
  check('a session refuses a plain-http model URL', (await call('POST', '/v1/sessions', { key: SK, body: sbody({ model: { url: 'http://x.example/v1', name: 'm', key: MODEL_KEY } }) })).status === 422);
  check('a session refuses a lifetime over the plan (30 min)', (await call('POST', '/v1/sessions', { key: SK, body: sbody({ ttl_s: 99999 }) })).status === 422);
  check('a session refuses a request limit over the plan (500)', (await call('POST', '/v1/sessions', { key: SK, body: sbody({ max_requests: 100000 }) })).status === 422);
  check('a session refuses a lifetime under a minute', (await call('POST', '/v1/sessions', { key: SK, body: sbody({ ttl_s: 5 }) })).status === 422);
  check('a session refuses a workspace from a bundle that is not the organization\'s', (await call('POST', '/v1/sessions', { key: SK, body: sbody({ workspace: { bundle_id: 'tb_000000000000', task: 'x' } }) })).status === 422);

  const s1 = await mkSession({ ttl_s: 600, max_requests: 8 });
  check('a session is created, with a token shown once', s1.r.status === 202 && /^ses_[0-9a-f]{16}$/.test(s1.id) && /^mts_[0-9a-f]{32}$/.test(s1.token) && s1.r.json.status === 'pending'
    && s1.r.json.intent_url.endsWith(`/v1/sessions/${s1.id}/intent`) && s1.r.json.mcp_url.endsWith('/mcp'), s1.r.text);
  check('the token is stored only as a hash', rows(`SELECT token_hash FROM live_sessions WHERE id = '${s1.id}'`)[0].token_hash === sha(s1.token));
  check('the session is a job with one run', rows(`SELECT task FROM runs WHERE id = '${s1.runId}'`)[0].task === '_session');
  check('a second live session is refused on the preview plan (1 at a time)', (await call('POST', '/v1/sessions', { key: SK, body: sbody() })).status === 429);
  check('an intent before a runner has started the session is refused', (await intent(s1, READ)).status === 409);
  check('an intent with no token is refused', (await call('POST', `/v1/sessions/${s1.id}/intent`, { body: READ })).status === 401);
  check('an intent with a wrong token is refused', (await intent(s1, READ, 'mts_' + '0'.repeat(32))).status === 401);
  check('an API key is not a session token', (await intent(s1, READ, KA)).status === 401);
  check('an intent with a foreign Origin is refused', (await call('POST', `/v1/sessions/${s1.id}/intent`, { key: s1.token, body: READ, headers: { origin: 'https://evil.example' } })).status === 403);
  check('a malformed cookie is ignored, not a 500', (await call('GET', '/', { headers: { cookie: 'mitm_s=%' } })).status < 500);
  check('an unknown session looks the same as a wrong token', (await call('POST', '/v1/sessions/ses_0000000000000000/intent', { key: s1.token, body: READ })).status === 401);

  // The runner's side
  sql(`UPDATE runs SET status = 'killed' WHERE status = 'queued' AND task != '_session'`);
  const sl = await call('POST', '/runner/v1/lease', { key: KR });
  check('the runner leases the session, with its limits and policy', sl.status === 200 && sl.json.kind === 'session' && sl.json.session.id === s1.id
    && sl.json.session.max_requests === 8 && sl.json.policy.tripwire === 10 && !sl.text.includes(MODEL_KEY), sl.text);
  check('another runner cannot act on the session', (await call('POST', `/runner/v1/sessions/${s1.id}/ready`, { key: other })).status === 404);
  check('a customer key cannot act as the runner', (await call('POST', `/runner/v1/sessions/${s1.id}/ready`, { key: KA })).status === 401);
  const t0 = Date.now();
  check('a runner polling an idle session is told 204 after the wait', (await call('GET', `/runner/v1/sessions/${s1.id}/next?wait=1`, { key: KR })).status === 204 && Date.now() - t0 >= 900);
  check('the runner marks the session ready', (await call('POST', `/runner/v1/sessions/${s1.id}/ready`, { key: KR })).json?.status === 'ready');
  check('the agent sees it ready', (await call('GET', `/v1/sessions/${s1.id}`, { key: s1.token })).json?.status === 'ready');

  const fr1 = fakeRunner(s1);
  await sleep(300);
  const a1 = await intent(s1, READ);
  check('an allowed intent returns the broker\'s verdict and result', a1.status === 200 && a1.json.verdict === 'allow' && a1.json.result.content === 'hello', a1.text);
  check('the relay gave the intent an id the broker can use', /^[0-9a-f-]{36}$/.test(fr1.seen[0]?.id || '') && fr1.seen[0].params.path === '/workspace/a');
  const a2 = await intent(s1, { action: 'exec', params: { argv: ['ls'] } });
  check('a refused intent is still a 200 with the verdict', a2.status === 200 && a2.json.verdict === 'deny' && a2.json.reason === 'not allowed here', a2.text);
  const own = { ...READ, id: 'abcdefgh1' };
  check('an intent may bring its own id', (await intent(s1, own)).status === 200);
  check('reusing an intent id is refused as a replay', (await intent(s1, own)).status === 409);
  const par = await Promise.all([intent(s1, READ), intent(s1, READ), intent(s1, READ)]);
  check('several intents at once are each answered', par.every((p) => p.status === 200 && p.json.verdict === 'allow'), par.map((p) => p.status).join());
  check('a request body over 4 MiB is refused', (await call('POST', `/v1/sessions/${s1.id}/intent`, { key: s1.token, raw: 'x'.repeat(5 * 1024 * 1024), headers: { 'content-type': 'application/json' } })).status === 413);
  check('a body that is not an intent is refused', (await intent(s1, { nope: true })).status === 400);
  const live = await call('GET', `/v1/sessions/${s1.id}`, { key: SK });
  check('the owner sees live counts', live.json?.requests === 6 && live.json.max_requests === 8 && live.json.runner_attached === true, live.text);
  await intent(s1, READ); await intent(s1, READ);
  const capped = await intent(s1, READ);
  check('past the request limit the relay refuses (429)', capped.status === 429 && capped.json.error.code === 'request_cap', capped.text);
  check('other organization cannot read the session', (await call('GET', `/v1/sessions/${s1.id}`, { key: KB })).status === 404);
  check('other organization cannot kill the session', (await call('POST', `/v1/sessions/${s1.id}/kill`, { key: KB })).status === 404);
  check('a key without the kill scope cannot kill it', (await call('POST', `/v1/sessions/${s1.id}/kill`, { key: KRO })).status === 403);
  check('there is no log until the session has ended', (await call('GET', `/v1/sessions/${s1.id}/log`, { key: SK })).status === 404);
  const dl = await endSession(s1);
  await Promise.race([fr1.done, sleep(15000)]); fr1.stop = true;
  check('ending a session tells the runner to end it', dl.status === 202 && fr1.notices.some((n) => n.end === true), JSON.stringify(fr1.notices));
  check('the session is ended and refuses more', (await call('GET', `/v1/sessions/${s1.id}`, { key: SK })).json.status === 'ended' && (await intent(s1, READ)).status === 409);
  await call('POST', `/runner/v1/runs/${s1.runId}/artifacts`, { key: KR, body: { kind: 'log', body: '{"summary":{"chain":{}}}' } });
  check('the owner reads the log once it is uploaded', (await call('GET', `/v1/sessions/${s1.id}/log`, { key: SK })).status === 200);
  await call('POST', `/runner/v1/runs/${s1.runId}/complete`, { key: KR, body: { status: 'finished', result: { overall: 'pass', completed: true } } });

  // halted by the broker's tripwire
  const s2 = await mkSession({ ttl_s: 600 });
  await goReady(s2);
  const fr2 = fakeRunner(s2, { haltOn: true });
  await sleep(300);
  const h1 = await intent(s2, { action: 'exec', params: { argv: ['cat', '/etc/shadow'] } });
  check('the broker\'s halt reaches the agent as a refusal', h1.status === 200 && h1.json.verdict === 'deny' && h1.json.reason.startsWith('run halted'), h1.text);
  await Promise.race([fr2.done, sleep(15000)]); fr2.stop = true;
  check('after a halt the session is over, nothing more is forwarded', (await call('GET', `/v1/sessions/${s2.id}`, { key: SK })).json.status === 'halted'
    && (await intent(s2, READ)).status === 409 && fr2.notices.some((n) => n.end && n.why === 'halted') && fr2.seen.length === 1, JSON.stringify(fr2.notices));
  check('a halted session frees its place on the plan', (await mkSession({ ttl_s: 60 })).r.status === 202);
  // (that last one stays pending; cancel it so the next test can create)
  await call('DELETE', `/v1/sessions/${rows(`SELECT id FROM live_sessions WHERE status = 'pending' ORDER BY created_at DESC LIMIT 1`)[0].id}`, { key: SK });
  sql(`UPDATE runs SET status = 'killed' WHERE task = '_session' AND status = 'queued'`);

  // the owner's kill
  const s3 = await mkSession({ ttl_s: 600 });
  await goReady(s3);
  const fr3 = fakeRunner(s3, { silent: true });
  await sleep(300);
  const waiting = intent(s3, READ);
  await sleep(300);
  const kr = await call('POST', `/v1/sessions/${s3.id}/kill`, { key: SK });
  const w = await waiting;
  check('killing a session answers the request that was waiting', kr.status === 202 && w.status === 409 && w.json.error.code === 'session_killed', w.text);
  await Promise.race([fr3.done, sleep(15000)]); fr3.stop = true;
  check('the runner is told to kill, at once', fr3.notices.some((n) => n.kill === true), JSON.stringify(fr3.notices));
  check('the run is marked for the kill switch (its next heartbeat says kill)', (await call('POST', `/runner/v1/runs/${s3.runId}/heartbeat`, { key: KR })).json?.kill === true);
  check('a killed session refuses everything', (await intent(s3, READ)).status === 409 && (await call('GET', `/v1/sessions/${s3.id}`, { key: SK })).json.status === 'killed');
  await call('POST', `/runner/v1/runs/${s3.runId}/complete`, { key: KR, body: { status: 'finished', result: { overall: 'pass' } } });

  // the organization stop reaches live sessions
  const s4 = await mkSession({ ttl_s: 600 });
  await goReady(s4);
  const fr4 = fakeRunner(s4);
  await sleep(300);
  check('a session works before the organization stop', (await intent(s4, READ)).status === 200);
  check('the organization stop kills live sessions too', (await call('POST', '/v1/kill', { key: KA })).status === 202 && (await call('GET', `/v1/sessions/${s4.id}`, { key: SK })).json.status === 'killed');
  await Promise.race([fr4.done, sleep(15000)]); fr4.stop = true;
  check('and the runner is told', fr4.notices.some((n) => n.kill === true));
  check('no session can be created while the organization is stopped', (await call('POST', '/v1/sessions', { key: SK, body: sbody() })).status === 409);
  await call('DELETE', '/v1/kill', { key: KA });
  await call('POST', `/runner/v1/runs/${s4.runId}/complete`, { key: KR, body: { status: 'finished', result: { overall: 'pass' } } });

  // no runner attached
  const s5 = await mkSession({ ttl_s: 600 });
  await goReady(s5);
  const nr = await intent(s5, READ);
  check('a ready session with no runner polling answers 503, not a hang', nr.status === 503 && nr.json.error.code === 'runner_unavailable', nr.text);
  // expiry
  sql(`UPDATE live_sessions SET expires_at = ${Math.floor(Date.now() / 1000) - 5} WHERE id = '${s5.id}'`);
  const ex = await intent(s5, READ);
  check('an expired session answers 410', ex.status === 410, ex.text);
  await endSession(s5);
  sql(`UPDATE live_sessions SET status = 'ended' WHERE id = '${s5.id}'`);
  await call('POST', `/runner/v1/runs/${s5.runId}/complete`, { key: KR, body: { status: 'finished', result: { overall: 'pass' } } });

  // a pending session that nobody starts expires, and its run is not left queued
  const s6 = await mkSession({ ttl_s: 60 });
  sql(`UPDATE live_sessions SET expires_at = ${Math.floor(Date.now() / 1000) - 5} WHERE id = '${s6.id}'`);
  await call('POST', '/runner/v1/lease', { key: KR });
  check('a pending session that expires is reaped (and its run is not leased)', rows(`SELECT status FROM live_sessions WHERE id = '${s6.id}'`)[0].status === 'expired'
    && rows(`SELECT status FROM runs WHERE id = '${s6.runId}'`)[0].status === 'killed');

  // a runner that goes silent loses the session
  const s7 = await mkSession({ ttl_s: 600 });
  await goReady(s7);
  sql(`UPDATE runs SET lease_expires_at = ${Math.floor(Date.now() / 1000) - 100} WHERE id = '${s7.runId}'`);
  await call('POST', '/runner/v1/lease', { key: KR });
  const lost = await call('GET', `/v1/sessions/${s7.id}`, { key: SK });
  check('a runner that stopped answering loses the session', lost.json.status === 'lost' && (await intent(s7, READ)).status === 409, lost.text);

  // MCP: the same session, spoken to the way an agent framework would
  console.log('\nMCP endpoint');
  const sm = await mkSession({ ttl_s: 600 });
  await goReady(sm);
  const frm = fakeRunner(sm);
  await sleep(300);
  const mcp = (body, headers = {}, token = sm.token) => call('POST', `/v1/sessions/${sm.id}/mcp`, { key: token, body, headers });
  const rq = (id, method, params) => ({ jsonrpc: '2.0', id, method, params });
  const minit = await mcp(rq(1, 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '1' } }));
  check('initialize negotiates the version and declares tools', minit.status === 200 && minit.json.result.protocolVersion === '2025-06-18'
    && minit.json.result.capabilities.tools && minit.json.result.serverInfo.name === 'monkeyitm-session' && minit.json.id === 1, minit.text);
  check('there is no MCP session id (every call stands alone)', minit.headers.get('mcp-session-id') === null);
  check('an unknown protocol version is answered with one we support', (await mcp(rq(2, 'initialize', { protocolVersion: '1999-01-01' }))).json.result.protocolVersion === '2025-06-18');
  check('an older version is echoed back', (await mcp(rq(3, 'initialize', { protocolVersion: '2025-03-26' }))).json.result.protocolVersion === '2025-03-26');
  const mnote = await mcp({ jsonrpc: '2.0', method: 'notifications/initialized' });
  check('a notification is accepted with 202 and no body', mnote.status === 202 && mnote.text === '');
  check('ping answers an empty result', (await mcp(rq(4, 'ping'))).json.result && Object.keys((await mcp(rq(5, 'ping'))).json.result).length === 0);
  const mtl = await mcp(rq(6, 'tools/list'));
  check('tools/list names the five tools with schemas', mtl.json.result.tools.map((t) => t.name).sort().join() === 'exec,http_get,llm_chat,read_file,write_file'
    && mtl.json.result.tools.every((t) => t.inputSchema.type === 'object' && t.description) && mtl.json.result.nextCursor === undefined, mtl.text);
  const mrd = await mcp(rq(7, 'tools/call', { name: 'read_file', arguments: { path: '/workspace/a', why: 'checking the notes' } }));
  check('a tool call returns the broker\'s result as text', mrd.json.result.isError === false && mrd.json.result.content[0].type === 'text' && mrd.json.result.content[0].text.includes('hello'), mrd.text);
  check('the reason given reaches the broker as the justification, and the tool name is the action',
    frm.seen.at(-1).action === 'read_file' && frm.seen.at(-1).justification === 'checking the notes' && frm.seen.at(-1).params.path === '/workspace/a' && !('why' in frm.seen.at(-1).params), JSON.stringify(frm.seen.at(-1)));
  const mex = await mcp(rq(8, 'tools/call', { name: 'exec', arguments: { argv: ['ls'] } }));
  check('a refused call is a tool error that carries the broker\'s reason and says what to do',
    mex.json.result.isError === true && mex.json.result.content[0].text.includes('Refused by the session broker: not allowed here') && mex.json.result.content[0].text.includes('Do not retry'), mex.text);
  check('an unknown tool is a protocol error (-32602)', (await mcp(rq(9, 'tools/call', { name: 'rm_rf', arguments: {} }))).json.error.code === -32602);
  for (const [why2, args, tool] of [['a missing argument', {}, 'read_file'], ['an unexpected argument', { path: '/workspace/a', extra: 1 }, 'read_file'], ['argv that is not a list', { argv: 'ls' }, 'exec'],
    ['a timeout out of range', { argv: ['ls'], timeout_s: 99999 }, 'exec'], ['a bad write mode', { path: '/workspace/a', content: 'x', mode: 'delete' }, 'write_file'], ['a NUL in a path', { path: '/workspace/a\u0000b' }, 'read_file'],
    ['a message with an unknown role', { messages: [{ role: 'root', content: 'x' }] }, 'llm_chat']]) {
    const r = await mcp(rq(10, 'tools/call', { name: tool, arguments: args }));
    check(`invalid arguments are refused before reaching the broker: ${why2}`, r.json.error?.code === -32602, r.text);
  }
  check('nothing invalid reached the broker', frm.seen.length === 2, frm.seen.length);
  check('a method we do not offer is -32601', (await mcp(rq(11, 'resources/list'))).json.error.code === -32601);
  check('a body that is not JSON is a 400 parse error', await (async () => { const r = await call('POST', `/v1/sessions/${sm.id}/mcp`, { key: sm.token, raw: '{nope', headers: { 'content-type': 'application/json' } }); return r.status === 400 && r.json.error.code === -32700; })());
  check('a message that is not JSON-RPC 2.0 is a 400 invalid request', await (async () => { const r = await mcp({ id: 1, method: 'ping' }); return r.status === 400 && r.json.error.code === -32600; })());
  const mbatch = await mcp([rq(12, 'ping'), rq(13, 'tools/list'), { jsonrpc: '2.0', method: 'notifications/initialized' }], { 'mcp-protocol-version': '2025-03-26' });
  check('a batch (an older protocol version) is answered with an array, notifications omitted', Array.isArray(mbatch.json) && mbatch.json.length === 2 && mbatch.json[1].result.tools.length === 5, mbatch.text);
  check('a batch is refused under protocol version 2025-06-18, which removed it', (await mcp([rq(14, 'ping')], { 'mcp-protocol-version': '2025-06-18' })).status === 400);
  check('an unsupported MCP-Protocol-Version header is a 400', (await mcp(rq(15, 'ping'), { 'mcp-protocol-version': '1999-01-01' })).status === 400);
  check('a foreign Origin is refused (DNS-rebinding defence)', (await mcp(rq(16, 'ping'), { origin: 'https://evil.example' })).status === 403);
  check('GET is answered 405 (no event stream)', (await call('GET', `/v1/sessions/${sm.id}/mcp`, { key: sm.token })).status === 405);
  check('DELETE is answered 405 (no MCP sessions)', (await call('DELETE', `/v1/sessions/${sm.id}/mcp`, { key: sm.token })).status === 405);
  check('no token is refused', (await call('POST', `/v1/sessions/${sm.id}/mcp`, { body: rq(17, 'ping') })).status === 401);
  check('a wrong token is refused', (await mcp(rq(18, 'ping'), {}, 'mts_' + '1'.repeat(32))).status === 401);
  check('an API key is not a session token here either', (await call('POST', `/v1/sessions/${sm.id}/mcp`, { key: KA, body: rq(19, 'ping') })).status === 401);
  const mbig = await mcp(rq(20, 'tools/call', { name: 'write_file', arguments: { path: '/workspace/a', content: 'x'.repeat(1000001) } }));
  check('a write over 1 MB is refused before the broker', mbig.json.error?.code === -32602 && frm.seen.length === 2);
  check('MCP calls count toward the session\'s request limit', (await call('GET', `/v1/sessions/${sm.id}`, { key: SK })).json.requests === 2);
  await call('POST', `/v1/sessions/${sm.id}/kill`, { key: SK });
  const mdead = await mcp(rq(21, 'tools/call', { name: 'read_file', arguments: { path: '/workspace/a' } }));
  check('after the owner stops the session a tool call is a tool error that says so', mdead.status === 200 && mdead.json.result.isError === true && mdead.json.result.content[0].text.includes('session_killed'), mdead.text);
  check('and the tool list still works', (await mcp(rq(22, 'tools/list'))).json.result.tools.length === 5);
  await Promise.race([frm.done, sleep(15000)]); frm.stop = true;
  await call('POST', `/runner/v1/runs/${sm.runId}/complete`, { key: KR, body: { status: 'finished', result: { overall: 'pass' } } });

  // a runner that reports the broker halted the session ends it as halted (not just ended)
  const sh = await mkSession({ ttl_s: 600 });
  await goReady(sh);
  const frh = fakeRunner(sh);
  await sleep(300);
  await call('POST', `/runner/v1/runs/${sh.runId}/complete`, { key: KR, body: { status: 'finished', result: { overall: 'fail', halted: true, halt_cause: 'critical attempt' } } });
  await Promise.race([frh.done, sleep(15000)]); frh.stop = true;
  check('a session whose run completes halted is shown as halted, and its agent is told so', (await call('GET', `/v1/sessions/${sh.id}`, { key: SK })).json.status === 'halted'
    && (await intent(sh, READ)).json?.error?.code === 'session_halted' && frh.notices.some((n) => n.end && n.why === 'halted'), JSON.stringify(frh.notices));

  // a session's workspace comes from a bundle task
  sql(`UPDATE task_bundles SET deleted_at = 1 WHERE org_id = (SELECT org_id FROM api_keys WHERE key_hash = '${sha(KA)}') AND deleted_at IS NULL`);
  const wsb = await mkB([{ ...GOOD, id: 'ws-task', files: { 'workspace/note.txt': 'from the bundle', 'tests/run-tests.sh': '#!/bin/bash\n' } }], 'ws');
  const sw = await mkSession({ ttl_s: 600, workspace: { bundle_id: wsb.json.id, task: 'ws-task' } });
  check('a session can be opened on a bundle task\'s workspace', sw.r.status === 202, sw.r.text);
  leaseNow(sw);
  const bw = await call('POST', `/runner/v1/runs/${sw.runId}/bundle`, { key: KR });
  check('the runner holding the session fetches that workspace', bw.status === 200 && bw.json.task.files['workspace/note.txt'] === 'from the bundle', bw.text);
  const sno = await mkSession({ ttl_s: 600 }).catch(() => null);
  check('a second live session is still refused while this one is open', sno && sno.r.status === 429);
  await call('POST', `/runner/v1/runs/${sw.runId}/complete`, { key: KR, body: { status: 'finished', result: { overall: 'pass' } } });
  check('a session with no workspace has no bundle to fetch', await (async () => {
    const s9 = await mkSession({ ttl_s: 600 });
    leaseNow(s9);
    const r = await call('POST', `/runner/v1/runs/${s9.runId}/bundle`, { key: KR });
    await call('POST', `/runner/v1/runs/${s9.runId}/complete`, { key: KR, body: { status: 'finished', result: { overall: 'pass' } } });
    return r.status === 409;
  })());

  // tenant isolation with a second organization
  const bsk = await call('POST', '/api/keys', { body: { label: 'bob-sess', scopes: ['sessions:write', 'jobs:read', 'kill'] }, headers: cookie(2) });
  const bs = await call('POST', '/v1/sessions', { key: bsk.json.key, body: sbody({ ttl_s: 600 }) });
  check('another organization can open its own session', bs.status === 202, bs.text);
  const s8 = await mkSession({ ttl_s: 600 });
  check('a session token opens only its own session', (await call('POST', `/v1/sessions/${s8.id}/intent`, { key: bs.json.token, body: READ })).status === 401);
  check('a session list shows only the organization\'s own sessions', (await call('GET', '/v1/sessions', { key: bsk.json.key })).json.sessions.every((x) => x.id === bs.json.id));
  await call('DELETE', `/v1/sessions/${s8.id}`, { key: SK });
  await call('DELETE', `/v1/sessions/${bs.json.id}`, { key: bsk.json.key });
  check('the audit log records session creation, end and kill', ['session.create', 'session.end', 'session.kill'].every((x) => rows(`SELECT action FROM audit WHERE action = '${x}'`).length > 0));

  check('revoking a key stops it at once', (await call('DELETE', `/v1/api-keys/${ro.json.id}`, { key: KA })).status === 200
    && (await call('GET', '/v1/jobs', { key: KRO })).status === 401);
}

try {
  await main();
} catch (e) {
  failed++;
  console.log('\nERROR', e.stack || e);
} finally {
  if (server) {
    if (sh) spawnSync('taskkill', ['/pid', String(server.pid), '/T', '/F'], { stdio: 'ignore' });
    else server.kill('SIGKILL');
  }
  await new Promise((r) => setTimeout(r, 500));
  try { rmSync(dir, { recursive: true, force: true }); } catch { /* still in use */ }
  console.log(`\n${pass} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
}
