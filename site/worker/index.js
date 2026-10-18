// MonkeyITM-VM site Worker: GitHub sign-in, terms acceptance and the gate in
// front of the test environment. Static pages are served from ./public; only
// the routes listed in wrangler.jsonc ("run_worker_first") reach this code.

import cliHtml from '../private/cli.html';
import realHtml from '../private/real.html';
import * as vm from './vm.js';
import { handleApi, cookieKeys } from './api.js';
import { TESTER_TERMS_VERSION, TESTER_AGREEMENT_HTML } from './tester.js';
export { SessionRelay } from './relay.js';

const MAX_TURNS = 60;

// The real-test notice (/terms section 20) has its own version: bump it when that notice
// changes in substance and everyone must accept it again before their next real run.
const REAL_TERMS_VERSION = '2026-10-11-real-v1';
const REAL_MAX_BODY = 80 * 1024;

// Bump this whenever /terms changes in substance: everyone must accept again.
const TERMS_VERSION = '2026-10-17-v2';
const SESSION_SECONDS = 7 * 24 * 3600;
const STATE_SECONDS = 600;
const SESSION_COOKIE = 'mitm_s';
const STATE_COOKIE = 'mitm_state';

const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const randomToken = (bytes) => hex(crypto.getRandomValues(new Uint8Array(bytes)));
const sha256 = async (s) => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
const now = () => Math.floor(Date.now() / 1000);

const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

function readCookies(req) {
  const out = {};
  for (const part of (req.headers.get('cookie') || '').split(';')) {
    const i = part.indexOf('=');
    if (i <= 0) continue;
    try { out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()); } catch { /* a malformed value is ignored, not a 500 */ }
  }
  return out;
}

function cookie(name, value, url, maxAge) {
  const secure = url.protocol === 'https:' ? '; Secure' : '';
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`;
}

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Cache-Control': 'no-store',
};

function respond(body, { status = 200, type = 'text/html; charset=utf-8', headers = {} } = {}) {
  const h = new Headers({ 'Content-Type': type, ...SECURITY_HEADERS });
  for (const [k, v] of Object.entries(headers)) {
    if (Array.isArray(v)) v.forEach((x) => h.append(k, x));
    else h.set(k, v);
  }
  return new Response(body, { status, headers: h });
}

const json = (obj, status = 200, headers = {}) =>
  respond(JSON.stringify(obj), { status, type: 'application/json', headers });

const redirect = (location, headers = {}) =>
  respond(null, { status: 302, headers: { Location: location, ...headers } });

// ---------------------------------------------------------------- pages

function page(title, body) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>${esc(title)} · MonkeyITM-VM</title><link rel="icon" href="/favicon.png"><link rel="apple-touch-icon" href="/apple-touch-icon.png">
<style>
:root{--bg:#070a0f;--panel:#0e141d;--border:#1c2634;--text:#e7edf5;--dim:#8b98ab;--cyan:#39d0ff;--yellow:#ffcc4d;--red:#ff5470}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,sans-serif}
a{color:var(--cyan)}main{max-width:640px;margin:48px auto;padding:0 16px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:24px}
h1{font-size:24px;margin:0 0 12px}p,li{color:var(--dim)}label{display:flex;gap:10px;align-items:flex-start;margin:14px 0;color:var(--text)}
input[type=checkbox]{margin-top:5px;width:18px;height:18px;flex:none}
button,.btn{display:inline-block;background:var(--cyan);color:#04121a;border:0;border-radius:10px;padding:11px 18px;font-weight:600;font-size:15px;cursor:pointer;text-decoration:none}
button:disabled{opacity:.4;cursor:not-allowed}.ghost{background:transparent;color:var(--text);border:1px solid var(--border)}
.danger{background:transparent;color:var(--red);border:1px solid var(--red)}.row{display:flex;gap:10px;flex-wrap:wrap;margin-top:18px}
.err{color:var(--red)}.small{font-size:13px}
</style></head><body><main>${body}
<p class="small" style="margin-top:28px">&copy; 2026 Daniel Oden. Open source (Apache-2.0; hosted service AGPL-3.0). <a href="/terms">Terms of Use and Privacy</a> &middot; <a href="/#legal">Legal notices</a></p>
</main></body></html>`;
}

const errorPage = (title, msg, status = 400) =>
  respond(page(title, `<div class="card"><h1>${esc(title)}</h1><p>${msg}</p><div class="row"><a class="btn ghost" href="/">Back to home</a></div></div>`), { status });

function acceptPage(user) {
  const again = user.terms_version && user.terms_version !== TERMS_VERSION;
  return page('Accept the terms', `<div class="card">
<h1>${again ? 'Our terms have changed' : 'Before you enter'}</h1>
<p>Signed in as <b>${esc(user.login)}</b> (${esc(user.email)}). The test environment is available only to people who accept its terms.</p>
<p>In short: it is a <b>simulation</b>; a containment layer mediates and <b>records</b> what your agent does; how that layer works is <b>confidential</b>; your model API key goes <b>straight from your browser to your provider</b>, never to us; nothing here is a warranty, a safety certification or an offer.</p>
<p><a href="/terms" target="_blank" rel="noopener">Read the full Terms of Use and Privacy notice</a> (version ${TERMS_VERSION}).</p>
<form id="f">
<label><input type="checkbox" id="terms"> <span>I am at least 18 years old, and I have read and agree to the Terms of Use and Privacy notice, version ${TERMS_VERSION}. <b>(required)</b></span></label>
<label><input type="checkbox" id="mkt"> <span>Email me product updates and invitations to the developer network. Optional; you can unsubscribe any time from your account page.</span></label>
<div class="row"><button id="go" disabled>Agree and continue</button><a class="btn ghost" href="/account">Account</a></div>
<p id="msg" class="err"></p>
</form></div>
<script>
const t=document.getElementById('terms'),go=document.getElementById('go');
t.addEventListener('change',()=>go.disabled=!t.checked);
document.getElementById('f').addEventListener('submit',async e=>{e.preventDefault();go.disabled=true;
 const r=await fetch('/api/accept',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({terms:t.checked,marketing:document.getElementById('mkt').checked,version:'${TERMS_VERSION}'})});
 if(r.ok)location.href='/demo';else{document.getElementById('msg').textContent='Could not save: '+(await r.text());go.disabled=false;}});
</script>`);
}

function accountPage(user, invited, tester = false) {
  const accepted = user.terms_accepted_at ? new Date(user.terms_accepted_at * 1000).toISOString().slice(0, 10) : 'not yet';
  return page('Your account', `<div class="card">
<h1>Your account</h1>
<p>GitHub: <b>${esc(user.login)}</b><br>Email: <b>${esc(user.email)}</b><br>Invitation: <b>${invited ? 'yes' : 'not yet'}</b><br>Real-test notice: <b>${user.real_terms_version ? esc(user.real_terms_version) : 'not accepted'}</b><br>Terms accepted: ${esc(user.terms_version || 'none')} (${accepted})${tester ? `<br>Security testing agreement: <b>${user.tester_terms_version === TESTER_TERMS_VERSION ? `signed by ${esc(user.tester_signed_name)} on ${new Date(user.tester_accepted_at * 1000).toISOString().slice(0, 10)}` : '<a href="/security-agreement">not signed</a>'}</b>` : ''}</p>
<label><input type="checkbox" id="mkt" ${user.marketing_opt_in ? 'checked' : ''}> <span>Email me product updates and developer-network invitations.</span></label>
<p id="saved" class="small"></p>
<div class="row"><a class="btn" href="/demo">Open the test environment</a><a class="btn ghost" href="/demo/real">Real test</a><button class="ghost" id="out">Sign out</button></div>
${invited ? `<h1 style="margin-top:28px;font-size:18px">API keys</h1>
<p class="small">For the API, the command line client and MCP. A key is shown once: copy it when it appears.</p>
<div class="row"><button id="mk">Create an API key (all scopes)</button></div>
<pre id="newkey" style="white-space:pre-wrap;word-break:break-all"></pre>` : ''}
<h1 style="margin-top:28px;font-size:18px">Delete my account</h1>
<p class="small">Removes your account, email address, consent records and sessions from our database, and deletes your real-test runs and logs from the test host. This cannot be undone.</p>
<div class="row"><button class="danger" id="del">Delete my account</button></div>
</div>
<script>
const post=(u,b)=>fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})});
document.getElementById('mkt').addEventListener('change',async e=>{const r=await post('/api/marketing',{marketing:e.target.checked});
 document.getElementById('saved').textContent=r.ok?'Saved.':'Could not save.';});
const mk=document.getElementById('mk');
if(mk)mk.onclick=async()=>{const out=document.getElementById('newkey');
 const r=await post('/api/keys',{label:'from account page',scopes:['jobs:write','jobs:read','sessions:write','kill','keys:admin']});
 const j=await r.json().catch(()=>({}));
 out.textContent=r.ok?'Your key (shown once):\\n'+j.key:'Could not create a key: '+((j.error&&(j.error.message||j.error))||r.status)+(r.status===403?' (accept the terms in the test environment first)':'');};
document.getElementById('out').onclick=async()=>{await post('/api/logout');location.href='/';};
document.getElementById('del').onclick=async()=>{if(!confirm('Delete your account permanently?'))return;
 const r=await post('/api/delete');if(r.ok)location.href='/?deleted=1';else alert('Could not delete.');};
</script>`);
}

// The public "Escape the Monkey" challenge (docs/launch/CHALLENGE_RULES.md). Off until the Worker variable
// CHALLENGE_PUBLIC is "1"; [OPEN] markers are filled in before launch.
function challengePage() {
  return page('Escape the Monkey', `<div class="card">
<h1>Escape the Monkey</h1>
<p>Bring your own AI agents and try to break out of MonkeyITM-VM: read the flag your agents are not allowed to read,
reach the network, or get out of the workbench. Every request your agents make is decided, executed or refused, and
logged in a tamper-evident chain, and you get the log.</p>
<h2>How it went the first time</h2>
<p>[OPEN: the independent red-team result, with a link to the full write-up and evidence.]</p>
<h2>Rules</h2>
<ul>
<li>Invited participants only. Request access below and choose "Trying to break it".</li>
<li>Invited participants sign the Security Testing Authorization and Confidentiality Agreement before they start.</li>
<li>Use your own agents, prompts and model endpoint; up to [OPEN: N] agents in a group run.</li>
<li>Out of bounds: other people's accounts, our providers (GitHub, Vercel, Cloudflare, NVIDIA), flooding.</li>
<li>Proof: the flag value plus your run id; we check it against the log. Report privately first.</li>
<li>Reward: [OPEN]. Window: [OPEN].</li>
</ul>
<h2>Scoreboard</h2>
<p>[OPEN: attempts, blocks, escapes.]</p>
<h2>What this does and does not show</h2>
<p>MonkeyITM contains agents that run through it. It is not antivirus and does not protect a machine from software
already running outside it. Results here are tests, not guarantees.</p>
<div class="row"><a class="btn" href="/?ref=challenge#request">Request access</a><a class="btn ghost" href="/">About MonkeyITM</a></div>
</div>`);
}

function notInvitedPage(user) {
  return page('Invitation needed', `<div class="card">
<h1>Access is by invitation</h1>
<p>You are signed in as <b>${esc(user.login)}</b> (${esc(user.email)}), but this account has not been invited to the test environment yet.</p>
<p>Early access is limited and invitations are sent one at a time. If you have not already, <a href="/#request">request access</a> using the same email address. If you were invited under a different address or GitHub account, sign in with that one.</p>
<div class="row"><a class="btn ghost" href="/">Back to home</a><a class="btn ghost" href="/account">Account</a></div>
</div>`);
}

// An invitation matches the signed-in account's verified email or its login. A tester invite (on either
// match) makes the account a security tester, who must sign the testing agreement (worker/tester.js).
async function inviteInfo(env, user) {
  const row = await env.DB.prepare(
    `SELECT MAX(tester) AS tester, COUNT(*) AS n FROM invites WHERE revoked_at IS NULL
       AND (lower(email) = lower(?) OR lower(github_login) = lower(?))`,
  ).bind(user.email, user.login).first();
  return { invited: !!(row && row.n), tester: !!(row && row.tester) };
}

function testerAgreementPage(user) {
  return page('Security testing agreement', `<div class="card">
<h1>Security Testing Authorization and Confidentiality Agreement</h1>
<p>Signed in as <b>${esc(user.login)}</b> (${esc(user.email)}). You were invited as a security tester. Please read and sign
this agreement before you start; it is what permits your testing.</p>
${TESTER_AGREEMENT_HTML}
<form id="f">
<label><span>Your full legal name</span><br><input id="name" autocomplete="name" maxlength="120" style="width:100%"></label>
<label><input type="checkbox" id="ok"> <span>I have read and agree to this agreement, version ${TESTER_TERMS_VERSION}. <b>(required)</b></span></label>
<div class="row"><button id="go" disabled>Sign and continue</button><a class="btn ghost" href="/account">Account</a></div>
<p id="msg" class="err"></p>
</form></div>
<script>
const ok=document.getElementById('ok'),nm=document.getElementById('name'),go=document.getElementById('go');
const upd=()=>go.disabled=!(ok.checked&&nm.value.trim().length>=3);ok.addEventListener('change',upd);nm.addEventListener('input',upd);
document.getElementById('f').addEventListener('submit',async e=>{e.preventDefault();go.disabled=true;
 const r=await fetch('/api/tester-accept',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({accept:ok.checked,name:nm.value.trim(),version:'${TESTER_TERMS_VERSION}'})});
 if(r.ok)location.href='/account';else{document.getElementById('msg').textContent='Could not save: '+(await r.text());upd();}});
</script>`);
}

// ---------------------------------------------------------------- access requests

const REQUEST_LIMITS = { name: 120, email: 254, organization: 160, role: 120, use_case: 2000 };
const REQUESTS_PER_ADDRESS_PER_DAY = 3;

async function requestAccess(req, env) {
  const body = await readJson(req);
  if (!body) return json({ error: 'expected a JSON form' }, 400);
  // Honeypot: a field people never see. Bots that fill it get a quiet "ok".
  if (typeof body.website === 'string' && body.website !== '') return json({ ok: true });

  const f = {};
  for (const [k, max] of Object.entries(REQUEST_LIMITS)) {
    const v = typeof body[k] === 'string' ? body[k].trim() : '';
    if (!v) return json({ error: `please fill in ${k.replace('_', ' ')}` }, 400);
    if (v.length > max) return json({ error: `${k.replace('_', ' ')} is too long (max ${max} characters)` }, 400);
    f[k] = v;
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(f.email)) return json({ error: 'please enter a valid email address' }, 400);
  if (body.no_confidential !== true) return json({ error: 'please confirm the last box' }, 400);

  // Optional funnel fields: a short source tag from the link (?ref=) and what the person wants.
  const source = typeof body.source === 'string' && /^[a-z0-9_-]{1,40}$/.test(body.source) ? body.source : null;
  const interest = ['tester', 'developer', 'enterprise'].includes(body.interest) ? body.interest : null;

  const t = now();
  const day = Math.floor(t / 86400);
  const ip = req.headers.get('cf-connecting-ip') || 'unknown';
  const ipDayHash = await sha256(`${env.REQUEST_SALT || 'monkeyitm-requests'}|${day}|${ip}`);
  const recent = await env.DB.prepare(
    'SELECT COUNT(*) AS n FROM access_requests WHERE ip_day_hash = ? AND created_at > ?',
  ).bind(ipDayHash, t - 86400).first();
  if ((recent?.n || 0) >= REQUESTS_PER_ADDRESS_PER_DAY) {
    return json({ error: 'too many requests from this network today; please try again tomorrow' }, 429);
  }
  // A repeat from the same email within a week is accepted but not stored twice.
  const dup = await env.DB.prepare(
    'SELECT id FROM access_requests WHERE lower(email) = lower(?) AND created_at > ? LIMIT 1',
  ).bind(f.email, t - 7 * 86400).first();
  if (!dup) {
    await env.DB.prepare(
      `INSERT INTO access_requests (name, email, organization, role, use_case, created_at, ip_day_hash, source, interest)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(f.name, f.email, f.organization, f.role, f.use_case, t, ipDayHash, source, interest).run();
  }
  return json({ ok: true });
}

// ---------------------------------------------------------------- sessions

async function currentUser(req, env) {
  const token = readCookies(req)[SESSION_COOKIE];
  if (!token || !/^[0-9a-f]{64}$/.test(token)) return null;
  return env.DB.prepare(
    `SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ? AND s.expires_at > ?`,
  ).bind(await sha256(token), now()).first();
}

async function startSession(env, userId) {
  const token = randomToken(32);
  await env.DB.batch([
    env.DB.prepare('DELETE FROM sessions WHERE expires_at <= ?').bind(now()),
    env.DB.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)')
      .bind(await sha256(token), userId, now() + SESSION_SECONDS),
  ]);
  return token;
}

// State-changing requests must come from our own pages.
function sameOrigin(req, url) {
  const origin = req.headers.get('origin');
  return origin !== null && origin === url.origin;
}

async function readJson(req) {
  if (!(req.headers.get('content-type') || '').startsWith('application/json')) return null;
  try {
    return await req.json();
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- GitHub OAuth

const githubWeb = (env) => env.GITHUB_BASE || 'https://github.com';
const githubApi = (env) => env.GITHUB_API || 'https://api.github.com';

function login(url, env) {
  if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET) {
    return errorPage('Sign-in is not open yet', 'Sign-in for the test environment is being set up. Please check back soon.', 503);
  }
  const state = randomToken(16);
  const q = new URLSearchParams({
    client_id: env.GITHUB_CLIENT_ID,
    redirect_uri: `${url.origin}/api/callback`,
    scope: 'read:user user:email',
    state,
    allow_signup: 'true',
  });
  return redirect(`${githubWeb(env)}/login/oauth/authorize?${q}`, {
    'Set-Cookie': cookie(STATE_COOKIE, state, url, STATE_SECONDS),
  });
}

async function callback(req, url, env) {
  const clearState = cookie(STATE_COOKIE, '', url, 0);
  const state = url.searchParams.get('state');
  const code = url.searchParams.get('code');
  const expected = readCookies(req)[STATE_COOKIE];
  if (url.searchParams.get('error')) return errorPage('Sign-in cancelled', 'GitHub sign-in was cancelled. <a href="/api/login">Try again</a>.');
  if (!state || !code || !expected || state !== expected) {
    return errorPage('Sign-in expired', 'That sign-in link is invalid or expired. <a href="/api/login">Start again</a>.');
  }

  const tokenRes = await fetch(`${githubWeb(env)}/login/oauth/access_token`, {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: env.GITHUB_CLIENT_ID,
      client_secret: env.GITHUB_CLIENT_SECRET,
      code,
      redirect_uri: `${url.origin}/api/callback`,
    }),
  });
  const tokenBody = await tokenRes.text();
  let tok = {};
  try { tok = JSON.parse(tokenBody); } catch { /* fall through to the error below */ }
  if (!tok.access_token) {
    console.log('github token exchange failed', { status: tokenRes.status, body: tokenBody });
    return errorPage('Sign-in failed', 'GitHub did not confirm the sign-in. <a href="/api/login">Try again</a>.', 502);
  }

  const gh = (path) =>
    fetch(`${githubApi(env)}${path}`, {
      headers: { Authorization: `Bearer ${tok.access_token}`, Accept: 'application/vnd.github+json', 'User-Agent': 'monkeyitm-vm-site' },
    }).then((r) => (r.ok ? r.json() : null));
  const [profile, emails] = await Promise.all([gh('/user'), gh('/user/emails')]);
  // The GitHub token is used only for these two reads and then discarded.
  const email = Array.isArray(emails) ? emails.find((e) => e.primary && e.verified)?.email : null;
  if (!profile?.id) return errorPage('Sign-in failed', 'Could not read your GitHub profile. <a href="/api/login">Try again</a>.', 502);
  if (!email) {
    return errorPage('Verified email needed', 'Your GitHub account needs a verified primary email address. Add one in GitHub settings, then <a href="/api/login">sign in again</a>.');
  }

  const t = now();
  const user = await env.DB.prepare(
    `INSERT INTO users (github_id, login, email, created_at, last_login) VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(github_id) DO UPDATE SET login = excluded.login, email = excluded.email, last_login = excluded.last_login
     RETURNING id`,
  ).bind(profile.id, String(profile.login || ''), email, t, t).first();
  const session = await startSession(env, user.id);
  return redirect('/demo', { 'Set-Cookie': [clearState, cookie(SESSION_COOKIE, session, url, SESSION_SECONDS)] });
}

// ---------------------------------------------------------------- real test (hosted nucleus)

const hostConfigured = (env) => !!(env.NUCLEUS_URL && env.NUCLEUS_SECRET);
const realModels = (env) => String(env.NUCLEUS_MODELS || '').split(',').map((s) => s.trim()).filter(Boolean);
const hostUser = (user) => `gh:${user.github_id}`;

// A signed request to the nucleus host: time, nonce and an HMAC over method, path with
// query and the body's hash. Only this Worker holds the secret.
async function hostCall(env, method, pathAndQuery, bodyObj) {
  const body = bodyObj === undefined ? '' : JSON.stringify(bodyObj);
  const ts = String(now());
  const nonce = randomToken(16);
  const msg = `${ts}\n${nonce}\n${method}\n${pathAndQuery}\n${await sha256(body)}`;
  const key = await crypto.subtle.importKey('raw', enc.encode(env.NUCLEUS_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = hex(await crypto.subtle.sign('HMAC', key, enc.encode(msg)));
  return fetch(env.NUCLEUS_URL.replace(/\/+$/, '') + pathAndQuery, {
    method,
    headers: { 'X-Nucleus-Time': ts, 'X-Nucleus-Nonce': nonce, 'X-Nucleus-Sig': sig, 'Content-Type': 'application/json' },
    body: body || undefined,
    signal: AbortSignal.timeout(20000),
  });
}

const hostDown = () => json({ error: 'The test host is not reachable right now. Please try again later.' }, 503);

// Pass the host's answer through. Its errors are short messages meant for the person.
async function relay(res, extraHeaders = {}) {
  const type = res.headers.get('content-type') || 'application/json';
  return respond(await res.text(), { status: res.status, type, headers: extraHeaders });
}

async function realApi(req, url, env, path, user, invited) {
  const method = req.method;
  if (!user) return json({ error: 'not signed in' }, 401);
  if (!invited) return json({ error: 'access is by invitation' }, 403);
  if (user.terms_version !== TERMS_VERSION) return json({ error: 'please accept the terms first', next: '/accept' }, 403);
  if (!hostConfigured(env)) return json({ error: 'The real test is not open yet.' }, 503);
  const realOk = user.real_terms_version === REAL_TERMS_VERSION;
  const u = encodeURIComponent(hostUser(user));
  const sub = path.slice('/api/real'.length) || '/';

  if (method === 'GET' && sub === '/config') {
    let singleDone = false;
    try {
      const r = await hostCall(env, 'GET', `/v1/runs?user=${u}`);
      if (r.ok) singleDone = (await r.json()).runs.some((x) => (x.mode || 'single') === 'single' && x.status === 'done');
    } catch { return hostDown(); }
    return json({ models: realModels(env), real_terms_version: REAL_TERMS_VERSION, real_terms_accepted: realOk, group_open: singleDone });
  }

  if (method === 'POST') {
    if (!sameOrigin(req, url)) return json({ error: 'bad origin' }, 403);
    const text = await req.text();
    if (text.length > REAL_MAX_BODY) return json({ error: 'too large' }, 413);
    let body = {};
    try { body = text ? JSON.parse(text) : {}; } catch { return json({ error: 'expected JSON' }, 400); }

    if (sub === '/accept') {
      if (body.accept !== true || body.version !== REAL_TERMS_VERSION) return json({ error: 'the current notice must be accepted' }, 400);
      await env.DB.prepare('UPDATE users SET real_terms_version = ?, real_terms_accepted_at = ? WHERE id = ?')
        .bind(REAL_TERMS_VERSION, now(), user.id).run();
      return json({ ok: true });
    }

    if (sub === '/runs') {
      if (!realOk) return json({ error: 'please accept the real-test notice first', need: 'real_terms' }, 403);
      // Only known fields go to the host; it checks them again.
      const clean = { user: hostUser(user), task: body.task, fixtures: body.fixtures, model: body.model, mode: body.mode };
      try { return await relay(await hostCall(env, 'POST', '/v1/runs', clean)); } catch { return hostDown(); }
    }

    const del = sub.match(/^\/runs\/([0-9a-f]{16})\/delete$/);
    if (del) {
      try { return await relay(await hostCall(env, 'DELETE', `/v1/runs/${del[1]}?user=${u}`)); } catch { return hostDown(); }
    }
    return json({ error: 'not found' }, 404);
  }

  if (method === 'GET') {
    if (sub === '/runs') {
      try { return await relay(await hostCall(env, 'GET', `/v1/runs?user=${u}`)); } catch { return hostDown(); }
    }
    const one = sub.match(/^\/runs\/([0-9a-f]{16})$/);
    if (one) {
      try { return await relay(await hostCall(env, 'GET', `/v1/runs/${one[1]}?user=${u}`)); } catch { return hostDown(); }
    }
    const log = sub.match(/^\/runs\/([0-9a-f]{16})\/log$/);
    if (log) {
      const fmt = url.searchParams.get('format') === 'txt' ? 'txt' : 'json';
      try {
        const res = await hostCall(env, 'GET', `/v1/runs/${log[1]}/log?user=${u}&format=${fmt}`);
        const dl = url.searchParams.get('download') === '1'
          ? { 'Content-Disposition': `attachment; filename="monkeyitm-run-${log[1]}.${fmt === 'txt' ? 'txt' : 'json'}"` } : {};
        return await relay(res, dl);
      } catch { return hostDown(); }
    }
  }
  return json({ error: 'not found' }, 404);
}

// ---------------------------------------------------------------- router

// When the free plan runs out (daily database or Durable Object quotas) or anything else fails, the site says it is at
// capacity instead of showing an error: a traffic spike is the signal to move to a paid plan (docs/CAPACITY.md).
function atCapacity(req) {
  const p = new URL(req.url).pathname;
  const headers = { 'Retry-After': '3600', 'Cache-Control': 'no-store' };
  if (p.startsWith('/v1/') || p.startsWith('/api/') || p.startsWith('/runner/') || p.startsWith('/admin/')) {
    return new Response(JSON.stringify({ error: { code: 'at_capacity', message: 'MonkeyITM is at capacity right now. Please try again later.' } }),
      { status: 503, headers: { ...headers, 'Content-Type': 'application/json' } });
  }
  return new Response(page('At capacity', `<div class="card"><h1>We're at capacity</h1>
<p>More people are trying MonkeyITM right now than our free hosting can serve. That's a good problem, and we're working on
more room. Please try again in an hour.</p>
<p>The code is open source, so you can also run it yourself.</p>
<div class="row"><a class="btn ghost" href="/">Back to home</a></div></div>`), { status: 503, headers: { ...headers, 'Content-Type': 'text/html; charset=utf-8' } });
}

export default {
  async fetch(req, env) {
    try {
      return await handle.fetch(req, env);
    } catch (e) {
      console.error('request failed', e && (e.stack || e.message || e));
      return atCapacity(req);
    }
  },
};

const handle = {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';
    const method = req.method;

    // Per-address rate limit on everything the Worker answers (static pages are served without it), so one address
    // cannot spend the free-plan quotas or the database reads behind every bad key. Runners are exempt: they are
    // few, hold a token only the owner issues, and long-poll on purpose. Cloudflare always sets cf-connecting-ip.
    const ip = req.headers.get('cf-connecting-ip');
    if (env.RL_IP && ip && !path.startsWith('/runner/v1/')) {
      const { success } = await env.RL_IP.limit({ key: `ip:${ip}` });
      if (!success) {
        return new Response(JSON.stringify({ error: { code: 'rate_limited', message: 'too many requests from this address; slow down and try again in a minute' } }),
          { status: 429, headers: { 'Content-Type': 'application/json', 'Retry-After': '60' } });
      }
    }

    // Public API v1 (docs/API_V1.md): keyed by bearer tokens, not by the site's session cookie.
    if (path.startsWith('/v1/') || path.startsWith('/runner/v1/') || path.startsWith('/admin/')) {
      return handleApi(req, env, url, path);
    }

    if (path === '/api/login' && method === 'GET') return login(url, env);
    if (path === '/api/callback' && method === 'GET') return callback(req, url, env);
    if (path === '/demo.html') return redirect('/demo');
    if (path === '/challenge' && method === 'GET') {
      if (env.CHALLENGE_PUBLIC !== '1') return new Response('Not found', { status: 404 });
      return respond(challengePage());
    }
    if (path === '/api/request-access' && method === 'POST') {
      if (!sameOrigin(req, url)) return json({ error: 'bad origin' }, 403);
      return requestAccess(req, env);
    }

    const user = await currentUser(req, env);
    const inv = user ? await inviteInfo(env, user) : { invited: false, tester: false };
    const invited = inv.invited;
    // A security tester who has not signed the current testing agreement gets nothing but the agreement.
    const testerPending = inv.tester && user.tester_terms_version !== TESTER_TERMS_VERSION;

    if (path.startsWith('/api/real/')) {
      if (testerPending) return json({ error: 'sign the security testing agreement first' }, 403);
      return realApi(req, url, env, path, user, invited);
    }

    if (method === 'GET' && path === '/demo/real') {
      if (!user) return redirect('/api/login');
      if (!invited) return respond(notInvitedPage(user), { status: 403 });
      if (user.terms_version !== TERMS_VERSION) return redirect('/accept');
      if (testerPending) return redirect('/security-agreement');
      return respond(realHtml);
    }
    if (method === 'GET' && (path === '/demo' || path.startsWith('/demo/'))) {
      if (!user) return redirect('/api/login');
      if (!invited) return respond(notInvitedPage(user), { status: 403 });
      if (user.terms_version !== TERMS_VERSION) return redirect('/accept');
      if (testerPending) return redirect('/security-agreement');
      return respond(cliHtml);
    }
    if (method === 'GET' && path === '/security-agreement') {
      if (!user) return redirect('/api/login');
      if (!inv.tester) return respond(notInvitedPage(user), { status: 403 });
      if (user.terms_version !== TERMS_VERSION) return redirect('/accept');
      return respond(testerAgreementPage(user));
    }
    if (method === 'GET' && path === '/accept') {
      if (!user) return redirect('/api/login');
      if (!invited) return respond(notInvitedPage(user), { status: 403 });
      if (user.terms_version === TERMS_VERSION) return redirect('/demo');
      return respond(acceptPage(user));
    }
    if (method === 'GET' && path === '/account') {
      if (!user) return redirect('/api/login');
      if (testerPending && user.terms_version === TERMS_VERSION) return redirect('/security-agreement');
      return respond(accountPage(user, invited, inv.tester));
    }
    if (method === 'GET' && path === '/api/me') {
      if (!user) return json({ signed_in: false }, 401);
      return json({
        signed_in: true,
        login: user.login,
        email: user.email,
        terms_current: user.terms_version === TERMS_VERSION,
        marketing_opt_in: !!user.marketing_opt_in,
      });
    }

    // API keys for the public API: the signed-in, invited user who accepted the terms.
    if (path === '/api/keys' && (method === 'GET' || method === 'POST')) {
      if (method === 'POST' && !sameOrigin(req, url)) return json({ error: 'bad origin' }, 403);
      if (!user) return json({ error: 'not signed in' }, 401);
      if (!invited) return json({ error: 'access is by invitation' }, 403);
      if (user.terms_version !== TERMS_VERSION) return json({ error: 'accept the current terms first' }, 403);
      if (testerPending) return json({ error: 'sign the security testing agreement first' }, 403);
      return cookieKeys(req, env, user);
    }

    if (method === 'POST' && path.startsWith('/api/')) {
      if (!sameOrigin(req, url)) return json({ error: 'bad origin' }, 403);
      if (!user) return json({ error: 'not signed in' }, 401);
      const body = (await readJson(req)) || {};
      const t = now();
      // Everything that touches the test environment needs an invitation.
      if ((path === '/api/accept' || path.startsWith('/api/cli/')) && !invited) {
        return json({ error: 'access is by invitation' }, 403);
      }

      if (path === '/api/tester-accept') {
        if (!inv.tester) return json({ error: 'only invited security testers sign this agreement' }, 403);
        if (user.terms_version !== TERMS_VERSION) return json({ error: 'accept the current terms first' }, 403);
        const name = typeof body.name === 'string' ? body.name.trim() : '';
        if (body.accept !== true || body.version !== TESTER_TERMS_VERSION) return json({ error: 'the current agreement must be accepted' }, 400);
        if (name.length < 3 || name.length > 120) return json({ error: 'type your full name to sign' }, 400);
        await env.DB.batch([
          env.DB.prepare('UPDATE users SET tester_terms_version = ?, tester_accepted_at = ?, tester_signed_name = ? WHERE id = ?')
            .bind(TESTER_TERMS_VERSION, t, name, user.id),
          env.DB.prepare('INSERT INTO tester_signatures (github_id, login, email, signed_name, version, signed_at) VALUES (?, ?, ?, ?, ?, ?)')
            .bind(user.github_id, user.login, user.email, name, TESTER_TERMS_VERSION, t),
        ]);
        return json({ ok: true });
      }
      if (testerPending && path.startsWith('/api/cli/')) return json({ error: 'sign the security testing agreement first' }, 403);
      if (path === '/api/accept') {
        if (body.terms !== true || body.version !== TERMS_VERSION) return json({ error: 'the current terms must be accepted' }, 400);
        const mkt = body.marketing === true ? 1 : 0;
        await env.DB.prepare(
          `UPDATE users SET terms_version = ?, terms_accepted_at = ?, marketing_opt_in = ?, marketing_changed_at = ? WHERE id = ?`,
        ).bind(TERMS_VERSION, t, mkt, t, user.id).run();
        return json({ ok: true });
      }
      if (path === '/api/marketing') {
        await env.DB.prepare('UPDATE users SET marketing_opt_in = ?, marketing_changed_at = ? WHERE id = ?')
          .bind(body.marketing === true ? 1 : 0, t, user.id).run();
        return json({ ok: true });
      }
      if (path === '/api/logout') {
        const token = readCookies(req)[SESSION_COOKIE];
        await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(await sha256(token)).run();
        return json({ ok: true }, 200, { 'Set-Cookie': cookie(SESSION_COOKIE, '', url, 0) });
      }
      if (path === '/api/delete') {
        // Their real runs and logs go too. If the host cannot be reached, keep the account
        // so the promise holds, and say so.
        if (hostConfigured(env)) {
          try {
            const u = encodeURIComponent(hostUser(user));
            const list = await hostCall(env, 'GET', `/v1/runs?user=${u}`);
            if (!list.ok) throw new Error('list');
            for (const r of (await list.json()).runs) {
              const d = await hostCall(env, 'DELETE', `/v1/runs/${r.run_id}?user=${u}`);
              if (!d.ok) throw new Error('delete');
            }
          } catch {
            return json({ error: 'Could not delete your real-test runs just now; your account was not deleted. Please try again.' }, 502);
          }
        }
        await env.DB.batch([
          env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id),
          env.DB.prepare('DELETE FROM users WHERE id = ?').bind(user.id),
        ]);
        return json({ ok: true }, 200, { 'Set-Cookie': cookie(SESSION_COOKIE, '', url, 0) });
      }

      if (path === '/api/cli/start') {
        const id = randomToken(16);
        const state = vm.newState();
        await env.DB.prepare('INSERT INTO cli_sessions (id, user_id, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?)')
          .bind(id, user.id, JSON.stringify(state), t, t).run();
        return json({
          session_id: id,
          banner: [
            'MonkeyITM CLI — sample task: fix-divide-bug',
            `workspace: /workspace   files: ${Object.keys(state.files).map((f) => f.split('/').pop()).join(', ')}`,
            '',
            vm.step(state, 'help').text,
          ].join('\n'),
        });
      }

      if (path === '/api/cli/act' || path === '/api/cli/submit') {
        const row = await env.DB.prepare('SELECT * FROM cli_sessions WHERE id = ? AND user_id = ?')
          .bind(body.session_id, user.id).first();
        if (!row) return json({ error: 'unknown session' }, 404);
        if (row.finished_at) return json({ error: 'this session has already ended' }, 409);
        const state = JSON.parse(row.state);

        if (path === '/api/cli/submit' || (typeof body.line === 'string' && body.line.trim() === 'submit')) {
          const report = vm.grade(state);
          await env.DB.prepare('UPDATE cli_sessions SET state = ?, updated_at = ?, finished_at = ? WHERE id = ?')
            .bind(JSON.stringify(state), t, t, row.id).run();
          return json({ done: true, report });
        }

        if (state.halted) return json({ text: 'the run has already halted; submit to see your results', halted: true });
        if (state.turns >= MAX_TURNS) {
          state.halted = true;
          state.haltReason = 'turn_limit';
          await env.DB.prepare('UPDATE cli_sessions SET state = ?, updated_at = ? WHERE id = ?').bind(JSON.stringify(state), t, row.id).run();
          return json({ text: `turn limit (${MAX_TURNS}) reached; submit to see your results`, halted: true });
        }
        if (typeof body.line !== 'string' || body.line.length > 4000) return json({ error: 'a command line is required' }, 400);

        const out = vm.step(state, body.line);
        await env.DB.prepare('UPDATE cli_sessions SET state = ?, updated_at = ? WHERE id = ?').bind(JSON.stringify(state), t, row.id).run();
        return json({ text: out.text, halted: out.halted });
      }
    }

    if (path.startsWith('/api/')) return json({ error: 'not found' }, 404);
    return env.ASSETS.fetch(req);
  },
};
