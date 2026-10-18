// SessionRelay: one Durable Object per live session (docs/SESSIONS_DESIGN.md).
//
// A pure mailbox between the customer's agent and the runner's broker. The customer's request waits
// here until the runner (holding a long-poll open, outbound) takes it, asks its broker and posts the
// reply. The Worker has already checked the session token and the session's row in D1; this object
// is reachable only through the Worker's binding. It keeps its working state in memory (one write per
// state change, one per 20 requests, to stay inside the free plan's row-write allowance) and decides
// nothing about policy: the broker does.

const MAX_PENDING = 8;
const INTENT_TIMEOUT_MS = 120_000;
const RUNNER_ALIVE_MS = 30_000;
const MAX_WAIT_S = 25;
const SEEN_CAP = 50_000;
const TERMINAL = ['ended', 'killed', 'expired', 'lost', 'halted'];
const HALT_PREFIXES = ['run halted by tripwire', 'run stopped by the owner'];

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
const err = (status, code, message) => json({ error: { code, message } }, status);
const now = () => Math.floor(Date.now() / 1000);

export class SessionRelay {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
    this.meta = null;
    this.pending = new Map();   // intent id -> { resolve, timer }
    this.queue = [];            // messages for the runner: { id, intent } | { kill: true } | { end: true }
    this.waiter = null;         // the runner's open long-poll: { resolve, timer }
    this.lastPoll = 0;
    this.seen = new Set();
    this.unsaved = 0;
    ctx.blockConcurrencyWhile(async () => { this.meta = (await ctx.storage.get('meta')) || null; });
  }

  async save() {
    this.unsaved = 0;
    await this.ctx.storage.put('meta', this.meta);
  }

  async setD1(status) {
    // Best effort: the row in D1 is what the API shows; a failure here must not break the relay.
    try {
      await this.env.DB.prepare(`UPDATE live_sessions SET status = ?, ended_at = COALESCE(ended_at, ?) WHERE id = ? AND status IN ('pending','ready')`)
        .bind(status, now(), this.meta.id).run();
    } catch (e) { console.error('relay D1 update failed', e && e.message); }
  }

  /** Wake the runner's long-poll (if any) with the next message. */
  deliver() {
    if (this.waiter && this.queue.length) {
      const w = this.waiter;
      this.waiter = null;
      clearTimeout(w.timer);
      w.resolve(this.queue.shift());
    }
  }

  failPending(status, code, message) {
    for (const [id, p] of this.pending) {
      clearTimeout(p.timer);
      p.resolve({ failure: { status, code, message } });
      this.pending.delete(id);
    }
  }

  async finish(status, notice) {
    if (!this.meta || TERMINAL.includes(this.meta.status)) return;
    this.meta.status = status;
    await this.save();
    await this.setD1(status);
    const map = { killed: [409, 'session_killed', 'the session was stopped by its owner'], ended: [409, 'session_ended', 'the session has ended'],
      expired: [410, 'session_expired', 'the session has expired'], lost: [503, 'runner_lost', 'the runner went away'], halted: [409, 'session_halted', 'the session was halted'] };
    this.failPending(...map[status]);
    this.queue.push(notice);
    this.deliver();
  }

  async alarm() {
    if (this.meta && !TERMINAL.includes(this.meta.status)) await this.finish('expired', { end: true, why: 'expired' });
  }

  async fetch(req) {
    const url = new URL(req.url);
    const op = url.pathname.replace(/^\/+/, '');
    if (op === 'init' && req.method === 'POST') return this.init(await req.json());
    if (!this.meta) return err(404, 'not_found', 'no such session');
    if (op === 'intent' && req.method === 'POST') return this.intent(await req.json());
    if (op === 'next' && req.method === 'GET') return this.next(parseInt(url.searchParams.get('wait') || '25', 10));
    if (op === 'reply' && req.method === 'POST') return this.reply(await req.json());
    if (op === 'control' && req.method === 'POST') return this.control(await req.json());
    if (op === 'status' && req.method === 'GET') return json(this.status());
    return err(404, 'not_found', 'no such relay route');
  }

  status() {
    return {
      status: this.meta.status, requests: this.meta.requests, max_requests: this.meta.max_requests, expires_at: this.meta.expires_at,
      halted: this.meta.status === 'halted', pending: this.pending.size,
      runner_attached: Date.now() - this.lastPoll < RUNNER_ALIVE_MS,
    };
  }

  async init(b) {
    if (this.meta) return json({ ok: true, repeated: true });
    this.meta = { id: b.id, status: 'pending', requests: 0, max_requests: b.max_requests, expires_at: b.expires_at };
    await this.save();
    await this.ctx.storage.setAlarm(b.expires_at * 1000);
    return json({ ok: true });
  }

  async control(b) {
    if (b.op === 'ready') {
      if (this.meta.status === 'pending') { this.meta.status = 'ready'; await this.save(); }
      return json(this.status());
    }
    if (['kill', 'end', 'lost', 'halted'].includes(b.op)) {
      const status = { kill: 'killed', end: 'ended', lost: 'lost', halted: 'halted' }[b.op];
      await this.finish(status, b.op === 'kill' ? { kill: true } : { end: true, why: status });
      return json(this.status());
    }
    return err(400, 'bad_request', 'unknown control operation');
  }

  async intent(b) {
    const m = this.meta;
    if (m.status === 'pending') return err(409, 'not_ready', 'the session is not ready yet (no runner has started it)');
    if (m.status === 'killed') return err(409, 'session_killed', 'the session was stopped by its owner');
    if (m.status === 'halted') return err(409, 'session_halted', 'the session was halted (tripwire or owner stop); nothing more will run');
    if (m.status === 'expired') return err(410, 'session_expired', 'the session has expired');
    if (TERMINAL.includes(m.status)) return err(409, `session_${m.status}`, `the session is ${m.status}`);
    if (now() >= m.expires_at) { await this.finish('expired', { end: true, why: 'expired' }); return err(410, 'session_expired', 'the session has expired'); }
    if (m.requests >= m.max_requests) return err(429, 'request_cap', `this session's request limit (${m.max_requests}) is used up`);
    if (this.pending.size >= MAX_PENDING) return err(429, 'busy', `at most ${MAX_PENDING} requests may wait at once`);
    if (Date.now() - this.lastPoll > RUNNER_ALIVE_MS) return err(503, 'runner_unavailable', 'the runner is not connected; try again shortly');

    const intent = b.intent;
    if (!intent || typeof intent !== 'object' || typeof intent.action !== 'string') return err(400, 'bad_request', 'send {"action": ..., "params": {...}}');
    const id = typeof intent.id === 'string' && /^[\w-]{8,64}$/.test(intent.id) ? intent.id : crypto.randomUUID();
    if (this.seen.has(id)) return err(409, 'replay', 'that intent id was already used in this session');
    this.seen.add(id);
    if (this.seen.size > SEEN_CAP) this.seen.delete(this.seen.values().next().value);
    m.requests += 1;
    if (++this.unsaved >= 20) this.ctx.waitUntil(this.save());

    const outcome = await new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        resolve({ failure: { status: 504, code: 'runner_timeout', message: 'the broker did not answer in time' } });
      }, INTENT_TIMEOUT_MS);
      this.pending.set(id, { resolve, timer });
      this.queue.push({ id, intent: { ...intent, id } });
      this.deliver();
    });
    if (outcome.failure) return err(outcome.failure.status, outcome.failure.code, outcome.failure.message);
    return json(outcome.reply);
  }

  async next(waitS) {
    this.lastPoll = Date.now();
    if (this.waiter) {   // a newer poll replaces an older one
      clearTimeout(this.waiter.timer);
      this.waiter.resolve(null);
      this.waiter = null;
    }
    if (!this.queue.length) {
      const wait = Math.min(Math.max(Number.isFinite(waitS) ? waitS : MAX_WAIT_S, 0), MAX_WAIT_S);
      if (wait === 0) return new Response(null, { status: 204 });
      await new Promise((resolve) => {
        const timer = setTimeout(() => { this.waiter = null; resolve(null); }, wait * 1000);
        this.waiter = { resolve: (msg) => { if (msg) this.queue.unshift(msg); resolve(msg); }, timer };
      });
    }
    this.lastPoll = Date.now();
    const msg = this.queue.shift();
    return msg ? json(msg) : new Response(null, { status: 204 });
  }

  async reply(b) {
    const p = typeof b.id === 'string' ? this.pending.get(b.id) : null;
    if (!p) return err(404, 'not_found', 'no request is waiting for that answer');
    this.pending.delete(b.id);
    clearTimeout(p.timer);
    p.resolve({ reply: b.reply });
    // The broker says every later request will be refused (tripwire or owner stop): the session is over.
    const reason = b.reply && typeof b.reply.reason === 'string' ? b.reply.reason : '';
    if (HALT_PREFIXES.some((h) => reason.startsWith(h))) await this.finish('halted', { end: true, why: 'halted' });
    return json({ ok: true });
  }
}
