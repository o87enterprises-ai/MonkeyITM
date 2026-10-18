-- Live sessions (docs/SESSIONS_DESIGN.md). A session is a job with one long run (task '_session');
-- this table holds what is specific to it. The session token is stored only as a hash. Per-intent
-- traffic never touches this table: the relay (a Durable Object) holds it, to stay inside free limits.
CREATE TABLE live_sessions (
  id           TEXT PRIMARY KEY,
  org_id       TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  job_id       TEXT NOT NULL,
  run_id       TEXT NOT NULL,
  token_hash   TEXT NOT NULL,
  status       TEXT NOT NULL,        -- pending | ready | ended | killed | expired | lost | halted
  created_at   INTEGER NOT NULL,
  ready_at     INTEGER,
  ended_at     INTEGER,
  expires_at   INTEGER NOT NULL,
  max_requests INTEGER NOT NULL
);
CREATE INDEX live_sessions_org ON live_sessions(org_id, status);
CREATE UNIQUE INDEX live_sessions_run ON live_sessions(run_id);
