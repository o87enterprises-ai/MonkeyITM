-- Public API v1 (docs/API_V1.md), step 1: organizations, API keys, jobs, runs, runners.
--
-- Everything customer-owned carries org_id and every query filters on it. API keys and runner
-- tokens are stored only as SHA-256 hashes. A job's model key, when given inline, is stored
-- encrypted (AES-GCM, key from the KEY_SECRET Worker secret) and wiped when the job ends.

CREATE TABLE orgs (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  owner_user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  plan          TEXT NOT NULL DEFAULT 'preview',   -- preview | subscriber | enterprise
  created_at    INTEGER NOT NULL,
  killed_at     INTEGER                            -- organization-wide emergency stop
);

CREATE TABLE api_keys (
  id           TEXT PRIMARY KEY,
  org_id       TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  key_hash     TEXT NOT NULL UNIQUE,
  prefix       TEXT NOT NULL,                      -- first characters, for display only
  label        TEXT NOT NULL,
  scopes       TEXT NOT NULL,                      -- space-separated
  created_at   INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at   INTEGER
);
CREATE INDEX api_keys_org ON api_keys(org_id);

CREATE TABLE jobs (
  id                TEXT PRIMARY KEY,
  org_id            TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  name              TEXT NOT NULL,
  status            TEXT NOT NULL,                 -- queued | running | finished | killed
  spec              TEXT NOT NULL,                 -- validated request, never the model key
  gate              TEXT,                          -- pass | pass_with_concerns | fail | incomplete
  created_at        INTEGER NOT NULL,
  finished_at       INTEGER,
  kill_requested_at INTEGER,
  stopped_at        INTEGER,                       -- when the last run actually stopped
  idem_key          TEXT,
  model_key_enc     TEXT,
  runs_total        INTEGER NOT NULL
);
CREATE INDEX jobs_org ON jobs(org_id, created_at);
CREATE UNIQUE INDEX jobs_idem ON jobs(org_id, idem_key) WHERE idem_key IS NOT NULL;

CREATE TABLE runs (
  id                TEXT PRIMARY KEY,
  job_id            TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  org_id            TEXT NOT NULL,
  task              TEXT NOT NULL,
  repeat_index      INTEGER NOT NULL DEFAULT 0,
  status            TEXT NOT NULL,                 -- queued | leased | running | finished | killed | error
  runner_id         TEXT,
  lease_expires_at  INTEGER,
  heartbeat_at      INTEGER,
  kill_requested_at INTEGER,
  created_at        INTEGER NOT NULL,
  started_at        INTEGER,
  finished_at       INTEGER,
  result            TEXT,                          -- pass | pass_with_concerns | fail | error
  completed         INTEGER,
  beyond_scope      INTEGER,
  critical          INTEGER,
  halted            INTEGER,
  halt_cause        TEXT,
  note              TEXT
);
CREATE INDEX runs_job ON runs(job_id);
CREATE INDEX runs_queue ON runs(status, created_at);
CREATE INDEX runs_org_active ON runs(org_id, status);

-- Logs, scores, transcripts and reports, one row per run and kind. Held here until object
-- storage is worth its cost; each is size-capped by the API.
CREATE TABLE artifacts (
  run_id     TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  kind       TEXT NOT NULL,                        -- log | score | transcript | report
  body       TEXT NOT NULL,
  size       INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (run_id, kind)
);

CREATE TABLE runners (
  id         TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  label      TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER
);

CREATE TABLE audit (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id   TEXT NOT NULL,
  at       INTEGER NOT NULL,
  actor    TEXT NOT NULL,                          -- key id, "user:<login>" or "owner"
  action   TEXT NOT NULL,
  detail   TEXT NOT NULL
);
CREATE INDEX audit_org ON audit(org_id, at);

-- Runs created per organization per month. Kept apart from the runs table so deleting a job
-- does not give its runs back to the quota.
CREATE TABLE usage (
  org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  month  TEXT NOT NULL,           -- 2026-10
  runs   INTEGER NOT NULL,
  PRIMARY KEY (org_id, month)
);

-- A per-organization counter for the few calls that need a rate limit.
CREATE TABLE rate (
  org_id TEXT NOT NULL,
  bucket TEXT NOT NULL,
  window INTEGER NOT NULL,
  n      INTEGER NOT NULL,
  PRIMARY KEY (org_id, bucket, window)
);
