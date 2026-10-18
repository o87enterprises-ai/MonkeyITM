-- State for the gated CLI test environment. One row per attempt.
-- `state` holds the mock machine, denial count and transcript as JSON; it is
-- server-authoritative and never sent to the client in raw form.
CREATE TABLE cli_sessions (
  id          TEXT PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  state       TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL,
  finished_at INTEGER
);
CREATE INDEX cli_sessions_user ON cli_sessions(user_id);
