-- Accounts for the gated test environment. Only what sign-in and consent need.
CREATE TABLE users (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  github_id            INTEGER NOT NULL UNIQUE,
  login                TEXT NOT NULL,
  email                TEXT NOT NULL,
  created_at           INTEGER NOT NULL,
  last_login           INTEGER NOT NULL,
  terms_version        TEXT,
  terms_accepted_at    INTEGER,
  marketing_opt_in     INTEGER NOT NULL DEFAULT 0,
  marketing_changed_at INTEGER
);

-- Only a SHA-256 of each session token is stored.
CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);
CREATE INDEX sessions_user ON sessions(user_id);
