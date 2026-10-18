-- A permanent record of each signed Security Testing Authorization and Confidentiality Agreement. Unlike the
-- columns on users, it survives the tester deleting their account: the confidentiality duties outlast it.
CREATE TABLE IF NOT EXISTS tester_signatures (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  github_id INTEGER NOT NULL,
  login TEXT NOT NULL,
  email TEXT,
  signed_name TEXT NOT NULL,
  version TEXT NOT NULL,
  signed_at INTEGER NOT NULL,
  ip_hash TEXT
);
CREATE INDEX IF NOT EXISTS tester_signatures_login ON tester_signatures (login);
