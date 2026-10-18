-- Invitation-only early access.
--
-- access_requests: what someone sent through the public request form. Only what
-- an invitation decision needs; the IP address is never stored, only a salted
-- daily hash used to limit how often one address can send the form.
CREATE TABLE access_requests (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  name         TEXT NOT NULL,
  email        TEXT NOT NULL,
  organization TEXT NOT NULL,
  role         TEXT NOT NULL,
  use_case     TEXT NOT NULL,
  created_at   INTEGER NOT NULL,
  ip_day_hash  TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'new'   -- new | invited | declined
);
CREATE INDEX access_requests_ip ON access_requests(ip_day_hash, created_at);
CREATE INDEX access_requests_email ON access_requests(email);

-- invites: who may enter the test environment. Matched on the signed-in
-- GitHub account's verified email or its login, so the owner can invite
-- someone before they have ever signed in. Added by hand (see site/README.md).
CREATE TABLE invites (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  email        TEXT,
  github_login TEXT,
  note         TEXT,
  created_at   INTEGER NOT NULL,
  revoked_at   INTEGER,
  CHECK (email IS NOT NULL OR github_login IS NOT NULL)
);
CREATE INDEX invites_email ON invites(email);
CREATE INDEX invites_login ON invites(github_login);
