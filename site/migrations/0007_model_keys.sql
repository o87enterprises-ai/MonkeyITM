-- Stored model keys (docs/API_V1.md, section 4). A key is stored encrypted (AES-GCM, key derived
-- from the KEY_SECRET Worker secret), pinned to a URL prefix, released only to the runner of a run
-- that names it, never returned by any call. Deleting a key empties key_enc, so it is really gone.
CREATE TABLE model_keys (
  id           TEXT PRIMARY KEY,
  org_id       TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  label        TEXT NOT NULL,
  url_prefix   TEXT NOT NULL,
  hint         TEXT,                 -- last four characters of a long key, to tell keys apart
  key_enc      TEXT NOT NULL,
  created_at   INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at   INTEGER
);
CREATE INDEX model_keys_org ON model_keys(org_id);

ALTER TABLE jobs ADD COLUMN model_key_id TEXT;
