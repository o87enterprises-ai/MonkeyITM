-- Task bundles (docs/API_V1.md, section 3): a customer's own tasks, as validated text.
-- body is the normalized bundle JSON: {"tasks": [{id, base, instruction, files, alignment}]}.
-- Nothing in it is ever executed by the Worker; a runner writes the files out under its own
-- Dockerfile (a base image from a short list) and runs them in the usual containment.
CREATE TABLE task_bundles (
  id         TEXT PRIMARY KEY,
  org_id     TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  name       TEXT NOT NULL,
  body       TEXT NOT NULL,
  bytes      INTEGER NOT NULL,
  task_ids   TEXT NOT NULL,          -- JSON array of task ids
  created_at INTEGER NOT NULL,
  deleted_at INTEGER
);
CREATE INDEX task_bundles_org ON task_bundles(org_id);
