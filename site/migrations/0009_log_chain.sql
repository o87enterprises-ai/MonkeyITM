-- The head and length of each run's log hash chain (docs/LOG_CHAIN.md), as the runner reported them
-- when the run ended. Kept so the log held here can be checked against it later, and signed into the
-- incident export.
ALTER TABLE runs ADD COLUMN log_chain_head TEXT;
ALTER TABLE runs ADD COLUMN log_chain_rows INTEGER;
