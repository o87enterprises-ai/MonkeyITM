-- Consent to the real-test notice (what is stored from a real run, who sees it, deletion).
-- Separate from the Terms of Use so the notice can change without re-asking everything.
ALTER TABLE users ADD COLUMN real_terms_version TEXT;
ALTER TABLE users ADD COLUMN real_terms_accepted_at INTEGER;
