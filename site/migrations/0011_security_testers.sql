-- Invited security testers: an invite can be marked as a tester invite, and a tester must sign the
-- Security Testing Authorization and Confidentiality Agreement (typed full name, version, time) before
-- entering the test environment or creating API keys.
ALTER TABLE invites ADD COLUMN tester INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN tester_terms_version TEXT;
ALTER TABLE users ADD COLUMN tester_accepted_at INTEGER;
ALTER TABLE users ADD COLUMN tester_signed_name TEXT;
