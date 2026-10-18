-- Launch funnel: where an access request came from (?ref= on the link) and what the person wants.
ALTER TABLE access_requests ADD COLUMN source TEXT;
ALTER TABLE access_requests ADD COLUMN interest TEXT;
