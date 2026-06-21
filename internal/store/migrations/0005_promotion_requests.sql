-- Optional explicit IT-approval gate for promote_to_live (PLAN §10). When the
-- gate is enabled (BEAMHALL_PROMOTE_APPROVAL=on), promote_to_live records a
-- pending request instead of going live; a DIFFERENT IT operator must approve
-- it (four-eyes / separation of duties). Off by default — promote_to_live
-- promotes immediately. A beam has at most one pending request at a time.
CREATE TABLE promotion_requests (
    id           TEXT PRIMARY KEY,
    beamhall_id  TEXT NOT NULL REFERENCES beamhalls (id),
    beam_id      TEXT NOT NULL REFERENCES beams (id),
    release_id   TEXT NOT NULL,
    requested_by TEXT NOT NULL,                       -- identity id of the requester
    status       TEXT NOT NULL DEFAULT 'pending',     -- pending | approved | rejected
    reason       TEXT NOT NULL DEFAULT '',            -- decision note (rejection reason)
    created_at   INTEGER NOT NULL,
    decided_by   TEXT NOT NULL DEFAULT '',            -- identity id of the approver/rejecter
    decided_at   INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX promotion_requests_pending ON promotion_requests (beamhall_id) WHERE status = 'pending';
CREATE UNIQUE INDEX promotion_requests_one_pending ON promotion_requests (beam_id) WHERE status = 'pending';
