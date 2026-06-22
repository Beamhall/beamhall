-- Four-eyes approval for the SENSITIVE admin tier (PLAN §5.9). A sensitive
-- admin action (today: directory federation; later: restore/upgrade) is not
-- executed by the requesting IT operator — it records a pending request that a
-- DIFFERENT IT operator must approve (separation of duties), at which point the
-- backplane executes the stored intent. Generic by action_type so new sensitive
-- actions reuse the same flow.
--
-- The payload may carry secrets (e.g. an LDAP bind credential), so it is stored
-- vault-sealed (age) in payload_cipher; only the non-secret `summary` is shown
-- in listings. These are appliance-level admin actions (no beamhall scope).
CREATE TABLE admin_action_requests (
    id            TEXT PRIMARY KEY,
    action_type   TEXT NOT NULL,                     -- e.g. 'federate_directory'
    summary       TEXT NOT NULL DEFAULT '',          -- non-secret human description for listings
    payload_cipher BLOB NOT NULL,                    -- vault-sealed JSON intent (may contain secrets)
    requested_by  TEXT NOT NULL,                     -- identity id of the requester
    status        TEXT NOT NULL DEFAULT 'pending',   -- pending | approved | rejected
    reason        TEXT NOT NULL DEFAULT '',          -- decision note (rejection reason)
    result        TEXT NOT NULL DEFAULT '',          -- execution result/error recorded on approval
    created_at    INTEGER NOT NULL,
    decided_by    TEXT NOT NULL DEFAULT '',          -- identity id of the approver/rejecter
    decided_at    INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX admin_action_requests_pending ON admin_action_requests (status) WHERE status = 'pending';
