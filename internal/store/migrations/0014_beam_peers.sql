-- Beam-to-beam grants (PLAN §5.15 Stage 3). One row per SOURCE beam: what it
-- may reach — peer beams (relayed through the backplane, by target beam id)
-- and external destinations (per-beam egress entries). The row's presence is
-- the grant; revocation is an upsert with the entry removed or a delete.
-- Targets are validated at write time but filtered at READ time (the relay's
-- live-gate), so a destroyed target never resurrects through a stale grant.
CREATE TABLE beam_peers (
    source_beam_id TEXT PRIMARY KEY REFERENCES beams (id),
    beamhall_id    TEXT NOT NULL REFERENCES beamhalls (id),
    peers_json     TEXT NOT NULL DEFAULT '{}',
    updated_by     TEXT NOT NULL DEFAULT '',
    updated_at     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX beam_peers_beamhall ON beam_peers (beamhall_id);

-- Relay credentials: the SHA-256 of each beam's injected c2c key. The value
-- itself lives in the secrets vault (and in the workload at /run/secrets);
-- this hash is only the relay's O(1) caller lookup. UNIQUE doubles as the
-- lookup index and the duplicate-hash guard.
CREATE TABLE c2c_keys (
    beam_id    TEXT PRIMARY KEY REFERENCES beams (id),
    key_hash   TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL DEFAULT 0
);
