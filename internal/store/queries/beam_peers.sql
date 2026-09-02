-- name: UpsertBeamPeers :exec
INSERT INTO beam_peers (source_beam_id, beamhall_id, peers_json, updated_by, updated_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT (source_beam_id) DO UPDATE SET
    peers_json = excluded.peers_json,
    updated_by = excluded.updated_by,
    updated_at = excluded.updated_at;

-- name: GetBeamPeers :one
SELECT * FROM beam_peers WHERE source_beam_id = ?;

-- name: ListBeamPeers :many
SELECT * FROM beam_peers ORDER BY source_beam_id;

-- name: DeleteBeamPeers :exec
DELETE FROM beam_peers WHERE source_beam_id = ?;
