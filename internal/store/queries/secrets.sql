-- name: UpsertSecret :one
INSERT INTO secrets (id, beamhall_id, beam_id, key, channel, value_ref, version, created_by, created_at)
VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
ON CONFLICT (beamhall_id, beam_id, key, channel) DO UPDATE SET
    value_ref  = excluded.value_ref,
    version    = secrets.version + 1,
    created_by = excluded.created_by,
    created_at = excluded.created_at
RETURNING *;

-- name: GetSecret :one
SELECT * FROM secrets WHERE beamhall_id = ? AND beam_id = ? AND key = ? AND channel = ?;

-- name: ListSecretsByBeamhall :many
SELECT * FROM secrets WHERE beamhall_id = ? ORDER BY beam_id, key, channel;

-- name: DeleteSecret :exec
DELETE FROM secrets WHERE beamhall_id = ? AND beam_id = ? AND key = ? AND channel = ?;
