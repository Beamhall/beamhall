-- name: InsertResource :exec
INSERT INTO resources (
    id, beamhall_id, beam_id, channel, type, status, connection_secret_json,
    spec_json, backing_handle, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetResource :one
SELECT * FROM resources WHERE id = ?;

-- name: ListResourcesByBeamhall :many
SELECT * FROM resources WHERE beamhall_id = ? ORDER BY created_at;

-- name: ListResourcesByBeam :many
SELECT * FROM resources WHERE beam_id = ? ORDER BY created_at;

-- name: ListResourcesByBeamAndChannel :many
SELECT * FROM resources WHERE beam_id = ? AND channel = ? ORDER BY created_at;

-- name: CountResourcesByBeamhallAndType :one
-- Counts LOGICAL resources against quota: the live channel's mirror database is
-- a consequence of promote (bounded by the preview count), not a new logical
-- resource, so it does not additionally count toward MaxDBCount.
SELECT COUNT(*) FROM resources WHERE beamhall_id = ? AND type = ? AND channel <> 'live';

-- name: UpdateResource :execrows
UPDATE resources SET
    status = ?, connection_secret_json = ?, spec_json = ?, backing_handle = ?,
    updated_at = ?
WHERE id = ?;

-- name: DeleteResource :exec
DELETE FROM resources WHERE id = ?;
