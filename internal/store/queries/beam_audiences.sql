-- name: UpsertBeamAudience :exec
-- published_by/published_at survive a re-publish: they record the first one.
INSERT INTO beam_audiences (beam_id, beamhall_id, audience_json, published_by, published_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (beam_id) DO UPDATE SET
    audience_json = excluded.audience_json,
    updated_at = excluded.updated_at;

-- name: GetBeamAudience :one
SELECT * FROM beam_audiences WHERE beam_id = ?;

-- name: ListBeamAudiences :many
SELECT * FROM beam_audiences ORDER BY published_at;

-- name: ListBeamAudiencesByBeamhall :many
SELECT * FROM beam_audiences WHERE beamhall_id = ? ORDER BY published_at;

-- name: DeleteBeamAudience :exec
DELETE FROM beam_audiences WHERE beam_id = ?;
