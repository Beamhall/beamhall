-- name: InsertRelease :exec
INSERT INTO releases (
    id, beam_id, build_id, version, channel, config_snapshot_json, secret_refs_json,
    security_profile_json, route_id, status, created_at, activated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: NextReleaseVersion :one
SELECT COALESCE(MAX(version), 0) + 1 FROM releases WHERE beam_id = ?;

-- name: GetRelease :one
SELECT * FROM releases WHERE id = ?;

-- name: ListReleasesByBeam :many
SELECT * FROM releases WHERE beam_id = ? ORDER BY version DESC;

-- name: UpdateReleaseStatus :execrows
UPDATE releases SET status = ? WHERE id = ?;

-- name: ActivateRelease :execrows
UPDATE releases SET status = 'active', activated_at = ? WHERE id = ?;

-- name: SetReleaseRoute :execrows
UPDATE releases SET route_id = ? WHERE id = ?;

-- name: SetReleaseWorkload :execrows
UPDATE releases SET handle_driver = ?, handle_ref = ? WHERE id = ?;
