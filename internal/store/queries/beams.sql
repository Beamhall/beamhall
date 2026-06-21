-- name: InsertBeam :exec
INSERT INTO beams (
    id, beamhall_id, slug, display_name, runtime_hint, mode, state,
    current_release_id, desired_release_id, live_release_id, live_state,
    security_template, preview_pause_after, resumed_at, git_remote_url, repo_id,
    created_by, created_at, updated_at, status, preview_host
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetBeam :one
SELECT * FROM beams WHERE id = ?;

-- name: GetBeamBySlug :one
SELECT * FROM beams WHERE beamhall_id = ? AND slug = ? AND status = 'active';

-- name: ListBeamsByBeamhall :many
SELECT * FROM beams WHERE beamhall_id = ? AND status = 'active' ORDER BY slug;

-- name: CountBeamsByBeamhall :one
SELECT COUNT(*) FROM beams WHERE beamhall_id = ? AND status = 'active';

-- name: CountLiveBeamsByBeamhall :one
SELECT COUNT(*) FROM beams WHERE beamhall_id = ? AND mode = 'live' AND status = 'active';

-- name: PromoteBeam :execrows
-- Reserves a live slot by flipping mode to live in the same tx as the slot count.
-- The preview channel's state is untouched; live_release_id/live_state are set
-- by the orchestrator once the live workload is healthy.
UPDATE beams SET mode = 'live', updated_at = ? WHERE id = ?;

-- name: UpdateBeam :execrows
UPDATE beams SET
    display_name = ?, runtime_hint = ?, mode = ?, state = ?,
    current_release_id = ?, desired_release_id = ?,
    live_release_id = ?, live_state = ?, security_template = ?,
    preview_pause_after = ?, resumed_at = ?, git_remote_url = ?, repo_id = ?,
    status = ?, updated_at = ?, preview_host = ?
WHERE id = ?;
