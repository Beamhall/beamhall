-- name: InsertBuild :exec
INSERT INTO builds (
    id, beam_id, source_ref, source_kind, builder, status, image_ref,
    image_digest, sbom_ref, cve_scan_status, log_stream_id, triggered_by,
    started_at, finished_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetBuild :one
SELECT * FROM builds WHERE id = ?;

-- name: ListBuildsByBeam :many
SELECT * FROM builds WHERE beam_id = ? ORDER BY started_at DESC;

-- name: UpdateBuild :execrows
UPDATE builds SET
    status = ?, image_ref = ?, image_digest = ?, sbom_ref = ?,
    cve_scan_status = ?, log_stream_id = ?, finished_at = ?
WHERE id = ?;
