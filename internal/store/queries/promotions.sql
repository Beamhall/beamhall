-- name: InsertPromotionRequest :exec
INSERT INTO promotion_requests (id, beamhall_id, beam_id, release_id, requested_by, status, created_at)
VALUES (?, ?, ?, ?, ?, 'pending', ?);

-- name: GetPromotionRequest :one
SELECT * FROM promotion_requests WHERE id = ?;

-- name: GetPendingPromotionByBeam :one
SELECT * FROM promotion_requests WHERE beam_id = ? AND status = 'pending';

-- name: ListPendingPromotionRequests :many
SELECT * FROM promotion_requests WHERE beamhall_id = ? AND status = 'pending' ORDER BY created_at;

-- name: DecidePromotionRequest :execrows
UPDATE promotion_requests
SET status = ?, reason = ?, decided_by = ?, decided_at = ?
WHERE id = ? AND status = 'pending';
