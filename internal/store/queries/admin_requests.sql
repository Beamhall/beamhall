-- name: InsertAdminActionRequest :exec
INSERT INTO admin_action_requests (id, action_type, summary, payload_cipher, requested_by, status, created_at)
VALUES (?, ?, ?, ?, ?, 'pending', ?);

-- name: GetAdminActionRequest :one
SELECT * FROM admin_action_requests WHERE id = ?;

-- name: ListPendingAdminActionRequests :many
SELECT * FROM admin_action_requests WHERE status = 'pending' ORDER BY created_at;

-- name: DecideAdminActionRequest :execrows
UPDATE admin_action_requests
SET status = ?, reason = ?, result = ?, decided_by = ?, decided_at = ?
WHERE id = ? AND status = 'pending';
