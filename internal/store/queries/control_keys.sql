-- name: GetControlKey :one
SELECT * FROM control_keys WHERE kind = ?;

-- name: InsertControlKey :exec
INSERT INTO control_keys (kind, sealed, created_at) VALUES (?, ?, ?);
