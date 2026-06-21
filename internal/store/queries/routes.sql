-- name: InsertRoute :exec
INSERT INTO routes (
    id, beam_id, release_id, kind, hostname, random_token, backend_addr,
    tls_cert_ref, status, created_at, retired_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetRoute :one
SELECT * FROM routes WHERE id = ?;

-- name: GetActiveRouteByHostname :one
SELECT * FROM routes WHERE hostname = ? AND status = 'active';

-- name: ListActiveRoutes :many
SELECT * FROM routes WHERE status = 'active' ORDER BY hostname;

-- name: ListRoutesByBeam :many
SELECT * FROM routes WHERE beam_id = ? ORDER BY created_at DESC;

-- name: RetireRoute :execrows
UPDATE routes SET status = 'retired', retired_at = ? WHERE id = ?;
