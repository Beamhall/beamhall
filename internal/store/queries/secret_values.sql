-- name: PutSecretValue :exec
INSERT INTO secret_values (ref, ciphertext, created_at) VALUES (?, ?, ?);

-- name: GetSecretValue :one
SELECT ciphertext FROM secret_values WHERE ref = ?;

-- name: DeleteSecretValue :exec
DELETE FROM secret_values WHERE ref = ?;
