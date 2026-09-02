-- name: InsertC2CKey :execrows
-- ON CONFLICT DO NOTHING makes the insert the mint mutex: exactly one of two
-- racing mints proceeds to seal the key material.
INSERT INTO c2c_keys (beam_id, key_hash, created_at)
VALUES (?, ?, ?)
ON CONFLICT (beam_id) DO NOTHING;

-- name: GetC2CKeyByHash :one
SELECT * FROM c2c_keys WHERE key_hash = ?;

-- name: GetC2CKeyByBeam :one
SELECT * FROM c2c_keys WHERE beam_id = ?;

-- name: DeleteC2CKey :exec
DELETE FROM c2c_keys WHERE beam_id = ?;
