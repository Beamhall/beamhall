-- name: InsertIdentity :exec
INSERT INTO identities (id, external_subject, email, display_name, idp_issuer, status, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetIdentity :one
SELECT * FROM identities WHERE id = ?;

-- name: GetIdentityByIssuerSubject :one
SELECT * FROM identities WHERE idp_issuer = ? AND external_subject = ?;

-- name: ListIdentities :many
SELECT * FROM identities ORDER BY email;

-- name: UpdateIdentity :execrows
UPDATE identities SET email = ?, display_name = ?, status = ? WHERE id = ?;

-- name: InsertMembership :exec
INSERT INTO memberships (id, identity_id, beamhall_id, role, granted_by, granted_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetMembership :one
SELECT * FROM memberships WHERE identity_id = ? AND beamhall_id = ?;

-- name: ListMembershipsByBeamhall :many
SELECT * FROM memberships WHERE beamhall_id = ? ORDER BY granted_at;

-- name: ListMembershipsByIdentity :many
SELECT * FROM memberships WHERE identity_id = ? ORDER BY granted_at;

-- name: DeleteMembership :exec
DELETE FROM memberships WHERE id = ?;

-- name: DeleteIdentity :exec
DELETE FROM identities WHERE id = ?;
