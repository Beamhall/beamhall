-- name: UpsertBranding :exec
INSERT INTO branding (beamhall_id, branding_json, updated_at)
VALUES (?, ?, ?)
ON CONFLICT (beamhall_id) DO UPDATE SET
    branding_json = excluded.branding_json,
    updated_at = excluded.updated_at;

-- name: GetBranding :one
SELECT * FROM branding WHERE beamhall_id = ?;

-- name: DeleteBranding :exec
DELETE FROM branding WHERE beamhall_id = ?;

-- name: UpsertBrandingLogo :exec
INSERT INTO branding_logos (beamhall_id, logo, logo_mime, logo_etag, updated_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT (beamhall_id) DO UPDATE SET
    logo = excluded.logo,
    logo_mime = excluded.logo_mime,
    logo_etag = excluded.logo_etag,
    updated_at = excluded.updated_at;

-- name: GetBrandingLogo :one
SELECT * FROM branding_logos WHERE beamhall_id = ?;

-- name: GetBrandingLogoMeta :one
SELECT beamhall_id, logo_mime, logo_etag, updated_at FROM branding_logos WHERE beamhall_id = ?;

-- name: DeleteBrandingLogo :exec
DELETE FROM branding_logos WHERE beamhall_id = ?;
