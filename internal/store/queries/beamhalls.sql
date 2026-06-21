-- name: InsertBeamhall :exec
INSERT INTO beamhalls (
    id, slug, display_name, department, status, security_context_id,
    network_policy_json, quota_json, live_slot_limit, created_by, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetBeamhall :one
SELECT * FROM beamhalls WHERE id = ?;

-- name: GetBeamhallBySlug :one
SELECT * FROM beamhalls WHERE slug = ?;

-- name: ListBeamhalls :many
SELECT * FROM beamhalls ORDER BY slug;

-- name: UpdateBeamhall :execrows
UPDATE beamhalls SET
    display_name = ?, department = ?, status = ?, network_policy_json = ?,
    quota_json = ?, live_slot_limit = ?, updated_at = ?
WHERE id = ?;

-- name: InsertSecurityContext :exec
INSERT INTO security_contexts (
    id, beamhall_id, runtime_class, userns_remap, cap_drop_json, cap_add_json,
    seccomp_profile, apparmor_profile, no_new_privileges, read_only_rootfs,
    tmpfs_json, cgroup_limits_json, template
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetSecurityContextByBeamhall :one
SELECT * FROM security_contexts WHERE beamhall_id = ?;

-- name: UpdateSecurityContext :execrows
UPDATE security_contexts SET
    runtime_class = ?, userns_remap = ?, cap_drop_json = ?, cap_add_json = ?,
    seccomp_profile = ?, apparmor_profile = ?, no_new_privileges = ?,
    read_only_rootfs = ?, tmpfs_json = ?, cgroup_limits_json = ?, template = ?
WHERE id = ?;
