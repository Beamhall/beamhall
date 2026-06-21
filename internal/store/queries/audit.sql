-- name: AppendAuditEvent :one
INSERT INTO audit_events (
    id, at, actor_id, actor_token_jti, beamhall_id, beam_id, action, decision,
    reason, request_digest, result_status, source_ip, prev_hash, hash
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING seq;

-- name: LastAuditEvent :one
SELECT * FROM audit_events ORDER BY seq DESC LIMIT 1;

-- name: ListAuditEvents :many
SELECT * FROM audit_events WHERE seq > ? ORDER BY seq LIMIT ?;

-- name: ListAuditEventsByBeamhall :many
SELECT * FROM audit_events WHERE beamhall_id = ? AND seq > ? ORDER BY seq LIMIT ?;

-- name: MaxAuditSeq :one
SELECT COALESCE(MAX(seq), 0) FROM audit_events;

-- name: AuditHashBySeq :one
SELECT hash FROM audit_events WHERE seq = ?;

-- name: AuditCutSeqByAge :one
-- The newest event strictly older than the cutoff: the prune-through point for
-- an age-based retention policy (0 when nothing is that old).
SELECT COALESCE(MAX(seq), 0) FROM audit_events WHERE at < ?;

-- name: DeleteAuditEventsThrough :execrows
DELETE FROM audit_events WHERE seq <= ?;

-- name: InsertAuditCheckpoint :exec
INSERT INTO audit_checkpoints (through_seq, anchor_hash, pruned_count, at, pruned_by)
VALUES (?, ?, ?, ?, ?);

-- name: LatestAuditCheckpoint :one
SELECT through_seq, anchor_hash, pruned_count, at, pruned_by
FROM audit_checkpoints ORDER BY through_seq DESC LIMIT 1;
