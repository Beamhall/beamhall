-- name: ListArmedPauses :many
SELECT * FROM armed_pauses;

-- name: UpsertArmedPause :exec
INSERT INTO armed_pauses (beam_id, deadline) VALUES (?, ?)
ON CONFLICT (beam_id) DO UPDATE SET deadline = excluded.deadline;

-- name: DeleteArmedPause :exec
DELETE FROM armed_pauses WHERE beam_id = ?;
