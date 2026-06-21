-- Dual-channel beams: a beam keeps a permanent preview channel (state +
-- current_release_id) and gains an optional live channel pinned by promote
-- (live_release_id). Resources and secrets gain a channel so the live channel
-- gets its own database + connection secret while sharing user/beamhall secrets.
--
-- Channel values: 'preview' | 'live' on resources; '' (shared) | 'preview' |
-- 'live' on secrets ('' injects into both channels; DB connection secrets are
-- channel-specific so the same app key resolves to a different DSN per channel).

ALTER TABLE beams ADD COLUMN live_release_id TEXT NOT NULL DEFAULT '';
ALTER TABLE beams ADD COLUMN live_state TEXT NOT NULL DEFAULT '';

-- Pre-existing live-mode beams predate the split: point their live channel at
-- the release they were already serving so production keeps running.
UPDATE beams SET live_release_id = current_release_id, live_state = 'live'
WHERE mode = 'live' AND current_release_id <> '';

ALTER TABLE resources ADD COLUMN channel TEXT NOT NULL DEFAULT 'preview';
ALTER TABLE secrets   ADD COLUMN channel TEXT NOT NULL DEFAULT '';

-- The app key (e.g. MAIN_URL) is now unique per channel, not globally, so
-- preview and live can each hold their own DSN under the same key.
DROP INDEX secrets_scope_key;
CREATE UNIQUE INDEX secrets_scope_key ON secrets (beamhall_id, beam_id, key, channel);
