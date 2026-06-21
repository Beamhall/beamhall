-- Tag each release with the channel it served (preview | live) so production
-- rollback can target prior LIVE releases without the operator guessing version
-- numbers across the interleaved preview+live history.
ALTER TABLE releases ADD COLUMN channel TEXT NOT NULL DEFAULT 'preview';

-- Backfill: the release each beam is currently serving live is, by definition,
-- a live release. (Superseded historical live releases predate this column and
-- stay 'preview'; a fresh promote cycle tags them correctly going forward.)
UPDATE releases SET channel = 'live'
WHERE id IN (SELECT live_release_id FROM beams WHERE live_release_id <> '');
