-- Beam soft-delete: destroy_beam archives a Beam rather than dropping the row,
-- so audit events, releases, and builds keep their foreign-key targets. Quota
-- counting and slug uniqueness consider only ACTIVE beams: destroying a beam
-- frees its quota slot and releases its slug for reuse.
ALTER TABLE beams ADD COLUMN status TEXT NOT NULL DEFAULT 'active';

DROP INDEX beams_beamhall_slug;
CREATE UNIQUE INDEX beams_beamhall_slug ON beams (beamhall_id, slug) WHERE status = 'active';
