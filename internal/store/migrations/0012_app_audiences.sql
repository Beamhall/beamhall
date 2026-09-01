-- Who an app is published to (the using tier). One row per published beam:
-- the row's presence IS the publication — an app is unpublished by default and
-- unpublishing is a delete. Audiences live here, never in the IdP: group names
-- in audience_json are matched against a claim in the user's token at read
-- time. published_by/published_at record the FIRST publication; re-publishing
-- only touches audience_json and updated_at.
CREATE TABLE beam_audiences (
    beam_id       TEXT PRIMARY KEY REFERENCES beams (id),
    beamhall_id   TEXT NOT NULL REFERENCES beamhalls (id),
    audience_json TEXT NOT NULL DEFAULT '{}',
    published_by  TEXT NOT NULL DEFAULT '',
    published_at  INTEGER NOT NULL DEFAULT 0,
    updated_at    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX beam_audiences_beamhall ON beam_audiences (beamhall_id);

-- A plain-language line telling the people who USE an app what it is for. The
-- builder writes it at create_beam; IT may overwrite it when publishing.
ALTER TABLE beams ADD COLUMN description TEXT NOT NULL DEFAULT '';
