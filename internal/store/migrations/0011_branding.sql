-- Company branding IT defines for the apps teams build (header/footer/logo/
-- palette). Keyed by owner: '' is the facility-wide default every beamhall
-- inherits; a beamhall_id row overrides it field-wise. No FK on beamhall_id:
-- the '' facility scope has no parent row.
CREATE TABLE branding (
    beamhall_id   TEXT PRIMARY KEY,
    branding_json TEXT NOT NULL DEFAULT '{}',
    updated_at    INTEGER NOT NULL DEFAULT 0
);

-- The logo lives in the database, not the data dir: backups archive only the
-- manifest, the VACUUMed database, secret.key and repos/, so a file on disk
-- would silently miss every backup. Separate table so the hot branding read
-- never loads the blob.
CREATE TABLE branding_logos (
    beamhall_id TEXT PRIMARY KEY,
    logo        BLOB NOT NULL,
    logo_mime   TEXT NOT NULL DEFAULT '',
    logo_etag   TEXT NOT NULL DEFAULT '',
    updated_at  INTEGER NOT NULL DEFAULT 0
);
