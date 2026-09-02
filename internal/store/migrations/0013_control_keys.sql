-- Vault-sealed control-plane key material (e.g. the app-assertion signing
-- key). Lives in the store, not the data dir, so it rides admin_backup_now
-- with the database — a key that workloads verify against must survive a
-- restore, or every deployed app's verification breaks at once.
CREATE TABLE control_keys (
    kind       TEXT PRIMARY KEY,
    sealed     TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT 0
);
