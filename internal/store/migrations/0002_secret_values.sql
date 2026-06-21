-- 0002_secret_values.sql — at-rest ciphertext store for secret values.
--
-- secrets.value_ref points here. Kept in a separate table (not a column on
-- secrets) so a rewrite can stage new ciphertext under a fresh ref before the
-- metadata row flips, and so the blob is the only place plaintext-derived bytes
-- ever live. internal/secret owns the age envelope; the store never decrypts.
-- ref is opaque to the store. ciphertext is an age-encrypted blob.

CREATE TABLE secret_values (
    ref        TEXT PRIMARY KEY,
    ciphertext BLOB NOT NULL,
    created_at INTEGER NOT NULL
);
