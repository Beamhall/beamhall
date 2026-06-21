-- 0001_init.sql — Beamhall control-plane schema (see docs/PLAN.md §5.2).
--
-- Conventions (enforced by the store wrapper, internal/store):
--   * TEXT id columns are ULIDs. Pointer columns use '' (never NULL) for
--     "unset" so generated code stays free of sql.Null* types.
--   * INTEGER *_at columns are UTC unix nanoseconds; 0 means "unset".
--     preview_pause_after is a Go time.Duration in nanoseconds.
--   * TEXT *_json columns hold JSON-encoded domain sub-structs.
--   * Foreign keys point child -> parent only. Cyclic pointer pairs
--     (beamhall<->security_context, beam<->release, release<->route) keep the
--     back-pointer as a plain TEXT column maintained transactionally by the
--     store, because SQLite enforces FKs at insert time and the pairs are
--     created together.
--   * Nothing is hard-deleted except memberships, secrets, and armed_pauses;
--     beamhalls/beams/routes/releases retire via status so audit references
--     stay resolvable.

CREATE TABLE identities (
    id               TEXT PRIMARY KEY,
    external_subject TEXT NOT NULL,
    email            TEXT NOT NULL,
    display_name     TEXT NOT NULL,
    idp_issuer       TEXT NOT NULL,
    status           TEXT NOT NULL,
    created_at       INTEGER NOT NULL
);
CREATE UNIQUE INDEX identities_issuer_subject ON identities (idp_issuer, external_subject);

CREATE TABLE beamhalls (
    id                  TEXT PRIMARY KEY,
    slug                TEXT NOT NULL,
    display_name        TEXT NOT NULL,
    department          TEXT NOT NULL,
    status              TEXT NOT NULL,
    security_context_id TEXT NOT NULL DEFAULT '',
    network_policy_json TEXT NOT NULL,
    quota_json          TEXT NOT NULL,
    live_slot_limit     INTEGER NOT NULL,
    created_by          TEXT NOT NULL,
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL
);
CREATE UNIQUE INDEX beamhalls_slug ON beamhalls (slug);

CREATE TABLE security_contexts (
    id                 TEXT PRIMARY KEY,
    beamhall_id        TEXT NOT NULL REFERENCES beamhalls (id),
    runtime_class      TEXT NOT NULL,
    userns_remap       BOOLEAN NOT NULL,
    cap_drop_json      TEXT NOT NULL,
    cap_add_json       TEXT NOT NULL,
    seccomp_profile    TEXT NOT NULL,
    apparmor_profile   TEXT NOT NULL,
    no_new_privileges  BOOLEAN NOT NULL,
    read_only_rootfs   BOOLEAN NOT NULL,
    tmpfs_json         TEXT NOT NULL,
    cgroup_limits_json TEXT NOT NULL,
    template           TEXT NOT NULL
);
CREATE UNIQUE INDEX security_contexts_beamhall ON security_contexts (beamhall_id);

CREATE TABLE memberships (
    id          TEXT PRIMARY KEY,
    identity_id TEXT NOT NULL REFERENCES identities (id),
    beamhall_id TEXT NOT NULL REFERENCES beamhalls (id),
    role        TEXT NOT NULL,
    granted_by  TEXT NOT NULL,
    granted_at  INTEGER NOT NULL
);
CREATE UNIQUE INDEX memberships_identity_beamhall ON memberships (identity_id, beamhall_id);
CREATE INDEX memberships_beamhall ON memberships (beamhall_id);

CREATE TABLE beams (
    id                  TEXT PRIMARY KEY,
    beamhall_id         TEXT NOT NULL REFERENCES beamhalls (id),
    slug                TEXT NOT NULL,
    display_name        TEXT NOT NULL,
    runtime_hint        TEXT NOT NULL,
    mode                TEXT NOT NULL,
    state               TEXT NOT NULL,
    current_release_id  TEXT NOT NULL DEFAULT '',
    desired_release_id  TEXT NOT NULL DEFAULT '',
    security_template   TEXT NOT NULL,
    preview_pause_after INTEGER NOT NULL,
    resumed_at          INTEGER NOT NULL,
    git_remote_url      TEXT NOT NULL,
    repo_id             TEXT NOT NULL DEFAULT '',
    created_by          TEXT NOT NULL,
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL
);
CREATE UNIQUE INDEX beams_beamhall_slug ON beams (beamhall_id, slug);

CREATE TABLE builds (
    id              TEXT PRIMARY KEY,
    beam_id          TEXT NOT NULL REFERENCES beams (id),
    source_ref      TEXT NOT NULL,
    source_kind     TEXT NOT NULL,
    builder         TEXT NOT NULL,
    status          TEXT NOT NULL,
    image_ref       TEXT NOT NULL,
    image_digest    TEXT NOT NULL,
    sbom_ref        TEXT NOT NULL,
    cve_scan_status TEXT NOT NULL,
    log_stream_id   TEXT NOT NULL DEFAULT '',
    triggered_by    TEXT NOT NULL,
    started_at      INTEGER NOT NULL,
    finished_at     INTEGER NOT NULL
);
CREATE INDEX builds_beam ON builds (beam_id);

CREATE TABLE releases (
    id                    TEXT PRIMARY KEY,
    beam_id                TEXT NOT NULL REFERENCES beams (id),
    build_id              TEXT NOT NULL REFERENCES builds (id),
    version               INTEGER NOT NULL,
    config_snapshot_json  TEXT NOT NULL,
    secret_refs_json      TEXT NOT NULL,
    security_profile_json TEXT NOT NULL,
    route_id              TEXT NOT NULL DEFAULT '',
    status                TEXT NOT NULL,
    created_at            INTEGER NOT NULL,
    activated_at          INTEGER NOT NULL
);
CREATE UNIQUE INDEX releases_beam_version ON releases (beam_id, version);

CREATE TABLE routes (
    id           TEXT PRIMARY KEY,
    beam_id       TEXT NOT NULL REFERENCES beams (id),
    release_id   TEXT NOT NULL DEFAULT '',
    kind         TEXT NOT NULL,
    hostname     TEXT NOT NULL,
    random_token TEXT NOT NULL,
    backend_addr TEXT NOT NULL,
    tls_cert_ref TEXT NOT NULL,
    status       TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    retired_at   INTEGER NOT NULL
);
CREATE UNIQUE INDEX routes_active_hostname ON routes (hostname) WHERE status = 'active';
CREATE INDEX routes_beam ON routes (beam_id);

CREATE TABLE resources (
    id                     TEXT PRIMARY KEY,
    beamhall_id            TEXT NOT NULL REFERENCES beamhalls (id),
    beam_id                 TEXT NOT NULL DEFAULT '',
    type                   TEXT NOT NULL,
    status                 TEXT NOT NULL,
    connection_secret_json TEXT NOT NULL,
    spec_json              TEXT NOT NULL,
    backing_handle         TEXT NOT NULL,
    created_at             INTEGER NOT NULL,
    updated_at             INTEGER NOT NULL
);
CREATE INDEX resources_beamhall ON resources (beamhall_id);
CREATE INDEX resources_beam ON resources (beam_id);

CREATE TABLE secrets (
    id          TEXT PRIMARY KEY,
    beamhall_id TEXT NOT NULL REFERENCES beamhalls (id),
    beam_id      TEXT NOT NULL DEFAULT '',
    key         TEXT NOT NULL,
    value_ref   TEXT NOT NULL,
    version     INTEGER NOT NULL,
    created_by  TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);
CREATE UNIQUE INDEX secrets_scope_key ON secrets (beamhall_id, beam_id, key);

-- audit_events is append-only: no UPDATE/DELETE queries exist, and seq
-- (AUTOINCREMENT) gives the hash chain a gapless-claim total order that
-- survives ULID clock skew. No FKs: an audit row must outlive (and never be
-- blocked by) the entities it mentions.
CREATE TABLE audit_events (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    id              TEXT NOT NULL UNIQUE,
    at              INTEGER NOT NULL,
    actor_id        TEXT NOT NULL,
    actor_token_jti TEXT NOT NULL,
    beamhall_id     TEXT NOT NULL,
    beam_id          TEXT NOT NULL,
    action          TEXT NOT NULL,
    decision        TEXT NOT NULL,
    reason          TEXT NOT NULL,
    request_digest  TEXT NOT NULL,
    result_status   TEXT NOT NULL,
    source_ip       TEXT NOT NULL,
    prev_hash       TEXT NOT NULL,
    hash            TEXT NOT NULL
);
CREATE INDEX audit_events_beamhall ON audit_events (beamhall_id, seq);

-- armed_pauses backs scheduler.Store (internal/scheduler): one absolute
-- preview-pause deadline per beam, upserted on Arm and removed on Disarm/fire.
CREATE TABLE armed_pauses (
    beam_id   TEXT PRIMARY KEY,
    deadline INTEGER NOT NULL
);
