# Beamhall — implementation status & resume guide

This is the **living status doc**: read it (plus `docs/PLAN.md` for the design and
`docs/lab-phase0-validation.md` for hardware evidence) to resume work in a new
session. The in-session task list is ephemeral and is NOT a source of truth — this
file is.

_Last updated: **Phases 2 and 3 complete** — backplane (store; secret vault;
audit chain; PEP; orchestrator; build pipeline; Postgres provisioner; MCP +
OAuth) PLUS agent error-UX diagnosis, the negative-security suite, the
rollback/destroy/show_metrics + build-bomb-cap lifecycle surface, the OIDC
Admin console, and the git smart-HTTP push transport. All lab-verified
(`internal/e2e`: demo flow, negsec proofs, lifecycle, git-push, all on the lab
VM). Phase 4 (pilot + backup/restore + threat-model doc) in progress; latest:
**admin lifecycle over MCP + the owned-IdP administration seam (3rd stable seam)
+ a persistent bundled Keycloak** (see the Phase 4 entries below — code-complete +
unit-tested, lab verification pending). Project was renamed Workcell→Beamhall
(product + domain entities: `Workcell`→`Beamhall` workspace, `App`→`Beam`
workload; module `github.com/Beamhall/beamhall`, binary `beamhalld`, env
`BEAMHALL_*`). Branch model: feature branches fast-forward-merged to `main`;
no PRs (per operator). Commit email `marcosmachado@gmail.com`. Repo:
`git@github.com:Beamhall/beamhall.git`._

## Going open source (in progress)

Beamhall is being released as an **open-source project** under **Apache-2.0**
(domain: `beamhall.com`). Added at repo root: `LICENSE` (canonical Apache-2.0),
`NOTICE`, `CONTRIBUTING.md`, `SECURITY.md` (private disclosure → `security@beamhall.com`),
`CODE_OF_CONDUCT.md`, and a public-facing `README.md`. A marketing + docs site
lives in `website/` (Astro + Starlight, static → Cloudflare Pages; `npm run dev`
in that dir). **Before the repo flips public**, internal test-VM SSH/IP details
were scrubbed from the committed docs (the concrete address now lives only in the
maintainer's private ops notes / agent memory, referenced as `$BEAMHALL_TEST_HOST`).
Remaining for the public flip: GitHub issue templates, and wiring the Cloudflare
Pages project + the `beamhall.com` DNS.

**First public releases (2026-06-21):** ~~decide on a goreleaser/CI workflow~~
**DONE** — `.github/workflows/release.yml` (tag `v*` → GoReleaser → published
GitHub Release with checksums), and `install.sh` now **fetches the released
binary by arch + verifies the checksum** (local path stays the dev fast-path).
Cut **v0.1.0** (the install path) and **v0.1.1** (usable MCP-created workspaces +
a true one-liner bundled IdP). The supported install is now:
`curl -fsSL https://raw.githubusercontent.com/Beamhall/beamhall/v0.1.1/packaging/install.sh | sudo bash -s -- --base-domain <d> --tls internal`.
Product fixes found by a **from-scratch MCP-driven pilot** (clean snapshot → live
beam, simulating a first-time IT admin; see the 2026-06-21 section in
`docs/lab-phase0-validation.md` and the new `docs/getting-started.md`):
**v0.1.1** — (1) `admin_create_beamhall` over MCP defaulted to a **zero quota** →
unusable workspace, now defaults 5/1/2 + optional overrides; (2) the bundled-IdP
setup is a true `curl|bash` one-liner (self-fetches its sibling files).
**v0.1.2** — **role-gated IT admin over MCP**: an IT admin couldn't get the hidden
`admin:it` scope through `claude mcp add`'s browser OAuth, so IT-admin is now
derived from the `admin:it` scope **OR** a configurable realm role
(`BEAMHALL_OAUTH_ADMIN_ROLE`, default `beamhall-it`; verifier extracts
`realm_access.roles`). The bundled realm adds the `beamhall-it` role + a public
`beamhall-admin-agent` client, so `claude mcp add --client-id beamhall-admin-agent`
gives admins a plain browser-OAuth admin connection gated by a role a builder can't
hold. Lab-verified; unit-tested. The Admin console + `--header` token paths still
work.

## Build & test

```sh
go build ./...
go vet ./...
go test -race ./...        # all unit tests (integration tests skip without BEAMHALL_DOCKER_IT)
```

**Lab integration tests** run against the lab VM (they require Docker, root, and
— for the gateway — a running Caddy). Pattern (see each test file's top comment
for specifics):

The integration host address is kept out of this public repo; export it as
`BEAMHALL_TEST_HOST` (maintainers: see the private ops notes).

```sh
GOOS=linux GOARCH=amd64 go test -c ./internal/<pkg> -o /tmp/<pkg>.test
scp /tmp/<pkg>.test root@"$BEAMHALL_TEST_HOST":/tmp/
ssh root@"$BEAMHALL_TEST_HOST" 'BEAMHALL_DOCKER_IT=1 BEAMHALL_IT_IMAGE=bh-smoke-beam /tmp/<pkg>.test -test.v'
```

- `internal/driver` — `TestDockerDriverLifecycle` (runc + runsc).
- `internal/egress` — `TestEgressDefaultDenyAndAllowlist` (root; deny/allow/metadata).
- `internal/gateway` — `TestGatewayRoutesToContainer` (needs `caddy start` first; uses `:8088`).
- `internal/e2e` — `TestMCPEndToEnd`: the canonical demo flow against a real
  `beamhalld` process over real MCP + OAuth (build the daemon first:
  `GOOS=linux GOARCH=amd64 go build -o /tmp/beamhalld ./cmd/beamhalld`, scp
  both, run the test binary; needs Caddy + build daemon + registry +
  Postgres; uses `:18443`/`:8089`). ~26 s warm.

## Test appliance VM

- SSH: `root@$BEAMHALL_TEST_HOST` (key auth) — full root, the standing test target.
  The concrete address is kept in the maintainer's private ops notes, not in this
  public repo.
- Ubuntu 26.04 LTS, kernel 7.0, cgroup v2, 4 vCPU / 3.3 GiB RAM (below the 8 GiB
  rec — fine for smoke tests, tight for real `pack` builds).
- Provisioned by `scripts/lab-bootstrap.sh`: Docker 29 (userns-remap=default),
  runc 1.4, gVisor `runsc` (registered runtime), pack 0.40.6, Caddy 2.11.
- The smoke image `bh-smoke-beam` (Paketo Node runtime, serves `beamhall ok` on
  `$PORT`) is loaded for integration tests. It is the phase-0 Paketo image with
  the app source overlaid via plain `docker build` (recipe at
  `/root/bh-smoke/Dockerfile` on the VM) — the buildpack lifecycle can't run on
  the userns-remapped daemon, and a from-source `pack` rebuild belongs to the
  item-4 build pipeline. All three integration suites re-passed under the new
  names after the rename (see lab-phase0-validation.md, re-provisioning
  section).

## Status by phase

### Phase 0 — foundations ✅ (lab-validated)
| Item | Where | Verified |
|---|---|---|
| Domain entities + Beam FSM | `internal/domain` | unit (`fsm_test.go`) |
| `RuntimeDriver` interface | `internal/driver/driver.go` | — |
| Config + entrypoint | `internal/config`, `cmd/beamhalld` | builds, graceful shutdown |
| Preflight + lab bootstrap | `scripts/preflight.sh`, `lab-bootstrap.sh` | lab: 0 warnings |
| gVisor + hardening gate | `scripts/runsc-smoke.sh` | lab: real Paketo beam under runc + runsc |

### Phase 1 — runtime substrate ✅ (lab/race-verified)
| Item | Where | Verified |
|---|---|---|
| Docker `RuntimeDriver` impl | `internal/driver/dockerdriver.go` | lab: runc + runsc, secrets, lifecycle |
| Egress reconciler (iptables DOCKER-USER) | `internal/egress` | lab: deny/allow/metadata |
| Durable preview-pause scheduler | `internal/scheduler` | unit+race: boot catch-up, retry |
| Caddy gateway (routes + on-demand TLS ask) | `internal/gateway` | lab: route→container→retire |

**Three bugs the lab caught** (see `docs/lab-phase0-validation.md`): egress
ESTABLISHED-rule bypass (removed), `Exec` premature exit code (fixed), and the
`pack`-build-vs-userns-remap constraint (builds run off the runtime daemon).

### Phase 2 — backplane + agent flow (in progress)
| Item | Where | Verified |
|---|---|---|
| SQLite control-plane store | `internal/store` | unit+race: round-trips, scheduler seam, restore, concurrency, missing-id→ErrNotFound |
| `age` secret service + log scrubber | `internal/secret` | unit+race: encrypt-at-rest, inject, version+GC, key-seal isolation, scoped scrub |
| Hash-chained audit log | `internal/audit` | unit+race: chain build, mutation/rehash/deletion detection, truncation blind spot, concurrency, export round-trip |
| Policy PEP (item 4, stage 1) | `internal/policy` | unit+race: role matrix, forbidden list, cross-beamhall isolation, audited decisions, quota gates, concurrent-promote race |
| Orchestrator core (item 4, stage 2) | `internal/orch` | unit+race (fake driver/gateway, real store/vault/PEP/audit/scheduler): deploy happy path, start-failure→failed, pause/resume URL re-mint, scheduler PauseFunc, builder-403 promote, redeploy supersede, scrubbed logs, boot route restore. **Lab: vault→driver junction verified** — real driver + vault, in-container secret read, HTTP, pause/resume/promote, chain Verify (see lab doc) |
| Build pipeline (item 4, stage 3) | `internal/build` | unit+race: repo snapshot/checkout round-trip (exec bit, symlinks), pack invocation flags, registry digest, pipeline compose, orch source-deploy. **Lab: full path verified** — pack on the dedicated build daemon → loopback registry → runtime pull-by-digest → hardened run (see lab doc) |
| Postgres provisioner (item 4, stage 4) | `internal/resource` | unit: orch create_database (vault seal, quota, resource row, DSN auto-inject on deploy, no DSN in audit). **Lab: scoped role works on own db, `42501` denied on sibling db, beam-side reachability via attached network, Drop** (see lab doc) |
| OAuth resource server (item 5) | `internal/auth` | unit: valid RS256/ES256 accepted; wrong iss/aud, expired, nbf, no-exp/sub, garbage, alg=none, HS256 all rejected; JWKS rotation refetch + cooldown DoS bound; Entra `scp` arrays; Origin allowlist |
| MCP server (item 5) | `internal/mcp` | unit (full HTTP stack, fake backplane): 401 + WWW-Authenticate w/o token, RFC 9728 metadata, tool contract list, per-tool scope gates, unknown-identity refusal, tarball escape/zip-bomb rejection, progress notifications, PEP denial passthrough. **Lab E2E (`internal/e2e`): the whole demo flow — see below** |
| Scrubber heuristics (item 5) | `internal/secret` | unit: PEM/JWT/vendor-prefix/URL-credential/high-entropy redacted; git SHAs, sha256 digests, UUIDs, prose untouched. **Lab: a beam that logged its own secret returned `***REDACTED***` through show_logs** |
| Full-stack E2E (item 5) | `internal/e2e` + `cmd/beamhalld` wiring | **Lab: real beamhalld process, real JWTs (local JWKS): create_beam → set_secret → create_database → deploy_beam (tarball→pack→registry→hardened run, SSE progress in the MCP client) → preview URL via Caddy with both secret files in-container → scrubbed show_logs → pause (URL dies) / resume (new URL) → builder promote denied by the PEP (scope present, role short) → IT promote via admin:it → live URL → audit chain verifies: 17 events, deny recorded, no secret values** |

MCP + OAuth specifics (`internal/mcp`, `internal/auth`, item 5):
- **Token validation at the boundary, authorization in the PEP** (PLAN §6).
  `auth.Verifier` implements the go-sdk `auth.TokenVerifier`: JWKS (kid cache,
  rotation refetch, 30 s cooldown), exact `iss`, `aud` == resource URI, exp/nbf
  (30 s leeway), RS256/ES256 only — HMAC/`none` rejected at config time. Scopes
  from `scope` string or Entra `scp` array. The MCP layer maps (issuer, sub) →
  registered Identity (`GetIdentityByIssuerSubject`); unknown-but-valid tokens
  get "ask IT to register". `admin:it` scope ⇒ `Actor.ITAdmin`.
- **Scopes are coarse capability classes** (`internal/auth/scopes.go`); each
  tool checks one before touching the backplane and refuses with
  `insufficient_scope: …` (the client's step-up cue). Which-beamhall stays
  data-driven in the PEP — the E2E proves a token *with* `beams:promote` still
  gets the PEP denial when the role is builder.
- Tools (PLAN §5.7): list_beams, create_beam, deploy_beam, get_repo,
  create_database, provision_email/show_email, provision_object_store/show_object_store,
  set_secret, show_logs, show_metrics, pause_preview,
  resume_preview, promote_to_live, rollback, archive_beam, destroy_beam;
  create_queue answers "not enabled in this build" (object storage graduated to
  provision_object_store, PLAN §5.13). Addressing is by slugs. Tools return
  handles/intents only — create_database returns the secret key +
  `/run/secrets/<KEY>` path, never the DSN.
- **Beam CRUD / archival**: `destroy_beam` and `archive_beam` share one terminal
  archival path (`Status=archived`: workload + URL retired, quota slot + slug
  freed, **source repo + audit retained**; `ListBeamsByBeamhall` filters
  `status='active'`). They differ by *who* and *what*: **`archive_beam`** is
  **builder self-service, preview-only** (the "rejected idea → shelve it" case;
  orch `archivePreview` refuses live beams), scope `beams:operate`, policy
  `ActionArchiveBeam` (builder+). **`destroy_beam`** stays **IT-gated** and works
  on **live** beams (production teardown). Archival is terminal + data-retained
  (no in-place revive — start again = new beam, optionally `get_repo`-cloning the
  retained source). Decisions locked with the operator 2026-06-15.
  **Teardown reclaims resources** (lab finding, non-technical-user sim): destroy/
  archive now drops the beam's managed Postgres db/role + resource row (frees the
  `max_db_count` quota; `store.DeleteResource`) and **retires the git repo** to
  `<hall>/.retired/` (so a reused slug starts fresh, source preserved). Also:
  `create_database` is idempotent per `(beam,name)`.
- **Deploy loop hardening** (lab finding, non-technical-user sim — see
  lab-phase0-validation): the push command is now
  `git -c pack.window=0 push --no-thin …` — a **delta-free** pack, because go-git's
  receive-pack can't resolve REF_DELTA packs ("reference delta not found" broke
  every redeploy). The one-time push **token is spent only on a successful deploy**
  (a failed build leaves it valid for fix-and-re-push). `push_command`+`git_remote`
  ride in `deploy_beam`'s **structuredContent** (clients that drop the text block
  still get them).
- **Discovery (`list_beams`, scope `beamhalls:read`)**: the agent's entry point on
  a fresh machine/session — lists the beamhalls the caller is a **member of** and
  their active beams (slug, mode, state, URL). **Membership-scoped** via
  `ListMembershipsByIdentity` (no global enumeration — preserves the
  EscapeItsBeamhall isolation property); archived beams excluded (the list query
  filters `status='active'`). Wired the previously-unused `beamhalls:read` scope.
- **deploy_beam transports** (preferred → fallback): **git push** is the default —
  call `deploy_beam` with no source and it mints a one-time, beam-scoped token and
  returns a ready-to-run `git push` remote (`internal/gitserver`, smart-HTTP
  receive-pack, build streams back as `remote:` lines). `source_tarball` (base64
  gzip tar ≤ 8 MB compressed, 64 MB/4096-entry decompression caps, path-escape +
  non-local symlink rejection, exec-bit-only modes) is the **fallback** for
  git-less clients / when push isn't working. `image_ref`+`image_digest` pins a
  prebuilt image. All converge on the same `Pipeline.BuildFromDir`/commit SHA.
  Agent-facing tool text now leads with git and labels the tarball FALLBACK ONLY.
- **Beamhall is the home of the beam's source** (no BYO git host needed). The
  managed per-beam repo is **cloneable**: the git server serves `upload-pack`
  (read) alongside `receive-pack` (push), and **`get_repo`** mints a one-time,
  read-only, beam-scoped clone token + a ready-to-run `git clone` command — used
  to restore/sync a project on a new machine. Two token kinds in
  `gitserver.TokenStore`: push (one-time, 15m) and read (reusable within TTL,
  1h); kinds don't cross (a push token can't clone, a read token can't push).
  **Implication: the repos volume (`<DataDir>/repos`) is now canonical source,
  same backup/DR tier as Postgres — back it up.** A browsable web git host
  (Gitea/Forgejo) is deliberately *not* bundled; revisit only if humans need to
  browse code/branches/PRs in a UI.
- **SSE progress**: pack output → `build.WithProgress(ctx, w)` (per-call
  context writer, tee'd with `Pipeline.Logs`) → line-buffered
  `progressNotifier` → MCP progress notifications on the caller's token.
  Lab-verified live in the client. Cancellation: the SDK cancels the tool
  context on MCP CancelledNotification; pack runs under exec.CommandContext.
- RFC 9728 Protected Resource Metadata at
  `/.well-known/oauth-protected-resource`; 401s carry the WWW-Authenticate
  challenge pointing at it. Origin allowlist middleware wraps `/mcp`
  (DNS-rebinding defense; requests without Origin — CLI clients — pass).
- The **signed internal identity assertion** MCP→backplane (PLAN §6) is an
  in-process `orch.Actor` today — single binary, no network hop. Revisit only
  if the MCP front end ever splits out.
- `cmd/beamhalld` is fully wired (driver, gateway w/ listen+TLS-off config,
  scheduler ↔ orchestrator late-bound PauseFunc, builder, provisioner, egress
  boot reconcile per beamhall bridge, MCP+metadata+healthz+caddy-ask mux,
  graceful shutdown). No insecure mode: without IdP env, /mcp answers 503.
- `cmd/bh-devidp` is a LAB-ONLY JWKS + token-mint server (Keycloak bundling is
  Phase 4 packaging); the E2E suite embeds its own equivalent.

Database provisioner specifics (`internal/resource` + `orch.CreateDatabase`):
- One appliance Postgres (`bh-postgres`, bootstrap step 10); each
  `create_database` mints `bh_<hall>_<beam>_<name>` + a `_rw` LOGIN role,
  `REVOKE ALL … FROM PUBLIC` (db-per-beam isolation, lab-proven with correct
  credentials → `42501`). Admin DSN is backplane-only (loopback :5433).
- Reachability without egress holes: the provisioner's `Attach` hook connects
  the Postgres container to the beamhall bridge
  (`driver.ConnectContainerToNetwork`); beams dial `bh-postgres:5432` —
  same-bridge traffic, DOCKER-USER untouched.
- The DSN is **sealed into the vault** under `<NAME>_URL` (e.g. `MAIN_URL`)
  — the agent learns the key only; the value surfaces as
  `/run/secrets/<NAME>_URL` on the next deploy (auto-injected via the
  existing secret scope; unit-proven). Vault failure rolls the database back.
  Resource row records type/status/secret-ref/spec; DSN never reaches audit.

Build pipeline specifics (`internal/build`):
- Per-beam **managed bare repos** (embedded go-git — no system git): every
  source path converges through `ImportSnapshot` (dir → snapshot commit on
  `main` → SHA = immutable `Build.source_ref`); `CheckoutTo` materializes the
  build dir. The smart-HTTP push transport + MCP `source_tarball` arrive with
  item 5 — both end at `BuildFromDir`.
- **Packer** shells out to `pack build --publish --network host
  --trust-builder` with `DOCKER_HOST` pointed at the **dedicated non-remapped
  build daemon** (`docker-build.service`, provisioned by `lab-bootstrap.sh`
  step 8 — own config so it never inherits userns-remap; `bridge:none`,
  `iptables:false`). Never point it at the runtime daemon (lab finding).
  10-minute default timeout (runaway-build defense).
- Image naming: `<registry>/<hall-slug>/<beam-slug>:<sha12>`; digest resolved
  from the registry (`Docker-Content-Digest`), deploys use the pull ref
  `<repo>@sha256:...`. Internal registry = `registry:2` loopback-only on
  `127.0.0.1:5000` (bootstrap step 9).
- `driver.Deploy` now **pulls the image if absent** (pull-by-digest,
  idempotent) — the runtime daemon only pulls and runs.
- Orchestrator: `DeployBeamFromSource` (same PEP action as deploy_beam) runs
  the `Builder` seam (`WithBuilder(*build.Pipeline)`) inside the same
  lifecycle as pinned-image deploys via the shared `buildStep`; pack output
  streams to `Pipeline.Logs` (the future SSE source).

Orchestrator specifics (`internal/orch`):
- Every operation: PEP `Authorize` (decision audited) → effect → `outcome`
  audit event (`ResultStatus` ok/failed) — deny = 1 chain event, allowed op = 2.
- `DeployBeam` lifecycle: FSM `deploy`→building → Build row (stage 2: pinned
  image digest, `SourceImageRef`; the pack pipeline replaces this input) →
  Release (snapshot: secret keys in scope, SecurityContext, port) →
  `vault.Inject` → `driver.Deploy` (per-Beamhall network `bh-<id>`, hardened
  profile, secret file mounts) → `Start`/`Status` → activate release, retire
  predecessor (stop+destroy old workload, retire old route), mint route
  (random preview / stable live by mode), arm pause timer (preview only).
  Failures land the Beam in `failed` via `EvBuildFail`/`EvStartFail`.
- Pause retires the route (paused preview URL dies); resume thaws, mints a
  **new** random URL, re-arms. The scheduler fires the same path via
  `PauseFunc` (a stale timer on a live beam refuses on the FSM).
- `PromoteToLive` = FSM check → transactional `store.PromoteBeam` (effective
  limit) → disarm → stable `<beam>.<hall>.<base>` route. `ShowLogs` scrubs
  via `vault.ScrubberFor` backplane-side before bytes leave the process.
- Workload handles persist on releases (migration `0003`,
  `store.SetReleaseWorkload`) so pause/stop/destroy survive restarts;
  `Boot` re-upserts active routes into the gateway.
- Not yet wired into `cmd/beamhalld` — the MCP server (item 5) is the caller;
  remaining for item 4: build pipeline (stage 3), Postgres provisioner +
  vault→driver lab junction test (stage 4).

Policy PEP specifics (`internal/policy`):
- `Authorize(Request)` order: forbidden list → identity active → beamhall
  active → it_admin bypass (membership only — never the forbidden list) →
  membership lookup (no membership = cross-Beamhall isolation) → role matrix.
  Returns `*Denial` (→ MCP 403); **every decision is appended to the audit
  chain** (deny = 1 event; allowed ops get a second outcome event from the
  orchestrator). An unauditable decision is treated as denied.
- Role matrix is additive (viewer ⊂ builder ⊂ beamhall_admin); builders
  deliberately lack `promote_to_live`/`destroy_beam` (the demo's 403).
  Forbidden actions (get_secret, mutate security/quota/egress, raw runtime,
  dockerfile) are named `Action`s so attempts land in the audit log precisely.
- Quota gates fail closed on unset limits: `CheckBeamQuota`,
  `CheckDatabaseQuota` (→ `*QuotaError`), `EffectiveLiveSlotLimit` =
  min(LiveSlotLimit, Quota.MaxLiveSlots). The live-slot count-and-flip is
  transactional in `store.PromoteBeam` (new, `ErrQuota` sentinel) — race-tested
  with 8 concurrent promotes into 1 slot.

Audit log specifics (`internal/audit`):
- `Logger.Append` seals each event onto the chain: `Hash` = SHA-256 over a
  versioned, length-prefixed canonical encoding (`beamhall-audit-v1`) of all
  fields except `seq`/`Hash`, including `PrevHash`. Genesis `PrevHash` = `""`.
  Caller-supplied hash fields are always overwritten.
- Atomicity: `store.AuditChainAppend` runs read-head → seal → insert inside one
  `BEGIN IMMEDIATE` transaction, so concurrent appends cannot fork the chain —
  the Logger holds no in-process chain state (restart-safe by construction).
- `Verify` walks the log and checks seq contiguity (AUTOINCREMENT + no deletes
  ⇒ a gap means removed rows), `PrevHash` linkage, and hash recomputation;
  returns all violations, not just the first. Documented blind spot: a
  truncated tail passes until the next append exposes the seq gap
  (sqlite_sequence high-water mark) — the off-box anchor is `Export`.
- `Export` streams JSON Lines with a resumable `afterSeq` cursor (the SIEM
  shipping loop, PLAN §6).
- `cmd/beamhalld` runs `Verify` at boot and logs violations loudly but does
  **not** refuse to start (availability over bricking). Whether boot should
  hard-fail on a broken chain is an open orchestrator-phase decision.

Secret service specifics (`internal/secret`):
- `age` X25519 envelope encryption. Values are sealed to the vault key before
  they reach the store; **write-only** — no get-value API an agent can reach.
  Read paths are backplane-only: `Inject` (→ `[]driver.SecretMount` at
  `/run/secrets/<key>`, tmpfs, never env) and `ScrubberFor` (redacts values from
  `show_logs`/`show_metrics`).
- Ciphertext lives **in SQLite** (`secret_values` table, migration `0002`); the
  store holds opaque `value_ref` pointers and never decrypts. A rewrite stages a
  fresh blob, flips the metadata pointer (version++), then GCs the old blob.
- Root key = age identity at `$BEAMHALL_DATA_DIR/secret.key` (0600).
  `LoadOrCreateKey` generates-if-absent for dev/lab (warns); **production must
  supply it out-of-band** (systemd `LoadCredential`/KMS/TPM). Malformed key = hard
  fail, never silently regenerated. `cmd/beamhalld` loads it + builds the vault at
  boot (not yet wired to a consumer — orchestrator/MCP land in items 4–5).
- Scrubber is exact-substring, longest-first, skips values < 4 bytes (avoids
  shredding logs on low-entropy short secrets), scoped to a beam's own + the
  beamhall-wide secrets.
- ~~Deferred (PLAN §6 premise)~~ ✅ **Heuristics landed with item 5**
  (`heuristics.go`): PEM private-key blocks, JWTs, vendor key prefixes
  (AWS/GitHub/Slack/Google/age/GitLab/sk-), URL userinfo credentials, and
  high-entropy base64 words ≥ 28 chars (Shannon ≥ 4.2; pure-hex excluded so
  git SHAs/sha256 digests survive). On by default via `ScrubberFor`
  (`WithHeuristics`); known-value pass still runs first.

Store specifics (decisions live in `internal/store/store.go` package doc and
`migrations/0001_init.sql` header):
- `modernc.org/sqlite` (pure-Go) + sqlc-generated queries (`internal/store/db`,
  regenerate with `cd internal/store && go run
  github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1 generate`) + go:embed'd migrations
  applied via `PRAGMA user_version`.
- WAL + busy_timeout + `BEGIN IMMEDIATE`, **single connection**
  (`MaxOpenConns(1)`): one writer, no SQLITE_BUSY class.
- Timestamps = int64 unix-nanos (0 = unset); nested domain structs = JSON TEXT;
  `''` (not NULL) for unset id pointers; FKs child→parent only (cyclic pairs
  like beam↔release keep plain back-pointer columns, store maintains them).
- Implements `scheduler.Store` (`Store.PauseStore()`) and the gateway boot
  restore source (`Store.ActiveRoutes()` → map to `gateway.Route` → `Restore`
  + `Apply`). `cmd/beamhalld` now opens the store at `$BEAMHALL_DATA_DIR/beamhall.db`.
- `audit_events.seq` (AUTOINCREMENT) is the hash-chain total order; chain
  hashing + append serialization live in `internal/audit` over
  `Store.AuditChainAppend` (transactional read-head → seal → insert).
- Single-row mutations (the 10 `Update*`/`ActivateRelease`/`SetReleaseRoute`/
  `RetireRoute`/`UpdateSecurityContext` wrappers) use sqlc `:execrows` and return
  `ErrNotFound` on a zero-row match via the `affected()` helper — a missing/stale
  id no longer succeeds silently as a no-op (e.g. promote pointed at a typoed
  release id). `RetireRoute` stays idempotent (re-retiring matches the row).
  Covered by `notfound_test.go`.

## Current package layout
```
cmd/beamhalld/        the appliance: full wiring of store+vault+audit+PEP+orch+build+resources+egress+MCP/OAuth; subcommands: backup, restore, admin {bootstrap, register-identity}
cmd/bh-devidp/        LAB-ONLY dev IdP (JWKS + token mint) until Keycloak bundling (Phase 4)
cmd/bh-demo/          canonical-demo agent driver (narrated MCP flow); see demo/
demo/                 canonical Request Tracker (Node beam-app) + run-demo.sh; lab-verified end-to-end
internal/domain/      entities + Beam FSM (pure)
internal/driver/      RuntimeDriver iface + Docker impl (runc/runsc, secrets, network, exec)
internal/egress/      iptables DOCKER-USER reconciler (default-deny + allowlist + always-deny)
internal/scheduler/   durable preview-pause (Store + PauseFunc interfaces; crash-correct)
internal/gateway/     Caddy Admin-API client (Upsert/Retire/Snapshot, AskHandler)
internal/store/       SQLite control-plane store (sqlc; migrations/ + queries/ + db/ generated)
internal/secret/      age envelope secret service (write-only) + log/metric scrubber
internal/audit/       hash-chained append-only audit log (Verify, JSON-Lines SIEM export)
internal/policy/      PEP: role/action matrix, forbidden list, quota gates (audited decisions)
internal/orch/        orchestrator: lifecycle reconciler wiring driver+gateway+scheduler+vault+audit behind the PEP (livechannel.go = the pinned live channel: promote/rollback/reconcile)
internal/build/       source→image pipeline: managed go-git repos + pack (build daemon) + registry digest
internal/resource/    managed-resource provisioners (Postgres: scoped role + db per beam)
internal/facility/mail/  email delivery facility (PLAN §5.12): go-smtp broker engine + control channel (broker server + beamhalld client). The bh-mail service container runs `beamhalld mail-relay`.
internal/facility/s3/    object-storage facility (PLAN §5.13): gofakes3 engine + our SigV4 verifier/normalizer + local + minio-go forward backends + control channel. The bh-objstore container runs `beamhalld object-store-relay`.
internal/auth/        OAuth resource server: JWKS/iss/aud/exp/scope validation, Origin check
internal/identityadmin/ owned-IdP administration seam (3rd stable seam): Provider iface + Keycloak Admin-REST impl + Disabled (BYO-IdP)
internal/mcp/         agent-facing MCP server (official go-sdk, Streamable HTTP): tools (incl. admin_* family), per-caller tools/list filtering (visibility.go), progress, tarball transport
internal/upgrade/     self-upgrade seam (Stager: Disabled default + Release impl): download + sha256-verify + stage a pinned release; operator-applied atomic swap
internal/diagnose/    failure-signature catalog: infra denials → agent-actionable hints (build/run/exit)
internal/web/         IT Admin console (/admin): OIDC login + session, views + audited IT actions
internal/gitserver/   git smart-HTTP push transport (/git): receive-pack + one-time deploy tokens → build+deploy
internal/e2e/         lab suites: demo flow + negsec + lifecycle (rollback/destroy) + git-push deploy
internal/config/      env config
scripts/              preflight, runsc-smoke, lab-bootstrap
scripts/agent-conformance/  four-persona MCP conformance suite (bh-mcp-proxy.py +
                      provision/verify/gates/teardown/bh-call) — see docs/agent-conformance.md
.mcp.json + .claude/agents/bh-*.md  the four authenticated personas (2 admin, 2 builder)
.claude/agents/       specialist subagents: release-guardian (owns releases) +
                      website-steward (owns website/) — main context delegates to them (see CLAUDE.md)
CHANGELOG.md + WORKFLOW.md  release notes (Keep a Changelog) + the release-process pointer
docs/                 PLAN.md, STATUS.md (this), lab-phase0-validation.md, threat-model.md,
                      beamhall-for-it.md (IT overview + planning surface),
                      getting-started.md (IT admin's step-by-step first-hour play),
                      admin-over-mcp.md, agent-conformance.md, idp-setup.md, air-gapped.md
.github/workflows/    ci.yml (build/vet/test + website) + release.yml (tag → GoReleaser → release; body from CHANGELOG)
website/              public marketing site (single-page Astro → Cloudflare); owned by the website-steward agent
```

## Key design decisions (pointers)
- **Dual-channel beams (preview + live)** — a beam runs a permanent **preview**
  channel (the builder's iterating workload: `Beam.State` + `CurrentReleaseID`,
  stable preview URL, auto-pauses) and an optional **live** channel
  (`Beam.LiveReleaseID` + `LiveState`, stable production URL, never pauses).
  `promote_to_live` **pins the live channel to the build the preview is running
  now** (same image digest) and brings up a *separate* live workload — it no
  longer flips mode and destroys the preview. Repeatable + zero-downtime
  (previous live serves until the new one is healthy; a failed promote leaves
  production untouched); `rollback` re-pins live to a prior live release. Each
  channel gets **its own database**: `create_database` provisions the preview
  DB; promote reconciles a fresh live DB under the **same app key** (e.g.
  `MAIN_URL`) so the same image connects to preview data in preview and
  production data in live. Migration `0007`; FSM `State` now tracks the preview
  channel only; `Mode=live` means "has a live channel". `internal/orch/livechannel.go`.
  Quota: the live DB is a **logical mirror** of an already-counted preview DB,
  so it does **not** additionally count against `MaxDBCount` (count excludes
  `channel='live'`). See **PLAN.md §5.x dual-channel**.
  Rollback targets prior **live** releases only (`releases.channel`, migration
  `0008`; picker filters to live history — no version guessing). The admin
  console shows a **Production history** panel per promoted beam (clean
  `v1,v2,…` live sequence, image pin, deployed-at, current marker) with a
  per-row **roll back** button → `POST /admin/beams/{id}/rollback`.
- **Audit retention** — the append-only hash chain is bounded via a
  checkpoint-anchored prune (`audit_checkpoints`, migration `0009`): a prune
  records the cut seq + chain anchor, deletes through it, and `Verify` resumes
  from the latest checkpoint, so the surviving chain stays tamper-evident and an
  un-checkpointed deletion still trips Verify. `beamhalld admin prune-audit
  -keep-days N|-keep N [-dry-run]` (manual) + opt-in `BEAMHALL_AUDIT_RETENTION_DAYS`
  (daemon prunes on boot + daily). No SIEM export yet (`Export(afterSeq)` seam
  exists). `internal/audit/prune.go`. See **PLAN.md §6 audit retention**.
- gVisor `runsc` is the regulated isolation tier on the one Docker driver;
  Firecracker is a future driver behind `RuntimeDriver` — **PLAN.md §3**.
- Builds run in a **separate non-userns-remapped context** (publish pinned image
  to internal registry; runtime daemon only pulls+runs) — **PLAN.md §4, §8**.
- Driver places workloads on a per-Beamhall bridge, exposes `BackendAddr` (no
  host-port publish); gateway routes to it. Egress `-i bridge` only affects
  container-originated traffic, so host→container (gateway) and host SSH are safe.
- **Facility brokers (the connector model)** — design captured **PLAN §5.11**
  (2026-06-24). Generalizes the `DatabaseProvisioner`/provisioned-auth pattern to
  managed primitives whose backend can live off-box (another IT box, or a governed
  relay to an external provider). Invariant: the beam always talks to an **in-hall
  endpoint** with a capability **meaningless outside the hall** (north side stable);
  *where* the backend lives + its privileged credential + egress are **admin-config
  pluggable** (south side) — **no SDK / no third-party ABI**. Per-facility decision:
  in-path relay (policy+audit chokepoint) vs out-of-path scoped-cred+egress.
  **Realization (operator, 2026-06-24): a shared service container per broker** —
  one `bh-mail`/`bh-s3` container attached to each beamhall bridge (the `bh-postgres`
  precedent: container-to-container, no host exposure, no beam-bridge egress hole),
  running Beamhall's own engine, driven beamhalld→broker only over a control channel
  (config-push provider+registrations to the broker's loopback port; audit-pull events
  into the hash chain). The S3 broker reuses this verbatim. See **PLAN §5.11**.

  **Email delivery facility (PLAN §5.12) — lab-verified 2026-06-25 (on `main`, e646265).**
  Built + unit/race-tested:
  - `internal/facility/mail` — the go-smtp v0.24 submission engine (PLAIN+LOGIN auth,
    per-beam sender allowlist, token-bucket rate limit, SMTP-smarthost forwarder,
    degrade-closed), plus the control channel: `control.go` (broker HTTP API + audit
    ring) and `client.go` (beamhalld side); round-trip tested.
  - `internal/orch/email.go` — `ProvisionEmail`/`ShowEmail`/`SetEmailSenders` (+ audit
    pairs), ChannelShared secret sealing (`SMTP_HOST/PORT/USER/PASS`), `domain.ResourceEmail`,
    `reclaimEmail` (in `reclaimResources`), `ReconcileEmail` + `DrainEmailAudit`
    (self-healing push + audit pull). Bridge attach via the `bh-postgres` precedent.
  - MCP: `provision_email`/`show_email` (builder) + `admin_set_email_senders` +
    **`admin_set_email_provider`** (IT) in `tools.go`/`admin.go`; `visibility.go` two-state
    gates (`emailWired` → the provider tool; `emailEnabled` → the builder tools); server
    `Instructions` anti-shadow-IT copy. `policy.ActionProvisionEmail`/`ActionShowEmail`.
  - `cmd/beamhalld` — the `mail-relay` subcommand (the `bh-mail` container entrypoint) +
    `WithEmail` wiring + the reconcile/audit-drain loop.
  - **Provider model (operator decision 2026-06-25, supersedes env-config):** the installer
    stands up the broker **plumbing only** (`BEAMHALL_MAIL_CONTROL_URL/_TOKEN/_BEAM_HOST`);
    an IT admin sets the smarthost at runtime via **`admin_set_email_provider`** (MCP), and
    the **broker holds+persists the credential** (root-only `provider.json` in its volume) —
    never the vault, the shared-secret table, or a beamhalld env. beamhalld learns `enabled`
    from the broker. `install.sh` stands it up by default (`--no-mail` to skip);
    `mail-broker-setup.sh` ships as a GoReleaser asset. See memory [[facility-config-via-mcp]].
  - **Lab-verified 2026-06-25** (appliance `10.255.255.153`, full pass in
    `docs/lab-phase0-validation.md`): control channel (provider push → broker
    `enabled:true`, registration push, audit-pull), `provision_email`→bridge-attach,
    `admin_set_email_senders`, deploy→`SMTP_*` injected, **send delivered to the sink**,
    disallowed sender → 550, **isolation** (beam→smarthost direct = BLOCKED, beam→`bh-mail`
    = REACHABLE), audit chain intact (`email_send` sent + rejected), destroy→broker
    deregister (old creds 535). **STARTTLS shipped + re-verified 2026-06-25:** the broker
    offers STARTTLS with a persisted self-signed cert (volume `bh-mail-tls`; stable across
    restarts), injected to beams as a 5th secret **SMTP_CA**; a strict Go `net/smtp` client
    does STARTTLS(verify SMTP_CA)→stock `PlainAuth`→send (proven live). `AllowInsecureAuth`
    stays on so nodemailer/Python smtplib also work plaintext. **Committed artifacts:**
    `scripts/mail-broker-setup.sh` (stands up the `bh-mail` topology from the installed
    binary; `--lab-sink` runs a test smarthost) and `scripts/agent-conformance/email-delivery.sh`
    (re-runnable conformance test — **passes live**, 8 steps). CHANGELOG `[Unreleased]` updated.
    **Remaining:** fold the broker into the production installer/packaging (today
    `mail-broker-setup.sh` stands it up; the appliance is set up this way).

  **Object-storage facility (PLAN §5.13) — lab-verified 2026-06-28 (branch
  `feature/objstore-facility`).** The **second** §5.11 facility; reuses the broker
  pattern. Built + unit/race-tested + lab-verified:
  - `internal/facility/s3` — gofakes3 engine (S3 verbs/listing/multipart + `s3afero`
    disk persistence) fronted by **our own SigV4-verifying middleware** (`sigv4.go`:
    seed-signature verify, per-beam bucket scoping, **aws-chunked normalizer** for the
    `STREAMING-*[-TRAILER]` body framing modern SDKs send, coarse quota, per-request
    audit). `s3.go` (Provisioner + provider persistence + backend swap), `forward.go`
    (minio-go `gofakes3.Backend` → external S3, `beam-<id>/<channel>/` prefix isolation),
    `control.go`/`client.go` (control channel). Tests use minio-go + synthetic chunked
    bodies; **the validation spike (step 0) is in `lab-phase0-validation.md`**.
  - `internal/orch/objectstore.go` — `ProvisionObjectStore`/`ShowObjectStore` (+ audit
    pairs), **per-channel** sealing (shared `S3_ENDPOINT/REGION/FORCE_PATH_STYLE` +
    per-channel `S3_BUCKET/ACCESS_KEY/SECRET_KEY`), `domain.ResourceObjectStore`,
    `reconcileLiveObjectStore` (promote mirror, in `livechannel.go`), `reclaimObjectStore`
    (deregister+**purge**, in `reclaimResources`), `ReconcileObjectStore` +
    `DrainObjectStoreAudit`. Reconcile reads the plaintext key from the vault via new
    **`secret.Vault.Reveal`** (SigV4 needs plaintext; it can't sit in `Spec`).
  - MCP: `provision_object_store`/`show_object_store` (builder) + `admin_set_object_store_provider`
    + `admin_set_object_store_quota` (IT) in `tools.go`/`admin.go`; `visibility.go` two-state
    gates (`objStoreWired`→provider/quota tools; `objStoreEnabled`→builder tools); server
    `Instructions` anti-shadow-IT copy (S3/R2/GCS/Supabase). `policy.ActionProvisionObjectStore`/
    `ActionShowObjectStore`. The inert `create_object_store` placeholder was retired.
  - `cmd/beamhalld` — `object-store-relay` subcommand (the `bh-objstore` entrypoint) +
    `WithObjectStore` wiring + reconcile/audit-drain loop. `internal/config` `BEAMHALL_OBJSTORE_*`.
  - **Enabled by default with a LOCAL backend** (the bundled-IdP analogue); IT switches to an
    external S3 at runtime via `admin_set_object_store_provider` (broker holds+persists
    `provider.json`). `install.sh` stands it up (`--no-objstore` to skip);
    `scripts/objstore-broker-setup.sh` (`--lab-minio`) ships as a GoReleaser asset. Plain HTTP
    on the bridge (SigV4 = request auth; no `S3_CA`). Per-channel buckets (preview≠live).
  - **Lab-verified 2026-06-28** (appliance `10.255.255.153`, `bh-objstore` broker): LOCAL
    round-trip via a stock minio-go client over plain HTTP, **cross-beam `AccessDenied`**,
    **forged-key `SignatureDoesNotMatch`**, destroy→deregister+purge, `object_store_op` audit
    events chained + `admin_verify_audit_chain` intact; **FORWARD** to an external MinIO with
    data landing under `company-bucket/beam-<id>/<channel>/` and the external credential never
    seen by the beam. Re-runnable: `scripts/agent-conformance/object-store.sh` (**passes live**).
    `beamhalld.pre-objstore` is the appliance rollback binary. CHANGELOG `[Unreleased]` updated.
  - **v1 notes:** local data not in `admin_backup_now` (recommend forward-to-S3 beyond pilot);
    FORWARD multipart via gofakes3's in-memory fallback; presigned-URL auth rejected.

## Remaining work

### Phase 2 — backplane + agent flow ✅ COMPLETE
Recommended order:
1. ~~**SQLite control-plane store** (`internal/store`)~~ ✅ — all entities +
   armed pauses persisted; `scheduler.Store` + gateway restore source done (see
   Phase 2 table above).
2. ~~**`age` secret service + log scrubber** (`internal/secret`)~~ ✅ — envelope
   encryption at rest, `Inject`→`DeploySpec.Secrets`, write-only (no get),
   scoped scrubber (see Phase 2 table above).
3. ~~**Hash-chained audit log** (`internal/audit`)~~ ✅ — chain writer over the
   transactional store append, `Verify` (all violations), JSON-Lines export
   with resume cursor (see Phase 2 table above). Open point for item 4: should
   boot hard-fail on a broken chain (currently logs loudly and continues)?
4. **Backplane orchestrator / PEP** (`internal/orch`, `internal/policy`) —
   **← in progress, staged:**
   1. ~~Policy PEP (`internal/policy`)~~ ✅ — role matrix, forbidden list,
      audited decisions, quota gates, transactional `store.PromoteBeam` (see
      Phase 2 table above).
   2. ~~Orchestrator core (`internal/orch`)~~ ✅ — full lifecycle behind the
      PEP with outcome audits and boot route restore (see Phase 2 table
      above). Egress reconcile wiring deferred to stage 3/4 (needs driver
      `NetworkBridge` resolution at boot).
   3. ~~Build pipeline (`internal/build`)~~ ✅ — managed repos (go-git) +
      pack on the dedicated build daemon + internal registry + runtime
      pull-by-digest; orchestrator `DeployBeamFromSource`. Lab-verified end
      to end (see Phase 2 table). Push/tarball transports land with item 5.
   4. ~~Resource provisioner (Postgres)~~ ✅ — `internal/resource` +
      `orch.CreateDatabase`, lab-verified (see Phase 2 table). ~~Lab test for
      the vault→driver junction~~ ✅ — `orch_integration_test.go` verified the
      composition end-to-end (in-container secret read at
      `/run/secrets/PROBE`, HTTP, pause/resume/promote, chain Verify).

   **Item 4 is complete.**
5. ~~**MCP server + OAuth** (`internal/mcp`, `internal/auth`)~~ ✅ — official
   go-sdk Streamable HTTP, IdP-agnostic JWT validation, RFC 9728, per-tool
   scopes, tarball transport, SSE progress, scrubber heuristics, full
   `cmd/beamhalld` wiring incl. egress boot reconcile; lab E2E green (see
   Phase 2 table + MCP specifics above).

**Carried into Phase 3** (deliberately not in item 5): git smart-HTTP push
transport + one-time deploy tokens (ends at `Pipeline.BuildFromDir`; tarball
covers the demo), destroy/rollback MCP surface, `show_metrics`,
bundled Keycloak (Phase 4 packaging; `bh-devidp` covers the lab until then).

### Phase 3 — agent error UX + negative-security suite + thin Admin UI ✅ COMPLETE (all four items + the lifecycle/build-cap surface, lab-verified)

1. **Agent error UX** ✅ (`internal/diagnose` + orch/build/driver/mcp wiring,
   lab-verified):
   - `internal/diagnose`: failure-signature catalog → actionable hints. Build
     classifiers (no buildpack detected → add the project manifest; npm/pip
     resolution; timeout; network) and runtime classifiers (EROFS → write
     under /tmp; bind EACCES → use $PORT; EADDRINUSE; missing
     /run/secrets/<KEY> → set_secret then redeploy; OOM → IT quota; egress
     ETIMEDOUT/EAI_AGAIN → default-deny + allowlist; EPERM → dropped caps),
     plus exit-code names (125/126/127/137/139/143).
   - **Startup grace** (orch `awaitStartup`, default 2s, `WithStartupGrace`):
     a deploy only succeeds if the workload survives its first moments; a
     crash-on-boot fails the beam with exit code + scrubbed log tail +
     classified hint instead of minting a dead preview URL. Crash logs pass
     the vault scrubber before entering any error (no scrubber → no logs).
   - Build failures carry a 4KB tail of pack output + hint (self-contained
     error, independent of the progress stream).
   - `driver.Logs` demuxes Docker's stream-multiplex frames (plain text out).
   - `show_logs` appends a `[beamhall]` constraint hint when a running beam's
     logs match a signature (egress denials never crash the app — the
     constraint is invisible from inside the container).
   - Fixed along the way (E2E-exposed): **promote now retires the preview
     route** ("stable route up, preview route down" was promised but not
     implemented — production stayed reachable on the stale random URL and
     Boot restored it after restarts).
2. **Negative-security suite** ✅ (`internal/e2e` `TestAgentCannot`, lab-verified):
   six demoable "the agent cannot" proofs as real MCP calls with the builder
   holding every scope — ReadSecretsBack, ObtainDatabaseCredentials,
   EscapeItsBeamhall, MutateSecurityPosture, ExfiltrateData (beam probes
   1.1.1.1 + cloud metadata, both dropped, show_logs names the constraint),
   SupplyADockerfile (inert) — then the audit chain verifies with the denials
   on record. Shared lab harness extracted (`harness_integration_test.go`:
   `launchAppliance`/`connect`/`callTool`/`stop`/`openAndVerifyAudit`, second
   memberless hall "fort"). Two real fixes it forced:
   - **Egress re-asserted on every deploy** (orch `WithEgressSync`,
     fail-closed): per-beamhall bridges are lazy, so boot-only reconciliation
     left a new hall's first workloads unprotected until restart.
   - **Driver redeploy was broken** (fixed-per-beam container names collided
     on the new-up-before-old-down supersede): unique instance names, per-
     instance secret staging, `Destroy` reads the staging label pre-removal.
3. **Thin Admin UI + IT bootstrap actions** ✅ (`internal/web`, lab-verified):
   read-mostly html/template + htmx console at `/admin`, same binary, **same
   IdP as MCP**. Auth = OIDC Authorization Code flow + signed session cookie;
   only an access token carrying `admin:it` opens it (validated by the shared
   `auth.Verifier` — no separate ID-token path). First login auto-provisions
   the operator's Identity (`EnsureOperator`), closing the bootstrap gap the
   E2E/negsec suites worked around. Views: dashboard, beamhall detail
   (beams + promote/pause/destroy, members, egress editor), audit log with
   live chain-verify. IT actions (`orch/admin.go`, it_admin-gated, all
   audited): create beamhall (immutable SecurityContext from a hardening
   template), register identity, grant membership, set egress. CSRF token on
   every form; redirect URI request-derived (proxy-safe). `bh-devidp` gained
   OIDC discovery + a lab auth-code flow. Tested over the real HTTP stack +
   lab smoke of the wired appliance.
4. **Remaining MCP surface + build rate limits** ✅ *(git transport still
   pending — see below)*: `rollback` (re-activates a prior release's pinned
   image + hardening snapshot, no rebuild; new workload comes up healthy
   before the current one is touched — failed rollback is a no-op; defaults
   to the preceding version or `to_version N`), `destroy_beam` (terminal:
   tears workload+route down, archives the beam — frees its quota slot and
   releases its slug), `show_metrics` (driver.Stats). Build-bomb defense:
   non-blocking concurrent-build cap (`WithMaxConcurrentBuilds`, default 2;
   source deploys past it refused, not queued). Schema: `Beam.Status`
   (migration 0004, partial unique slug index on active beams);
   `operableBeam()` guards every mutating op against archived beams. The
   security-critical bring-up (`spawnWorkload`) is now shared by deploy and
   rollback so the egress-fail-closed sequence can't drift.
   ~~Still pending: git smart-HTTP push transport~~ ✅ (`internal/gitserver`,
   lab-verified with the stock git client): smart-HTTP `receive-pack` over the
   managed per-beam bare repos (embedded go-git server transport, no system
   git) at `/git/<hall>/<beam>.git`, authenticated by one-time, beam-scoped,
   short-TTL deploy tokens (`gitserver.TokenStore`, hash-stored). A push
   triggers a synchronous build+deploy of the pushed commit; pack output
   streams back on git's sideband ("remote: …" lines) and the preview URL
   prints on success; a build failure rejects the ref with the diagnosis.
   `Pipeline.BuildFromCommit` builds the pushed commit (no re-import);
   `orch.DeployBeamFromGit` runs the same PEP-gated lifecycle; `deploy_beam`
   with no inline source mints a token and returns a ready-to-run `git push`
   command (`mcp.WithGitTransport`). The git server provisions a beam's bare
   repo on first authorized push. **The agent's only credential is a token
   that can push to ONE repo — never Docker/registry/DB creds (PLAN §6).**
### Phase 4 — pilot (design partner), backup/restore, threat-model doc ← in progress
- **Backup/restore** ✅ (`internal/backup`, lab-verified): one 0600 `.tar.gz` =
  online store snapshot (`store.Snapshot`/VACUUM INTO) + secret root key +
  managed repos; `beamhalld backup`/`restore` subcommands; restore preserves
  prior state as `*.pre-restore`. Crown-jewel proof: a vault-sealed secret
  recovers after backup→restore with the restored key (unit + live-appliance
  lab test).
- **Threat-model doc** ✅ — `docs/threat-model.md`: the customer/security-team
  sign-off artifact (trust boundaries, host baseline, hardening, isolation
  tiers + residual shared-kernel risk, the threat table cross-referenced to the
  negative-security tests, egress, secrets, CIS Docker mapping, the Firecracker
  upgrade path). Every mitigation cites a test or lab finding.
- **Packaging** ✅ (`packaging/`): GoReleaser (static CGO-free amd64/arm64
  binaries + checksums; `goreleaser check` clean), a hardened systemd unit
  with `LoadCredential` for the root key, `install.sh`, and a Packer template
  (baseline + binary + service). `BEAMHALL_SECRET_KEY_FILE` adds the
  **load-only** production key path (out-of-band via systemd
  LoadCredential/KMS; refuses to boot if the key is missing) — lab-verified.
- **Install-as-systemd-service acceptance** ✅ (lab VM, unprivileged `beamhall`
  user — the production path, not a root hand-run). Caught + fixed two bugs no
  unit test could see (see lab-phase0-validation §"two bugs"): (1) `%d` doesn't
  expand in an `EnvironmentFile` → moved `BEAMHALL_SECRET_KEY_FILE` into the unit
  as `Environment=`; (2) in-process egress iptables needs `CAP_NET_ADMIN` →
  added `AmbientCapabilities`/`CapabilityBoundingSet`. Verified: key loaded
  out-of-band from the credentials tmpfs, `egress policy asserted`,
  `CapEff=CAP_NET_ADMIN` only, `/healthz` ok. Then with `bh-devidp` wired:
  `MCP server ready` + `Admin console ready`; unauthenticated `/mcp` → 401 w/
  `WWW-Authenticate` resource_metadata; a real minted token opens a live MCP
  session listing all 13 contract tools (JWKS/RS256 validated against the
  external IdP through the packaged binary); `/admin` sign-in 302s to the IdP
  `/authorize` with the right client_id/redirect_uri/scope/state.
  Backup/restore re-verified against the installed service with the **out-of-band
  key** (caught bug #3: `backup` only looked in the data dir; `backup.Create` now
  takes an explicit `keyPath` from `BEAMHALL_SECRET_KEY_FILE`, runs as root,
  archive embeds db+key, restore's recovered key byte-matches the live key →
  DR works). **`packer build` verified end-to-end** on the dev VM (nested virt
  enabled): baked a 20 GiB qcow2 with `beamhalld` + the disabled unit + the
  gVisor/Docker baseline, build credential locked. Fixed four template defects
  validate can't catch (int→number, NoCloud SSH seed, /tmp tmpfs disk, sizing
  vars — see lab-phase0-validation §"Packer bake"). Packaging is now fully
  exercised; nothing in this layer is unrun.
- **Canonical demo** ✅ (`demo/`): the Request Tracker (Node) driven end-to-end
  against the installed appliance — `EXIT=0` through create_beam → set_secret →
  create_database → deploy → scrubbed logs → builder-promote-denied → IT promote
  → v2 + rollback, with a **real** managed Postgres (`"database":"ready"`, live
  visit counter). Resolved PLAN §10 demo-stack → **Node**. New surface:
  `beamhalld admin bootstrap` + `admin register-identity` (scriptable IT setup,
  store-direct, safe alongside a running daemon) and `cmd/bh-demo` (the agent
  driver). See `demo/README.md`.
- **Bring-your-own OIDC** ✅ (decision: BYO first, over bundled Keycloak). Added
  **OIDC discovery** — set `BEAMHALL_OAUTH_ISSUER` only; `jwks_uri` is resolved
  from the discovery doc (issuer-validated), `BEAMHALL_OAUTH_JWKS_URL` optional.
  Verified against **real Keycloak 26** on the lab: discovery-resolved keys,
  token with the audience mapper → 200, without → 401 (confused-deputy defense).
  Recipe in `docs/idp-setup.md` (Keycloak/Okta/Entra) + reference realm in
  `scripts/keycloak-beamhall-realm.json`.
- **Bundled Keycloak (turnkey pilot IdP)** ✅ (`packaging/keycloak/`): one command
  (`setup-bundled-idp.sh`) brings up a pre-configured Keycloak **fronted by the
  gateway** (new `gateway.WithStaticRoute`), wires beamhalld, and registers seed
  identities — evaluators get a working Admin console + agent flow without
  touching a corporate IdP. **Full `bh-demo` flow verified `EXIT=0` against it.**
  Made discovery **lazy** (auth verifier + Admin console) so the appliance boots
  even while the co-located IdP is still starting (and survives IdP restarts).
  **Employee onboarding uses the pre-registered `beamhall-agent` client, not DCR**
  (`claude mcp add --client-id beamhall-agent …`): the realm gives it
  `beamhall-audience` as a *default* scope (aud/sub), the capability scopes as
  *optional* (explicitly requestable), `offline_access`, and loopback redirect
  wildcards; seed users carry the `offline_access` role. Live-validated end to end
  (employee browser OAuth → build → deploy). The whole chain of bundled-realm
  gaps + their fixes is in lab-phase0-validation.
  See `packaging/keycloak/README.md`; gotchas in lab-phase0-validation.
  NOTE: the test VM is currently configured for the bundled Keycloak (the seed
  credentials are written to a log under `/tmp` on the VM by the setup script);
  `bh-devidp` is also present if you switch back.
- **Admin lifecycle over MCP + owned-IdP administration (3rd stable seam)** ✅
  (`internal/identityadmin`, `internal/orch/identityadmin.go`,
  `internal/mcp/admin.go`). IT runs onboarding + IdP admin through the **same MCP
  channel** as everything else — no second web console. The `admin_*` tool family
  (admin:it scope, kept off the agent scope advertisement) is a **thin client over
  the orchestrator PEP/audit**, exactly like the Admin console: `admin_register_identity`,
  `admin_grant_membership`, `admin_list_identities`, `admin_create_beamhall`, and
  the owned-IdP ops `admin_create_user`/`admin_list_users`/`admin_set_user_password`/
  `admin_create_group`/`admin_list_groups`/`admin_add_user_to_group`/
  `admin_federate_directory`.
  - **MCP-first management surface (0.1.9+mcpadmin)** — closes the UPDATE/DELETE half
    so an MCP-only IT operator has full parity with (and beyond) the demoted web
    console. New tools (all it_admin, audited, live-verified on the appliance):
    `admin_query_audit` + `admin_verify_audit_chain` (read+verify the regulated
    hash-chained audit log — previously web-console-only), `admin_update_beamhall`
    (quota/live-slots/status suspend·archive·reactivate/metadata), `admin_revoke_membership`,
    `admin_set_identity_status` (per-principal kill switch; PEP-enforced),
    `admin_set_user_enabled` (bundled-IdP offboarding; new `Provider.SetUserEnabled`
    seam method), `admin_list_releases` (rollback targets). `admin_show_beamhall` now
    includes per-beam channel URLs.
  - **Routine lifecycle + sensitive tier + backup (0.1.9+mcpadmin, batches A/B)** —
    routine: `admin_set_membership_role` (in-place role change), `admin_remove_user_from_group`.
    sensitive (four-eyes, reuse the `admin_action_requests` flow + new `AdminActionType`s):
    `admin_set_security_context` (runtime-class runc↔runsc), `admin_unfederate_directory`,
    `admin_prune_audit`. backup: `admin_backup_now` + `admin_list_backups` (routine,
    online `VACUUM INTO` snapshot — **live-verified** on the appliance), `admin_restore_backup`
    (four-eyes; verifies + returns the operator stop→restore→start runbook, never a live
    in-process overwrite). New seam methods `Provider.RemoveUserFromGroup`/`UnfederateDirectory`;
    new `WithBackup` orch option + `BEAMHALL_BACKUP_DIR` config. Sensitive-tier gate reuses
    `BEAMHALL_IDP_SENSITIVE_ADMIN` as the general four-eyes master switch. See
    `docs/admin-over-mcp.md`.
  - **IdP hard-delete + self-upgrade (0.1.10+, the last deferred items)** —
    `admin_delete_user` / `admin_delete_group` (routine, irreversible; new
    `Provider.DeleteUser`/`DeleteGroup`; live-verified on throwaways) and
    `admin_request_upgrade` (the most-guarded action: fail-closed `upgrade.Stager`
    seam — `internal/upgrade`, default `Disabled` — behind `BEAMHALL_SELF_UPGRADE=on`
    + the sensitive tier + four-eyes; on approval it downloads the pinned release,
    **sha256-verifies against checksums.txt**, stages + self-version-checks the new
    binary, and returns the operator atomic apply/rollback runbook — never a live
    self-replacing restart). `WithUpgrader` orch option; `BEAMHALL_SELF_UPGRADE` /
    `BEAMHALL_RELEASE_BASE_URL` config. The admin-over-MCP surface is now complete
    (36 admin tools).
  - **Agent-conformance suite (2026-06-23, `scripts/agent-conformance/` + `.mcp.json`
    + `.claude/agents/bh-*.md`, `docs/agent-conformance.md`)** — exercises the agentic
    side with **four authenticated personas** so isolation + four-eyes are proven the
    way agents actually hit them. Each persona drives Beamhall over its own **stdio MCP
    proxy** (`bh-mcp-proxy.py`, evolved from the pilot `bhmcp.py`) that ROPC-mints +
    auto-refreshes that identity's token and bridges Claude Code ⇄ Streamable-HTTP MCP;
    the four proxies are four `.mcp.json` servers, one tool-scoped persona subagent
    each (`bh-admin-alice/-bob` via the `beamhall-it` role, `bh-builder-carol→team-blue`
    / `bh-builder-dave→team-green`). `provision.sh` (idempotent, over SSH) creates the
    IdP users via Keycloak Admin REST (with a **complete profile** — an incomplete one
    triggers Keycloak "Account is not fully set up" → ROPC 400; gotcha logged),
    assigns `beamhall-it` to the admins, registers the four identities + bootstraps the
    two workspaces; `gates.sh` reversibly toggles `BEAMHALL_IDP_SENSITIVE_ADMIN` /
    `BEAMHALL_PROMOTE_APPROVAL`; `verify.sh` + `bh-call.sh` drive a persona without a
    Claude restart. **Live-verified end-to-end:** cross-workspace `denied … no membership`
    both directions; builders see 16 tools / 0 `admin_*`, admins' menu tracks state live
    (30↔35 as the sensitive tier toggles); admin four-eyes (cross-approve executes,
    self-approve refused with the four-eyes message); audit chain `VERIFIED — intact`
    with the denials + request/approve pairs against distinct actor IDs. Native
    multi-proxy is primary; Apple `container` documented as an optional OS-level tier.
  - **Self-teaching tool copy (2026-06-23, convention in `CLAUDE.md`)** — the agent
    sees only a tool's `Description` + schema hints + result message, never `docs/`, so
    entry-point tools now front-load the Beamhall-specific next step/gotcha in the
    `Description` itself (not just the result tail): `admin_create_user`,
    `admin_register_identity`, `admin_create_beamhall` each state up front that an IdP
    account / registration / empty workspace grants **no access** until
    `admin_register_identity` + `admin_grant_membership`. New requirement in `CLAUDE.md`
    so contributors' assistants keep tool copy self-teaching. Builder surface swept to
    the same checklist: `promote_to_live` now front-loads the IT-approval four-eyes flow
    (files a request a *different* operator approves via `approve_promotion`),
    `create_beam` names its inverse (`archive_beam`), and `pause_preview`/`resume_preview`
    name each other.
  - **Discoverability + anti-shadow-IT steering (2026-06-23)** — closes the generic-intent
    gap (a user says "create an app", not "create a beam", and the agent may have
    Fly.io/Vercel/Neon MCPs enabled). The MCP server now ships an `Instructions` string
    (`serverInstructions` in `internal/mcp/server.go`, surfaced in the `initialize`
    response) that (a) translates the jargon — beam = app/website/service/API/project,
    beamhall = workspace — so generic intent routes here, and (b) makes Beamhall the only
    sanctioned deploy target over BOTH local hosting and external providers (named
    explicitly), framing external deploys as shadow IT that leaks code/credentials and
    bypasses the audit trail. The three entry points (`list_beams`, `create_beam`,
    `deploy_beam`) carry the same everyday synonyms + steer. `CLAUDE.md` convention
    extended to make jargon-translation + anti-shadow-IT steering a product requirement.
  - **Provisioned auth — beam SSO (2026-06-23, BUILT + lab-verified)** — a beam reuses the
    bundled Keycloak so its app inherits company sign-in, ergonomics mirroring
    `create_database` (no IdP config, no credential to the agent). Full design in **PLAN
    §5.10** (+ §10 entry); shipped in `internal/identityadmin` (6 OIDC-client methods +
    `keycloak_clients.go`), `internal/orch/auth.go` (+ lifecycle hooks), and MCP tools
    `provision_auth`/`show_auth` (builder) + `admin_set_auth_groups` (IT). v1 = in-app
    library mode, bundled-IdP only; per-channel OIDC clients; **audience isolation** as the
    load-bearing invariant (an app-client token is **401'd by `/mcp`** — proven live);
    exact redirect URIs auto-synced across preview rotation; admin-curated group exposure
    (separation of duties); scope boundary = corporate SSO, NOT public self-signup (that
    stays app-managed). **Lab-verified end-to-end** — two re-runnable conformance scripts:
    `auth-isolation.sh` (audience-isolation 401 + positive control, provision→show→
    archive-reclaim, group allowlist, menu 16→18 builder / 30→31 admin) and
    `auth-redirect-sync.sh` (the **full live deploy→pause→resume→promote→destroy lifecycle**:
    redirects sync to the live host on deploy, empty on pause, re-sync to the rotated host on
    resume, promote **mirrors a distinct live client** with its own audience + own secret +
    the carried group allowlist on the stable live host, destroy reclaims **both** channel
    clients). All Keycloak REST shaping worked first-try (`docs/lab-phase0-validation.md`).
    Deferred (designed, not built): gateway forward-auth, isolated end-user realms, `rotate_auth`.
  - **Per-caller `tools/list` filtering (multi-level menu, 0.1.9+mcpadmin)** —
    `internal/mcp/visibility.go`: a `tools/list` receiving middleware on the shared
    `s.srv` returns only the tools a caller's token could invoke (builder surface vs
    full `admin_*` menu), plus appliance-state gates (bundled-IdP tools hidden on
    BYO-IdP; the four-eyes sensitive tools hidden until the sensitive tier is on;
    backup tools hidden unless a backup dir is configured; `admin_request_upgrade`
    hidden unless self-upgrade is on). The
    token rides on `req.Extra` (Streamable HTTP attaches it to every request, incl.
    `tools/list`), so the same `TokenInfo` `resolveActor` reads is available at list
    time. **Discovery only** — handlers still enforce via `resolveActor` (filtering
    never widens access). Updates ride `tools/list_changed` (Claude Code re-lists on
    notify/reconnect — verified live: a redeploy added the 7 new tools and dropped
    `admin_federate_directory` from the menu because the sensitive tier is off). CI
    drift test (`TestToolVisibilityTableMatchesRegistry`) fails if a new tool is left
    unclassified. go-sdk v1.6.1; no fork.
  - **The third stable seam** is `identityadmin.Provider` (mirrors `RuntimeDriver`):
    a Keycloak Admin-REST impl drives the **bundled** IdP; a `Disabled` impl is used
    for **bring-your-own-IdP** (Beamhall validates the customer's tokens but does NOT
    administer a directory it does not own). Keeps the agnosticism boundary clean:
    *authentication* is IdP-agnostic; *administration* is offered only for the owned
    IdP. Tools are intent-shaped (no raw Keycloak passthrough) so the MCP contract
    never leaks Keycloak. Beamhall holds the IdP admin credential (service-account
    client `beamhall-idp-admin`, `realm-admin`); the agent never does.
  - **Risk tiering (guardrail decision, 2026-06-21):** routine onboarding ops run
    autonomously (audited); `admin_federate_directory` is the **SENSITIVE** tier
    (it changes who can sign in to the whole appliance) and goes through a
    **four-eyes approval flow** (below). `BEAMHALL_IDP_SENSITIVE_ADMIN=on` is the
    master enable (off ⇒ not requestable).
  - **Four-eyes flow for the sensitive tier** ✅ (migration `0010_admin_action_requests`,
    `internal/store/admin_request.go`, `internal/orch/identityadmin.go`,
    `internal/mcp/admin.go`): `admin_federate_directory` **files a pending request**;
    a **different** IT operator runs `admin_approve_request` (the requester can't
    approve their own — separation of duties), which executes the stored intent and
    records the result; `admin_reject_request` discards it; `admin_list_pending_requests`
    lists them. Generic `action_type` so restore/upgrade reuse it. The request payload
    can carry a secret (the LDAP bind credential) so it's **vault-sealed at rest**
    (`Vault.Seal`/`Open` over age); only a non-secret summary is listed. Execution
    failure leaves the request pending (retryable). Unit-tested at all three layers
    (store round-trip + decide-once; orch sealing/four-eyes/execute-on-approval;
    MCP request/approve/reject scope-gated). **Lab verification pending pilot.**
  - Config: `BEAMHALL_IDP_ADMIN_URL/REALM/CLIENT_ID/CLIENT_SECRET` +
    `BEAMHALL_IDP_SENSITIVE_ADMIN`; wired in `cmd/beamhalld` (Keycloak provider when
    configured, else Disabled). Unit-tested at all three layers (seam via httptest
    Keycloak stub; orchestrator tiering/fail-closed; MCP scope-gate + BYO-IdP hint).
    **Not yet lab-verified against a live Keycloak Admin REST — pending pilot.**
- **Bundled Keycloak is now PERSISTENT** ✅ (`packaging/keycloak/`): named volume
  `beamhall-keycloak-data` (H2 in-volume), `--rm` dropped, realm **seeded once** on
  first boot (not re-imported on restart) — so users/groups/config created at
  runtime survive reboots and long evaluation gaps (the months-later-resume case).
  `setup-bundled-idp.sh` is first-install-vs-re-run aware (re-run preserves state and
  reuses secrets; `RESET=1` wipes + re-seeds). The realm now also seeds the
  `beamhall-idp-admin` service-account client the admin-over-MCP IdP tools use.
  Postgres is the documented scale path. **Not yet lab-verified.**
- **Promote-approval gate (four-eyes)** ✅ (`BEAMHALL_PROMOTE_APPROVAL=on`, default
  off). When on, `promote_to_live` files a request a **different** IT operator
  approves (PLAN §10 resolved). New: migration 0005 `promotion_requests`, policy
  `request_promotion`, orch Request/Approve/Reject/ListPending, and MCP tools
  `list_pending_promotions`/`approve_promotion`/`reject_promotion` (admin:it).
  Unit-tested (request/four-eyes/approve→live/reject/one-pending) + lab-verified
  end-to-end against the bundled Keycloak. Approval surfaces in BOTH the MCP
  tools and the **Admin console** (a "Pending promotions" approve/reject section;
  the direct-promote button hides when the gate is on) — web-tested.
- **Air-gapped builds** ✅ (PLAN §10 resolved for the build pipeline). `pack` pull
  policy + run-image are configurable (`BEAMHALL_PACK_PULL_POLICY=if-not-present`,
  `BEAMHALL_CNB_RUN_IMAGE`); `scripts/airgap-bundle.sh`/`airgap-load.sh` mirror the
  CNB builder/run + IdP/support images over offline media. Unit-tested + lab-
  verified (deploy builds with the local builder, no re-pull; bundle/load
  roundtrip). JWKS moot with an internal IdP; CVE DBs N/A until scanning;
  npm/pip mirrors are operator-side. See `docs/air-gapped.md`.
- **Turnkey one-command installer** ✅ (`packaging/install.sh`, validated from a
  bare-OS Proxmox snapshot). Consolidates `preflight.sh` + `lab-bootstrap.sh` +
  the service install into one idempotent script (groups baseline / substrate /
  appliance): Docker from the official repo with a distro fallback + **hard runc
  ≥ 1.2.8 verify**, userns-remap + runsc, the dedicated build daemon, gateway,
  registry, managed Postgres (generated password), generated age key + config,
  hardened unit, start → `/healthz`. Product-named throughout (`beamhall-build`,
  `beamhall-gateway`, `beamhall-postgres`, `beamhall-registry`; no "lab"). The
  bundled-IdP path (`packaging/keycloak/`) wired end-to-end against it: real
  Keycloak token → correct `aud`/`sub`/scopes → MCP 200. Bugs found+fixed: a
  **gateway boot-apply bug** (static IdP route never pushed with zero beams; `Boot`
  now calls `gw.Apply`, new on the orch `GatewayAPI`), Postgres attach using a
  stale `bh-postgres` name (now `cfg.PGBeamHost`), plus four installer/IdP
  packaging bugs — see `docs/lab-phase0-validation.md`. Follow-up: beamhalld needs
  a real `--version`/`--help` (DONE — `version`/`help` subcommands; unknown args
  now exit 2 instead of starting the daemon). `install.sh`
  supersedes `lab-bootstrap.sh` as the supported install path.
- **Comprehensive from-scratch pilot** ✅ (bundled Keycloak, **runsc tier**), end to
  end on the freshly-installed appliance:
  - Agent flow (`bh-demo`): create → set_secret → create_database → deploy →
    scrubbed logs → builder-promote denied → IT promote → rollback, with no raw
    credentials. Real Keycloak tokens (correct `aud`/`sub`/scopes).
  - **gVisor isolation proven**: the beam runs `runtime=runsc`, sees
    `Linux 4.19.0-gvisor` (not the host kernel), read-only rootfs, all caps
    dropped, no-new-privileges — the sign-off money shot.
  - **Egress**: outbound to a public host and to cloud metadata both dropped;
    only same-bridge IP reachable. Exfiltration proof holds.
  - **runsc DB-DNS fix** (commit `9932159`): gVisor can't reach Docker's embedded
    DNS, so managed Postgres was unreachable by name; the driver now injects
    `--add-host` for network peers. Verified: DB-backed counter works under runsc.
  - **Four-eyes gate** (`BEAMHALL_PROMOTE_APPROVAL=on`): agent's promote files a
    request; the agent can't approve its own (insufficient_scope); a different IT
    operator approves → live. One-pending guard + quota gate compose correctly.
  - **DR**: full disaster (lost data dir + key) → restore → key byte-identical →
    boot, audit verified, routes restored, recovered beam's sealed DSN works.
- **Remaining (needs the design partner / pilot environment):** run the
  canonical demo against the real partner; validate the `runsc` tier in their
  environment; the open questions below.

### Open questions still pending (PLAN §10 + security §)
- ~~**Admin-over-MCP client for `admin:it`**~~ **RESOLVED (v0.1.2):** IT-admin is
  now derived from the `admin:it` scope OR the `beamhall-it` realm role
  (`BEAMHALL_OAUTH_ADMIN_ROLE`); bundled realm ships a public `beamhall-admin-agent`
  client so `claude mcp add --client-id beamhall-admin-agent` works via plain
  browser OAuth, gated by a role a builder can't hold. Lab-verified + unit-tested.
- ~~**No quota-edit surface**~~ **RESOLVED (0.1.9+mcpadmin):** `admin_update_beamhall`
  edits an existing workspace's quota (`max_beams`/`max_live_slots`/`max_databases`),
  lifecycle status (`active`/`suspended`/`archived`), and metadata over MCP — wraps
  `store.UpdateBeamhall`, it_admin-gated + audited. (Security-context/runtime-class
  edits stay deferred — they weaken isolation posture, so they want a four-eyes
  design before exposure; see PLAN §10.)
- Y (preview auto-pause hours) default; per-Beamhall vs global.
- IdP for the first pilot: bundled Keycloak vs customer Okta/Entra day one.
  (Partly resolved: the bundled IdP is now **persistent** + administrable over MCP,
  so a growing multi-week/multi-month pilot can run on it and later LDAP/AD-federate
  via `admin_federate_directory` without changing Beamhall's issuer — see the
  admin-over-MCP entry above and `docs/admin-over-mcp.md`.)
- `promote_to_live`: scope-gated vs mandatory IT human-in-the-loop.
- Egress allowlist in MUST-HAVE vs fast-follow (does the pilot beam need an internal API on day one?).
- Canonical demo stack: Node vs Python.
- Air-gapped update story (buildpack images, CVE DBs, JWKS).
- Phase-0 **regulated security-team sign-off** on the isolation model — the gate that decides whether hardened-Docker+runsc holds or a Firecracker driver becomes a funded expansion.
