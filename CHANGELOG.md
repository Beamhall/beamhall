# Changelog

All notable, user- and operator-facing changes to Beamhall are recorded here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project aims at [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(pre-1.0: the stable seams may still change — breaking changes are called out
explicitly under **Changed**). See [WORKFLOW.md](WORKFLOW.md) for how and when a
release is cut, and the format rules for the entries below.

The `[Unreleased]` section is the staging area: every PR/commit with a
user-facing change adds its line here, so cutting a release is just renaming this
section to the new version. Releases **v0.1.0–v0.1.11** predate this changelog —
see the [GitHub Releases](https://github.com/Beamhall/beamhall/releases) page for
their auto-generated notes.

## [Unreleased]

### Fixed
- Microsoft Entra ID access tokens now authenticate correctly: the `scp` claim
  is parsed in the space-delimited string form Entra emits (previously only
  the array form was read, so every Entra token was denied with
  `insufficient_scope`).
- Build output is now scrubbed like runtime logs: the live build progress
  stream (MCP notifications and the `git push` sideband) and the failure tail
  embedded in build errors pass the beam's secret scrubber before leaving the
  backplane.
- `install.sh` now fails the install when `checksums.txt` cannot be fetched,
  instead of silently skipping binary verification.
- Pause/resume (including the auto-pause timer) now serialize against
  deploy/promote/rollback/destroy on the same beam, so a pause firing during a
  promote can no longer erase the live channel from the beam record, and one
  racing a destroy can no longer resurrect an archived beam.
- Approving a sensitive admin action is now serialized and fully decided under
  one guard: two concurrent approvals can no longer execute the action twice,
  an approve can no longer interleave with a reject, and approval re-checks the
  sensitive-tier switch (a request filed while the tier was on is not
  approvable after the operator turns it off).
- `archive_beam`'s preview-only guard is re-checked under the beam's lifecycle
  lock, closing a race where an archive racing an in-flight promote could tear
  down a beam that had just gone live (bypassing the IT-gated destroy path).
- A failed container create no longer leaves the beam's decrypted secret files
  staged on the tmpfs; the daemon also sweeps staging directories no container
  references at startup.

### Changed
- A request with `Origin: null` (an opaque browser origin) is now refused by
  the `/mcp` origin allowlist instead of bypassing the check.
- `beamhalld` refuses to start when the operator-supplied secret key file
  (`BEAMHALL_SECRET_KEY_FILE`) is group- or world-accessible; chmod it to 0600.
- The git transport rejects malformed repository paths outright (hall/beam
  URL segments must be well-formed slugs).
- `set_secret` keys are validated (1–64 letters, digits, or underscores): the
  key is the container-side mount target `/run/secrets/<key>`, so path-shaped
  keys are refused instead of relocating the mount inside the workload.
- Managed-database identifiers now carry a short digest suffix
  (`bh_<hall>_<beam>_<name>_<8hex>`), so distinct workspaces/beams whose
  hyphenated names flatten to the same identifier can no longer collide on the
  shared Postgres. Existing databases keep their recorded names.

## [0.5.0] - 2026-08-28

### Changed
- **BREAKING: `admin_request_upgrade` now requires `expected_sha256`.** The
  operator supplies the release binary's SHA-256 (from the GitHub Release's
  `checksums.txt`, obtained out-of-band) with the request; an upgrade request
  without it is refused. A same-channel checksum download is no longer trusted
  on its own.
- **BREAKING: `beamhalld` fails closed at startup** unless the decrypted-secret
  staging dir (`BEAMHALL_SECRETS_DIR`) is tmpfs-backed **and** the Docker
  daemon runs userns-remap. In-place upgraders: install the updated systemd
  unit first — its `RuntimeDirectory=beamhall` provisions the tmpfs and sets
  `BEAMHALL_SECRETS_DIR` — before restarting the daemon.

### Security
- **Object storage: cross-beam isolation holes closed.** A beam could read or
  overwrite another beam's objects via `x-amz-copy-source`, and tamper across
  prefixes via `..` key traversal; both now resolve against the requesting
  beam's own namespace only. The storage quota can no longer be bypassed with a
  lying `X-Amz-Decoded-Content-Length` or oversized chunks.
- **Decrypted secrets never touch persistent disk.** Secret files are staged on
  a tmpfs (`BEAMHALL_SECRETS_DIR`; the systemd unit provisions a
  `RuntimeDirectory` for it) before being bind-mounted into a container, and
  `beamhalld` **fails closed at startup** if the path isn't tmpfs-backed — or if
  the Docker daemon isn't running userns-remap. Failed bring-ups now reliably
  reclaim the container *and* its staged secret dir; arbitrary `set_secret`
  values are swept on destroy.
- **Per-beam serialization.** Deploys, promotes, rollbacks, destroys, and
  four-eyes approve/reject on the same beam are serialized — a destroy racing a
  slow build can no longer resurrect an archived beam, and approve/reject can
  no longer disagree with what actually shipped.
- **Promotion/rollback integrity.** Four-eyes approval pins the exact release
  it approved; rollback refuses preview-channel releases (no production data
  crossover); a failed re-promote or rollback leaves the existing live route
  active instead of dropping production traffic — across restarts too.
- **Egress reconciler is atomic.** Rule updates no longer flush to a transient
  allow-all window, and the cloud-metadata deny (169.254.169.254 et al.) is
  unconditional, covering bridges with no policy attached.
- **Audit trail hardening.** The recorded `SourceIP` ignores client-supplied
  `X-Forwarded-For` unless the peer is a configured trusted proxy; pruning the
  entire log no longer manufactures a permanent false "chain broken" verdict.
- **Admin console session hardening.** Sessions are capped at the IdP access
  token's expiry, CSRF tokens are per-session (logout included), the OAuth
  redirect URI rejects unrecognized hosts, and cookie `Secure` derivation is
  explicit.
- **Identity kill-switch applies to IT admins.** A disabled identity is
  rejected even when it carries the admin role — an admin can no longer
  re-enable themselves through a live session.
- **Self-upgrade requires a pinned digest.** `admin_request_upgrade` demands an
  operator-supplied `expected_sha256`, verified before the downloaded binary is
  ever staged or executed — the release channel alone is no longer trusted.
- **Mail facility.** The smarthost credential is only ever sent over verified
  STARTTLS (opportunistic downgrade refused), and the sender allowlist is
  enforced on the `From:` header, not just the SMTP envelope.
- **Assorted fixes** from the same review: quota check-then-act races enforced
  in the store, vault set/delete made atomic, restore forces `0600` on the
  restored secret key and the DR runbook no longer auto-starts before
  out-of-band key placement, build timeouts kill the whole `pack` process
  group, broker audit-drain survives a broker restart without dropping events,
  JWKS refetch hardening, and ~20 further low-severity hardening items.

### Added
- `BEAMHALL_OAUTH_TRUST_FLAT_ROLES` (default off): opt-in trust of a flat
  top-level `roles` claim for admin elevation, for IdPs that can mint it from a
  source the subject cannot influence. Keycloak's nested `realm_access.roles`
  remains the default path.

## [0.4.0] - 2026-07-02

### Added
- **Object-storage facility (`provision_object_store`).** A builder gives a beam
  **S3-compatible object storage** with one MCP call, the same way `create_database`
  gives it a database: no storage account, and **no credential the agent or the app
  can use outside the hall**. The app reads `/run/secrets/S3_ENDPOINT`, `S3_REGION`,
  `S3_BUCKET`, `S3_ACCESS_KEY`, `S3_SECRET_KEY`, `S3_FORCE_PATH_STYLE` and uses any
  stock S3 SDK (boto3/aws-sdk/minio) — Beamhall stores the bytes and the app can't
  tell whether they live on the appliance or in the company's real S3.
  `show_object_store` reports the wiring without revealing the keys. Storage runs
  through a shared **`bh-objstore` broker container** on each beamhall bridge (the
  second instance of the **facility-broker pattern**), which **verifies every
  request's AWS SigV4 signature** — that, not the network, is what isolates beams
  (the broker is one shared container on all bridges). **Batteries included:** the
  installer stands the broker up **on by default** with a local disk backend
  (`install.sh --no-objstore` to skip), so a pilot has object storage with no
  external account. An **IT admin can switch the backend to the company's S3 at
  runtime with `admin_set_object_store_provider`** (AWS/MinIO/Wasabi/R2 — the
  endpoint + credential are held and persisted by the broker, never in a beam or
  the agent's reach), with every beam namespaced under its own key prefix inside one
  admin-supplied bucket. **Per-channel:** preview and live get **separate buckets**
  (like the database), so preview iteration can't read or delete production data;
  `promote_to_live` provisions the live bucket. IT can cap per-beam storage with
  **`admin_set_object_store_quota`**. Every mutation and denial is **audited**
  (object/op only, never contents) to the hash chain. Lab-verified end-to-end
  (local + forward modes, cross-beam isolation, forged-key rejection, reclaim).
  (PLAN §5.13)

### Changed
- **Anti-shadow-IT copy now covers object storage.** The MCP server instructions
  name S3-style providers (Amazon S3, Cloudflare R2, Google Cloud Storage,
  Backblaze B2) among the external services to route through Beamhall instead of
  wiring into the app, and teach the agent that "store files/uploads/blobs" maps to
  `provision_object_store`.

### Removed
- **Retired the inert `create_object_store` placeholder tool** (it only ever
  returned "not enabled in this build"); object storage now ships for real as
  `provision_object_store`.

## [0.3.0] - 2026-06-25

### Added
- **Email delivery facility (`provision_email`).** A builder gives a beam
  **outbound email** with one MCP call, the same way `create_database` gives it a
  database: no mail-provider setup, and **no credential the agent or the app can
  use outside the hall**. The app reads `/run/secrets/SMTP_HOST/PORT/USER/PASS`
  (plus `SMTP_CA`, the broker's STARTTLS certificate) and sends with any stock SMTP
  library — connect, STARTTLS verifying `SMTP_CA`, then AUTH; Beamhall relays to the
  company's real mail provider (Mailgun/SES/internal smarthost), which the app never learns.
  `show_email` reports the wiring without revealing the password. IT curates which
  From addresses/domains a beam may send as with **`admin_set_email_senders`**
  (separation of duties — anti-spoof across beams); the relay also rate-limits per
  beam and **audits every message** (envelope only) to the hash chain. Delivery
  runs through a shared **`bh-mail` broker container** on each beamhall bridge
  (container-to-container, no host exposure, no beam egress hole) — the first
  instance of the **facility-broker pattern** the S3 broker will reuse. The
  installer stands the broker up by default (`install.sh --no-mail` to skip); an
  **IT admin turns email on at runtime with `admin_set_email_provider`** (the
  smarthost + credential are held and persisted by the broker, never in a beam or
  the agent's reach), then allows each beam's senders. Until a provider is
  configured, `provision_email` steps aside with a `set_secret` fallback recipe.
  Outbound email uses STARTTLS (the broker's cert is injected as `SMTP_CA`).
  (PLAN §5.11, §5.12)

### Changed
- **Anti-shadow-IT copy now covers email.** The MCP server instructions name
  email providers (Mailgun, SendGrid, Amazon SES, Postmark) among the external
  services to route through Beamhall instead of wiring into the app directly.

## [0.2.0] - 2026-06-24

The **Identity pillar** ships: a beam can now inherit company sign-in the same
way it inherits a database — one MCP call, no IdP setup, no credential to the agent.

### Added
- **Provisioned auth (beam SSO).** A builder gives a beam **company sign-in** with
  one MCP call (`provision_auth`), the same way `create_database` gives it a
  database: no IdP configuration, and **no credential ever reaches the agent**.
  The beam becomes an OIDC relying party against the bundled Keycloak Beamhall
  already uses, so employees sign in with the accounts they already have. The
  issuer/client-id/client-secret are sealed and file-injected at deploy
  (`/run/secrets/OIDC_*`); `show_auth` reports the wiring without ever exposing a
  secret. **Audience-isolated** so an app token can never be replayed against the
  backplane, redirect URLs **auto-synced** as the preview URL rotates, and
  **separate preview/production credentials**. IT curates which employee groups a
  beam's tokens may carry with `admin_set_auth_groups` (separation of duties).
  v1 is in-app library mode on the bundled IdP; on a bring-your-own corporate IdP
  the tool steps aside with a `set_secret` recipe. (PLAN §5.10)

### Changed
- **Agents are steered to Beamhall and off shadow IT.** The MCP server
  instructions and the deploy entry points now route generic intent ("create an
  app", "put my site online") to Beamhall and explicitly discourage local one-off
  hosting and external providers (Fly.io, Vercel, Netlify, Heroku, Render, Neon,
  Supabase, the cloud CLIs). Entry-point tool copy teaches the Beamhall workflow
  itself — an IdP account ≠ Beamhall access, and the everyday synonyms (app =
  beam, workspace = beamhall) — so an agent with no access to these docs can still
  complete the workflow and warn the user.

### Security
- **Audience isolation proven end-to-end on the appliance**: a token minted for a
  beam's own OIDC client is rejected (HTTP 401) by `/mcp`, so an app token cannot
  reach the backplane. Two re-runnable conformance checks ship in
  `scripts/agent-conformance/`: `auth-isolation.sh` (the 401 sign-off) and
  `auth-redirect-sync.sh` (the full deploy → pause → resume → promote → destroy
  lifecycle: redirects track the host, promote mirrors a distinct live client,
  destroy reclaims both channel clients).

### Fixed
- The agent-conformance MCP proxy recovers from appliance restarts (stale session
  / dropped connection) instead of wedging.

[Unreleased]: https://github.com/Beamhall/beamhall/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/Beamhall/beamhall/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/Beamhall/beamhall/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Beamhall/beamhall/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Beamhall/beamhall/compare/v0.1.11...v0.2.0
