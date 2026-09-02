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

### Security
- **Workloads can no longer reach the host's listeners.** A container
  addressing the host itself (its bridge gateway IP, or any host-owned
  address) is delivered locally through INPUT — a path the `DOCKER-USER`
  egress chain, which hooks FORWARD, never sees. Before this fix a beam could
  open TCP to the backplane's HTTP listener (`/mcp`, `/admin`, git — all
  bearer-auth'd, but exposed) and to the gateway, and through the gateway
  call **any other beam's public URL, across beamhalls**, ungoverned. Two
  guards close the path, asserted by the same reconcile that runs at boot and
  before every workload start: a new `BEAMHALL-INPUT` iptables chain drops
  all bridge-originated traffic to the host except established replies and
  the gateway ports, and the gateway now refuses (403) requests arriving
  from container bridge subnets for every hostname except the bundled IdP —
  preserving in-container OIDC for apps using `provision_auth`. Proven by
  the new `TestAgentCannot/ReachTheHostOrSiblingBeams` negative-security
  test; `docs/threat-model.md` §7 now describes the workload→host model
  honestly (the host IP was previously claimed always-denied, which the
  FORWARD hook could not enforce).
- **`deny_all` egress now ignores stored allowlist entries.** Previously the
  reconciler applied a beamhall's allowlist regardless of its egress mode, so
  switching a hall back to `deny_all` without also clearing the list left
  the old holes open. Entries stay stored but inert until IT switches the
  mode back to `allowlist`.

### Fixed
- **A malformed egress allowlist entry can no longer break every deploy.**
  Entries are rendered into one appliance-wide iptables transaction, so a
  single stored `host:port` suffix (which the docs wrongly advertised — rules
  match the destination address only) or IPv6 literal failed that transaction
  and with it every subsequent deploy on the appliance. `admin_set_egress`,
  `admin_create_beamhall`, and the bootstrap CLI now validate each entry at
  write time (IPv4, IPv4 CIDR, or hostname) and refuse anything else with a
  teaching error; the tool copy and Admin console no longer suggest `:port`.

## [0.6.1] - 2026-09-01

### Added
- **Apps can now DO things for their users — over MCP.** Any app (beam) may
  expose tools to its users' AI agents by serving two plain HTTP routes on its
  own origin (`GET /.beamhall/tools` for the menu, `POST
  /.beamhall/tools/<name>` to invoke — see the new `docs/app-tools.md`), and
  the new using-tier tool **`use_app`** brokers the calls: the backplane
  relays the request to the app's live workload and delivers the caller's
  identity as a short-lived **Beamhall-signed assertion** (ES256; subject,
  email, groups, channel, and the invoked tool; verified by the app against
  `/run/beamhall/assertion.json`, mounted into every workload from its next
  deploy) — the user's IdP token is never forwarded and there is nothing to
  sign into. No enable-switch exists: serving the contract is enough, and the
  existing governance chain gates the reach (IT promotes to production, IT
  publishes the audience; users reach only the live channel). Every brokered
  call is audited under the user's identity, bounded by size caps and a
  per-identity rate limit (`BEAMHALL_USE_APP_RATE_PER_MIN`/`_BURST`,
  `BEAMHALL_APP_TOOL_TIMEOUT_SECS`), and scrubbed like logs.
- **`try_beam_tool`** — the builder-side twin of `use_app`: exercise your
  app's tool surface on the PREVIEW channel before promotion, with the same
  signed assertion (marked `channel: "preview"`).
- **`update_beam`** — builders can fix an app's catalog copy (the description
  users see, and the display name) after creation, without redeploying;
  previously only IT could, at publish time.
- The app-assertion signing key is generated on first boot and kept sealed
  inside the control-plane store, so it survives restarts, backups, and
  restores (a regenerated key would break every tool-serving app's
  verification at once). If the sealed key cannot be read, `beamhalld`
  refuses to start rather than quietly mint a new one. Migration 0013.

### Changed
- **The standing agent orientation gains app tools.** The MCP server
  instructions — the first thing an agent reads, every session — now teach the
  using tier to call `use_app` (the menu first, then the tool) and give
  builders a new **APPS WITH THEIR OWN TOOLS** section: the two routes to
  serve, the assertion header to verify, and the path from `try_beam_tool` on
  preview through `promote_to_live` and `admin_set_app_audience` to users
  calling `use_app`. Existing agents change behavior on their next session
  with no action from you.
- `describe_app` and `list_apps` now report `agent_tools` for live apps that
  answer the contract, so a user's agent knows an app can be acted through
  before it calls it (probed once at workload start).

### Security
- The threat model gains the brokered-call analysis (`docs/threat-model.md`):
  per-beam assertion audience + ~60 s expiry + tool binding against replay;
  the documented app-side MUST (verify on both routes — they live on the
  app's public origin); and the honest note that relayed menus/results are
  app-authored content entering the user's agent, bounded by caps, scrubbing,
  and IT-published-only reach.

## [0.6.0] - 2026-09-01

The **using tier** ships: the apps built here now reach the people they were
built for. Beamhall becomes three tiers — IT admins run the platform, builders
build in it, and everyone else simply *uses* what has been published to them,
through their own AI agent, with no capability to change anything. **Company
branding** lands alongside it, so what those people open looks like it came
from their company.

### Added
- **Apps for the people who use them.** IT can now publish an app to an
  audience — everyone, named IdP groups, or named people — with the new
  `admin_set_app_audience` tool, and those people's own AI agents discover it
  with the two new tools `list_apps` and `describe_app`: what the app is for,
  who owns it, and the URL to open. This is a third tier below IT admins and
  builders: a using-tier token (the new `beams:use` scope, the new
  `beamhall-user-agent` client on the bundled IdP) holds no workspace
  membership and can reach nothing that changes, deploys, or inspects an app.
  Apps are unpublished by default; an out-of-audience app is indistinguishable
  from one that does not exist; unpublishing removes it from every user's list
  immediately. Audiences live in Beamhall's own store, never in your IdP —
  group names are matched against a claim in the user's token
  (`BEAMHALL_OAUTH_GROUPS_CLAIM`, default `groups`; set it empty for
  named-people-only audiences). Users register themselves on first contact
  (`BEAMHALL_USER_AUTO_REGISTER`, default on) so IT never hand-registers every
  employee. Beams gain a plain-language `description` (set by the builder at
  `create_beam`, curated by IT when publishing) that users see in their list.
  Existing appliances pick the new scope, client, and groups mapper up
  automatically at startup — additively; nothing an operator configured is
  changed or removed.
- **Company branding.** IT defines the header, footer, logo, and colour palette
  the apps built here should wear with the new `admin_set_branding` tool —
  company-wide, or per workspace as a field-by-field override — and building
  agents read the resolved view with the new `show_branding` tool and apply it
  to the UIs they build. The appliance serves the logo and a hot-linkable
  palette stylesheet (`--brand-*` CSS custom properties) at public URLs on the
  base domain, so an IT palette change reaches running apps with no redeploy,
  and injects the resolved values into every workload as
  `/run/beamhall/brand.json` from its next deploy. Branding is always current,
  not pinned to a release: a rollback brings back the old build wearing
  today's branding. Logos are PNG only (max 1 MB) and ride the standard backup.

### Changed
- **Every agent that connects here gets new standing orientation.** The MCP
  server instructions — the first thing an agent reads, every session — gain a
  **USING APPS OTHERS BUILT** section (a "what internal tools do we have?"
  request routes to `list_apps`/`describe_app`, and a published internal app is
  preferred over signing the user up for external SaaS) and a **COMPANY
  BRANDING** section (call `show_branding` before writing or restyling any web
  UI, and apply what it returns). Existing builder agents change behavior on
  their next session with no action from you.
- **`beams:use` now appears in the `scopes_supported` list the appliance
  advertises** (the RFC 9728 protected-resource metadata every MCP client
  reads). Operators on a bring-your-own IdP have one new scope to define and
  grant for the user tier; `admin:it` stays deliberately excluded from that
  list, as an out-of-band IT capability.
- **The bundled realm is brought up to date at boot.** An appliance upgraded in
  place never re-runs its install-time realm import, so it would otherwise never
  learn a scope or client added after the day it was installed. `beamhalld` now
  converges the realm at startup — additive and idempotent, verified live on the
  appliance — creating only what this release needs: the `beams:use` client
  scope, the `beamhall-user-agent` public client with its groups-claim mapper,
  and `beams:use` attached as an optional scope on the existing
  `beamhall-agent`. It never modifies, narrows, or removes anything an operator
  configured.
- `create_beam` takes an optional `description`: the one-line "what this app is
  for" that end users see once IT publishes the app to them.

### Fixed
- **Same-workspace container traffic no longer depends on a kernel module
  staying unloaded.** The per-workspace egress DROP now explicitly exempts
  same-bridge traffic: with `br_netfilter` loaded (which Docker may do at any
  time), the old ruleset silently severed every intra-workspace connection —
  including each app's own links to the managed Postgres and mail brokers.
  External and cloud-metadata destinations remain denied exactly as before. The
  corrected ruleset is asserted at daemon startup, so it lands on the next
  restart with no operator action.

### Security
- **IT-authored branding HTML runs in the workload's origin, never the control
  origin.** The header/footer HTML IT sets with `admin_set_branding` is injected
  into the apps teams build and is deliberately **not** sanitized — IT is
  already inside the trust base, and sanitizing it is a documented non-goal
  (`docs/threat-model.md` §2). The appliance's own `/brand/` routes serve only
  magic-checked `image/png` (SVG is rejected — an SVG is an active document) and
  `text/css` generated from charset-validated palette values, both with
  `nosniff`, so nothing IT uploads can script the origin that hosts `/admin` and
  `/mcp`.
- **App audiences are a discovery boundary, not a network control.** An
  unpublished or out-of-audience app is indistinguishable from one that does not
  exist, and a using-tier token carries no capability scope and no workspace
  membership — but a live app's URL stays reachable to anyone who already holds
  it. Network reachability remains the gateway's and the app's own sign-in's
  job. Group-based audiences trust the IdP-issued group claim: source
  `BEAMHALL_OAUTH_GROUPS_CLAIM` from directory membership the subject cannot
  influence, or disable group audiences by setting it empty.

## [0.5.1] - 2026-08-31

A hardening release: a second adversarial verification pass over the control
plane, closed end to end. No new tools and no seam changes — existing behavior
tightened, plus two refusals an operator can hit at startup (see **Changed**).

### Changed
- **`beamhalld` refuses to start when the operator-supplied secret key file
  (`BEAMHALL_SECRET_KEY_FILE`) is world-accessible; chmod it to 0600, or
  0640/0440 with a trusted group.** The supported install is unaffected —
  `install.sh` writes `/etc/beamhall/secret.key` as 0400, and systemd
  `LoadCredential`'s root-owned 0440 copy loads fine (verified on the
  appliance) — but a hand-placed world-readable key file now blocks the boot
  instead of silently sealing every secret to a readable key.
- A request with `Origin: null` (an opaque browser origin, e.g. a sandboxed
  iframe) is now refused by the `/mcp` origin allowlist instead of bypassing
  the check. CLI MCP clients, which send no `Origin` at all, are unaffected.
- `install.sh` now fails the install when `checksums.txt` cannot be fetched,
  instead of silently skipping binary verification.
- `set_secret` keys are validated (1–64 letters, digits, or underscores): the
  key is the container-side mount target `/run/secrets/<key>`, so path-shaped
  keys are refused instead of relocating the mount inside the workload.
- The git transport rejects malformed repository paths outright (hall/beam
  URL segments must be well-formed slugs).
- Managed-database identifiers now carry a short digest suffix
  (`bh_<hall>_<beam>_<name>_<8hex>`), so distinct workspaces/beams whose
  hyphenated names flatten to the same identifier can no longer collide on the
  shared Postgres. Existing databases keep their recorded names.
- `docs/threat-model.md` now cites this wave's mitigations (tmpfs secret
  staging, build-path scrubbing, audit-prune checkpointing, control-plane
  serialization), and `docs/admin-over-mcp.md` documents the dual-digest
  verification `admin_request_upgrade` performs.

### Removed
- `docs/PLAN.md` — the design contract (architecture, phasing, strategy) is no
  longer published in the repo; it is maintainer-local. Public docs and code
  comments still cite it as "PLAN §x.y"; operators evaluating the security
  model should read `docs/threat-model.md` and `docs/beamhall-for-it.md`. The
  file remains in git history at `v0.5.0` and earlier.

### Fixed
- Microsoft Entra ID access tokens now authenticate correctly: the `scp` claim
  is parsed in the space-delimited string form Entra emits (previously only
  the array form was read, so every Entra token was denied with
  `insufficient_scope`).
- A build interrupted by a daemon restart no longer wedges the beam in
  `building` forever: boot moves it to `failed` with a redeploy hint (the
  normal redeploy path recovers it).
- `admin_set_membership_role` is now a single in-place update — a failure can
  no longer land between revoke and re-grant and silently drop the membership.
- The auto-pause timer clears instead of retrying every cycle forever when its
  beam can no longer be paused (e.g. it is in `failed`).
- Mail relay: a message carrying more than one `From:` header is rejected
  (only the first was checked against the sender allowlist while a recipient's
  client may render the second); the upstream forwarder refuses to deliver
  unauthenticated when a smarthost credential is configured but the smarthost
  does not offer AUTH.

### Security
- **Lifecycle races closed.** Pause/resume (including the auto-pause timer) now
  serialize against deploy/promote/rollback/destroy on the same beam, so a
  pause firing during a promote can no longer erase the live channel from the
  beam record, and one racing a destroy can no longer resurrect an archived
  beam. `archive_beam`'s preview-only guard is re-checked under the beam's
  lifecycle lock, closing a race where an archive racing an in-flight promote
  could tear down a beam that had just gone live (bypassing the IT-gated
  destroy path).
- **Four-eyes approval is decided under one guard.** Approving a sensitive
  admin action is serialized and fully decided under the lock: two concurrent
  approvals can no longer execute the action twice, an approve can no longer
  interleave with a reject, and approval re-checks the sensitive-tier switch (a
  request filed while the tier was on is not approvable after the operator
  turns it off).
- **Decrypted secrets no longer survive a failed bring-up.** A failed container
  create unstages the beam's secret files from the tmpfs; the daemon also
  sweeps staging directories no container references at startup.
- **Workspace containment on the auth/secret paths.** `show_auth` and
  `set_secret` verify the addressed beam belongs to the authorized workspace,
  and `set_secret` refuses archived beams.
- **Build output is scrubbed like runtime logs.** The live build progress
  stream (MCP notifications and the `git push` sideband) and the failure tail
  embedded in build errors pass the beam's secret scrubber before leaving the
  backplane.
- **An IT admin action whose audit-chain append fails now reports that
  failure** (the action's effect stands, but success is never claimed
  unaudited) — matching the PEP's audit-or-deny posture for agent actions.

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

[Unreleased]: https://github.com/Beamhall/beamhall/compare/v0.6.1...HEAD
[0.6.1]: https://github.com/Beamhall/beamhall/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/Beamhall/beamhall/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/Beamhall/beamhall/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/Beamhall/beamhall/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/Beamhall/beamhall/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Beamhall/beamhall/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Beamhall/beamhall/compare/v0.1.11...v0.2.0
