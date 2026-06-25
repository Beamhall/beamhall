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

[Unreleased]: https://github.com/Beamhall/beamhall/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Beamhall/beamhall/compare/v0.1.11...v0.2.0
