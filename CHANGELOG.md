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

[Unreleased]: https://github.com/Beamhall/beamhall/compare/v0.1.11...HEAD
