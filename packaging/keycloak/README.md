# Bundled Keycloak — turnkey IdP for a Beamhall pilot

For **evaluation/pilots only**: bring up a pre-configured Keycloak so you can try
Beamhall (Admin console + agent flow) **without touching your corporate IdP**.
For production, point Beamhall at your own OIDC IdP (`docs/idp-setup.md`) and
disable this.

## What it gives you

One command stands up Keycloak as a systemd-managed container, **fronted by the
Beamhall gateway** at `idp.<base-domain>` (so browser-based OIDC works with the
same TLS/hostname as beams), with a ready realm:

- the Beamhall capability **client scopes** + the required **audience mapper**;
- a confidential **`beamhall-admin`** client for the Admin console (redirect
  `/admin/callback`);
- a public **`beamhall-agent`** client (PKCE) for the AI agent / Claude Code;
- seed users **`it-admin`** and **`builder`** (random passwords, printed once).

It also wires `beamhall.env` to trust the bundled IdP and registers the two seed
identities (so the IT user can sign in and the builder can deploy).

## Run it

```sh
# the appliance must already be installed (packaging/install.sh) and running
sudo BASE_DOMAIN=beamhall.acme.internal bash packaging/keycloak/setup-bundled-idp.sh
# lab / TLS-off gateway: add SCHEME=http
```

The script prints the Admin console URL and the seed credentials — **save them**.
Then open `https://<base-domain>/admin`, sign in as `it-admin`, and you have a
working Beamhall.

To connect an engineer's agent, use the **pre-registered** `beamhall-agent`
client (no dynamic client registration — MCP clients that try DCR hit Keycloak's
default registration policies):

```sh
claude mcp add --transport http --client-id beamhall-agent beamhall https://<base-domain>/mcp
# then authenticate and sign in as builder (the script prints the password)
```

The realm pre-configures `beamhall-agent` so this just works: `beamhall-audience`
is a **default** scope (mints `aud`/`sub`), the capability scopes are **optional**
(so the agent can request them explicitly), `offline_access` is allowed, the
loopback redirect URIs accept the agent's callback, and the seed users carry the
`offline_access` role.

## Administering the IdP over MCP

The setup also seeds the `beamhall-idp-admin` service-account client and wires
`BEAMHALL_IDP_ADMIN_*`, so an **`admin:it`** operator manages users, groups, and
directory federation through the **`admin_*` MCP tools** — no need to open the
Keycloak console. Beamhall holds the admin credential; the agent never does.
Directory federation (`admin_federate_directory`) is the **sensitive** tier: it
files a request that a **different** IT operator must approve (`admin_approve_request`)
before it executes — four-eyes/separation of duties. It is **off by default**
(`BEAMHALL_IDP_SENSITIVE_ADMIN=on` to permit requesting it). Full guide:
`docs/admin-over-mcp.md`. (On a bring-your-own-IdP deployment these IdP tools are
disabled — Beamhall administers only the IdP it owns.)

## How it fits together

```
browser / agent ──TLS──> Beamhall gateway (Caddy)
                              │  idp.<base-domain>  ──> 127.0.0.1:8090 (Keycloak)
                              │  <base-domain>/mcp, /admin ──> beamhalld
beamhalld trusts issuer = <scheme>://idp.<base-domain>/realms/beamhall
(JWKS resolved via OIDC discovery; resolution is lazy, so beamhalld boots even
 while Keycloak is still starting)
```

## Notes & limits

- **Persistent.** Keycloak's data dir lives in the named Docker volume
  `beamhall-keycloak-data`, so the realm is seeded **once on first boot** and
  runtime changes made in the Keycloak console (users, groups, config) **survive
  restarts and reboots** — they are not wiped or re-imported. To wipe all runtime
  identity state and re-seed from scratch, re-run with `RESET=1`:
  `sudo RESET=1 BASE_DOMAIN=... bash packaging/keycloak/setup-bundled-idp.sh`.
  Still pilot-grade, not a production IdP: it runs `start-dev` with an embedded
  H2 DB, which is fine for a single-host pilot; the scale path is Postgres (point
  Keycloak at an external DB) — but for production you'd switch to your own IdP
  anyway.
- **Single-host DNS.** The script adds a hosts entry mapping `idp.<base-domain>`
  to the gateway. For multi-host or real clients, publish that name in DNS.
- **Secrets.** The rendered realm (`/etc/beamhall/keycloak/realm.json`) is
  world-readable so the userns-remapped container can read it; it holds
  pilot-grade credentials generated once on first install (printed then, and the
  client secret recorded in `beamhall.env`). A re-run preserves them; use `RESET=1`
  to rotate. The bundled IdP is not for production.
- **Switching to your IdP:** set the real issuer in `beamhall.env`
  (`docs/idp-setup.md`), `systemctl disable --now beamhall-keycloak`, and remove
  `BEAMHALL_BUNDLED_IDP_UPSTREAM`.
