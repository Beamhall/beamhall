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

- **Ephemeral by design.** Keycloak runs `start-dev` with an in-container H2 DB
  (`--rm`); the realm re-imports on each start, so seed users persist but
  *runtime* changes made in the Keycloak console do not survive a restart. Fine
  for a pilot; not a production IdP.
- **Single-host DNS.** The script adds a hosts entry mapping `idp.<base-domain>`
  to the gateway. For multi-host or real clients, publish that name in DNS.
- **Secrets.** The rendered realm (`/etc/beamhall/keycloak/realm.json`) is
  world-readable so the userns-remapped container can read it; it holds
  pilot-grade, regenerated credentials. The bundled IdP is not for production.
- **Switching to your IdP:** set the real issuer in `beamhall.env`
  (`docs/idp-setup.md`), `systemctl disable --now beamhall-keycloak`, and remove
  `BEAMHALL_BUNDLED_IDP_UPSTREAM`.
