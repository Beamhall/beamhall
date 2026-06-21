# Connecting Beamhall to your identity provider (OIDC)

Beamhall is an OAuth 2.1 **resource server**: it never issues tokens, it only
validates the access tokens your IdP mints. Any IdP that publishes an OIDC
discovery document and signs JWTs with **RS256/ES256** works — Keycloak, Okta,
Microsoft Entra ID, Auth0, Ping, etc. (Symmetric `HS*` and `none` are refused.)

This guide is the recipe per IdP. The Keycloak path is **lab-verified**; Okta and
Entra are documented from their token formats and the same four requirements.

## What Beamhall needs from any IdP

1. **OIDC discovery.** Beamhall resolves the signing keys from
   `<issuer>/.well-known/openid-configuration` (`jwks_uri`). You configure only
   the issuer; no need to know the per-IdP JWKS path.
2. **`aud` = the Beamhall resource URI.** Access tokens **must** carry the
   Beamhall resource URI in `aud` (default `https://<base-domain>/mcp`). This is
   the confused-deputy defense — a token minted for another service cannot be
   replayed at Beamhall. *Most IdPs do not add a custom audience by default; this
   is the #1 thing to configure (see Keycloak's audience mapper below).*
3. **Scopes.** The capability scopes Beamhall understands, delivered in the
   `scope` (space-separated string) or `scp` (array) claim:
   `beamhalls:read beams:write beams:deploy beams:operate beams:promote
   secrets:write resources:write logs:read metrics:read admin:it`.
4. **A stable `sub`.** Each principal (engineer or agent) has a stable subject.
   IT registers it once: `beamhalld admin register-identity -issuer <iss>
   -subject <sub> -email <e>` (and `admin bootstrap` to grant a workspace role).
   This holds even for `admin:it` operators — the scope is the *membership*
   bypass, not an *identity* bypass; every action audits against a known
   identity.

> **Just evaluating?** Skip this and run the **bundled Keycloak** instead — a
> pre-configured pilot IdP that needs no corporate-IdP setup. See
> `packaging/keycloak/README.md`. Come back here to point at your own IdP for
> production.

## Beamhall configuration

In `/etc/beamhall/beamhall.env`:

```sh
BEAMHALL_OAUTH_ISSUER=https://idp.example.com/realms/beamhall   # copy VERBATIM from the discovery doc
# BEAMHALL_OAUTH_AUDIENCE defaults to https://<base-domain>/mcp; set if different
# BEAMHALL_OAUTH_JWKS_URL is OPTIONAL — only set to skip discovery / pin a key endpoint
# BEAMHALL_OAUTH_DISCOVERY_URL overrides the discovery endpoint if non-standard
```

The issuer must match the IdP's `iss` claim **exactly** (trailing slashes
matter). Beamhall verifies the discovery document's `issuer` equals what you
configured and refuses to start on a mismatch.

The Admin console uses the same IdP (OIDC Authorization Code flow): set
`BEAMHALL_ADMIN_CLIENT_ID`/`SECRET` to a confidential client whose redirect URI
is `https://<base-domain>/admin/callback`, and grant `admin:it` to your IT users.

---

## Keycloak (lab-verified)

1. **Realm** — e.g. `beamhall`. Issuer is `https://<kc-host>/realms/beamhall`.
2. **Client scopes** — one per capability you grant (`beams:deploy`,
   `secrets:write`, …), each with *Include in token scope* on.
3. **Audience mapper (required).** Add a client scope (e.g. `beamhall-audience`)
   with a protocol mapper of type **Audience**:
   `included.custom.audience = https://<base-domain>/mcp`, *Add to access token*
   on. Assign it (default or optional) to the agent client. **Without this, the
   token's `aud` omits the Beamhall resource URI and Beamhall returns 401** —
   verified in the lab.
4. **Client** — a confidential client for the agent (direct-access-grants or
   service-account, per how the agent obtains tokens) with the capability scopes
   + the audience scope assigned.

A ready-to-import realm with exactly this shape lives at
`scripts/keycloak-beamhall-realm.json` (audience mapper as an *optional* scope so
you can see the aud-enforcement behavior both ways).

## Okta (custom authorization server)

- Create a **custom authorization server**; its issuer is
  `https://<org>.okta.com/oauth2/<authServerId>`.
- Add an **audience** equal to the Beamhall resource URI, or set the resource
  URI as the authorization server's audience.
- Define the capability **scopes**; add an access-policy rule that grants them.
  Okta delivers scopes in the `scp` array (Beamhall reads both `scp` and
  `scope`).
- JWKS is resolved via discovery (`/v1/keys`) — no manual path needed.

## Microsoft Entra ID (Azure AD)

- Register Beamhall as an **application (the resource)** and *Expose an API*:
  the **Application ID URI** becomes the audience. Set
  `BEAMHALL_OAUTH_AUDIENCE` to that URI (or the app's client ID, matching the
  token's `aud`).
- Define **delegated scopes** (`scp`) for user-driven agents. *Note:* app-only
  (client-credentials) tokens put permissions in `roles`, not `scp` — Beamhall
  reads `scope`/`scp`; prefer delegated scopes for agents, or map roles to
  scopes.
- Use the **v2.0 endpoint**; issuer is
  `https://login.microsoftonline.com/<tenant>/v2.0`. Discovery resolves the
  keys.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| MCP returns **401** with a valid-looking token | `aud` missing the Beamhall resource URI | Add the audience mapper / API audience (step 2 above) |
| beamhalld **won't start**: "discovery issuer … does not match" | configured issuer ≠ the IdP's `iss` | Copy `issuer` from the discovery doc verbatim (trailing slash!) |
| Tools return **insufficient_scope** | the capability scope isn't in the token | Add the scope to the client / access policy |
| "identity … is not registered" | the `sub` was never registered | `beamhalld admin register-identity …` (and `bootstrap` for a role) |
| beamhalld **won't start**: discovery fetch failed | IdP unreachable, or no discovery doc | Check connectivity; or set `BEAMHALL_OAUTH_JWKS_URL` explicitly |
