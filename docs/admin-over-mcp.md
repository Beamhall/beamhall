# Administering Beamhall over MCP

Beamhall's operator surface is MCP, like the rest of the product: an IT
administrator drives onboarding and identity-provider administration through the
**same agent channel** as beam work — no separate web console required. This guide
covers the `admin_*` tool family, how it stays IdP-agnostic, and the guardrails.

## Who can use it

Every `admin_*` tool requires **IT-admin**, which Beamhall derives from *either*
the **`admin:it`** scope *or* the **`beamhall-it`** realm role
(`BEAMHALL_OAUTH_ADMIN_ROLE`, default `beamhall-it`). Every admin action runs
through the backplane PEP and is written to the audit chain, so IT actions are as
accountable as agent actions — each audits against a known identity.

Two ways an IT operator connects, both gated so a builder can never reach these
tools:

1. **Role-gated admin client (recommended).** Connect with the bundled
   `beamhall-admin-agent` client and a normal browser login:
   `claude mcp add --transport http --client-id beamhall-admin-agent beamhall-admin https://<base>/mcp`.
   The client grants the capability scopes by default and elevates to IT admin
   **only** for users holding the `beamhall-it` realm role (the bundled `it-admin`
   has it; assign it to other IT users). This works because `admin:it` is
   deliberately hidden from the scope advertisement — and `claude mcp add` can't
   request hidden scopes — so the *role* (user-gated in the IdP), not a scope, is
   the gate. A builder authenticating with the same client gets no admin.
2. **Header token.** Pass a pre-minted `admin:it` token via
   `--header "Authorization: Bearer …"` (token endpoint with `scope=openid admin:it`).
   The same scope opens the `/admin` web console. Good for short-lived automation.

## Two kinds of "identity"

Beamhall has **two stores**, and onboarding touches both:

1. **The IdP's user store** (the bundled Keycloak): where login accounts live.
   Managed by `admin_create_user`, `admin_set_user_password`, groups, federation.
2. **Beamhall's own identity + membership store**: where *access* lives — which
   `(issuer, subject)` may act, and with what role in which beamhall. Managed by
   `admin_register_identity` + `admin_grant_membership`.

IdP groups do **not** automatically grant Beamhall access — the membership store
is the authorization source. So onboarding a person is always: account exists in
the IdP **and** their subject is registered + granted a membership in Beamhall.

## Onboarding a user end to end (bundled IdP)

```
admin_create_user        username=alice email=alice@acme.internal
admin_set_user_password  user_id=<id> password=<temp>      # they change it at first login
# after alice signs in once (so her subject is known/stable):
admin_register_identity  issuer=<bundled issuer> subject=alice email=alice@acme.internal
admin_grant_membership   beamhall=<slug> role=builder identity_id=<id>
```

For many users a week, drive these from the agent in a loop, or use the
`/admin` console — both go through the same audited backplane path.

## The tool family

| Tool | Tier | Effect |
|---|---|---|
| `admin_register_identity` | routine | register an `(issuer, subject)` so it can be granted membership |
| `admin_grant_membership` | routine | grant a registered identity a role (`builder`/`beamhall_admin`/`viewer`) in a beamhall |
| `admin_list_identities` | routine (read) | list registered identities |
| `admin_create_beamhall` | routine | create a workspace with an immutable hardening profile (`runc`/`runsc`) |
| `admin_create_user` | routine | create a local account in the bundled IdP |
| `admin_list_users` | routine (read) | search bundled-IdP accounts |
| `admin_set_user_password` | routine | set a temporary password (change-at-next-login) |
| `admin_create_group` / `admin_list_groups` | routine | organize bundled-IdP users |
| `admin_add_user_to_group` | routine | add a user to a group |
| `admin_federate_directory` | **sensitive** | connect the bundled IdP to LDAP/Active Directory |

The owned-IdP tools require Beamhall to be running its **bundled** IdP. On a
bring-your-own-IdP deployment they return a clear notice telling you to manage
users in your own IdP — Beamhall validates your tokens but does not administer a
directory it doesn't own. (See "IdP-agnostic by design" below.)

## IdP-agnostic by design

Beamhall validates tokens from **any** OIDC IdP (Keycloak, Okta, Entra, …) —
*authentication* is agnostic. But *administering* an IdP is inherently
IdP-specific, so administration is offered **only for the IdP Beamhall owns** (the
bundled Keycloak), behind a provider seam (`internal/identityadmin`). For a
corporate IdP you manage users in that IdP; for the bundled IdP, Beamhall holds
the admin credential (a service-account client, never the agent) and mediates.

This is why the admin tools are intent-shaped (`admin_create_user`, not "run a
raw Keycloak call"): the MCP contract never leaks Keycloak, and swapping the owned
IdP later wouldn't change the tools.

## Guardrails: tiered by risk

- **Routine** ops (onboarding: users, passwords, groups, identities, memberships)
  run autonomously and are audited.
- **Sensitive** ops change *who can sign in to the whole appliance*. Today that is
  `admin_federate_directory`; restores and upgrades will join it. These go through
  a **four-eyes approval flow** (below): the requesting operator never executes them;
  a *different* IT operator must approve. The master switch
  `BEAMHALL_IDP_SENSITIVE_ADMIN=on` controls whether sensitive actions can be
  requested at all — with it off they fail closed.

Why this matters: an `admin:it` agent that can create identities and grant
memberships can *manufacture access*. `admin:it` is a master key — keep it
out-of-band, keep the sensitive tier behind a second operator.

## Four-eyes approval (sensitive actions)

A sensitive action is filed as a **pending request**, then a second IT operator
approves it before it executes (separation of duties):

```
# operator A files the request:
admin_federate_directory  name=corp-ad ...        # returns request_id; does NOT execute
# operator B (a different IT person) reviews and approves:
admin_list_pending_requests                        # shows the non-secret summary
admin_approve_request  request_id=<id>             # executes now; records the result
#   or
admin_reject_request   request_id=<id> reason=...  # discards it
```

- **Separation of duties is enforced:** the requester cannot approve their own
  request — a *different* `admin:it` identity must.
- **Secrets stay sealed:** the request payload (e.g. the LDAP **bind password**) is
  encrypted at rest with the appliance's age key; only a non-secret summary appears
  in `admin_list_pending_requests`. The credential is opened only at execution.
- **Failure is retryable:** if execution fails (e.g. the directory is unreachable),
  the request stays pending — fix the cause and approve again.
- The flow is **generic** (`action_type`), so future sensitive actions (restore,
  upgrade) use the same request → approve path.

## Connecting to an existing directory (LDAP / Active Directory)

When a pilot graduates from local accounts to the company directory, federate the
**bundled Keycloak** to it — Beamhall's issuer does not change, so nothing in
Beamhall's config changes. Federation is a sensitive action, so it goes through
four-eyes approval:

```
# enable the sensitive tier first (operator decision):
#   BEAMHALL_IDP_SENSITIVE_ADMIN=on  in /etc/beamhall/beamhall.env, then restart beamhalld
# operator A files the request:
admin_federate_directory \
  name=corp-ad vendor=ad \
  connection_url=ldaps://dc1.corp.example:636 \
  users_dn="OU=Beamhall,OU=Users,DC=corp,DC=example" \
  bind_dn="CN=svc-beamhall,OU=Service,DC=corp,DC=example" bind_password=<pw>
# operator B (a different IT person) approves it:
admin_approve_request request_id=<id>
```

The bind password is sealed at rest while the request is pending. Once approved,
directory users can authenticate. They are **new** `(issuer, subject)` records
(the issuer is still your Keycloak), so register the ones who should use Beamhall
(`admin_register_identity`) and grant memberships — the same routine step as any
onboarding. Retire the earlier local test accounts when ready.

## Persistence

The bundled Keycloak is **persistent** (named volume `beamhall-keycloak-data`): the
realm is seeded once on first boot and runtime changes (users, groups, federation)
survive reboots and long evaluation gaps. Re-running `setup-bundled-idp.sh`
preserves state; `RESET=1` wipes and re-seeds. See
`packaging/keycloak/README.md`. For production, point Beamhall at your own IdP
(`docs/idp-setup.md`) and disable the bundled one.
