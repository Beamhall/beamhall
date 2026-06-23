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
| `admin_add_user_to_group` / `admin_remove_user_from_group` | routine | manage group membership in the bundled IdP |
| `admin_set_user_enabled` | routine | enable/disable a bundled-IdP account (offboarding without deletion) |
| `admin_delete_user` / `admin_delete_group` | routine (irreversible) | permanently delete a bundled-IdP account / group (prefer disable for reversible offboarding) |
| `admin_federate_directory` / `admin_unfederate_directory` | **sensitive** | connect/disconnect the bundled IdP to/from LDAP/Active Directory |

### Workspace + membership lifecycle (read/update/offboard)

| Tool | Tier | Effect |
|---|---|---|
| `admin_list_beamhalls` | routine (read) | list every workspace appliance-wide (not membership-scoped) |
| `admin_show_beamhall` | routine (read) | one workspace in detail: egress, quota, members+roles, beams (+channel URLs) |
| `admin_update_beamhall` | routine (loud) | change quota (`max_beams`/`max_live_slots`/`max_databases`), **status** (`active`/`suspended`/`archived`), or metadata. `suspended` freezes the workspace — the PEP then **denies every action in it**; `archived` decommissions it |
| `admin_revoke_membership` | routine | remove an identity's access to a workspace (the `admin_grant_membership` inverse) |
| `admin_set_membership_role` | routine | change a member's role in place (e.g. `viewer`→`builder`) |
| `admin_set_identity_status` | routine | `disabled` = per-principal kill switch (the identity keeps its row + audit history but **every** authorization fails); `active` restores it |
| `admin_set_egress` | routine | set a workspace's egress policy (`deny_all`/`allowlist`) |
| `admin_set_security_context` | **sensitive** | change a workspace's runtime isolation class (`runc`↔`runsc`) — alters the hardening posture, four-eyes |
| `admin_list_releases` | routine (read) | a beam's production-release history (`v1,v2,…`) — the `to_version` targets for `rollback` |

### Audit (the regulated trail, now MCP-readable)

| Tool | Tier | Effect |
|---|---|---|
| `admin_query_audit` | routine (read) | read the hash-chained audit log — every allow/deny decision (who/what/where/why), appliance-wide or `beamhall`-scoped, paginated via `after_seq` |
| `admin_verify_audit_chain` | routine (read) | walk the hash chain and report intact / list integrity violations (tamper-evidence) |
| `admin_prune_audit` | **sensitive** | prune the log to a retention checkpoint (destroys tamper-evidence below it), four-eyes |

### Backup / restore

| Tool | Tier | Effect |
|---|---|---|
| `admin_backup_now` | routine | write an online snapshot (control-plane DB + sealed secret key + git repos) to the backup directory |
| `admin_list_backups` | routine (read) | list backups (newest first) with size, contents, and integrity-verification status |
| `admin_restore_backup` | **sensitive** | restore from a named backup (overwrites the whole control plane). Four-eyes; never applied live — on approval the archive is verified and you get the exact stop→restore→start command (restore is a stop-the-world operation) |

### Self-upgrade (the most-guarded action)

| Tool | Tier | Effect |
|---|---|---|
| `admin_request_upgrade` | **sensitive** | upgrade the appliance to a target release (e.g. `v0.1.11`) — replaces the policy-enforcing binary |

Self-upgrade is the control plane modifying the binary that enforces policy, so
it carries **four** independent gates: it is **fail-closed** (off unless
`BEAMHALL_SELF_UPGRADE=on`, and then only the *staging* runs in-process), behind
the **sensitive tier**, behind **four-eyes** approval, and the final irreversible
**swap + restart is an operator step**, never autonomous. On approval the backplane
downloads the pinned release, **verifies its sha256 against `checksums.txt`**, stages
the new binary (and sanity-checks that it runs and self-reports the target version),
then hands back the exact atomic apply + rollback commands:

```
admin_request_upgrade version=v0.1.11        # operator A files it
admin_approve_request request_id=<id>        # operator B approves → stages + verifies
# then on the host (atomic swap + restart; the current binary is kept as rollback):
cp /usr/local/bin/beamhalld /usr/local/bin/beamhalld.rollback \
  && mv <staged> /usr/local/bin/beamhalld && systemctl restart beamhalld
# rollback: mv /usr/local/bin/beamhalld.rollback /usr/local/bin/beamhalld && systemctl restart beamhalld
```

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
- **Sensitive** ops change *who can sign in*, the *isolation posture*, *tamper-evidence*,
  *all appliance state*, or *the policy-enforcing binary itself*:
  `admin_federate_directory` / `admin_unfederate_directory`,
  `admin_set_security_context` (runtime-class), `admin_prune_audit`,
  `admin_restore_backup`, and `admin_request_upgrade`. These go through a
  **four-eyes approval flow** (below): the requesting operator never executes them;
  a *different* IT operator must approve. The master switch
  `BEAMHALL_IDP_SENSITIVE_ADMIN=on` controls whether sensitive actions can be
  requested at all — with it off they fail closed and stay off the tool menu.
  (`admin_restore_backup` also needs a backup directory; `admin_request_upgrade`
  also needs `BEAMHALL_SELF_UPGRADE=on` — both are additionally fail-closed.)

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

## The tool menu is per-caller (multi-level menu)

`tools/list` is filtered per caller, so an agent only ever sees the tools its
token could actually invoke — the same gate the handler enforces, applied at
discovery time. This keeps a builder agent's context free of the ~25 `admin_*`
tools it can't use, and shows an IT operator the full admin menu. The cut is two
cheap, fail-closed axes (no extra DB read):

- **Privilege tier** — a builder token (capability scopes, no `admin:it`) sees
  only the builder surface; an `admin:it` token (scope **or** the `beamhall-it`
  realm role) additionally sees the `admin_*` family. Mirrors `resolveActor`
  exactly: a tool is shown **iff** the caller would pass its scope/role check.
- **Appliance state** — bundled-IdP tools are hidden on a bring-your-own-IdP
  deployment; the four-eyes sensitive tools are hidden until the sensitive tier is
  enabled; the backup tools are hidden unless a backup directory is configured; and
  `admin_request_upgrade` is hidden unless self-upgrade is turned on. (No point
  offering a tool that can only answer "not enabled.") This was observed live:
  redeploying with the sensitive tier off, and self-upgrade off, kept the four-eyes
  tools and `admin_request_upgrade` off the menu, while the routine tools and the
  configured-backup tools appeared.

This is **discovery, not authorization** — every handler still calls
`resolveActor`, so a hidden tool invoked directly is still refused. When the
appliance state changes (e.g. enabling the sensitive tier, or a future build
adding tools), the server emits a `tools/list_changed` and connected agents
re-list, picking up their newly-correct menu without reconnecting. Source:
`internal/mcp/visibility.go`; a CI drift test
(`TestToolVisibilityTableMatchesRegistry`) fails if a new tool is left
unclassified.

## Persistence

The bundled Keycloak is **persistent** (named volume `beamhall-keycloak-data`): the
realm is seeded once on first boot and runtime changes (users, groups, federation)
survive reboots and long evaluation gaps. Re-running `setup-bundled-idp.sh`
preserves state; `RESET=1` wipes and re-seeds. See
`packaging/keycloak/README.md`. For production, point Beamhall at your own IdP
(`docs/idp-setup.md`) and disable the bundled one.
