# Beamhall — getting started (an IT admin's first hour)

> **Who this is for:** the IT/infrastructure person standing up Beamhall for the
> first time, to let engineers (and their AI agents) build and deploy internal
> apps without ever handling a real credential. **No prior Beamhall knowledge or
> deep infra expertise assumed.** Follow it top to bottom.
>
> **What you'll have at the end:** a running appliance, an identity provider, a
> workspace, an onboarded engineer, and a real app deployed and promoted to a
> stable URL — all governed, audited, and isolated (gVisor/runsc).
>
> This is the concrete walkthrough. For the *why* (architecture, security model,
> decisions IT must make), read `docs/beamhall-for-it.md`. For the security
> sign-off artifact, `docs/threat-model.md`.

Throughout, replace `beamhall.example.com` with **your** base domain. The pilot
this guide is modeled on used `beamhall.internal`.

---

## Vocabulary (10 seconds)

| Term | Meaning |
|---|---|
| **Beam** | one internal app/service an engineer deploys |
| **Beamhall** | a workspace that groups beams; owns a security tier, quota, egress policy, and memberships |
| **Preview** | a just-deployed beam on a random, auto-pausing URL (the iterate loop) |
| **Live** | a beam promoted to a stable URL — an IT-governed step |
| **MCP** | the governed protocol the engineer's AI agent speaks to Beamhall |

---

## Part 0 — Before you start (prerequisites)

1. **A Linux host you control** — a plain VM is fine (Ubuntu 24.04+/Debian 12;
   the pilot used Ubuntu 26.04). 4 vCPU / 8 GiB RAM recommended (4 GiB works for
   evaluation). No virtualization extensions needed to *run* Beamhall.
2. **DNS** — a wildcard `*.<base-domain>` pointing at the host's IP, plus
   `idp.<base-domain>`. Beams get hostnames like
   `<beam>.<workspace>.<base-domain>` and previews like
   `<random>.preview.<base-domain>`, so a wildcard is the simplest. *(In the
   pilot, the gateway/DNS resolver already published `*.beamhall.internal`.)*
3. **`curl`** on the host (most server images have it).

That's it. Everything else the installer lays for you.

---

## Part 1 — Install the appliance (one command)

SSH to the host as root and run:

```sh
curl -fsSL https://raw.githubusercontent.com/Beamhall/beamhall/main/packaging/install.sh \
  | sudo bash -s -- --base-domain beamhall.example.com --tls internal
```

> This installs the **latest published release** (the script resolves it for you).
> Pin a specific version for reproducibility with `--version vX.Y.Z`.

What this does (idempotent — safe to re-run):

- fetches the **released `beamhalld` binary** for your CPU and verifies its
  checksum (no building from source);
- lays the whole runtime: Docker + user-namespace remapping, **gVisor `runsc`**
  (the regulated isolation tier), a dedicated buildpack build daemon, an internal
  image registry, the **Caddy gateway**, and managed **PostgreSQL**;
- generates the **age secret root key** and config, installs a hardened systemd
  service, and starts it. `/healthz` is green at the end.

**TLS choice (`--tls`):**
- `internal` — Caddy mints certificates from its own private CA. Best for a
  private domain. Install the gateway CA on client machines (Part 1b).
- `on` — public ACME (Let's Encrypt); use only if the domain is internet-reachable.
- `off` — plain HTTP (quickest, least production-like).

> 🔑 **Back up the secret root key NOW.** The installer prints its location
> (`/etc/beamhall/secret.key`). It seals **every** secret Beamhall stores —
> **lose it and every secret (and every backup) is unrecoverable.** Copy it to
> your KMS/vault and keep it offline. (Supply your own with `--secret-key` instead
> of generating one.)

### Part 1b — Trust the gateway CA on client machines (only for `--tls internal`)

Engineers' workstations (and yours) must trust Caddy's private CA so HTTPS to
`*.<base-domain>` validates. The installer saved the root cert on the host at
`/usr/local/share/ca-certificates/beamhall-gateway-ca.crt`. Distribute it:

- **macOS:** add it to the login keychain and mark it trusted (Keychain Access,
  or `security add-trusted-cert`).
- **Linux:** drop it in `/usr/local/share/ca-certificates/` and run
  `update-ca-certificates`.
- **Per-tool, no system change:** point a tool at the file directly — `curl
  --cacert beamhall-gateway-ca.crt …`, or `NODE_EXTRA_CA_CERTS=…` for Node-based
  clients.

You can fetch the cert any time: `curl -s http://<host>:2019/pki/ca/local | jq -r
.root_certificate` (the gateway admin API is loopback-only on the host).

---

## Part 2 — Turn on identity (the bundled IdP, for a pilot)

Beamhall validates OAuth tokens from your IdP; until one is wired, `/mcp` and the
Admin console are closed. The fastest way to evaluate — **without touching your
corporate IdP** — is the bundled Keycloak. One command (the installer prints this
exact line, pinned to the version you installed):

```sh
curl -fsSL https://raw.githubusercontent.com/Beamhall/beamhall/main/packaging/keycloak/setup-bundled-idp.sh \
  | sudo BASE_DOMAIN=beamhall.example.com BEAMHALL_REF=main bash
```

It stands up Keycloak (fronted by your gateway at `idp.<base-domain>`), seeds two
users — **`it-admin`** and **`builder`** — wires `beamhalld` to trust it, and
registers their Beamhall identities. **It prints the URLs and the generated
passwords once — save them.** Example output:

```
Admin console : https://beamhall.example.com/admin   (it-admin / <password>)
IdP issuer    : https://idp.beamhall.example.com/realms/beamhall
Agent client  : beamhall-agent (public, PKCE)   user: builder / <password>
```

> The bundled IdP is **persistent** (a named Docker volume): users/groups/config
> you create survive reboots and long evaluation gaps. For production, point
> Beamhall at your corporate IdP (`docs/idp-setup.md`) and disable the bundled
> one. Re-running the setup preserves state; `RESET=1` wipes and re-seeds.

---

## Part 3 — Create a workspace and onboard an engineer

You have **two equivalent, fully-audited paths**. Both go through the same policy
engine and audit log. Pick whichever you prefer.

### Path A — the Admin console (web; easiest for a human)

Open `https://<base-domain>/admin`, sign in as **`it-admin`**. From there you can:

- **create a workspace** (Beamhall) — choose the isolation tier (**runsc** = the
  regulated gVisor tier; runc = lighter) and the quota;
- **grant memberships** (builder / beamhall_admin / viewer);
- edit **egress** policy, view **state/logs/history**, **promote/rollback**, and
  watch the **audit log verify** live.

### Path B — administer over MCP (drive it from an agent)

Beamhall's admin surface is also MCP: the `admin_*` tool family lets an IT
operator onboard people and manage the bundled IdP from an agent — no console.
Every `admin_*` tool requires the **`admin:it`** scope, which is deliberately a
**master key**: keep it tightly held.

**Connecting an admin agent.** IT admin is gated by the **`beamhall-it` realm
role** (a builder can never hold it), so an IT operator connects with the
dedicated admin client and a normal browser login — no token juggling:

```sh
claude mcp add --transport http --client-id beamhall-admin-agent \
  beamhall-admin https://beamhall.example.com/mcp
# sign in as an IT user (the bundled it-admin has the beamhall-it role)
```

The bundled IdP gives this client the full capability scope set by default and
elevates to IT admin **only** when the signed-in user has the `beamhall-it` role
(the bundled `it-admin` does; grant it to other IT users in the Keycloak console,
or `admin_create_user` + assign the role). A builder who authenticates with this
same client gets no admin — the role, not the client, is the gate.

> *Alternative (no dedicated client):* pass a pre-minted `admin:it` token as a
> header — `claude mcp add --transport http --header "Authorization: Bearer
> $TOKEN" …` where `$TOKEN` comes from the IdP token endpoint with
> `scope=openid admin:it`. Useful for short-lived automation.

Then ask the agent to run the onboarding tools. The full chain to onboard a new
hire **Dana** into a new **runsc** workspace **engineering** is:

```
admin_create_beamhall  slug=engineering runtime_class=runsc        # quota defaults to 5 beams / 1 live / 2 db
admin_create_user      username=dana email=dana@acme.example
admin_set_user_password user_id=<id> password=<temp>               # she changes it at first login
admin_create_group     name=engineers
admin_add_user_to_group user_id=<id> group_id=<id>
admin_register_identity issuer=<bundled issuer> subject=dana       # Beamhall-side identity
admin_grant_membership beamhall=engineering role=builder subject=dana
```

> **Two stores, both required.** The IdP holds *login accounts*
> (`admin_create_user`); Beamhall holds *access* (`admin_register_identity` +
> `admin_grant_membership`). An IdP account alone grants no Beamhall access. The
> bundled IdP issues `sub` = username, so you can register a user's identity as
> soon as the account exists. Full reference: `docs/admin-over-mcp.md`.

> **Sensitive tier (four-eyes).** `admin_federate_directory` (connect the bundled
> IdP to LDAP/AD) changes *who can sign in to the whole appliance*, so it's filed
> as a request a **different** IT operator must approve. It's off until you set
> `BEAMHALL_IDP_SENSITIVE_ADMIN=on`.

---

## Part 4 — Point an engineer's agent at Beamhall

Give the engineer this one line (the bundled-IdP setup prints it). It uses the
pre-registered agent client; first use opens a browser login:

```sh
claude mcp add --transport http --client-id beamhall-agent \
  beamhall https://beamhall.example.com/mcp
# then authenticate and sign in (as builder, or as the user you onboarded)
```

Their workstation must resolve `*.<base-domain>` to the appliance and trust the
gateway CA (Part 1b).

---

## Part 5 — The engineer deploys a beam (what they ask their agent to do)

A first deploy, end to end — every step is an MCP tool call the agent makes:

1. `create_beam` — name the app in the workspace.
2. `set_secret` — store a secret (write-only; it becomes a file
   `/run/secrets/<KEY>` *inside* the workload, never readable back).
3. `create_database` — provision managed Postgres; returns only the **key + file
   path** (`/run/secrets/MAIN_URL`), **never the connection string**.
4. `deploy_beam` (no source) — returns a one-time `git push` remote. The engineer
   commits and pushes; Beamhall runs buildpacks (no Dockerfile), builds the image,
   and deploys it hardened under runsc. Build progress streams back; a **preview
   URL** prints on success.
5. `show_logs` — logs, with any secret values **scrubbed** before the agent sees
   them.

The app reads its secret and database connection string from the injected files.
**The agent never saw either value.**

---

## Part 6 — Governance: promote to live

Promotion to a stable URL is an **IT decision**. A builder cannot self-promote —
`promote_to_live` is **denied by role**, even if their token carries the
`beams:promote` scope. An IT operator promotes (Admin console, or `promote_to_live`
with an `admin:it` token):

- the beam goes live at `https://<beam>.<workspace>.<base-domain>`;
- the **preview channel keeps running** on its own URL with its **own database**
  (iterate on preview; production data stays separate);
- `rollback` re-pins live to a prior version.

For regulated environments, turn on the **four-eyes promote gate**
(`BEAMHALL_PROMOTE_APPROVAL=on`): the agent *requests* promotion and a **different**
IT operator approves.

---

## Part 7 — Show your security team (the "agent cannot" proofs, live)

These are demonstrable on the running appliance and underpin the sign-off:

- **No secret read-back.** There is no tool to read a secret or a database
  password; the values exist only as files inside the workload.
- **Strong isolation (runsc tier).** The beam container runs `runtime=runsc` and
  sees a **gVisor user-space kernel** (`uname -r` → `…-gvisor`), with a read-only
  root filesystem, **all Linux capabilities dropped**, and no-new-privileges —
  not the host kernel.
- **Default-deny egress.** Outbound to an arbitrary host or to cloud metadata is
  dropped; only same-workspace traffic (e.g. its database) is reachable.
- **Role beats scope.** A builder holding `beams:promote` is still denied
  promotion — authorization is enforced at the policy point, not by the token.
- **Tamper-evident audit.** Every action (allowed *and* denied) is in a
  hash-chained log that verifies on boot and in the Admin console.

---

## Part 8 — Day 2

- **Backups:** `beamhalld backup <path>` — one online archive including the secret
  root key and the managed git repos. Schedule it. Restore with `beamhalld restore`.
- **Audit retention:** set `BEAMHALL_AUDIT_RETENTION_DAYS=<N>` (prunes on boot +
  daily, keeping the chain verifiable) or run `beamhalld admin prune-audit` on demand.
- **Move to your corporate IdP:** set `BEAMHALL_OAUTH_ISSUER` in
  `/etc/beamhall/beamhall.env`, restart, and disable the bundled Keycloak
  (`docs/idp-setup.md`; Okta/Entra/Keycloak recipes). Beamhall's issuer is the only
  thing that changes — workspaces, beams, and audit are untouched.
- **Connect the company directory (LDAP/AD):** federate the bundled IdP via
  `admin_federate_directory` (four-eyes) without changing Beamhall's issuer.

---

## Appendix — what's automated vs. what you decide

**Automated (one command each):** install the runtime + binary; stand up the
bundled IdP; create workspaces / onboard users (console or MCP); build + deploy
(git push); backup/restore.

**Your decisions:** base domain + DNS; TLS mode; isolation tier per workspace
(runc vs **runsc**); quota per workspace; promote governance (direct vs four-eyes);
egress allowlist (default is deny-all); bundled IdP now vs. corporate IdP from
day one.

**The pilot this guide mirrors** ran exactly these steps on a bare Ubuntu host and
ended with a Node "visit-counter" beam (a sealed-secret greeting + a Postgres-backed
counter) **live** under runsc at `counter.engineering.beamhall.internal`, its preview
channel still iterating on a separate database — with the builder's self-promotion
denied and IT promotion succeeding.
