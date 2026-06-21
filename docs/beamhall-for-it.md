# Beamhall — IT Department Guide

> **Audience:** the IT/infrastructure team that will run Beamhall inside your
> own environment. This document explains what Beamhall is, why you'd want it,
> how it works, what it requires of you, and how to get started. It is also a
> **living planning document**: the *Status & roadmap* and *Decisions we need
> from IT* sections are where we adjust stories and prioritize deliverables.
>
> Status legend: ✅ built & lab-verified · 🟡 planned / pilot-gated · 🔵 decision pending
>
> Deeper references: `docs/threat-model.md` (security sign-off artifact),
> `docs/PLAN.md` (design contract), `demo/README.md` (the working demo).

---

## 1. What Beamhall is

Beamhall is a **self-hosted infrastructure backplane that lets AI agents safely
build and deploy internal applications — "beams" — inside your environment,
without ever handing the agent a real credential.**

An engineer points their AI coding agent (e.g. Claude Code) at Beamhall. The
agent asks Beamhall, over a governed protocol (MCP), to *create a beam, attach a
database, set a secret, deploy, show logs, promote to production, roll back.*
Beamhall does the privileged work — building the image, injecting secrets,
hardening the container, wiring the network and the public URL — and returns
only **references and URLs**, never the secret values, DSNs, or host access.

It ships as a **single Go binary** that runs as a systemd service (or a baked VM
image) on a Linux host you control. It is not SaaS; nothing leaves your network.

**Vocabulary**

| Term | Meaning |
|---|---|
| **Beam** | One internal app/service the agent deploys (a web app, an internal tool). |
| **Beamhall** | A workspace/tenant that groups beams, owns a security profile, quota, and egress policy. Memberships live here. |
| **Preview** | A just-deployed beam on a random, throwaway URL that auto-pauses when idle. |
| **Live** | A promoted beam on a stable URL — an explicit IT-governed step. |

---

## 2. Why you'd want it (benefits for IT)

- **No raw credentials reach the agent or the developer.** Secrets and database
  connection strings are injected as files *inside* the workload at runtime.
  There is no tool that reads a secret back, and no agent path to host access.
  ✅
- **Every privileged action goes through one policy enforcement point**, gated
  by your IdP's scopes and per-workspace roles. Promotion to production is an
  IT decision, not something an agent can self-authorize. ✅
- **Tamper-evident audit.** Every action (allowed *and* denied) is recorded in a
  hash-chained, append-only log that verifies on boot. ✅
- **Strong workload isolation by default** — dropped Linux capabilities,
  no-new-privileges, read-only root filesystem, seccomp, user-namespace
  remapping, per-workspace network with **default-deny egress**, and an optional
  **gVisor (runsc)** tier for a user-space kernel boundary. ✅ (see
  `docs/threat-model.md`)
- **No Dockerfiles to review.** Beams are built with Cloud Native Buildpacks
  from source — a consistent, supply-chain-friendlier build path. ✅
- **Self-hosted and self-contained.** One binary; the appliance's own state is
  embedded SQLite; beams get real managed Postgres. Online backup includes the
  secret root key for true disaster recovery. ✅
- **Governed lifecycle.** Preview → promote-to-live → rollback, with idle
  previews auto-pausing to reclaim resources. ✅

**The "money shot" for a security review:** ask the agent to print a database
password, read the egress rules, or loosen seccomp — there is no tool to read
secrets, no raw credentials exist to print, the hardening baseline is immutable,
and an outbound call to a blocked host is dropped. Demonstrable live.

---

## 3. How it works

```
   Developer + AI agent (Claude Code)
            │  MCP over HTTPS  (OAuth token: scopes, no secrets)
            ▼
   ┌─────────────────────────────────────────────────────────┐
   │  beamhalld  (single Go binary on your host)              │
   │                                                          │
   │   MCP server ── Policy Enforcement Point ── Audit (chain)│
   │       │              │           │                       │
   │   Buildpacks     Secrets (age)  Orchestrator             │
   │   (no Dockerfile)  injected      │                       │
   │                    as files      ▼                       │
   │                          Docker driver  (runc | runsc)   │
   │                          per-workspace bridge,           │
   │                          default-deny egress (iptables)  │
   └───────────────┬───────────────────────┬─────────────────┘
                   ▼                        ▼
            Caddy gateway            Managed Postgres
       (preview/live URLs, TLS)   (per-beam DB, DSN as a secret file)
```

**The code lives in Beamhall.** Each beam has a managed git repo on the
appliance — no external GitHub/GitLab required. The agent ships changes by
`git push` (via a one-time deploy token) and can **clone it back** on a new
machine via `get_repo` (a one-time, read-only token). Treat the repos volume as
canonical source: include it in your backups, same as the database.

**A deploy, end to end:** the agent calls `deploy_beam`, gets a one-time
`git push` remote, and pushes its source (the tarball upload is a fallback) → the
**dedicated build daemon** runs buildpacks and pushes the image to an internal
registry → the orchestrator stages secret files, applies the immutable security
profile, attaches the workspace network, re-asserts egress rules, and starts the
container on the runtime daemon → the Caddy gateway publishes a preview URL →
build/deploy progress streams back to the agent. Logs are **scrubbed** of secret
values before the agent ever sees them. Promotion to a stable live URL is a
separate, IT-scoped call.

**What the agent can never do:** read a secret, obtain a raw DSN or host
credential, change the hardening baseline, or reach a blocked egress
destination. Promotion requires an IT role even if the agent's token nominally
carries the scope.

---

## 4. What IT owns (operational responsibilities)

| You own | What it means |
|---|---|
| **The host** | A Linux host (bare metal or an ordinary VM) meeting the baseline in §5. You patch and monitor it. |
| **The secret root key** | A single age key seals every stored secret. It is delivered **out-of-band** (systemd `LoadCredential` / KMS / vault) and **never** lives in the image or env file. **Losing it loses every secret.** It also travels inside backups, so back it up separately to your KMS/vault. ✅ |
| **The identity provider** | Beamhall validates OAuth/OIDC tokens from *your* IdP (issuer, audience, scopes). You define which people/agents get which scopes. 🔵 *(bundled Keycloak vs. your existing Okta/Entra is a decision — §8)* |
| **Workspaces & memberships** | IT creates beamhalls, sets their security profile/egress/quota, and grants engineers/agents roles. Via the Admin console or the `beamhalld admin` CLI. ✅ |
| **DNS & TLS** | A wildcard domain for beam URLs (`*.<base-domain>`) and a TLS strategy: public ACME (`BEAMHALL_GATEWAY_TLS=on`) for an internet-reachable domain, or **internal CA** (`=internal`) for a private domain like `*.beamhall.internal` — Caddy mints trusted certs from its local CA; install the gateway root (`GET <caddy-admin>/pki/ca/local`) on workstations. `=off` serves plain HTTP. ✅ |
| **Backups** | Schedule `beamhalld backup` (online, safe on a running appliance). ✅ |
| **Audit log retention** | The audit log is hash-chained and append-only (tamper-evident), so it grows over time. Bound it without losing integrity: set `BEAMHALL_AUDIT_RETENTION_DAYS=<N>` and the appliance prunes events older than N days on boot and daily, **or** run it on demand — `beamhalld admin prune-audit -keep-days 90` (or `-keep 50000` to keep a fixed number of newest events; add `-dry-run` to preview). Each prune records a checkpoint (the chain hash at the cut point) so the surviving chain still verifies and any *un*-recorded deletion is still detected. **Pruned events are deleted for good** (no SIEM export yet), so pick a window your compliance policy can stand behind. ✅ |

---

## 5. Requirements

**Host (validated: Ubuntu 24.04 LTS; Debian 12 supported).** No virtualization
extensions are required to *run* Beamhall — a plain VM is fine. (KVM is only ever
needed to *bake* a VM image, which is a build-side step, not a runtime need.)

The turnkey `install.sh` hard-checks the baseline before it lays anything (and
`scripts/preflight.sh` runs the same checks standalone):

- **Kernel ≥ 5.2** with **cgroup v2 unified hierarchy** active.
- **Docker** with **user-namespace remapping** (`/etc/subuid` + `/etc/subgid`
  ranges for the remap user).
- **runc ≥ 1.2.8** (patched for the 2025–26 runC CVEs).
- **gVisor `runsc`** — required only for the regulated runtime tier
  (`BEAMHALL_REQUIRE_RUNSC=1`).
- One free inbound **HTTPS port** for the control/MCP endpoint.

**Software baseline** (laid by `install.sh` — one command, no hand-steps): Docker
+ userns-remap, gVisor `runsc` as a runtime, the **pack** CLI + a **dedicated
non-remapped build daemon** and internal registry (buildpack builds can't run on
the remapped runtime daemon), Caddy (gateway), and the Paketo builder image.

**Services Beamhall expects:** managed **Postgres** for beam databases (the
appliance's own state is embedded SQLite — no extra DB for the control plane);
your **OIDC IdP**; **DNS** for `*.preview.<base-domain>` and
`*.<workspace>.<base-domain>`.

**Networking:** outbound access for the *build daemon* (buildpacks/registry
pulls). Workloads run **default-deny egress**; reaching an internal API needs an
explicit IT allowlist entry. 🔵 *(allowlist priority — §8)*

---

## 6. Getting started

1. **Provision a host** (bare Ubuntu 24.04+/Debian 12 — no virtualization needed)
   and run **one command**:
   ```
   sudo bash install.sh ./beamhalld --base-domain beamhall.example.com
   ```
   It lays the entire runtime (Docker from the official repo + userns-remap +
   gVisor `runsc`, the dedicated build daemon, the gateway, internal registry,
   managed Postgres), **generates** the age root key and config, installs the
   hardened systemd service, and starts it — `/healthz` is green at the end.
   Idempotent and re-runnable; it hard-verifies the CVE-patched runc floor and
   refuses to proceed otherwise. ✅ *(or boot the Packer-baked VM image)*
2. **Back up the generated age root key** at `/etc/beamhall/secret.key` to your
   KMS/vault — it seals every secret and **losing it loses them all**. (Supply
   your own with `--secret-key` instead of generating one.) ✅
3. **Wire identity.** Either point at your IdP — set `BEAMHALL_OAUTH_ISSUER` in
   `/etc/beamhall/beamhall.env` (`docs/idp-setup.md`) — or evaluate instantly with
   the bundled Keycloak:
   `sudo BASE_DOMAIN=beamhall.example.com bash packaging/keycloak/setup-bundled-idp.sh`
   (turnkey realm, seed `builder`/`it-admin`, fronted by the gateway). ✅
4. **Create a workspace and register the agent identity** — Admin console, or
   `beamhalld admin bootstrap … -role builder -runtime runc` (`register-identity`
   for the IT operator). The bundled-IdP script does this for you. ✅
5. **Point the agent at Beamhall** (each engineer, on their workstation):
   `claude mcp add --transport http beamhall https://<base-domain>/mcp` → first
   use opens an in-session OAuth login against your IdP. With the **bundled
   Keycloak**, pin the pre-registered agent client (the setup script prints this
   exact command):
   `claude mcp add --transport http --client-id beamhall-agent beamhall https://<base-domain>/mcp`
   Then the engineer prompts the agent to build something; Beamhall does the rest.
   (Workstations must resolve `*.<base-domain>` to the appliance and trust the
   gateway CA when running internal TLS — see §4.)
6. **Watch it work:** run `demo/run-demo.sh` — the canonical Request Tracker
   goes create → deploy → preview → scrubbed logs → governed promote → rollback,
   with a real managed database. ✅ (`demo/README.md`)

---

## 7. Status & roadmap *(planning surface — adjust here)*

**Built and lab-verified ✅**

| Capability | Notes |
|---|---|
| Build → deploy → run | Buildpacks (no Dockerfile), internal registry, hardened run (runc/runsc) |
| Gateway + URLs + TLS | Caddy, random preview / stable live, ask-gated on-demand TLS |
| Default-deny egress isolation | Per-workspace bridge, iptables reconciler (asserts on every change + boot) |
| Secrets + log scrubbing | age-sealed, injected as files, never readable back, scrubbed from logs |
| Governed lifecycle | preview, idle auto-pause, resume (new URL), promote-to-live, rollback, destroy |
| MCP + OAuth + PEP | IdP-agnostic token validation, single policy point, scope+role matrix |
| Tamper-evident audit | hash-chained, append-only, verifies on boot |
| Admin console | OIDC-authenticated; workspaces, state/history/logs, IT actions |
| `beamhalld admin` CLI | Scriptable IT provisioning (bootstrap, register-identity) |
| Bring-your-own OIDC | IdP-agnostic with OIDC discovery; verified against real Keycloak (Okta/Entra recipes in `docs/idp-setup.md`) |
| Bundled Keycloak (pilot) | One-command turnkey IdP to evaluate without touching your corporate IdP (`packaging/keycloak/`) |
| Promote-approval gate (four-eyes) | Optional: an agent *requests* promotion; a different IT operator must approve before it goes live (`BEAMHALL_PROMOTE_APPROVAL=on`) |
| Air-gapped builds | Offline image mirroring for the build pipeline (`scripts/airgap-*.sh` + `docs/air-gapped.md`) |
| Managed Postgres per beam | DSN delivered as a secret file; live connectivity proven |
| Git push transport | Deploy by pushing to a managed per-beam remote |
| Backup / restore | Online snapshot incl. the secret root key; DR verified |
| Packaging | Static binaries (GoReleaser), hardened systemd unit, Packer VM image |

**Planned / pilot-gated 🟡**

| Item | Why it matters to IT |
|---|---|
| Run against a real pilot environment | Validate against your actual apps, IdP, and network |
| Validate the **gVisor (runsc)** tier in your environment | Confirm the regulated isolation tier on your kernel/workloads |
| Optional **explicit IT-approval gate** on promote | Human-in-the-loop production sign-off |
| **Firecracker microVM tier** | Only if your security team requires VM-level per-beam isolation (see §8) |

---

## 8. Decisions we need from IT 🔵

These are open and directly shape priorities — your answers turn into stories:

1. **Isolation model sign-off.** Is *hardened Docker (default) + gVisor tier*
   acceptable, with the residual shared-kernel risk documented in
   `docs/threat-model.md`? Or does policy require **VM-level isolation per beam**
   (the Firecracker tier — a larger build)? *This is the gating decision.*
2. **Identity provider.** ✅ Both paths now exist: **bring-your-own OIDC**
   (`docs/idp-setup.md`) and a **bundled Keycloak** for evaluation
   (`packaging/keycloak/`). Decision for *your* rollout: evaluate on the bundled
   IdP first, then point at your corporate IdP for production — or wire your own
   from day one.
3. **Promotion governance.** ✅ Both modes now exist: scope/role-gated direct
   promote, or the **explicit IT-approval gate** (`BEAMHALL_PROMOTE_APPROVAL=on`)
   where an agent requests and a different IT operator approves (four-eyes).
   Decision for your rollout: gate on or off (recommend **on** for regulated).
4. **Egress.** Ship fully isolated (default-deny) for the proving run, or is a
   **per-workspace allowlist to an internal API** needed on day one?
5. **Preview auto-pause window.** Default is 8h, IT-overridable per workspace —
   confirm or adjust.
6. **Air-gapped?** ✅ Supported: offline image mirroring for the build pipeline
   (`docs/air-gapped.md`) + an internal IdP for JWKS. Decision: confirm your
   internal package mirror (npm/pip) for beam dependencies, which is operator-side.

---

## 9. Where to go deeper

- `docs/threat-model.md` — trust boundaries, hardening profile, the
  "agent cannot" proofs, CIS Docker mapping, residual-risk statement.
- `demo/README.md` — the end-to-end demo you can run yourself.
- `docs/PLAN.md` — the full design contract and phased plan.
- `packaging/README.md` — binaries, systemd install, and VM image baking.
