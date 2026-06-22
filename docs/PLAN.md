# Beamhall — Evaluation, Architecture & MVP Development Plan

## Context

`beamhall_business_idea_mvp.md` proposes **Beamhall**: a self-hosted, MCP-controlled infrastructure backplane that lets AI coding agents (Claude Code first) safely create and deploy internal beams inside a company-controlled environment, *without* handing the agent raw Docker/Kubernetes/cloud/database credentials. The agent speaks only high-level intents (`create_beam`, `deploy_beam`, `set_secret`, …) through an MCP server; a Go backplane enforces policy and provisions resources.

This document is the output of a structured evaluation: 3 web-research agents verified the 2026 landscape (competitors, MCP ecosystem, secure-execution options), 4 design agents specified the stack/architecture/security/scope against the locked decisions, and an adversarial agent critiqued viability. It records **what to build, with which technologies, on which systems, and in what order**, plus an honest read on the risks. The repo is greenfield — only the brief exists today; everything below is to be created.

**Intended outcome:** a funded 2–4 person team can use this as the blueprint to ship a pilot-ready MVP whose single job is to *prove the thesis* — an AI agent safely builds, deploys, and promotes a real internal beam under IT governance with zero raw credentials reaching the agent — to a design-partner customer.

**Product vision (expanded, 2026).** Beamhall is best framed as an **application backplane that agent-built apps *inherit their infrastructure from*** — not merely a credential proxy. A beam inherits, as managed capabilities: **compute** (hardened runtime), **data + secrets** (managed Postgres, the `age` vault), **networking** (gateway routing, default-deny egress) — and, on the **near-term roadmap**, **identity** (apps inherit Beamhall's IdP configuration, so end-user auth works with zero setup) and **connectors** (a brokered, governed path from a beam to internal systems — ERP databases, integrations — without the beam ever holding their credentials). Two framing pillars reinforce the wedge:

- **A reliable path, not improvised infra.** Beamhall gives the agent one documented tool surface + a built-in knowledge base, so it deploys the same governed way every time instead of improvising GitHub Actions / Fly.io / Neon / guessed Dockerfiles. Determinism and self-containment are the value, and the knowledge base is what makes the agent *competent on Beamhall* rather than guessing from training data.
- **IT controls placement.** IT picks the substrate per workspace — private VM, dedicated VPC, or fully on-prem — for compliance or strictly-internal access; the single-ingress + default-deny model means no security group / load balancer can be misconfigured into accidental exposure.

"No raw credential reaches the agent" remains true, but is a **consequence** of the inherited-capability model, not the headline. Identity inheritance and connectors are tracked as the next capability expansions (§6/§10), behind the same MCP-contract + `RuntimeDriver` seams.

---

## 1. Evaluation & verdict

**Verdict: Go, with caveats — and the caveats are the work.** The product category is real: MCP *gateways* (TrueFoundry, Tyk, MintMCP) only gate *access to existing services*; self-hosted PaaS (Coolify ~50k★, Dokploy ~26k★) deploys beams but has **no MCP, no agent control, no per-team isolation/governance**; AI beam builders (Lovable, v0, Bolt, Replit) generate code but won't deploy into a customer-governed, isolated runtime. **Nobody combines agent-governed provisioning + IT isolation + self-hosting.** Closest competitor is Cursor's 2026 self-hosted agents — but that's a code-editor add-on with thin team permissions, not an infra backplane. The gap is genuine.

**Whether you can build it is not the risk. Two things are:**

- **Riskiest assumption (market):** that "IT can't safely give departments credentials, so they'll *buy a governance backplane*" is an **urgent, budgeted** pain — not a latent one. IT's default answer to "departments want to ship AI-built beams" is often *"no"* or *"file a ticket."* Beamhall only wins where a buyer is *actively trying to say yes* and is blocked **solely** on the infrastructure-credential problem. **De-risk this with a signed design-partner LOI before heavy build.**
- **Riskiest assumption (security/positioning):** the core promise — "safely run untrusted AI-generated code on the customer's network" — is **structurally hard to deliver on shared-kernel hardened Docker** to the strictest buyer. See §3.

**The wedge (what proves the thesis):** one Claude Code session over remote OAuth MCP drives `create_beam → create_database → set_secret → deploy_beam (preview) → promote_to_live (stable URL)` for **one** beam (an internal Request Tracker), every action audited. The load-bearing demo is **not** "agent deploys a beam" (Coolify + a 200-line MCP wrapper does that in a weekend). It is the **negative security proof**, run live: the agent provably (a) never receives Docker/Postgres/MinIO/cloud creds, (b) cannot read a secret back, (c) cannot weaken the Beamhall's security baseline, (d) cannot reach the control plane or another Beamhall (default-deny egress), (e) and every attempt is in the audit log. **That negative test is the product.** Everything else is scaffolding for it.

**Scope-creep is the primary failure mode.** Building the full resource catalog (Postgres + MinIO + queues + jobs + metrics + a second runtime driver) before the thesis is validated produces "a worse Coolify" and burns the runway. Hold the line in §6.

---

## 2. Locked decisions (inputs to this plan)

| # | Decision | Choice |
|---|----------|--------|
| 1 | Implementation language | **Go**, single-binary appliance (`beamhalld`) |
| 2 | Ambition | Funded 2–4 person team, **pilot-ready production-grade** MVP |
| 3 | Runtime hardening | **Hardened Docker baseline** — userns-remap, runc 1.2.8+, cap-drop ALL, seccomp + AppArmor, read-only rootfs, no-new-privileges, cgroup v2, default-deny egress, per-Beamhall networks |
| 4 | AI target & transport | **Claude Code first**, remote MCP over **Streamable HTTP + OAuth 2.1** |
| 5 | Runtime breadth | **Docker only** in MVP, behind a `RuntimeDriver` interface so Kubernetes slots in later without touching the MCP contract |
| 6 | First buyer | **Regulated (healthcare/finance/gov)** — see §3 tension |
| 7 | IdP strategy | **Bundle Keycloak 26.4+, but validate *any* OIDC** (IdP-agnostic token validation; customer Okta/Entra/Keycloak pluggable by config). **Bundled IdP is persistent** (survives reboots/long eval gaps) and **administrable over MCP** for the owned IdP only — *authentication* agnostic, *administration* owned-IdP-only behind the `identityadmin` seam (§5.9). |
| 8 | Secret backend | **`age` envelope encryption** in-appliance (root key unsealed via systemd `LoadCredential`/KMS/TPM); Vault documented as enterprise upgrade |

---

## 3. The regulated-buyer ⇄ shared-kernel tension (resolve explicitly)

You chose a **regulated first buyer** *and* **hardened shared-kernel Docker** (decision #3). These are in tension: hardened Docker raises the bar to roughly "kernel 0-day required," but it is **not a hardware/VM isolation boundary** — a namespace/cgroup-syscall kernel exploit can still cross it, and a regulated security review may reject shared-kernel isolation for *untrusted* AI-generated code outright. The critique named this a potential extinction-level positioning landmine (one breach at a regulated partner sinks a 2–4 person company).

**Decision (resolved): ship gVisor (`runsc`) as the regulated isolation tier on the one Docker driver; design the `RuntimeDriver` seam so a Firecracker driver is a clean *future* expansion — but do not build Firecracker for the MVP.** A verified 2026 comparison backs this on every load-bearing point:

1. **`runtime_class` is a first-class field on `SecurityContext`.** Default `runc` (hardened Docker, proving demo); **gVisor (`runsc`)** is the selectable regulated tier. Enabling it is **one field**, not a second driver: register `runsc` in `/etc/docker/daemon.json` (`runsc install`) and set `HostConfig.Runtime = "runsc"` when `runtime_class == "runsc"`. The `docker/docker` Go SDK, dockerd, OCI images/overlayfs, per-Beamhall bridge + `DOCKER-USER` egress, `docker pause`, and `/run/secrets` bind-mounts are **all untouched**. It runs in userspace — **no KVM, install-anywhere preserved** — and is a real isolation upgrade (userspace syscall interception) without microVM orchestration.
2. **Firecracker is explicitly out of MVP, kept as a Phase-2 *funded* driver behind the `RuntimeDriver` seam (§5.3).** It is **not** a Docker `--runtime`; the realistic 2026 path is containerd + Kata (or pre-GA firecracker-containerd) — a **full second driver on the containerd client**, plus a hard **`/dev/kvm` + nested-virt** host requirement that breaks the single-customer-VM appliance promise, plus re-plumbed TAP/CNI networking + egress, a rootfs/guest-kernel supply chain, virtio-fs secrets, and immature VM snapshot/restore for the pause model. **~10–20× the build effort** (gVisor ≈ 1–3 weeks elapsed incl. validation; Firecracker ≈ 2–4+ engineer-months to pilot grade) **plus a permanent ops tax** (guest-kernel CVEs, Kata/containerd skew, a second runtime to operate). The seam makes adding it later cheap; building it now is the exact scope-creep this plan warns against. It also **partly inverts the selling point** — userns-remap disappears, seccomp/AppArmor/cap-drop move in-guest, cgroups apply to the VMM — so the `docker inspect`-auditable baseline (§11) would have to be rebuilt as VM-level + in-guest checks.
3. **Decision rule for ever building Firecracker:** only if the design partner's security review delivers a **written** demand for a per-workload hardware-virtualization boundary that **explicitly rejects gVisor's userspace-kernel model**, *and* they run on KVM-capable hardware. *Hardware note (current):* nested virt is **no longer AWS-bare-metal-only** — it runs on virtual **C8i/M8i/R8i** and certain GCP/Azure SKUs; on-prem hypervisors usually have it **off by default**. So Firecracker means "qualify specific hardware," not "impossible on cloud." Absent that written sentence, gVisor stands.
4. **Phase-0 gate (non-negotiable, before orchestration code):** (a) get the regulated partner's **written sign-off** that hardened-Docker-default + gVisor-tier is acceptable; (b) prove the **actual Paketo Node/Python runtime images** survive the full hardening stack under **both `runc` and `runsc`** — not a hello-world. gVisor's "image just runs" is real but not free: ~74/351 syscalls unsupported, `io_uring` off by default, `/proc` edge cases, and `runsc` **netstack mode** (not host passthrough) must be configured for the always-deny-metadata egress test to bite (some beams need `--net-raw`/`--allow-packet-socket-write`). Put these on the Phase-0 checklist explicitly.
5. **Sales narrative:** lead with the negative-security proof + the honest threat-model doc (residual shared-kernel risk stated plainly; gVisor as the stronger tier; Firecracker named as the documented upgrade path). For the IT/security buyer, honesty is a sales asset.

> Net: this **firms** locked decision #3 — hardened Docker (`runc`) default + gVisor (`runsc`) regulated tier, both on the single Docker driver — and keeps Firecracker as a seam-compatible, separately-funded *future* driver, not MVP scope.

---

## 4. Technology stack (recommended)

| Concern | Choice | Why / alternative rejected |
|---|---|---|
| HTTP layer + layout | **stdlib `net/http` + `go-chi/chi/v5`**, domain-oriented `internal/` packages | `http.Handler`-native, composes cleanly with the MCP SDK handler + Caddy. echo/gin impose a custom `Context` that fights both. |
| MCP server | **official `github.com/modelcontextprotocol/go-sdk` (v1.6.1+)**, Streamable HTTP handler, **same binary** as backplane, separate `/mcp` listener | Spec conformance is the moat ("durable tool contract across Claude/Cursor/Windsurf"). `mark3labs/mcp-go` only as a throwaway spike. |
| Control-plane store | **embedded SQLite** (`modernc.org/sqlite`, pure-Go/CGO-free, WAL) + `sqlc` + embedded migrations | Zero extra process, trivial backup, clean static cross-compile. This is the appliance's *own* state — **beams still get real Postgres**. Postgres-for-control-plane only when HA/multi-node lands. |
| Container control | **`github.com/docker/docker/client`** against a **userns-remap** daemon, **runc 1.2.8+** | Direct, documented control path. Podman/containerd add ergonomics/rework cost for a small team. |
| Build (untrusted source) | **Cloud Native Buildpacks / Paketo via `pack`**, run in a **separate non-userns-remapped build context** (rootless BuildKit or a dedicated build daemon), publishing the pinned image to the appliance's internal registry — *no agent Dockerfile ever honored* | Auto-detect language, non-root build, CNCF audit backing, SBOM. Closes the malicious-build-instruction vector. **Lab-verified:** `pack build` cannot export to the userns-remapped *runtime* daemon (socket perm-denied) and `--network host` is forbidden under userns — builds must not run on the runtime daemon. See docs/lab-phase0-validation.md. |
| Gateway / TLS | **Caddy via Admin API**, on-demand TLS gated by an `ask` endpoint against backplane-known hosts | Imperative "create a route now" maps to the lifecycle; on-demand TLS fits ephemeral random preview hosts. The `ask` gate prevents ACME-abuse DoS. Custom `httputil.ReverseProxy` rejected (reimplements TLS automation). |
| Wildcard DNS/TLS | Three modes: (1) public DNS + ACME **DNS-01** wildcard; (2) internal DNS + private CA (`step-ca`/customer CA); (3) offline self-signed wildcard `.beamhall.internal` | Serves cloud, on-prem, and air-gapped regulated installs. |
| Beam database | **one shared Postgres 16, database-per-beam** + scoped role; creds backplane-held, file-injected | Isolation + clean teardown without Postgres-per-beam sprawl on one VM. |
| Object storage / queue | **MinIO** (bucket-per-beam) and **queue** — **FAST-FOLLOW, not MVP**. If/when queue: NATS JetStream, or **River-on-Postgres** (minimalist, reuses Postgres) | Canonical demo needs neither; defer to protect scope. |
| Secrets at rest | **`age` envelope encryption** in SQLite; root key via systemd `LoadCredential`/KMS/TPM. Inject **file-only at `/run/secrets/<key>`, never env** | Env leaks via `/proc`, `docker inspect`, logs are durable/unrecoverable. Vault = enterprise add-on, too heavy for MVP. |
| Identity | **Bundle Keycloak 26.4+**, fixed client creds (defer DCR/RFC 8707 until Keycloak 26.5); **validate any OIDC** (JWKS/iss/aud) so customer IdP plugs in | Turnkey sovereign default + BYO-IdP path. Beamhall **never builds an OAuth server** — it's a Resource Server only. |
| Admin UI | **Go `html/template` + htmx + Tailwind**, `go:embed`, same binary | Read-mostly IT console; no parallel React/Vite pipeline for a small team. SPA only if a business-user self-service portal is later sold. |
| Observability | Embedded-first: `prometheus/client_golang` + OTel SDK (OTLP off by default) + `slog` JSON; optional `--profile observability` (Grafana/Loki/Prometheus) and Falco runtime-security profile | Observable out of the box; regulated customers export to their own SIEM. |
| Packaging | **single static binary + systemd unit (hardened) + docker-compose dependency bundle + Packer-built VM image + preflight script**; GoReleaser | Collapses the "diverse customer environment" support risk for the pilot. |

---

## 5. Architecture

### 5.1 Single binary, internal packages
```
cmd/beamhalld/main.go
internal/mcp/        # go-sdk Streamable HTTP handler, tool registry, OAuth RS middleware, internal-assertion minting
internal/api/        # backplane HTTP API (the single Policy Enforcement Point)
internal/policy/     # authorize(): role/action matrix, quota checks, forbidden-action deny list
internal/domain/     # entities, value objects, Beam FSM (pure, no I/O)
internal/orch/       # reconciler, build pipeline, durable preview-pause scheduler
internal/driver/     # RuntimeDriver interface + dockerdriver (runc + runsc tiers); k8s later
internal/gateway/    # Caddy admin-API client, dynamic route table, ACME ask-gate
internal/resource/   # provisioners: postgres (MVP), object_store/queue (fast-follow)
internal/secret/     # age envelope encryption, file injection planner, log scrubber
internal/scm/        # managed per-beam git remote + post-receive build trigger
internal/store/      # SQLite control-plane store (sqlc)
internal/auth/       # IdP metadata, JWKS cache, membership/role store
internal/identityadmin/ # owned-IdP administration seam: Provider iface + Keycloak Admin-REST impl + Disabled (BYO-IdP)
internal/egress/     # policy -> iptables DOCKER-USER rules + always-deny set
internal/audit/      # hash-chained append-only log + SIEM export
internal/obs/        # OTel + Prometheus + slog
web/                 # templates + htmx + Tailwind (go:embed)
migrations/
```
**The three stable seams:** the high-level **MCP tool contract**, the **`RuntimeDriver` interface**, and the **`identityadmin.Provider` interface** (§5.9). All three let new clients, runtimes, and IdPs arrive later without breaking the product promise. The MCP layer is a thin OAuth-gated translation surface; **all** policy/orchestration lives in the backplane (so the Admin UI and any future client reuse the same enforcement).

### 5.2 Domain object model (spine)
```
Identity --< Membership >-- Beamhall          (M:N, role-scoped)
Beamhall 1--1 SecurityContext (immutable baseline; agent can never weaken)
Beamhall 1--* Beam / Resource / Secret / ScheduledJob
Beam      1--* Build      (immutable: source_ref, image_digest, sbom, cve_status)
Beam      1--* Release    (frozen tuple: image_digest + config + security_profile + secret_refs)
Beam      1--1 currentRelease (rollback flips this pointer; no rebuild)
Beam      1--* Route      (preview: random host regenerated each resume | live: stable host)
*        --* AuditEvent  (every state change + auth decision; hash-chained, append-only)
```
Key invariants: **`SecurityContext` is data, not code paths** — `{runtime_class, capabilities, seccomp, apparmor, read_only_rootfs, cgroup_limits, network_policy, egress_policy}` set by IT at creation, snapshotted into every Release, **immutable to the agent**. A `Release` is a `(image_digest, config, security_profile, secret_refs)` tuple → instant rollback. Secrets store **refs only** (values never in the metadata DB plaintext, never returned via MCP).

### 5.3 `RuntimeDriver` interface (the load-bearing seam)
```go
type RuntimeDriver interface {
    Name() string
    Capabilities() Capabilities // SupportsPause/Exec/Build

    Build(ctx, BuildRequest, progress chan<- Event) (BuildResult, error) // CNB/pack, non-root, no Dockerfile
    Deploy(ctx, DeploySpec) (Handle, error)  // create (not start) from pinned image digest
    Start(ctx, Handle) error
    Pause(ctx, Handle) error  // preview auto-pause / pause_preview (docker pause; k8s=scale-to-0)
    Resume(ctx, Handle) error
    Stop(ctx, Handle, grace time.Duration) error
    Destroy(ctx, Handle) error
    Logs(ctx, Handle, LogOptions) (io.ReadCloser, error)
    Stats(ctx, Handle) (Stats, error)
    Status(ctx, Handle) (Status, error) // returns BackendAddr for gateway registration
    Exec(ctx, Handle, cmd []string, ExecStreams) (int, error) // capability-gated, audited, off by default
}
```
`DeploySpec` carries `Network` (per-Beamhall bridge + egress), `Security` (incl. `runtime_class` → `runc`|`runsc`), `Resources` (cgroup v2), `SecretMounts` (→ `/run/secrets/`), `Bindings` (db/store/queue conn refs). Nothing here mentions MCP — the contract is decoupled. **k8s mapping later:** Deploy=Deployment(replicas:0)+Service, Start=scale-1, Pause/Stop=scale-0, Destroy=delete.

### 5.4 Beam lifecycle (FSM)
`Beam.State` tracks the **preview channel** (the workload the builder iterates on); it never leaves preview. `promote_to_live` adds a **separate live channel** (`LiveReleaseID`/`LiveState`) and flips `Mode` to `live` — the preview channel keeps running, so pause/resume/promote stay legal afterwards (see §5.8).
```
created --deploy_beam--> building --ok--> deployed --start--> running(preview; pause timer armed)
running --pause_timer/pause_preview--> paused --resume_preview--> running (NEW random route + re-armed timer)
running(preview) --promote_to_live--> running (Mode=live; ADDS pinned live channel; preview keeps running)
running/paused --deploy_beam(new source)--> building (new preview Release; old retained)
Mode=live --rollback(prev live)--> (re-pin live channel to a prior live Release, no rebuild; preview untouched)
* --build_fail/start_fail--> failed --deploy_beam--> ...
```
`rolled_back`/`superseded` are *Release* statuses, not Beam states — keeps the FSM small and "roll forward" trivial. The orchestrator is a **reconciler** driving each channel's `current_release → desired_release`, emitting an AuditEvent per transition.

### 5.5 Source ingestion — **Beamhall-managed per-beam Git remote**
`create_beam` provisions a managed repo (`go-git`/embedded) at `https://<base>/git/<beamhall>/<beam>.git` with a `post-receive` hook. `deploy_beam` returns a **one-time, short-TTL deploy token + remote URL**; Claude Code `git push`es source over HTTPS (idempotent, resumable, gives a commit SHA = immutable `Build.source_ref`). A **tarball-over-MCP fallback** (`source_tarball`, ≤~8 MB) covers tiny/no-VCS cases — both converge to a commit SHA. `post-receive` → `Build{queued}` → `driver.Build()` (`pack`, non-root) → SBOM + CVE scan → `Release` → `Deploy`/`Start` → gateway register. **Progress streams to Claude Code over Streamable-HTTP SSE; cancel via MCP `CancelledNotification` → `context` cancel.** The agent's deploy token scopes to **one beam's repo** — never Docker/registry/DB creds. *(Status: implemented — managed-git smart-HTTP push + one-time deploy tokens (`internal/gitserver`) is the **default** path (`deploy_beam` with no source returns the `git push` remote); the tarball transport is the **fallback**; SSE progress + cancel both done. All converge on the same BuildFromDir.)*

**Beamhall hosts the source (clone enabled).** The managed per-beam repo is also **cloneable** — the git server serves `upload-pack` (read) next to `receive-pack` (push), and the `get_repo` tool mints a one-time, read-only, beam-scoped clone token + `git clone` command. So a beam's code lives in Beamhall like its DB/secrets do; a developer (or the agent on a fresh machine) restores/syncs via `get_repo` → `git clone`, with no external git host required. Token kinds are distinct (push = one-time/15m, read = reusable-within-TTL/1h; neither crosses to the other operation). **Consequence:** the repos volume is now **canonical source**, so it carries the same backup/DR + quota obligations as Postgres data. A browsable web git host (Gitea/Forgejo) is intentionally out of scope — add only if the product needs humans browsing code/branches/PRs in a UI.

### 5.6 Gateway & the continuous-runtime pause timer
- **Live** = stable `https://<beam>.<beamhall>.<base>`; redeploy swaps backend addr atomically (zero-downtime). **Preview** = `https://<random>.preview.<base>`; `random_token` regenerated on **every** `resume_preview`, prior preview route retired immediately.
- The **orchestrator is the single route writer** (push-based `gateway.Upsert/Retire`), table rebuilt from persisted Routes on restart — no discovery scraping.
- **Pause timer is wall-clock continuous-runtime, not idle** (per the brief). On resume/start set `resumed_at = now`, schedule deadline `resumed_at + Y` in a **durable timer wheel persisted to the store** that **reconciles on boot** (must not run previews forever after a reboot, nor pause everything on boot). Deadline → `EvPauseTimer` → `driver.Pause()` → retire route. Live beams never arm it.

### 5.7 MCP tool → backplane → effect (every call: validate OAuth aud/iss/scope + membership → AuditEvent)
| Tool | Scope | Backplane op | Driver/resource effect |
|---|---|---|---|
| `create_beam` | beams:write | Beam.Create (quota/slug) | provision managed git repo |
| `deploy_beam` | beams:deploy | Build→Release→reconcile | Build(pack)→Deploy→Start; gateway.Upsert; SSE progress |
| `create_database` | resources:write | Resource.Provision(postgres) | db+scoped role; Secret(conn) created |
| `set_secret` | secrets:write | Secret.Put (write-only) | age-encrypt; mounted `/run/secrets` next deploy |
| `show_logs` | logs:read | LogStream.Query/tail | driver.Logs (SSE) — **scrubbed** |
| `show_metrics` | metrics:read | Metrics.Get | driver.Stats |
| `pause_preview`/`resume_preview` | beams:operate | Beam.Pause/Resume | driver.Pause/Resume; route retire / new random host |
| `promote_to_live` | beams:promote (IT) | Beam.Promote: pin live channel to preview's build (slot on first promote) | reconcile live DB; spawn separate live workload; gateway stable host; preview untouched |
| `rollback` | beams:deploy | re-pin live channel to a prior live Release | driver.Deploy(prev digest); gateway swap (preview unaffected) |

`create_object_store` / `create_queue` exist in the contract but are **fast-follow** (return "not enabled in this build").

### 5.8 Dual-channel beams (preview + live) — iterate after shipping
A beam is **two long-lived channels**, not a single workload that flips mode:
- **Preview channel** — the builder's iterating deployment (`Beam.State` + `CurrentReleaseID`, stable random preview host, auto-pauses on idle). Every `deploy_beam`/`git push` redeploys *this*. It never goes away.
- **Live channel** — the pinned production deployment (`Beam.LiveReleaseID` + `LiveState`, stable `<beam>.<beamhall>` host, never pauses). Exists only after the first promote.

**`promote_to_live` pins the live channel to the build the preview is running right now** (reuses the preview Release's image digest into a new live Release; brings up a *separate* live workload behind the stable host) and **leaves the preview running**. This is the answer to "how do I test a new version after production exists": keep pushing to preview, then promote again. Promote is **repeatable and zero-downtime** — the previous live workload serves until the new one is healthy; the stable hostname is repointed via `gateway.Upsert`; a **failed promote leaves production untouched** (first promote reverts its reserved slot). `rollback` re-pins live to a prior live Release; the preview channel is unaffected (to undo a preview change, just push again).

**Data isolation (the safety property):** each channel gets its **own database**. `create_database` provisions the *preview* DB; promote **reconciles** a fresh, empty live DB for each preview DB (backing name `bh_<hall>_<slug>-live_<name>`, distinct from preview's) and seals its DSN under the **same app key** (e.g. `MAIN_URL`, channel-scoped). So the *same image* connects to preview data in preview and production data in live — iterating in preview can never read or corrupt production. Re-promote reuses the existing live DB (production data persists across version bumps). User/beamhall secrets are `ChannelShared` (injected into both); only DB connection secrets are channel-specific. **Quota:** the live DB is a logical mirror of an already-counted preview DB, so it does **not** additionally count against `MaxDBCount` (`CountResourcesByBeamhallAndType` excludes `channel='live'`); the live-slot limit still gates how many beams can have a live channel. Decided with the operator 2026-06-16. Implementation: `internal/orch/livechannel.go`, migration `0007_dual_channel.sql`.

### 5.9 Admin lifecycle over MCP + the owned-IdP administration seam (third stable seam)

The operator should manage the appliance through the **same MCP channel** that drives beams — onboarding, identities, IdP administration (and, on the roadmap, backups / DB maintenance / upgrades) — not a separate web console. This is on-thesis ("MCP-controlled infrastructure backplane"). Two pieces make it clean:

**The `admin_*` tool family (admin:it).** IT-structural ops (`admin_register_identity`, `admin_grant_membership`, `admin_create_beamhall`, `admin_list_identities`) and owned-IdP ops (`admin_create_user`/`list_users`/`set_user_password`/`create_group`/`list_groups`/`add_user_to_group`/`federate_directory`) are exposed over MCP as a **thin client over the orchestrator** — the same PEP and audit chain the Admin console uses (§5.1: all enforcement in the backplane). `admin:it` is deliberately kept **off** the agent scope advertisement (`auth.AllScopes`) and granted out-of-band, so a builder token can never reach these tools. Routing IT actions through the orchestrator means every one audits against a known identity (PLAN §6) — the same promise as agent actions.

**The third stable seam: `identityadmin.Provider`** (mirrors `RuntimeDriver`). Administering an IdP is inherently IdP-specific, but it must not compromise the IdP-agnostic story. So: *authentication* validates any OIDC token (`internal/auth`); *administration* is offered **only for the IdP Beamhall owns** (the bundled Keycloak), behind the Provider seam — a Keycloak Admin-REST impl for the bundled IdP, a `Disabled` impl for **bring-your-own-IdP** (Beamhall does not administer a corporate directory it doesn't own; the customer manages users in their own IdP). Beamhall holds the IdP admin credential (a confidential service-account client, `beamhall-idp-admin` with `realm-admin`); the agent never does — the same "no raw credential reaches the agent" model applied to IdP admin. Tools are **intent-shaped** (`create_user`, `federate_directory`), never a raw Keycloak passthrough, so the stable MCP contract never leaks Keycloak and a future owned-IdP swap leaves the tool surface unchanged.

**Risk tiering (the guardrail decision, 2026-06-21).** Routine onboarding ops (create user, set a temporary password, create/join groups, register identity, grant membership) run **autonomously** and are audited. **Sensitive auth-config** — `admin_federate_directory` (it changes who can sign in to the whole appliance), and later restores/upgrades — goes through a **four-eyes approval flow** (built; see below). The master switch `BEAMHALL_IDP_SENSITIVE_ADMIN` governs whether sensitive actions can be requested at all (off ⇒ fail closed). **Self-upgrade is special** (the control plane modifying the binary that enforces policy) and gets the most care when it lands — atomic apply + rollback + confirmation, never "just another autonomous tool."

**Four-eyes flow for the sensitive tier (built; mirrors promotion approval).** A sensitive action is never executed by the requesting operator. `admin_federate_directory` **files a pending request** (`admin_action_requests`, migration `0010`; generic `action_type`, so restore/upgrade reuse it); a **different** IT operator runs `admin_approve_request` (separation of duties — the requester cannot approve their own), at which point the backplane **executes the stored intent** and records the result. `admin_reject_request` discards it; `admin_list_pending_requests` shows what's waiting. On execution failure the request stays pending (retryable). The request payload can carry a secret (the LDAP **bind credential**), so it is **vault-sealed at rest** (age, via `Vault.Seal`/`Open`) — only a non-secret `summary` is shown in listings; the credential round-trips sealed and is opened only at execution. Orchestrator: `RequestFederateDirectory`/`ApproveAdminAction`/`RejectAdminAction`/`ListPendingAdminActions` + an `executeAdminAction` dispatcher; all IT-gated and audited (`admin_request_*`/`admin_approve_*`/`admin_reject_*`).

**Blast-radius note.** An admin agent that can create identities and grant memberships *can manufacture access* — `admin:it` is a master key. Mitigations are part of the design, not later polish: admin:it strictly out-of-band, every admin tool audited, sensitive mutations gated on human confirmation. Implementation: `internal/identityadmin`, `internal/orch/identityadmin.go`, `internal/mcp/admin.go`; operator guide `docs/admin-over-mcp.md`.

---

## 6. Security & policy model (the purchase reason)

- **Token validation at MCP (authN only); authorization in the backplane (the single PEP).** MCP validates JWT signature (JWKS), `iss` (RFC 9207), `aud` == Beamhall resource URI (blocks confused-deputy), `exp/nbf`, and **`Origin`** (DNS-rebinding), then forwards a **signed internal identity assertion** (short-lived, key shared only MCP↔backplane — rotate it, network-isolate it). *(Status: with MCP and backplane in one process the "assertion" is an in-process Actor struct — no network hop to protect; the signed form becomes real only if the MCP front end ever splits out.)* The backplane resolves `Membership` → role, checks quota/status/immutable-context, mints/binds real creds, audits. **Scopes are coarse capability classes** (`beamhalls:read`, `beams:deploy`, `secrets:write`, `beams:promote`, `admin:it`); fine-grained "which Beamhall" is **data-driven** in the backplane (tokens can't encode every membership or revoke promptly). 403 `insufficient_scope` triggers Claude Code step-up.
- **Agent never receives raw credentials.** Tools return **handles/intents** only (`create_database` → logical DSN alias + injection plan, never user/pass/host). Backplane mints the Postgres role, age-encrypts it, file-injects at runtime; agent code reads `/run/secrets/db.primary` *inside the container* — Claude Code and the MCP transport never see it.
- **Per-Beamhall isolation:** one Docker bridge per Beamhall (`bh-<id>`), no cross-bridge routing; db-per-beam scoped roles; per-beam MinIO keys (fast-follow); secrets beam-scoped; **nothing crosses a boundary by default**.
- **Secrets lifecycle:** `set_secret` write-only (no `get_secret` tool); age envelope encryption at rest; **file injection only, never env**; `show_logs`/`show_metrics` pass a **backplane-side scrubber** (known-value match + entropy/JWT/key/PEM heuristics) **before** bytes reach MCP. Every write + injection audited (not the value).
- **Egress: default-deny.** Per-Beamhall DOCKER-USER `DROP` except an IT-only allowlist (FQDN/CIDR:port). **Always-deny** to `169.254.169.254`, link-local, host IP, and the management subnet — independent of the allowlist (SSRF/metadata defense). iptables (nftables still experimental in 2026). Agents can't change egress.
- **Audit: two-layer, correlated.** MCP intent log (tool, args-redacted, principal, decision) + backplane mutation log (before/after, result), correlated by `request_id`; **hash-chained append-only** table (tamper-evident) + syslog/JSON export to SIEM. Falco rules feed the same pipeline.
- **Audit retention (bounded growth, integrity preserved).** The chain is append-only, so old events are removed via a **checkpoint-anchored prune**: a prune records the seq it cut through + the chain hash at that point (`audit_checkpoints`, migration `0009`), deletes through it, and `Verify` resumes from the latest checkpoint instead of genesis — so the surviving chain stays tamper-evident AND any deletion *not* recorded by a checkpoint still trips Verify's seq-gap/prev_hash checks. The checkpoint row is the audit record of the prune (when/who/how many) — deliberately not a chain event, so KeepLast stays exact and re-pruning is idempotent (its count/by/at fields are informational, not hash-sealed). Invocation: `beamhalld admin prune-audit -keep-days N|-keep N [-dry-run]` (operator/cron) and an opt-in `BEAMHALL_AUDIT_RETENTION_DAYS` the daemon enforces on boot + daily. **No SIEM export in this build** (the `Export(afterSeq)` seam exists for it later) — pruned events are gone, so size the window to the compliance story. The Admin audit page shows a "pruned through seq X on DATE" banner.
- **Quotas/policy (IT-set, immutable to agents):** `max_beams`, `max_live_slots` (the commercial unit), cpu/mem/disk/pids cgroup ceilings, `max_db_size`. Rate-limit deploy/build (`429`), cap concurrent builds (build-bomb defense). Hard-deny regardless of role: read secrets, mutate security-context/quota/egress, touch another Beamhall, raw runtime access, agent-supplied Dockerfile, oversized args.

**Threat model (attack → MVP mitigation → deferred):** exfiltration→default-deny egress/always-deny metadata→L7 egress proxy; **container escape→hardened baseline + `runsc` tier for regulated→Firecracker microVM**; secret theft→file-only+scrubber+write-only→HSM/leases; lateral movement→per-Beamhall bridge+db-per-beam→mTLS mesh; resource exhaustion→cgroup v2+quotas+build limits+auto-pause→fair-share scheduling; malicious args→strict schemas+caps→prompt-injection detection; supply-chain→CNB-only+pinned builders+CVE-gate-before-promote→full SLSA; SSRF→always-deny metadata/host→L7 proxy. **Honesty rule:** the customer threat-model doc states the shared-kernel residual risk plainly and names `runsc`/Firecracker as the upgrade path.

---

## 7. MVP scope (defend the line)

**A) MUST-HAVE (proves the thesis):** single-binary appliance; remote Streamable-HTTP MCP (official go-sdk) + OAuth RS; bundled Keycloak + IdP-agnostic validation; object model with **immutable `SecurityContext` (incl. `runtime_class`)**; tools `create_beam, create_database, set_secret, deploy_beam, show_logs, pause_preview, resume_preview, promote_to_live`; **full hardening baseline** (userns-remap, runc 1.2.8+, cap-drop, seccomp/AppArmor, ro-rootfs, no-new-privs, cgroup v2, per-Beamhall bridge, DOCKER-USER default-deny) **+ `runsc` tier available**; Caddy gateway (random preview / stable live, ask-gated TLS); durable continuous-runtime pause scheduler; CNB/`pack` builds (no Dockerfile) with SSE progress; age secrets (file-injected); **hash-chained audit**; thin read-mostly Admin UI + IT actions; install preflight (cgroup v2, subuid/subgid, kernel, runc, port).

**B) FAST-FOLLOW (post-MVP, gated behind a *signed* pilot expansion):** `create_object_store` (MinIO); `create_queue` + worker; `rollback`; metrics beyond health; scheduled jobs; SBOM/CVE **gate** at promote; step-up re-auth UX polish; Cursor/Windsurf verification; backplane HA + backup/restore productization.

**C) EXPLICITLY OUT:** Kubernetes/Nomad/cloud drivers (define interface, ship Docker only); multi-cloud; DCR/RFC 7591; building an OAuth server; **Firecracker microVM orchestration** (gVisor `runsc` is the regulated answer, not Firecracker — unless Phase-0 review demands it as a funded expansion); connector marketplace; per-call billing; complex preview/live permission matrix; managed hosting / model provision; nftables; rootless Docker (userns-remap preferred for the appliance); OPA/Rego policy DSL (fixed code paths in MVP).

### Supported-systems matrix (launch)
| Dimension | Supported |
|---|---|
| Host OS | **Ubuntu 24.04 LTS** (primary), Debian 12 (secondary); RHEL 8.5+ fast-follow |
| Min specs | 4 vCPU / 8 GB / 60 GB SSD; **8 vCPU / 16 GB recommended** for a pilot department |
| Kernel / cgroup | Linux ≥ 5.2, **cgroup v2 required** (preflight-verified; avoids CVE-2022-0492) |
| Docker | 27.x, **userns-remap**, **runc 1.2.8+**; **gVisor `runsc`** registered for the regulated tier |
| AI client | **Claude Code only "supported"** (tested `claude mcp add --transport http …`, in-session OAuth, refresh on long ops, 403→re-auth). Cursor/Windsurf best-effort |
| Beam runtimes (CNB) | **Node.js, Python, static** at launch; Go fast-follow |
| Beam DB | **PostgreSQL 16** |
| Object store / queue | **fast-follow** (not at launch) |
| Admin UI | evergreen Chrome/Edge/Firefox/Safari (latest 2) |
| Network | one inbound HTTPS port; wildcard DNS+TLS for `*.preview.<domain>` / `*.<beamhall>.<domain>` |

### Canonical demo — Internal Request Tracker (DB + secret + logs + preview→live, no queue/store)
IT creates an "Operations" Beamhall (web-app hardening profile, default-deny egress, 1 live slot) and registers the builder with `beams:deploy + secrets:write` (**not** `beams:promote`). Builder: `claude mcp add --transport http beamhall https://beamhall.acme.internal/mcp` → in-session OAuth. Builder prompts Claude Code to build a request tracker → agent calls `create_beam → create_database → set_secret → deploy_beam` (preview, random URL, SSE build progress) → `show_logs` confirms a DB write. Builder requests promotion → **`promote_to_live` returns 403** (governance shown). IT reviews the audit log → runs `promote_to_live` → stable URL, slot consumed. An idle preview **auto-pauses after Y hours**; `resume_preview` → **new random URL**. **Money shot:** builder asks the agent to print the DB password / read egress rules / loosen seccomp → no tool to read secrets, no raw creds, baseline immutable, outbound call **dropped** — shown live.

---

## 8. Development plan (phased; ~6 months, overlapping)

> **Hard rule (all 6 months):** if a week's work doesn't move toward the **signed pilot** or the **negative-security demo**, it's scope creep — cut it. Gate every FAST-FOLLOW item behind a signed expansion, never speculative build.

**Phase 0 — Validate + de-risk (Weeks 0–4, before orchestration code).**
- **Close a design-partner LOI.** Given the regulated buyer choice, **get the security team's written acceptance of the isolation model** (hardened Docker default + `runsc` tier; threat-model doc with residual-risk statement). *This gate decides whether the locked Docker decision survives or a Firecracker driver becomes a funded expansion.*
- Appliance baseline: preflight script (cgroup v2, subuid/subgid, kernel, runc 1.2.8+, port); userns-remap daemon config; **register + smoke-test gVisor `runsc`**; one `web-app` hardening template with *sane* defaults (writable tmpfs, NET_BIND_SERVICE).
- **De-risk the most-likely-impossible thing first:** prove ONE Paketo-built beam actually runs and survives the *full* hardening stack under both `runc` and `runsc`.
- Define `domain` entities + FSM and the `RuntimeDriver` interface + `SecurityContext` (incl. `runtime_class`).

**Phase 1 — Runtime + gateway + lifecycle (Weeks 4–10).** Docker driver (Build via `pack`, Deploy/Start/Pause/Resume/Stop/Destroy/Logs/Stats/Status; per-Beamhall bridge; secret file mounts; cgroup limits; `runtime_class` switch). Caddy gateway + **ask-gated** on-demand TLS + dynamic route table (random preview / stable live). **Durable preview-pause scheduler with crash-correct boot reconciliation.** **iptables DOCKER-USER egress reconciler that asserts state from policy on every change and on boot** (drift here silently breaks isolation *or* beams — non-trivial, mandatory).

**Phase 2 — MCP + OAuth + backplane PEP (Weeks 8–14).** Official go-sdk Streamable HTTP server (same binary). Bundle Keycloak; **IdP-agnostic token validation** (JWKS/iss/aud/exp/scope/Origin); RFC 9728 Protected Resource Metadata; fixed client creds (skip DCR/RFC 8707). **Backplane as single PEP** (role/action matrix, quota, forbidden-action deny list, internal-assertion minting + key rotation). **Hash-chained append-only audit.** The full happy path `create_beam→create_database→set_secret→deploy_beam→promote_to_live`. **SSE progress on build/deploy is non-negotiable** (so long builds don't look hung). Managed per-beam git remote + `post-receive` trigger. age secret store + injection planner + log scrubber.

**Phase 3 — Agent error UX + negative-security suite + Admin UI (Weeks 12–18).** **#1 underestimated item:** translate `EPERM`/egress-denied/build-failure into **actionable MCP responses the agent can self-correct from** (hardening *will* break naive AI beams: writes outside tmpfs, privileged ports, outbound pulls). Write the **negative-security test as an automated, demoable suite** (the 5 "the agent cannot" proofs). Thin Admin UI (Beamhalls/beams/state/history/logs/usage/audit + IT actions: create Beamhall, set baseline/egress, allocate slots). **Pin and continuously test against a known Claude Code version** (its OAuth behavior is a moving target). Transactional live-slot quota (no concurrent-promote race) + zero-downtime cutover.

**Phase 4 — Pilot (Weeks 16–24).** Run the Request Tracker against the real design partner; iterate on what actually breaks. Backup/restore of control store + secret root key. Deliver the **hardening/threat-model doc** (distro/kernel/cgroup/subuid setup, firewall rule, CIS Docker Benchmark mapping, residual-risk statement, `runsc`/Firecracker upgrade path). Validate the `runsc` tier in the pilot environment. Packer VM image + GoReleaser release.

### Hardest engineering problems (rank — staff accordingly)
1. **Making the hardening stack not break beams, and surfacing failures legibly** (Phase 3 — mostly product-in-error-messages, underestimated everywhere).
2. **Egress reconciler / DNS-allowlist leakiness** (FQDN allowlists race CDN TTLs; honest MVP answer is allow-by-CIDR or ship an L7 proxy fast-follow).
3. **Durable continuous-runtime pause scheduler with crash-correct boot semantics** (`docker pause` holds RAM — preview cost story differs from k8s scale-to-zero; `SupportsPause` must drive explicit orchestrator behavior).
4. **Untrusted buildpack builds on the shared VM** (build containers carry the hardening profile; hard CPU/mem/time limits; cancellation; a runaway build is a DoS on every department). **Lab-verified constraint:** the buildpack lifecycle cannot run on the userns-remapped runtime daemon (socket perm-denied; `--network host` forbidden under userns) — builds run in a separate non-remapped context and publish the pinned image to the internal registry, which the runtime daemon pulls and runs. See docs/lab-phase0-validation.md.
5. **OAuth audience binding without full RFC 8707 in 2026 IdPs** (enforce aud/iss/scope in MCP middleware; rotate + isolate the internal MCP↔backplane signing key).
6. **Transactional live-slot enforcement + zero-downtime cutover** (concurrent-promote race; in-flight request drops).
7. **Ask-gated on-demand TLS** (unbounded ACME issuance = DoS vector if ungated).

---

## 9. Initial files to create (greenfield)
- `cmd/beamhalld/main.go` — single-binary entrypoint (chi API + MCP `/mcp` + Admin UI + orchestrator).
- `internal/domain/entities.go` — Beamhall, Beam, Build, Release, Route, Resource, Secret, **SecurityContext (incl. `runtime_class`)**, Membership, AuditEvent + FSM (`func (a *Beam) Can(ev Event) (BeamState, bool, string)`).
- `internal/driver/driver.go` + `internal/driver/dockerdriver.go` — `RuntimeDriver` interface + Docker impl (hardening profile application, `runc`/`runsc`, per-Beamhall network, `/run/secrets` injection).
- `internal/orch/orchestrator.go` — reconciler, build pipeline, **durable preview-pause scheduler**.
- `internal/mcp/server.go` + `internal/mcp/tools.go` — go-sdk Streamable HTTP handler, OAuth RS middleware, tool→backplane mapping, SSE progress, `CancelledNotification`.
- `internal/policy/auth.go` — `authorize(principal, action, beamhall_id)`; 401/403; forbidden-action deny list.
- `internal/secret/age.go` + `internal/secret/scrubber.go` — envelope encryption, file injection, log scrubbing.
- `internal/egress/iptables.go` — policy→DOCKER-USER reconciler + always-deny set.
- `internal/gateway/router.go` — Caddy admin client, route table, ask-gated TLS.
- `internal/audit/log.go` — hash-chained append-only log + SIEM export.
- `internal/store/migrations/0001_init.sql` (go:embed'd next to the store package), `web/` (templates+htmx+Tailwind), `deploy/compose.yaml` (Postgres/Keycloak/Caddy/[+MinIO/NATS fast-follow]), `deploy/beamhalld.service`, `scripts/preflight.sh`, `packer/`.

---

## 10. Open questions (defaults chosen; confirm or override during the pilot)
- **Y (preview auto-pause hours):** default **8h**, IT-overridable per Beamhall. *(Confirm with partner.)*
- **`promote_to_live` human gate:** ~~optional explicit IT-approval gate config~~ **BUILT** (`BEAMHALL_PROMOTE_APPROVAL=on`, default off). When on, `promote_to_live` files a request a **different** IT operator approves (four-eyes) via `approve_promotion`/`reject_promotion`/`list_pending_promotions`. Lab-verified end-to-end. For the regulated pilot, recommend **on**.
- **Bundled vs customer IdP for the pilot:** ~~bundled Keycloak vs customer Okta/Entra day one~~ **the bundled path now scales to a real pilot** — it is **persistent** (named volume; realm seeded once; runtime users/groups survive reboots) and **administrable over MCP** (the `admin_*` family + the `identityadmin` seam, §5.9), so a multi-week/multi-month growing pilot can run on it and later **LDAP/AD-federate** via `admin_federate_directory` *without changing Beamhall's issuer* (Keycloak stays the issuer; only the federated subjects re-register). Customer-IdP-day-one remains supported (BYO-IdP ⇒ `identityadmin.Disabled`). See `docs/admin-over-mcp.md`.
- **Sensitive-admin approval flow:** ~~build the four-eyes pending-approval flow~~ **BUILT** (§5.9). `admin_federate_directory` files a request (`admin_action_requests`, migration `0010`) that a **different** IT operator approves (`admin_approve_request`) before it executes — separation of duties, in-band, not a config flag. `BEAMHALL_IDP_SENSITIVE_ADMIN` remains the master enable (off ⇒ not even requestable). Payloads are vault-sealed at rest (the LDAP bind credential never sits in cleartext). Generic by `action_type`, so future sensitive actions (restore, upgrade) reuse the same flow. Unit-tested at store/orch/MCP layers; **lab verification pending pilot.**
- **Egress in MUST-HAVE:** ship **fully isolated** for the proving run; **per-Beamhall allowlist** is fast-follow **unless** the pilot beam must hit an internal API on day one (then promote to MUST-HAVE).
- **Demo beam stack:** ~~recommend Python, or Node~~ **RESOLVED → Node** (`demo/beam-app`, Node + `pg`). The canonical Request Tracker is built and lab-verified end-to-end (`demo/`, driven by `cmd/bh-demo` + the new `beamhalld admin bootstrap`/`register-identity`). Gotcha: omit an `engines.node` pin — pinning a newer Node selects a binary that needs `libatomic.so.1`, absent from the Paketo jammy run image (`exit 127` on boot); the buildpack default Node works.
- **Air-gapped updates:** ~~define an offline-update story~~ **BUILT** for the Paketo builder/run images (`scripts/airgap-bundle.sh`/`airgap-load.sh` + `BEAMHALL_PACK_PULL_POLICY=if-not-present`/`BEAMHALL_CNB_RUN_IMAGE`; lab-verified — builds use the local builder, no re-pull). JWKS is moot with an internal IdP (bundled Keycloak / on-prem). CVE DBs N/A until image scanning ships. Beam package mirrors (npm/pip) are operator-side. See `docs/air-gapped.md`.
- **Admin-over-MCP client for `admin:it` (NEW, open — found in the 2026-06-21 pilot):** `claude mcp add` exposes no OAuth-scope flag and requests only the *advertised* scopes, and `admin:it` is hidden by design — so an IT admin's normal browser-OAuth connection cannot obtain it. Working today: the **Admin console**, or **MCP with a pre-minted `admin:it` token via `--header`** (the bundled realm has `admin:it` as an *optional* scope on `beamhall-agent`). A first-class **public admin-agent client** would be smoother but must gate `admin:it` behind a realm role (`beamhall-it`), since the MCP layer treats `admin:it` ⇒ ITAdmin — an ungated client would let any realm user manufacture admin. Decision needed: ship a role-gated admin client (and the role→scope mapper) vs. keep admin on the console + header-token path. See `docs/getting-started.md` Part 3B and `docs/lab-phase0-validation.md` (pilot section).

---

## 11. Verification (how to prove "MVP done")
End-to-end against a real VM (Ubuntu 24.04, userns-remap, runc 1.2.8+, cgroup v2):
1. **Functional:** `claude mcp add --transport http beamhall https://<host>/mcp` → OAuth completes against bundled Keycloak; token refresh survives a >5-min build. Drive the full Request Tracker happy path; confirm `deploy_beam` builds via Paketo with **no Dockerfile** and streams SSE progress; preview auto-pauses after Y and `resume_preview` yields a **new** URL; `promote_to_live` gives a stable URL and decrements the slot.
2. **Security (gating — pilot fails without these):** automated **negative-security suite** proving the 5 "the agent cannot" facts; `docker inspect` confirms userns-remap + cap-drop + seccomp + AppArmor + ro-rootfs + no-new-privs + cgroup v2 (and `runsc` when the Beamhall selects it); a beam's outbound internet call is **dropped** unless whitelisted; metadata/host/management egress denied even if whitelisted; builder gets **403** on `promote_to_live`; every call + auth decision present in the **hash-chained** audit log; preflight fails clearly on missing cgroup v2 / subuid / kernel / runc.
3. **Operability:** single-binary install + preflight on Ubuntu 24.04 & Debian 12; documented backup/restore of control store + secret root key; threat-model/hardening doc delivered; `RuntimeDriver` Docker impl present (proving k8s is addable without changing the MCP contract).

**Implementation status:** this is the design contract; for current progress (Phases 0–2 complete and lab-verified — runtime substrate, store, secret vault, audit chain, policy PEP, orchestrator, build pipeline, Postgres provisioner, and the MCP server + OAuth resource server, with a full-stack lab E2E of the §7 demo flow; Phases 0–3 complete and lab-verified — through agent error-UX diagnosis, the six-proof negative-security suite, rollback/destroy/show_metrics + build-bomb cap, the OIDC Admin console, and the git smart-HTTP push transport; Phase 4 = pilot + backup/restore + threat-model doc), the package layout, lab-VM access, and the resume guide, see **docs/STATUS.md**. Lab evidence is in **docs/lab-phase0-validation.md**.
