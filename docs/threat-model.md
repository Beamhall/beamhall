# Beamhall — Security & Threat Model

**Audience:** the IT/security team evaluating Beamhall for a regulated or
security-conscious environment. This document states what Beamhall defends, how,
and — explicitly — the residual risk it does not eliminate. The honesty here is
deliberate: it is the artifact a security team signs off on (PLAN §8 Phase 0
gate), and every mitigation below is exercised by an automated test (the
negative-security suite, `internal/e2e/TestAgentCannot`) or verified on the lab
appliance (`docs/lab-phase0-validation.md`).

Status: the entire MUST-HAVE security surface is built and lab-verified. The one
decision this document supports is whether **hardened-Docker default + the
gVisor (`runsc`) tier** is an acceptable isolation boundary for your workloads,
or whether you require a per-workload hardware-virtualization boundary (the
documented Firecracker upgrade path, §10).

---

## 1. What Beamhall is, in one paragraph

Beamhall lets an AI agent (Claude Code over MCP) build and deploy internal apps
("beams") inside infrastructure **you** control, **without any raw credential
ever reaching the agent**. The agent calls a fixed set of tools; the backplane —
not the agent — mints credentials, enforces policy, runs builds, and operates
the runtime. The agent's blast radius is, by construction, the set of tools it
is allowed to call, evaluated against a server-side policy it cannot influence.

## 2. Trust boundaries

```
  Claude Code (untrusted)
      │  Streamable HTTP + OAuth bearer token
      ▼
  ┌─────────────────────────────────────────────── beamhalld (single binary) ──┐
  │  MCP server  ──authN (validate JWT: iss/aud/exp/scope/Origin)──►            │
  │  Backplane / PEP  ── single authorization point + audit writer ──►          │
  │  Orchestrator ──► Docker driver (runc | runsc), Caddy gateway, age vault     │
  └──────────────────────────────────────────────────────────────────────────┘
      │ per-Beamhall bridge, DOCKER-USER egress, /run/secrets tmpfs
      ▼
  Workloads (untrusted: agent-authored code)
```

Two populations are **untrusted**: the AI agent, and the workload code it ships.
Everything inside `beamhalld` is the trust base. The security model is about
keeping both untrusted populations inside their boundary.

- **Token validation at the edge, authorization in the backplane.** The MCP
  layer validates the JWT only (signature via the IdP's JWKS, `iss`, `aud` ==
  the Beamhall resource URI to block confused-deputy, `exp`/`nbf`, and the
  `Origin` header against DNS rebinding). It then forwards an in-process
  identity to the backplane, which is the **single Policy Enforcement Point**:
  it resolves the caller's membership → role, checks quota/status, and either
  performs the effect or denies — recording every decision on the audit chain.
- **Scopes are coarse capability classes** (`beams:deploy`, `secrets:write`,
  `admin:it`, …). *Which* beamhall a caller may act in is data-driven in the
  backplane (membership), never encoded in the token — so a token cannot grant
  cross-beamhall access even with every scope.

## 3. Host baseline (operator responsibility)

Beamhall's guarantees assume the host is provisioned per `scripts/preflight.sh`
and `scripts/lab-bootstrap.sh`:

| Requirement | Why |
|---|---|
| Linux ≥ 5.2, **cgroup v2** | Resource ceilings; avoids CVE-2022-0492 (cgroup v1 release_agent escape) |
| Docker with **userns-remap = default** | Container root ≠ host root; a container UID 0 maps to an unprivileged host UID |
| **runc ≥ 1.2.8** | Fixes the runc/CVE class (e.g. CVE-2024-21626 fd leak) |
| **gVisor `runsc`** registered as a runtime | The regulated isolation tier (§5), selectable per beamhall |
| subuid/subgid ranges for `dockremap` | Backing store for userns-remap |
| One inbound HTTPS port; wildcard DNS/TLS | The gateway is the only ingress |

The appliance runs as a single VM/host the customer owns. Beamhall does not
require `/dev/kvm` or nested virtualization (that is only relevant to the
Firecracker upgrade path, §10).

## 4. The hardening baseline (every workload, every beamhall)

Each beam runs under an **immutable `SecurityContext`** chosen by IT at beamhall
creation and unchangeable by the agent. The `web-app` default template applies:

- **userns-remap** (container root is an unprivileged host user)
- **cap-drop ALL**, adding back only the narrow set a template needs
  (`NET_BIND_SERVICE` for web-app; `CHOWN`/`DAC_OVERRIDE` for data/db templates)
- **no-new-privileges** (no setuid escalation)
- **read-only root filesystem**, writable only at `/tmp` (tmpfs)
- **seccomp** default profile; **AppArmor** profile
- **cgroup v2** CPU/memory/PID ceilings (IT-set quota)
- **per-Beamhall Docker bridge** — one network per beamhall, nothing crosses it
- **DOCKER-USER egress default-deny** (§7)

This profile is `docker inspect`-auditable on the running container and is
re-asserted on every deploy. The negative-security suite proves the agent has no
tool that can weaken any of it.

## 5. Isolation tiers and the residual shared-kernel risk

Beamhall ships **two isolation tiers on one Docker driver**, selected per
beamhall by the `runtime_class` field:

- **`runc` (default, hardened Docker).** Strong defense-in-depth, but workloads
  **share the host kernel**. A kernel-level container-escape vulnerability is, in
  principle, exploitable from a malicious workload despite the baseline. This is
  the residual risk, stated plainly.
- **`runsc` (gVisor, the regulated tier).** A userspace kernel intercepts
  workload syscalls, so the workload does not talk to the host kernel directly —
  a materially stronger boundary against kernel-escape, with **no KVM
  requirement** (installs anywhere). Enabling it is one field, not a second
  driver; the entire rest of the stack (egress, secrets, pause, gateway) is
  unchanged. gVisor's tradeoff: ~74/351 syscalls unsupported, `io_uring` off by
  default, and `runsc` must run in netstack mode for the always-deny-metadata
  egress rule to bite — all on the Phase-0 validation checklist.

**If your security review requires a per-workload hardware-virtualization
boundary that explicitly rejects gVisor's userspace-kernel model, that is the
Firecracker upgrade path (§10) — a separately-funded future driver, not MVP
scope.** Absent that written requirement, hardened-Docker + gVisor stands.

**Live evidence (from-scratch pilot, regulated `runsc` tier).** On a bare-OS
install driven end to end by an agent over MCP, a deployed beam ran
`runtime=runsc` and, queried *from inside the workload*, reported `Linux
4.19.0-gvisor` — gVisor's userspace kernel, not the host's 7.0 — with
`Starting gVisor...` in its dmesg, alongside a read-only rootfs, **all
capabilities dropped**, and no-new-privileges. The §5 shared-kernel boundary is
thereby **demonstrated, not merely asserted**. The same pilot showed the
exfiltration controls live (outbound to a public host and to `169.254.169.254`
both dropped; only same-bridge traffic passes), the four-eyes promote gate (the
agent files a request and **cannot approve its own**; a different IT operator
approves to live), and full disaster recovery (loss of the data dir *and* the
out-of-band key → restore → **byte-identical** key → a vault-sealed DB credential
still decrypts and works). It also caught and fixed a genuine regulated-tier gap
invisible to unit tests: gVisor cannot reach Docker's embedded DNS, so
managed-database reachability is now provided by injected `/etc/hosts` entries
rather than name resolution. Full reproducible record:
`docs/lab-phase0-validation.md`.

## 6. Threat model (attack → mitigation → residual → upgrade path)

Every "mitigation" below is enforced in code and exercised by a test; the
"verified" column points at the proof.

| Attack | Mitigation (MVP) | Residual | Upgrade path | Verified |
|---|---|---|---|---|
| **Data exfiltration** | Per-Beamhall DOCKER-USER default-deny egress; always-deny metadata/link-local/host/mgmt | A beam can reach IT-allowlisted destinations | L7 egress proxy with content inspection | `TestAgentCannot/ExfiltrateData` (1.1.1.1 + 169.254.169.254 both dropped) |
| **Container escape** | Hardened baseline (§4) + `runsc` tier for regulated beamhalls | Shared kernel under `runc` (§5) | Firecracker microVM (§10) | lab: real Paketo beam under runc **and** runsc |
| **Secret theft** | No `get_secret` tool; `set_secret` write-only; age-encrypted at rest; file-injected at `/run/secrets` (never env); logs/metrics scrubbed | A compromised *running* workload can read its own injected secrets (by design — it needs them) | HSM/lease-based short-lived secrets | `TestAgentCannot/ReadSecretsBack`, `ObtainDatabaseCredentials`; scrubber proven on a real leak |
| **Lateral movement** | One Docker bridge per beamhall; db-per-beam scoped roles; secrets beam-scoped | Same-beamhall beams share a bridge | mTLS service mesh | `TestAgentCannot/EscapeItsBeamhall`; Postgres `42501` cross-db isolation (lab) |
| **Resource exhaustion** | cgroup v2 CPU/mem/PID ceilings; live-slot quota; **concurrent-build cap** (build-bomb defense); auto-pause of idle previews | A beam can use up to its quota | Fair-share scheduling | build-cap unit test; quota race test |
| **Malicious build input** | Cloud Native Buildpacks only; **agent Dockerfiles ignored**; pinned trusted builder; builds run off the runtime daemon, publish a pinned digest | Buildpack/base-image CVEs | SBOM + CVE gate before promote; full SLSA | `TestAgentCannot/SupplyADockerfile` (payload inert) |
| **Privilege/posture tampering** | No agent-facing tool mutates seccomp/caps/quota/egress; `SecurityContext` immutable; forbidden actions are named and audited on attempt | — | — | `TestAgentCannot/MutateSecurityPosture` |
| **SSRF / metadata theft** | Always-deny `169.254.0.0/16` (incl. cloud metadata) + host IP + mgmt subnet, independent of any allowlist | — | L7 proxy | `TestAgentCannot/ExfiltrateData` |
| **Confused deputy / token replay** | `aud` == Beamhall resource URI; `iss` pinned; `Origin` checked (DNS rebinding); RS256/ES256 only (no `none`/HMAC) | — | — | `internal/auth` suite (forged alg, wrong aud/iss all rejected) |
| **App-token replay against the backplane** (provisioned auth, §5.10) | A beam's own OIDC client mints tokens with `aud` = its own client id only; Beamhall never attaches the resource-URI audience to app clients, and `CreateClient` post-asserts no effective mapper injects it (refusing otherwise) | — | — | `internal/identityadmin` post-assert unit test; **lab: an app-client token is 401'd by `/mcp`** while a correctly-scoped token gets 200 (`auth-isolation.sh`) |
| **Audit tampering** | Hash-chained, append-only audit log; boot-time `Verify`; JSON-Lines export to an off-box SIEM anchors the truncation blind spot | An attacker with DB write + the ability to recompute the whole chain forward could rewrite history; the off-box SIEM cursor detects divergence | WORM/remote-attested log sink | audit chain unit + lab Verify |

## 7. Network egress model

Default posture is **deny-all** per beamhall. IT may add an explicit allowlist
(FQDN/CIDR:port) via the Admin console. Regardless of the allowlist, an
**always-deny** set is enforced first by the iptables `DOCKER-USER` reconciler:
cloud metadata (`169.254.169.254`), link-local, the host IP, and the management
subnet. The reconciler **asserts the full desired state from policy on every
deploy and at boot** — drift cannot silently open or break isolation. Agents
have no tool to change egress; only IT can, and the change is audited.

## 8. Secrets

- `set_secret` is **write-only** — there is no tool to read a secret back.
- Values are **age (X25519) encrypted at rest** in SQLite, sealed to a root key
  the agent never sees.
- Injection is **file-only at `/run/secrets/<KEY>`** (tmpfs), never environment
  variables (env leaks via `/proc`, `docker inspect`, and crash dumps are
  durable).
- `create_database` returns the **secret key and injection plan**, never the
  connection string — the DSN is sealed into the vault and surfaces only as a
  file inside the workload.
- `show_logs`/`show_metrics` pass a **backplane-side scrubber** (known-value
  match + entropy/JWT/key/PEM heuristics) before any bytes reach the agent.
- The **root key is the crown jewel**: it must be supplied out-of-band in
  production (systemd `LoadCredential`/KMS/TPM), never auto-generated. Backups
  include it and are therefore as sensitive as the appliance (`internal/backup`,
  written 0600).

## 9. CIS Docker Benchmark — how Beamhall maps

Beamhall's baseline implements the load-bearing CIS Docker Benchmark controls;
the operator owns host-level controls. This is a guide, not a substitute for
your own CIS scan.

| CIS area | Beamhall control |
|---|---|
| 4.1 Run as non-root user | userns-remap; containers never run as host root |
| 4.5 Do not mount sensitive host dirs | Driver mounts only the per-beam secret tmpfs + writable `/tmp` |
| 5.3 Restrict Linux capabilities | cap-drop ALL + narrow template add-backs |
| 5.4 Do not use privileged containers | No privileged mode; no agent path to it |
| 5.7 Do not map privileged ports | `NET_BIND_SERVICE` only where the template needs it; gateway terminates TLS |
| 5.10/5.11 Memory & CPU limits | cgroup v2 quotas per beam |
| 5.12 Read-only root filesystem | Default; writable only at `/tmp` |
| 5.15 Restrict process restart | Restart policy disabled; the orchestrator owns lifecycle |
| 5.25 Restrict new privileges | no-new-privileges set |
| 5.28 PID cgroup limit | PID ceiling per beam |
| 5.29 Default bridge avoidance | Per-beamhall named bridge, never the default `docker0` |
| 1.2 host hardening, auditd, etc. | **Operator responsibility** (documented in preflight) |

## 10. The Firecracker upgrade path

The `RuntimeDriver` interface is designed so a Firecracker/microVM driver is a
clean future addition, **not** a rewrite. Beamhall does not build it for the MVP
because: it is a full second driver on containerd+Kata (not a Docker
`--runtime`); it requires `/dev/kvm` + nested virt on the host (breaking the
install-anywhere appliance promise); and it would re-plumb networking, secrets,
and the pause model (~10–20× the build effort plus a permanent ops tax). The
decision rule: build it **only** if your security review delivers a written
demand for a per-workload hardware-virtualization boundary that explicitly
rejects gVisor's model, **and** you run on KVM-capable hardware. Until then, the
gVisor tier is the stronger isolation answer.

## 11. Residual risk — the honest statement

1. **Shared kernel under `runc`.** A novel kernel container-escape could, in
   principle, be exploited from a malicious workload. Mitigation: run regulated
   beamhalls under `runsc`; keep the host kernel patched. This is the single
   risk that the gVisor tier and (further) Firecracker exist to reduce.
2. **A compromised running workload sees its own secrets.** By design — it needs
   them to function. Mitigation: scope secrets per beam; rotate; short-lived
   leases are the fast-follow.
3. **Build supply chain.** Buildpack base images and the trusted builder can
   carry CVEs. Mitigation: pin the builder; the SBOM + CVE-gate-at-promote is
   the fast-follow.
4. **The operator owns host hardening, key custody, and SIEM ingestion.**
   Beamhall provides the hooks (audit export, the out-of-band root key, the
   preflight script); the deployment owns the surrounding controls.

Beamhall's thesis is that for the AI-agent-deploys-internal-apps use case, this
posture — no raw credentials to the agent, an immutable hardening baseline, a
single audited policy point, default-deny egress, and a stronger isolation tier
on demand — is a defensible boundary, and that stating the residual risk plainly
is the right basis for a security team's sign-off.
