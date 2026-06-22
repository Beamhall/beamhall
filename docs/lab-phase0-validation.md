# Phase-0 lab validation

First-hardware validation of the hardened-Docker + gVisor runtime baseline and
the buildpack path (docs/PLAN.md §3, §8 Phase 0).

> **Naming note:** the project was renamed Workcell→Beamhall after these runs.
> Records below read `beamhall ok` / `bh-smoke-beam`, but the original phase-0/1
> validation used the old `workcell ok` / `wc-smoke-app` artifacts. The lab has
> since been re-provisioned under the new names and all suites re-passed — see
> the re-provisioning section at the end. Findings are otherwise unchanged.

**Host:** the test appliance VM — Ubuntu 26.04 LTS, kernel 7.0.0, 4 vCPU / 3.3 GiB
RAM, 97 GB disk, cgroup v2 unified. (Its concrete address is kept in private ops
notes, not in this public repo.)
**Stack installed** (via `scripts/lab-bootstrap.sh`): Docker 29.1.3, runc 1.4.0,
gVisor `runsc` release-20260601.0, pack 0.40.6; daemon `userns-remap=default`
(`dockremap` subuid/subgid auto-created) + `runsc` runtime registered.

## Results

| Check | Result |
|---|---|
| `preflight.sh` (cgroup v2, subuid/subgid, runc ≥ 1.2.8, userns-remap, runsc registered, port free) | PASS |
| Hardened HTTP beam under `runc` (cap-drop ALL +NET_BIND_SERVICE, no-new-privileges, read-only rootfs, tmpfs /tmp, pids/mem cgroup limits) | PASS — HTTP 200 |
| Same under gVisor `runsc` | PASS — HTTP 200 |
| gVisor actually sandboxes | CONFIRMED — in-container `uname -r` = `4.19.0-gvisor` vs host `7.0.0-22-generic` |
| Real **Paketo** Node beam (`pack build`) under `runc` and `runsc` with full hardening | PASS — served `beamhall ok` on both |

**Takeaway:** the regulated isolation tier (gVisor `runsc`) and the hardened-Docker
baseline both work on a current kernel and run a real buildpack-built beam. The
`runtime_class` switch (runc ↔ runsc) is viable as designed.

## Key finding — buildpack builds conflict with userns-remap

On a `userns-remap`-enabled **runtime** daemon, the standard `pack build` paths fail:

| Build approach | Result on userns-remapped daemon |
|---|---|
| `pack build` (default, exports to the daemon) | **FAIL** — lifecycle container hits `permission denied … /var/run/docker.sock` (its remapped root is not in the `docker` group) |
| `pack build --publish --network host` (reach a local registry on 127.0.0.1) | **FAIL** — `cannot share the host's network namespace when user namespaces are enabled` |
| `pack build --publish` to `127.0.0.1:5000` on the default bridge | **FAIL** — the lifecycle container's `127.0.0.1` is its own loopback, not the host registry |
| Build with userns **off**, `docker save` → re-enable userns → `docker load` → run | **WORKS** (used here to prove the run path) |

This is the concrete form of the plan's hardest-problem #4 (build isolation ≠
runtime isolation). **Decision for Beamhall's build pipeline:** do **not** run the
buildpack lifecycle against the userns-remapped runtime daemon. Build in a
**separate, non-remapped context** and hand the *pinned image* to the hardened
runtime daemon, e.g.:

- a dedicated **rootless BuildKit** / non-remapped build daemon, **or**
- `pack build --publish` to the appliance's **internal registry** from that
  build context;

then the runtime daemon (userns-remap + optional `runsc`) only ever **pulls the
pinned digest and runs it** under the hardening profile. This keeps build
isolation and runtime isolation as separate concerns and is the design the
`internal/build` + `internal/driver` split should reflect in Phase 1.

## Reproduce

```sh
sudo bash scripts/lab-bootstrap.sh          # one-time host setup
BEAMHALL_REQUIRE_RUNSC=1 bash scripts/preflight.sh
# hardened run under both runtimes uses the SecurityContext profile flags;
# see scripts/runsc-smoke.sh (point IMAGE= at a built beam for the buildpack gate)
```

> Memory note: `pack build` of a trivial Node beam fit in 3.3 GiB but the box is
> below the plan's 8 GiB recommendation; size the build context accordingly.

## Phase 1 — Docker RuntimeDriver verified on the lab

`internal/driver/dockerdriver.go` (docker/docker v28 SDK) was integration-tested
against the lab daemon (`internal/driver/dockerdriver_integration_test.go`, gated
on `BEAMHALL_DOCKER_IT=1`, cross-compiled to linux/amd64). Both tiers PASS:

| Tier | HTTP via bridge IP | in-container kernel | secret `/run/secrets/probe` | pause/resume/stats/logs |
|---|---|---|---|---|
| `runc` | `172.18.0.2:8080` | `7.0.0-22-generic` (host) | injected | OK |
| `runsc` | `172.19.0.2:8080` | `4.19.0-gvisor` (sandboxed) | injected | OK |

Confirms the driver correctly applies the `SecurityContext` (cap-drop ALL +NET_BIND_SERVICE,
no-new-privileges, read-only rootfs, tmpfs, cgroup v2 limits), selects the
`runtime_class` (runc/runsc), places workloads on a **per-Beamhall bridge** (note
the distinct `172.18`/`172.19` subnets), injects secrets as files (not env), and
exposes a `BackendAddr` for the gateway (no host-port publishing).

## Phase 1 — egress reconciler verified (negative-security property)

`internal/egress` programs a `BEAMHALL-EGRESS` chain jumped from `DOCKER-USER`.
Integration-tested on the lab (`internal/egress/egress_integration_test.go`):

| Step | Result |
|---|---|
| baseline (no policy) | container reaches `1.1.1.1:443` |
| default-deny | `1.1.1.1:443` **blocked**, `169.254.169.254` (metadata) **blocked** |
| allowlist `1.1.1.1/32` | `1.1.1.1` opens; `8.8.8.8` + metadata **still blocked** |

This is the first machine-checked "the agent cannot exfiltrate" proof. Ubuntu
26.04 ships `iptables` as the nft backend (`iptables v1.8.11 (nf_tables)`); Docker
29 and our reconciler share it, so DOCKER-USER rules take effect.

### Two bugs found and fixed via the lab (would have been invisible in unit tests)

1. **Egress bypass via an ESTABLISHED,RELATED RETURN rule.** Adding a top-of-chain
   conntrack-established RETURN let an *outbound* packet skip the deny whenever
   conntrack still held a (reused) tuple from an earlier allowed flow — a real
   policy bypass, and flaky (depended on ephemeral-port reuse timing). Removed it:
   every rule matches `-i <bridge>` (origin direction only); reply traffic
   ingresses on the external interface and is allowed by falling through. Bonus:
   a policy change now cuts existing outbound flows immediately.
2. **`DockerDriver.Exec` returned a premature exit code.** When called with no
   attached streams it inspected the exec before the process exited, returning a
   stale `0` — which made a *blocked* `nc` probe look reachable. Fixed by always
   attaching+draining stdout/stderr and polling `ExecInspect` until `!Running`.

## Phase 1 — Caddy gateway verified

`internal/gateway` programs a single Caddy (v2.11.4 on the lab) via its Admin API
(`POST /load`, full config incl. the `admin` block so the API survives reloads).
Integration-tested (`internal/gateway/gateway_integration_test.go`):

| Step | Result |
|---|---|
| deploy backend container, `Upsert` host→backend | route programmed |
| HTTP `Host: beam.wc.test` → Caddy `:8088` | served the beam (`beamhall ok`) |
| `Retire` the route | host no longer proxies to the backend |

On-demand TLS uses the current `apps.tls.automation.on_demand.permission`
(`{module:"http", endpoint:.../ask}`) — the deprecated `ask` string is gone as of
Caddy 2.8. `AskHandler` permits issuance only for currently-routed hosts (200)
and denies everything else (403), gating ACME abuse. (Routing verified over HTTP;
real ACME issuance needs public DNS and is exercised at deploy time, not in the lab.)

Phase 1 (runtime substrate) is complete: **driver + egress + pause scheduler +
gateway**, all lab- or race-verified.

## Rename re-provisioning — lab brought in line with Beamhall names

The lab was re-provisioned after the Workcell→Beamhall rename (see the naming
note at the top; commit `012ae0d`):

- **`bh-smoke-beam` image**: derived from the phase-0 Paketo image via a plain
  `docker build` overlaying `/workspace/app.js` (+`package.json`) to serve
  `beamhall ok` — recipe kept at `/root/bh-smoke/Dockerfile` on the VM. A plain
  build works fine on the userns-remapped daemon; it is only the **buildpack
  lifecycle** that cannot run there (the key finding above), and toggling
  userns off just to rebuild a smoke image would have meant temporarily
  weakening the runtime daemon. A from-source `pack` rebuild belongs to the
  separate-context build pipeline (Phase 2 item 4). Verified serving
  `beamhall ok` under both `runc` and `runsc` before the suites ran.
- **All three integration suites PASS** under the new env/image names
  (`BEAMHALL_DOCKER_IT=1`, `BEAMHALL_IT_IMAGE=bh-smoke-beam`):

| Suite | Result |
|---|---|
| `internal/driver` `TestDockerDriverLifecycle` | PASS — runc + runsc, full hardening, in-container kernel `4.19.0-gvisor` under runsc, secret at `/run/secrets/probe` |
| `internal/egress` `TestEgressDefaultDenyAndAllowlist` | PASS — baseline open → default-deny (internet+metadata blocked) → allowlist (1.1.1.1 only) |
| `internal/gateway` `TestGatewayRoutesToContainer` | PASS — route → served `beamhall ok` → retire → no longer routed |

  This is also the first hardware validation that the rename changed nothing
  runtime-visible (`beamhall.beam` labels, `bh-` resource prefixes).
- **Cleanup**: old `wc-smoke-app` image and `/root/wc-smoke` source removed;
  the test VM hostname relabeled to match the rename (cosmetic; SSH is by
  address); `userns-remap` untouched throughout; Caddy returned to its default
  stopped state.

## Phase 2 — orchestrator vault→driver junction verified

`internal/orch/orch_integration_test.go` drives the full orchestrator path on
the lab VM with the real Docker driver and a real age vault (fake gateway —
the Caddy path has its own test above):

| Step | Result |
|---|---|
| `SetSecret` (write-only vault) → `DeployBeam` (pinned `bh-smoke-beam`) | PASS — running under the full hardening profile on `bh-<id>` |
| **Junction**: in-container `cat /run/secrets/PROBE` | PASS — exact vault-sealed value (`vault.Inject` → driver `stageSecrets` composition proven) |
| HTTP via bridge backend addr | PASS — `beamhall ok` |
| `PausePreview` → `ResumePreview` → `PromoteToLive` via orchestrator | PASS — workload paused/resumed (driver state confirmed), promoted, live host minted |
| `audit.Verify` over the full lifecycle | PASS — chain intact (PEP decisions + outcomes) |

This closes the gap recorded at item 4: each half was verified separately
(secret unit tests, driver lab test); their composition now has hardware
evidence end-to-end through the PEP-gated orchestrator.

## Phase 2 — build pipeline verified (separate build daemon → registry → runtime pull)

The PLAN §4/§5.5 build architecture now runs on the lab, provisioned by
`lab-bootstrap.sh` steps 8–9:

- **`docker-build.service`** — a second dockerd (non-remapped, own
  config/socket/data/exec roots, `bridge:none` + `iptables:false` so it can
  never fight the egress chains). The runtime daemon's userns-remap was
  untouched throughout. Paketo builder/run images seeded from the runtime
  daemon via save|load (3.7 GB, one-time).
- **`bh-registry`** — `registry:2` on the runtime daemon, loopback-only
  `127.0.0.1:5000`, on its own named network (`docker0` does not exist on
  this VM — every container here runs on custom bridges).

| Step | Result |
|---|---|
| `pack build --publish --network host` via `DOCKER_HOST=unix:///run/docker-build.sock` | PASS — lifecycle reaches the loopback registry over the host network (the exact combination that fails on the remapped daemon) |
| Registry digest resolution (`HEAD /v2/<repo>/manifests/<tag>`) | PASS — `Docker-Content-Digest` matches pack's reported digest exactly |
| Runtime daemon `docker pull <repo>@sha256:...` + hardened run | PASS — served the source-built content |
| `internal/build` integration test (`TestBuildPipelineToRuntime`) | PASS — snapshot → managed-repo commit (tag = sha12) → pack → publish → driver pulls digest → hardened container serves `beamhall pipeline ok` (~26 s warm) |

Gotcha for next agents: the registry container needs an explicit
`--network` — the default bridge is absent on this VM and `docker run`
without one fails with "adding interface … to bridge docker0 failed".

## Phase 2 — Postgres provisioner verified (db-per-beam scoped roles)

`bh-postgres` (postgres:17-alpine; bootstrap step 10): admin on loopback
`127.0.0.1:5433` for the backplane, beams reach `bh-postgres:5432` after the
provisioner attaches the container to their Beamhall network — no egress
exception needed (same-bridge traffic; DOCKER-USER governs only egress).

| Check (`internal/resource` `TestPostgresProvisionIsolationAndReachability`) | Result |
|---|---|
| Provision: scoped role + database, `REVOKE ALL … FROM PUBLIC` | PASS — role creates/inserts/selects on its own database |
| **Isolation**: role with *correct* credentials vs sibling database | PASS — `42501 permission denied for database` (not a password failure; the replace must anchor on the URL path — the role name contains the db name) |
| Beam-side reachability: workload on the attached network, DSN as sealed | PASS — psql client container exited 0 |
| Drop removes database + role | PASS |

## Phase 2 — MCP + OAuth full-stack E2E (item 5; Phase 2 complete)

`internal/e2e` `TestMCPEndToEnd`: a real `beamhalld` process (full wiring),
real RS256 JWTs against a local JWKS, official go-sdk MCP client over
Streamable HTTP. The whole canonical demo flow passed in **26.4 s** (warm
caches):

| Check | Result |
|---|---|
| Boot: store, vault, audit Verify, scheduler, egress assert, MCP up | PASS |
| No token → 401 + `WWW-Authenticate` → RFC 9728 metadata | PASS (unit-level too) |
| create_beam / set_secret / create_database via MCP tools | PASS — create_database returns the key + `/run/secrets/MAIN_URL`, never the DSN |
| deploy_beam `source_tarball` → pack (build daemon) → registry → hardened run | PASS — **pack output streamed live as MCP progress notifications** |
| Preview URL via Caddy; beam read both `/run/secrets` files | PASS (`hasDB:true`, `hasToken:true`) |
| show_logs scrubbing: the beam logged its own API token | PASS — agent saw `***REDACTED***` |
| pause → URL dead; resume → **new** URL serves | PASS |
| promote as builder (scope granted, role short) | PASS — PEP denial `role "builder" does not grant "promote_to_live"` |
| promote as IT (`admin:it` bypass, no membership row) → stable live URL | PASS |
| Audit chain after shutdown: Verify clean, deny event present, no secret values | PASS — 17 events |

**Gotchas this run taught:**
- **Caddy never answers an unmatched host on a route-less server** — it holds
  the connection open (no 404/empty-200). Any probe of a retired route MUST
  use a bounded HTTP client; the first E2E run hung ~10 min on
  `http.DefaultClient` (no timeout) against exactly this.
- **`caddy start` hangs over non-interactive SSH** — the detached child
  inherits the pipes, so `ssh host 'caddy start'` never returns. Redirect:
  `caddy start </dev/null >/dev/null 2>&1`.
- **`pkill -f e2e.test` kills its own ssh shell** (the remote `bash -c`
  command line contains the pattern). Use `pkill -x` with exact names.
- Cosmetic: `ShowLogs` bytes still carry Docker's 8-byte stream multiplex
  frame headers (visible as stray prefix bytes); strip with the stdcopy
  demux in Phase 3 error-UX work.

## Phase 3 — agent error UX verified (item 1)

E2E re-run (46.7 s warm) with the diagnosis layer in place:

| Check | Result |
|---|---|
| Beam writing outside tmpfs (`/boom.txt`) → deploy_beam | PASS — tool error: "exited during startup with code 1 … Likely cause: … write only under /tmp", full EROFS stack (scrubbed) attached; **no dead preview URL minted** |
| show_logs bytes | PASS — no Docker stream-multiplex frame headers (driver now demuxes) |
| Promote retires the stale preview URL | PASS — old random URL stops answering once the stable live URL is up |
| Audit chain after the extended flow | PASS — 21 events, builder deny recorded, no secret values |

**Gotchas this arc taught:**
- **`caddy start` does not refuse a second instance** — Caddy listeners use
  SO_REUSEPORT, so two daemons silently share `127.0.0.1:2019` and config
  pushes round-robin between two independent configs. Symptom: routes
  "vanish" with zero errors anywhere; admin-API reads disagree between
  consecutive queries. Always check the admin API is down before
  `caddy start`; `pgrep -ac caddy` should be 1.
- **promote() never took the preview route down** (comment promised it, code
  didn't) — found because the single-caddy fix made route state
  deterministic. Production content stayed reachable on the stale random
  preview URL and `Boot` faithfully restored it after restarts.

## Phase 3 — negative-security suite verified (item 2)

`internal/e2e` `TestAgentCannot`, real MCP calls against a real beamhalld
(74 s). Each proof attempts the attack with the builder holding EVERY scope,
so only the real defenses stand:

| Proof | Attack attempted | Result |
|---|---|---|
| ReadSecretsBack | enumerate tools for get/read/export; re-set and inspect | PASS — no read tool exists; set_secret echoes nothing |
| ObtainDatabaseCredentials | read the DSN out of create_database | PASS — injection plan only, no `postgres://`/password/port |
| EscapeItsBeamhall | create/secret/logs in hall "fort" (no membership, full scopes) | PASS — PEP denials, audited |
| MutateSecurityPosture | find any tool touching seccomp/caps/egress/quota | PASS — no such surface exists |
| ExfiltrateData | beam fetches 1.1.1.1 + 169.254.169.254 | PASS — both dropped; show_logs names "DENIED BY DEFAULT" |
| SupplyADockerfile | tarball ships a malicious Dockerfile | PASS — inert; buildpacks built the source |

Audit chain after the run: clean, 30 events, 2 denials on record.

**The suite caught a real driver bug** (invisible to unit fakes): redeploying
over a running beam never worked on the real Docker driver. Containers used a
fixed per-beam name (`wc_<beamID>`, also a rename leftover), so the supersede
order (new container up BEFORE the old is retired) collided at
`ContainerCreate` with `Conflict … name already in use`. Fixed: unique
per-instance names (`bh_<beamID>-<rand>`), per-instance secret staging (so
destroying the old workload can't unstage the new one's `/run/secrets`), and
`Destroy` now reads the staging label BEFORE force-removing the container (it
had inspected post-removal, so staged-secret cleanup silently never ran).

**Egress reconciliation now runs on every deploy, not just boot.** Per-beamhall
bridges are created lazily at first deploy, so boot-only assertion left a new
beamhall's first workloads on an unprotected bridge until the next restart.
The orchestrator re-asserts after each deployment, fail-closed (a sync failure
fails the deploy — a beam never runs without its egress policy).

## Phase 3 — lifecycle completion verified (item 4: rollback / destroy / metrics)

`internal/e2e` `TestLifecycleRollbackDestroy` (56 s, two real pack builds):

| Step | Result |
|---|---|
| deploy v1 (tarball) → preview serves `marker:v1` | PASS |
| show_metrics on the running workload | PASS — `CPU 0.0%, memory 178651136/536870912 bytes, net rx/tx 1672/554` (real cgroup + net sample) |
| deploy v2 supersedes v1 → serves `marker:v2` | PASS |
| **rollback** (no rebuild) → fresh URL serves `marker:v1` again; v2 URL retired | PASS |
| destroy_beam as builder | PASS — refused (beamhall_admin only; governance) |
| destroy_beam as IT (`admin:it`) | PASS — workload removed, URL dead, slug freed |
| re-create the destroyed slug | PASS — partial unique index frees it |

Rollback exercises the new-up-before-old-down path (the target's fresh
container starts while the current one still runs), which is exactly what the
unique-instance-name fix from item 2 made safe.

**Negsec note:** adding `destroy_beam` (description: "frees its quota slot")
first tripped the `MutateSecurityPosture` proof, which had scanned tool
*descriptions* for posture nouns. Mentioning quota ≠ mutating it — the proof
now asserts on tool *names* plus description mutation-verbs, so it stays sharp
as the surface grows.

## Phase 3 — Admin console verified (item 3)

`internal/web` is unit-tested over the real HTTP stack (full OIDC login,
non-admin 403, unauth redirect, create-beamhall/register-identity/
grant-membership with audit assertions, CSRF). Lab smoke of the wired
appliance (`cmd/beamhalld` + `bh-devidp`, OIDC Authorization Code flow over
real processes):

| Check | Result |
|---|---|
| `Admin console ready` at boot with BEAMHALL_ADMIN_CLIENT_ID set | PASS |
| OIDC discovery → /authorize → /token → access-token validation (admin:it) | PASS |
| Session cookie set; /admin dashboard renders (200) | PASS — "Beamhalls" heading, operator identity, IT forms |

The console reuses the MCP layer's `auth.Verifier` to validate the **access
token** (aud = the Beamhall resource URI) for the admin:it scope — so there's
no separate ID-token/nonce path. First admin login auto-provisions the
operator's Identity (`EnsureOperator`), which closes the bootstrap
chicken-and-egg the E2E/negsec suites previously worked around by seeding the
store directly. `bh-devidp` gained OIDC discovery + a lab-only auth-code flow
(still no real authentication — lab network only).

Design note (request-derived redirect): the OIDC `redirect_uri` is derived
from the incoming request (scheme+host) unless `BEAMHALL_ADMIN_BASE_URL` pins
it — so the console works behind a reverse proxy without per-deployment config.

## Phase 3 — git smart-HTTP push transport verified (item 4 remainder)

`internal/gitserver` is unit-tested against go-git's real client (token auth,
one-time enforcement, unknown-repo rejection, deploy trigger with the pushed
SHA, sideband progress delivery). Lab E2E (`TestGitPushDeploy`) uses the
**stock git 2.53 binary**: deploy_beam (no source) → one-time push token →
`git push` → build → deploy → the beam serves the git-pushed content, with
"remote:" progress and the preview URL printed by `git push`.

**Two go-git server gotchas this exposed (both fixed):**
- **go-git's receive-pack advertisement omits `side-band-64k`** — so a stock
  git client never negotiates the sideband and shows no "remote:" progress.
  Add the capability to the advertisement before encoding.
- **go-git's receive-pack *server* then rejects a request that negotiated
  `side-band-64k`** ("unsupported capability"). The pushed packfile is not
  sidebanded (sideband is server→client only on push), so strip the
  capability from the request before `ReceivePack` applies the pack, and mux
  the *response* (report + progress) ourselves — which is what the client,
  having negotiated it, expects.

The bare repo is provisioned on first authorized push (a beam may never have
been built before its first `git push`); the git server and the build pipeline
share one `build.Repos`.

## Phase 4 — backup/restore verified

`internal/backup` round-trips in unit tests (store + secret key + repos +
audit chain survive; chain re-verifies clean; the crown-jewel test recovers a
vault-sealed secret after restore). Lab E2E (`TestBackupRestoreLive`, 0.8s):

| Check | Result |
|---|---|
| `beamhalld backup` of a LIVE appliance (daemon holding the WAL DB) | PASS — online snapshot from a second process under the running daemon |
| `beamhalld restore` into a fresh data dir | PASS — prior files preserved as `*.pre-restore` |
| Recover a vault-sealed secret with the restored key | PASS — plaintext matches |

This proves the concurrent online backup the unit tests can't: a separate
process snapshots the database (VACUUM INTO) while the appliance holds it open
under WAL. The secret root key travels in the archive — the backup is exactly
as sensitive as the appliance and is written 0600.

## Phase 4 — packaging + out-of-band secret key verified

`packaging/` ships GoReleaser (static CGO-free binaries, amd64+arm64, checksums;
`goreleaser check` clean), a hardened systemd unit (`beamhalld.service`: a
`beamhall` user in the docker group, `LoadCredential` for the root key, sandbox
directives compatible with Docker access), an `install.sh`, and a Packer
template that bakes baseline + binary + service.

New: `BEAMHALL_SECRET_KEY_FILE` selects the **load-only** key path
(`secret.LoadKey`) for production — the appliance loads the age root key
out-of-band (systemd `LoadCredential`/KMS) and refuses to start if it is
missing, instead of generating a throwaway key. Lab-smoked on the VM:

| Check | Result |
|---|---|
| `BEAMHALL_SECRET_KEY_FILE` set, key absent → boot | PASS — fails with "load secret root key (out-of-band)" |
| Key present out-of-band → boot | PASS — "secret root key loaded out-of-band" |
| Load-only honored (no key written into the data dir) | PASS |

### Gotcha — install-as-systemd-service caught three bugs invisible to hand-runs

Installing via `packaging/install.sh` + `systemctl enable --now` (running as the
unprivileged `beamhall` user, not root the way every prior lab run did) exposed
three packaging defects that no unit test or root hand-run could see:

1. **`%d` does not expand inside an `EnvironmentFile`.** We had
   `BEAMHALL_SECRET_KEY_FILE=%d/secret.key` in `beamhall.env`; systemd passed the
   literal string `%d/secret.key` and boot failed with
   `open %d/secret.key: no such file or directory`. The `%d` credentials-dir
   specifier only expands in unit directives, so it must live in the unit:
   `Environment=BEAMHALL_SECRET_KEY_FILE=%d/secret.key` (set after
   `EnvironmentFile=` so it wins). Removed from `beamhalld.env.example`.

2. **Egress isolation fails closed without `CAP_NET_ADMIN`.** The in-process
   `BEAMHALL-EGRESS` iptables/nf_tables reconciler needs `CAP_NET_ADMIN`; as the
   unprivileged service user it died with
   `iptables ... Permission denied (you must be root)` →
   `egress reconciliation FAILED — beam isolation may be degraded`. Every earlier
   lab run was root, so this was invisible. Fix: `AmbientCapabilities=CAP_NET_ADMIN`
   + `CapabilityBoundingSet=CAP_NET_ADMIN` in the unit. Not a real privilege gain
   (beamhalld already drives the root-equivalent Docker socket) — it just lets the
   security control run. Verified: `CapEff: 0000000000001000` (only CAP_NET_ADMIN),
   `egress policy asserted`, and `iptables -S BEAMHALL-EGRESS` shows the chain.

Both fixed and re-verified as an installed service: `secret root key loaded
out-of-band` from `/run/credentials/beamhalld.service/secret.key`, `egress policy
asserted`, `/healthz` → `ok`.

3. **Backup couldn't find the out-of-band key.** `beamhalld backup` looked only
   for `<dataDir>/secret.key`, but production keeps the key out-of-band
   (`/etc/beamhall/secret.key`), so the documented cron command failed:
   `secret root key /var/lib/beamhall/secret.key is missing — refusing to write
   an unrecoverable backup`. Fix: `backup.Create` takes an explicit `keyPath`,
   sourced from `BEAMHALL_SECRET_KEY_FILE`; backups run as root (the archive
   embeds the 0400 root key and is as sensitive as the appliance); `restore`
   prints where to re-install the recovered key out-of-band. Verified on the VM:
   archive = `MANIFEST.json + beamhall.db + secret.key`; restore reconstructs
   both and the recovered key **byte-matches** the live out-of-band key (DR onto
   a fresh host works). `install.sh` now prints the corrected root backup +
   restore commands.

### Packer bake — verified end-to-end (and four more template fixes)

With nested virt enabled on the dev VM (`/dev/kvm` + `vmx`), `packer build`
baked the appliance image in <4 min. Getting there fixed four defects that
`packer validate` cannot catch (validate only checks HCL, not a real boot):

- **`type = int` is invalid HCL** — Packer wants `number`; the bad type silently
  dropped the variable declarations (`To declare variable "cpus"…`).
- **No SSH path into the cloud image.** Ubuntu cloud images have no console
  login; Packer hung at "Waiting for SSH". Added a NoCloud seed
  (`packer/seed/{user-data,meta-data}`, CD label `cidata`) that sets the default
  user's password, plus `ssh_password`. A final provisioner then `passwd -l`s the
  account and `cloud-init clean`s so the exported image carries no build cred.
- **`/tmp` is a 1.7 GB tmpfs.** Running the build from `/tmp` wrote the multi-GB
  disk into RAM → `qemu-img: No space left on device` at ~3 GB. Fixed by running
  from the root fs with `PACKER_CACHE_DIR` on disk. Documented in the README.
- **8 GB/4 vCPU default didn't fit the 3.3 GB host.** Made `memory`/`cpus`
  variables (defaults unchanged) so a small host runs `-var memory=2048 -var cpus=2`.

Result verified with libguestfs on the qcow2: `beamhalld` + the **disabled**
unit installed, `runsc`/`containerd-shim-runsc-v1` present, `ubuntu` password
locked (`!…`). gVisor itself needs no KVM — `runsc` ran a container on this same
KVM-less-by-default VM earlier (`gvisor-kernel=4.19.0-gvisor`); the KVM
requirement is **only** the qemu *builder's*, never the customer's runtime
(unless the future Firecracker tier is funded).

## Canonical demo — verified end-to-end (and proved real DB connectivity)

`demo/` ships the canonical Request Tracker (Node, PLAN §7). Driven against the
**installed appliance** by `cmd/bh-demo` (agent) + the new `beamhalld admin`
CLI (IT), the full flow runs `EXIT=0`: create_beam → set_secret →
create_database → deploy (preview, HTTP 200 via gateway) → show_logs (token
`***REDACTED***`) → builder promote **denied by the PEP** → IT promote (live
URL) → v2 + rollback. New since the integration test: the demo app actually
**connects to the managed Postgres** — `/api/status` reports
`"database":"ready"` and the visit counter increments (live DB writes from a
cap-dropped, read-only-rootfs, egress-denied beam). The E2E test only checked
the DSN *file* existed; this proves end-to-end beam→Postgres connectivity.

## Bring-your-own OIDC — verified against real Keycloak

Added **OIDC discovery** to the token verifier: configure only
`BEAMHALL_OAUTH_ISSUER` and Beamhall resolves `jwks_uri` from
`<issuer>/.well-known/openid-configuration` (validating the doc's `issuer`
matches — refuses on mismatch). `BEAMHALL_OAUTH_JWKS_URL` is now optional.

Validated against **Keycloak 26** on the lab (`docs/idp-setup.md`,
`scripts/keycloak-beamhall-realm.json`): beamhalld configured with the issuer
only (no JWKS URL) came up — proving discovery resolved the keys from a real
IdP. Then:

| Keycloak token | `aud` | MCP |
|---|---|---|
| with the audience mapper | `https://lab.beamhall.internal/mcp` | **200** (accepted) |
| without the audience mapper | *(none)* | **401** (refused) |
| no token | — | **401** |

Confirms the **confused-deputy defense** against a production IdP and the
**Keycloak audience-mapper requirement**: out of the box Keycloak does *not* put
your resource URI in `aud`, so you must add an Audience protocol mapper or every
token is (correctly) refused. Colon-bearing scopes (`beams:deploy secrets:write`)
parse fine. Gotcha aside: `docker0` had to be recreated (`systemctl restart
docker`) — it was missing after the nested-virt reboot, so default-bridge
containers (Keycloak) failed with "adding interface to bridge docker0 failed";
per-beamhall bridges were unaffected, which is why beams kept working.

## Air-gapped builds — verified

The build pipeline is the one default internet dependency (Cloud Native
Buildpacks pull the builder + run images every build). Made `pack`'s pull policy
+ run-image configurable (`BEAMHALL_PACK_PULL_POLICY=if-not-present`,
`BEAMHALL_CNB_RUN_IMAGE`) and added `scripts/airgap-bundle.sh`/`airgap-load.sh` to
mirror the images over offline media. Lab-verified: with
`PACK_PULL_POLICY=if-not-present`, a deploy builds and serves (preview HTTP 200)
using the **already-local builder — which stayed local (no re-pull)**; the
bundle→load roundtrip works (a saved image loads into both the build and runtime
daemons and verifies present). Unit tests assert the air-gap flags are passed and
that a default (non-air-gap) build adds neither. JWKS needs no internet with an
internal IdP (the bundled Keycloak ran on-box here); npm/pip mirrors for beam
dependencies are operator-side.

## Promote-approval gate (four-eyes) — verified end-to-end

Optional explicit IT-approval gate for `promote_to_live` (PLAN §10),
`BEAMHALL_PROMOTE_APPROVAL=on` (default off). When on, an agent's
`promote_to_live` files a pending request instead of going live; a **different**
IT operator approves it via `approve_promotion` (four-eyes / separation of
duties). New: migration 0005 `promotion_requests` (one pending per beam via a
partial unique index), policy `request_promotion` action (builder+), orch
`RequestPromotion`/`ApprovePromotion`/`RejectPromotion`/`ListPendingPromotions`,
and the `list_pending_promotions`/`approve_promotion`/`reject_promotion` MCP
tools (admin:it). Lab-verified against the bundled Keycloak: builder
`promote_to_live` → "requested (id)"; IT `list_pending_promotions` shows it
(requested_by = builder); IT `approve_promotion` → beam **LIVE** (HTTP 200); the
requester cannot approve their own request (unit-tested four-eyes). The Admin
console surfaces a **Pending promotions** section (approve/reject) and hides the
direct-promote button when the gate is on (web unit test:
`TestPromoteApprovalConsole`). Approval runs in the daemon (it executes the real
promote, which needs the full orchestrator), so it's an MCP tool + the console
action — not the store-only admin CLI.

## Bundled Keycloak (turnkey pilot IdP) — verified end-to-end

`packaging/keycloak/` ships a one-command bundled IdP for evaluation:
`setup-bundled-idp.sh` brings up Keycloak as a systemd container **fronted by the
Beamhall gateway** (new `gateway.WithStaticRoute` → `idp.<base-domain>` →
127.0.0.1:8090), renders a realm (capability scopes, audience mapper, admin +
agent clients, seed users), wires `beamhall.env`, and registers the seed
identities. Lab-verified on the VM: the **full `bh-demo` flow runs `EXIT=0`
against the bundled Keycloak** (sub→200, deploy→preview HTTP 200, scrubbed logs,
builder promote denied by the PEP, IT promote→live HTTP 200), and `/admin`
sign-in 302s to the bundled IdP.

Real integration gotchas this surfaced (all fixed):

- **Boot-order race.** beamhalld did discovery eagerly at boot and crash-looped
  while the co-located IdP was still starting. Fix: **lazy JWKS discovery** — the
  verifier (and the Admin console) resolve the IdP's endpoints on first use, so
  the appliance boots and serves regardless of IdP readiness and survives IdP
  restarts. Best-effort eager attempt is kept for fast misconfig feedback.
- **Realm import rejects `_comment`.** Keycloak's `RealmRepresentation` rejects
  unknown top-level keys — no comment fields in import JSON.
- **userns-remap can't read a 0640 import file.** The Keycloak container runs as
  a remapped uid; the bind-mounted realm must be world-readable (0644).
- **Overriding `defaultClientScopes` drops `sub`.** Replacing the client's scopes
  with custom ones removed Keycloak's built-in `basic` scope, so user
  (password-grant) tokens had no `sub` — which Beamhall requires (identity +
  audit). Client-credentials tokens still had `sub`, which is why the earlier
  BYO test passed and this didn't. Fix: a username→`sub` mapper on the audience
  scope, which also makes `sub` a stable, predictable value (`builder`,
  `it-admin`) that matches the identities `setup-bundled-idp.sh` registers.
- **`docker0` missing after the nested-virt reboot** broke default-bridge
  containers (Keycloak); `systemctl restart docker` recreated it. Per-beamhall
  bridges were unaffected.

Two gotchas the demo surfaced:

- **`engines.node` pin → `libatomic.so.1` missing (`exit 127`).** Pinning
  `node >=18` made the buildpack pick a newer Node whose binary links
  `libatomic`, absent from the Paketo jammy run image; the beam crash-looped on
  boot. Dropping the pin (buildpack default Node) fixed it. The diagnose catalog
  correctly flagged "start command not found" but the real cause was in the log
  tail — keep showing the tail.
- **`admin:it` tokens still need a registered identity.** MCP `resolveActor`
  requires every actor — even IT — to map to a registered `Identity` (so every
  action audits against one); the `admin:it` scope is the membership *bypass*,
  not an identity bypass. The demo setup therefore registers the IT operator
  (`beamhalld admin register-identity`) in addition to the builder.

## Turnkey installer + bundled-IdP wiring (from-scratch pilot, Ubuntu 26.04)

Consolidated `preflight.sh` + `lab-bootstrap.sh` + the service install into one
idempotent `packaging/install.sh` (groups: baseline / substrate / appliance) and
validated it from a **bare-OS Proxmox snapshot** (`qm rollback 104
vm_host_root_mmkey`). Bugs a real admin would have hit, each now fixed:

- **Docker's official repo has no `resolute` (26.04) package yet** though the
  Release file 200s. The installer's `apt-cache policy docker-ce` candidate check
  falls back to the distro `docker.io` (29.1.3) and then **hard-verifies runc ≥
  1.2.8** — so it never silently ships a CVE-vulnerable runtime regardless of
  source. The dual-path + verify is the "no dependency quirks" guarantee.
- **`/etc/beamhall` must exist before the build-daemon config is written** (it was
  created only in a later group).
- **Caddy's init config can't live under `/etc/beamhall`** (0750 root:beamhall) —
  the `caddy` user can't traverse it (`permission denied`). Moved to `/etc/caddy`.
- **`beamhalld --version` starts the daemon** (unknown args fall through to "run
  the server"), so using it as an install smoke check *hangs* the installer.
  Removed; the systemd start is the real smoke. (Fixed: beamhalld now has
  `version`/`help` subcommands and rejects unknown commands/flags with exit 2
  instead of starting the daemon.)
- **`age-keygen` comment lines break the key parser** — beamhalld doesn't skip the
  `# created:` / `# public key:` lines, so it parses a comment as the key and
  fails `malformed secret key: mixed case`. Write **only** the `AGE-SECRET-KEY-`
  line.
- **Bundled Keycloak on the default `docker0` bridge fails** (docker0 drifts away;
  Beamhall never uses it). Gave Keycloak its own `beamhall-idp-net`, like the
  managed Postgres/registry containers.
- **Gateway boot-apply bug (code):** `orch.Boot` pushed Caddy config only by
  iterating beam routes, so with **zero beams the static IdP route was never
  materialized** — the IdP/Admin console were unreachable until the first deploy.
  `Boot` now calls `gw.Apply` unconditionally. Added `Apply` to the orch
  `GatewayAPI` interface.
- **Postgres attach hardcoded `bh-postgres` (code):** after the product rename to
  `beamhall-postgres`, `create_database`'s beam-side attach used a stale name.
  Now uses `cfg.PGBeamHost`.

End-to-end proof: from bare OS, one `install.sh` run → `/healthz` green; then
`setup-bundled-idp.sh` → a real `builder` token (Keycloak ROPC) carries the right
`aud` (`http://beamhall.internal/mcp`), `sub` (`builder`), and scopes, and
beamhalld accepts it at `/mcp` (HTTP 200). Internal pilot runs gateway TLS-off
(`http://` issuer); production flips TLS on with real DNS.

### runsc breaks Docker's embedded DNS → managed DB unreachable by name (fixed)

Running the canonical demo on a **runsc (regulated) workspace** deployed and
served (HTTP 200), but the app's managed-Postgres calls silently failed
(`database error: EAI_AGAIN`). Root cause: **gVisor's network sandbox cannot
reach Docker's embedded DNS** at `127.0.0.11` (`ECONNREFUSED` from inside a runsc
beam; works fine under runc). Since the DSN dials the Postgres container
*hostname* (`beamhall-postgres`), name resolution fails on the regulated tier.
Connectivity by IP worked (`172.21.0.2:5432` reachable) — only DNS-by-name broke.
The only gVisor-level workaround is `--network=host`, which defeats the isolation
being certified.

Fix (driver, runtime-agnostic): at deploy, `DockerDriver.peerHosts` enumerates the
beam network's existing endpoints and injects them as `--add-host name:ip`
(`HostConfig.ExtraHosts`), so beams resolve same-network peers — notably the
managed Postgres — via `/etc/hosts`, never the embedded DNS. Verified: a fresh
runsc beam's `/etc/hosts` carries `beamhall-postgres`, it connects by name, and
the live DB-backed counter increments with no error. This is the kind of gap that
only a real runsc-tier run surfaces — the demo's HTTP 200 hid a dead DB path.

## Bundled IdP + `claude mcp add` (real employee onboarding over internal TLS)

Driving a real employee through `claude mcp add` against the bundled Keycloak (on
the internal-CA TLS path) surfaced a chain of gaps — each a real seed-realm/flow
fix, all now baked into `realm-template.json` / `setup-bundled-idp.sh` /
`install.sh` so the next admin skips them:

- **Internal TLS needs the gateway endpoints fronted at the base domain.** Added
  an internal-CA TLS mode (`BEAMHALL_GATEWAY_TLS=internal`, Caddy local CA branded
  "Beamhall Internal Root CA") and a static gateway route `base-domain ->
  beamhalld`, so `https://<base>/mcp` + `/admin` work over the internal cert (not
  just the raw :8443 port). `install.sh --tls internal` installs the CA into the
  host trust store (beamhalld trusts the IdP over https) and prints it for client
  distribution. **beamhalld must trust the CA** for OIDC discovery; **regenerating
  the CA in place must also clear `certificates/` leaves** (stale leaf served).
- **MCP SDK loopback guard 403s gateway-proxied requests** (gateway dials loopback
  but presents the real Host). Disabled it (`DisableLocalhostProtection`);
  `auth.CheckOrigin` already covers DNS-rebinding/CSRF.
- **`admin:it` must not be in the agent `scopes_supported`** — a DCR/agent client
  requesting it would set `Actor.ITAdmin` (escalation). Dropped from `AllScopes`;
  IT capability is console-only.
- **DCR is a rabbit hole; use a pre-registered client instead.** Keycloak's DCR
  policies (Trusted Hosts; Allowed Client Scopes; default-scope-can't-be-requested;
  no defaults assigned when a `scope` field is sent) fight the flow. Pivoted to
  `--client-id beamhall-agent` (`claude mcp add` supports `--client-id`). The realm
  configures `beamhall-agent`: `beamhall-audience` **default** (aud/sub), capability
  scopes **optional** (so they're explicitly requestable — a *default* scope can't
  be requested), `offline_access` allowed, loopback redirect wildcards.
- **Seed users had no realm roles** → "Offline tokens not allowed". Added the
  `offline_access` role to `builder`/`it-admin`.

End state, live-verified: an engineer ran `claude mcp add --client-id
beamhall-agent`, logged in via the browser, and built+deployed a beam — no manual
OAuth surgery.

## Clone enabled — Beamhall is the home of the beam's source (live-verified)

The managed per-beam repo is now **cloneable**, so no external git host is needed
(`get_repo` tool + `gitserver` upload-pack). The git server always *could* serve
clone (go-git's `server.NewServer` speaks both); it had been gated to push-only.
Validated on the appliance against the existing `pilot/hello` beam:

- ROPC builder token (`scope=openid beams:write`, `aud=https://beamhall.internal/mcp`,
  `sub=builder`) → MCP `tools/call get_repo` returned a `git clone` command with a
  read token (and matching `structuredContent`).
- **`git clone` with stock git 2.53 over the internal-CA gateway TLS** pulled the
  real source (`server.js`, `package.json`, `.mcp.json`) and full history (3
  `deploy snapshot` commits) — clone works behind the same TLS/host as deploy.
- Negative path holds: `upload-pack` info/refs with **no token → 401**, **bad
  token → 403**.
- **Token kinds don't cross** (`gitserver.TokenStore`): push (one-time, 15m) vs
  read (reusable within TTL, 1h); a push token can't clone, a read token can't push
  (unit `TestCloneWithReadToken` / `TestReadTokenStore`).
- **Consequence (design):** the repos volume (`<DataDir>/repos`) is now **canonical
  source** — back it up at the Postgres tier. A browsable web git host
  (Gitea/Forgejo) is intentionally out of scope (add only if humans need to browse
  code/branches/PRs in a UI).
- **Cosmetic gotcha (not our bug):** the `hello` repo carries macOS AppleDouble
  `._*` files — they rode in from the original Mac-side push and now appear in
  clones. Harmless; a `.gitignore`/strip handles it.

Method note: the validation drove the real MCP JSON-RPC (`initialize` →
`notifications/initialized` → `tools/call`) over Streamable HTTP with a Bearer
token, the same surface Claude Code uses — not a server-side shortcut.

## `list_beams` discovery — membership-scoped (live-verified)

The agent had no way to discover existing halls/beams (every tool was
slug-addressed; `beamhalls:read` scope was defined but unused). Added `list_beams`
— the entry point on a fresh machine, complementing `get_repo`. Live on the
appliance: a builder ROPC token (`scope=openid beamhalls:read`) → MCP
`tools/call list_beams` returned `pilot (your role: builder) — 1 active beam(s):
hello [preview/paused]`. Membership scoping + scope-gating unit-proven
(`TestListBeamsMembershipScoped`): a registered identity with no memberships sees
nothing — not even that another team's beamhall exists — and a token lacking
`beamhalls:read` is refused. Archived beams are excluded (`ListBeamsByBeamhall`
filters `status='active'`).

## `archive_beam` — builder self-service shelving (live-verified)

For the "preview rejected → shelve it" case: `destroy_beam` was already a
soft-archive (`Status=archived`, source + audit retained, slug freed) but
IT-gated. Added **`archive_beam`** sharing that archival path, but
**builder-accessible and preview-only** (orch `archivePreview` refuses live
beams; `destroy_beam` remains the IT-gated live teardown). Live on the appliance,
non-destructively (the `hello` demo was left intact): a builder token
(`scope=…beams:write beams:operate beamhalls:read`) ran create_beam
`archive-probe` → it showed in `list_beams` → `archive_beam` → it vanished from
the active list while `hello` remained. Unit coverage: `TestArchiveBeamTool`
(operate-scoped tool), `policy.TestRoleMatrix` (builder grants archive, never
destroy; viewer denied), `orch.TestArchivePreviewBuilderSelfServiceLiveGated`
(preview archived + slug freed; live beam refused with status unchanged).
Decisions (builder self-service; terminal + data-retained) locked with the
operator.

## deploy_beam push remote was text-only → invisible to structured-output clients (fixed)

A real MCP user (Claude Code) reported the git push path "broken": `deploy_beam`
(no source) "returned no push remote," only `{beam,beamhall,mode,state}`. The
server was **not** at fault — a raw JSON-RPC probe confirmed `deploy_beam` returns
the `git push …` command in the result's `content` **text** block. The real cause:
**Claude Code surfaces only `structuredContent` to the model when a tool declares
an output schema, and drops the `content` text array.** `deploy_beam`'s structured
output carried only `{beam,beamhall,mode,state}` — the push command + one-time
**write** token lived solely in text, so the agent never saw them and fell back to
`get_repo`'s read-only token (→ 403). `get_repo` was unaffected because its
structured output already carried `clone_url`.

Fix: the no-source branch now puts `git_remote` + `push_command` (token embedded)
in **structuredContent** (regression `TestDeployBeamNoSourceSurfacesPushRemoteInStructured`).
Verified end-to-end by the real Claude Code agent against the appliance:
`deploy_beam` → `push_command` from structured output → `git push` → buildpack
build → deployed → `curl` preview URL **HTTP 200**.

**Lesson (general):** any *actionable* tool output (commands, tokens, URLs, IDs)
must live in **structured output**, not only the human-readable text block — a
text-only payload is invisible to clients that prefer `structuredContent`. Audited
the other tools: URL-returning ones (`resume_preview`/`promote_to_live`/`rollback`)
already put the URL in the struct, and text-only tools
(`create_database`/`set_secret`/`show_logs`) declare no schema so their text is
surfaced. `deploy_beam`'s git branch was the only leak.

## Non-technical-user simulation — hardening the deploy loop (7 driven agent runs)

Drove a real Claude Code agent with a **purely non-technical prompt** ("HR person,
knows nothing about apps/servers/git, wants an RSVP web page with a results page")
to test whether the MCP *guides* a clueless user and *does the right thing*. The
high-level guidance held every run — the agent discovered the beamhall via
`list_beams`, created the beam + DB + secret, built a DB-backed app, deployed, and
correctly punted the "permanent link" to IT (`promote_to_live` is IT-gated). But
the deploy loop was a friction trap; each root cause is now fixed, measured by the
agent's effort across runs (`deploy_beam` calls **14 → 7 → 6 → 4 → 3**, git
divergence/delta/500 errors **many → 0**):

- **A failed build burned the one-time push token.** A first-build failure (e.g.
  Node version) consumed the token, so the natural "fix and re-push" hit `403`,
  and agents spiralled into `rm -rf .git` → divergent history → `fetch first` →
  blocked force-push. Fix: `gitserver` spends the token **only on a successful
  deploy** (the commit is already on main, so fix-and-re-push just works). Plus a
  friendlier 403 ("run deploy_beam again for a fresh push command").
- **go-git receive-pack cannot resolve REF_DELTA packs** ("reference delta not
  found" → HTTP 500/400). The *first* push (empty repo) works; every *redeploy*
  sent a delta-compressed pack go-git choked on — the real reason agents kept
  re-initializing. `--no-thin` alone was insufficient (go-git fails on
  self-contained deltas too). Fix: the push command disables delta compression
  (`git -c pack.window=0 push --no-thin …`) → a delta-free pack go-git always
  decodes. **Verified: 3 consecutive pushes (1 first + 2 redeploys) all deploy,
  0 server delta errors.** Belt-and-suspenders: the server now returns a 400 with
  a `--no-thin` hint instead of an opaque 500.
- **Teardown leaked the database** → `max_db_count` quota silently exhausted over
  archive/redeploy cycles. Fix: destroy/archive now drops the backing Postgres
  db/role and deletes the resource row (new `DeleteResource`), reclaiming the
  slot. Verified live: archiving a beam dropped its db and freed the quota.
  Also: `create_database` is now **idempotent** per `(beam,name)`.
- **Teardown kept the managed git repo** → a *reused* slug (slugs are freed for
  reuse) inherited the archived beam's history → divergence. Fix: destroy/archive
  **retires the repo aside** (`<hall>/.retired/`, preserving the source per the
  "data retained" decision) so a reused slug starts from a fresh empty repo.
  Verified live + unit (`TestRetireFreesSlugForFreshRepo`).

Net: the final run published a working DB-backed, password-gated RSVP app with
**3 `deploy_beam` calls and zero git-divergence/delta/500 errors** — a clueless
user's agent now gets a clean path. Regression tests:
`TestFailedDeployKeepsTokenValid`, `TestCreateDatabaseIdempotent`,
`TestDestroyReclaimsDatabase`, `TestRetireFreesSlugForFreshRepo`,
`TestDeployBeamNoSourceSurfacesPushRemoteInStructured`.

## Dual-channel beams (preview + live) — 2026-06-16

Added a persistent **live channel** alongside the **preview** channel so a beam
can be iterated after it is in production (`promote_to_live` now *pins* the live
channel to the preview's current build instead of flipping mode and destroying
the preview). Findings/gotchas from building it:

- **sqlc lexer is byte-offset based — a non-ASCII char in a query comment
  corrupts the *next* generated query.** A `→` (3 bytes, 1 rune) in a `-- name:`
  comment shifted sqlc's slice offsets so the following `UPDATE … WHERE id = ?`
  generated as `WHERE id =` (the `?` dropped) → runtime `near "?": syntax error`.
  Invisible until a query actually ran. **Rule: keep `internal/store/queries/*.sql`
  ASCII-only.** (Hit on `beams.sql`; fixed by replacing the arrow.)
- **Per-channel data isolation needed a `channel` column on `resources` AND
  `secrets`** (migration `0007`), plus widening the secrets unique index to
  `(beamhall_id, beam_id, key, channel)` so the same app key (e.g. `MAIN_URL`)
  holds a *different* DSN per channel. The live workload reads the canonical
  `/run/secrets/MAIN_URL`; only the sealed value differs by channel.
- **Live DB vs `MaxDBCount` quota.** Promote provisions a *second* physical
  Postgres DB for the live channel. Counting it against `MaxDBCount` would block
  promote for any beam that has a database (the lab world runs `MaxDBCount=1`).
  Decision: the live DB is a **logical mirror** of an already-counted preview DB
  and does **not** additionally count (`CountResourcesByBeamhallAndType` excludes
  `channel='live'`); the live-slot limit still bounds how many beams go live.
- **Failed promote must not drop production.** The new live workload comes up
  healthy *before* the stable hostname is repointed (`gateway.Upsert` swaps
  atomically) and the old live workload is torn down only after. First promote
  reverts its reserved live slot on failure. Verified by unit tests; preview
  keeps running + auto-pausing throughout.

Regression tests: `TestPromoteIsolatesLiveDatabase` (own DB per channel under the
same key; re-promote reuses it; destroy drops both), `TestRollbackReactivatesPriorRelease`
(live-channel rollback), `TestPromoteBuilderDeniedAdminAllowed` (preview survives
promote), `TestSchedulerPauseFuncPausesViaOrchestrator` (preview still pauses
after promote), plus the updated `internal/domain` FSM suite.

**Lab deploy (2026-06-16):** cross-compiled `beamhalld` deployed to the VM; the
daemon **booted cleanly** (migration `0007` applied — a failed migration aborts
boot), routes restored, scheduler armed, and the pre-existing `anniversary-party`
beam survived intact. `list_beams` over real MCP returned the new dual-channel
surface (`mode`/`state`/`preview_url`, `[preview:running]` text). DB backed up at `beamhall.db.pre0007.bak`.

**Full agent-driven E2E (2026-06-16, beam `dualdemo` in `pilot`).** Real
buildpack builds (tarball → `pack` jammy-base → registry), real Caddy, real
Postgres, driven over MCP as builder + it-admin:
1. `create_beam` → `create_database main` → `deploy_beam` (v1) → preview serves
   `connected db = bh_pilot_dualdemo_main`.
2. builder `promote_to_live` **denied** by the PEP (`role "builder" does not
   grant "promote_to_live"`); it-admin promotes → live URL
   `dualdemo.pilot.beamhall.internal`. Postgres now has **two** databases —
   `bh_pilot_dualdemo_main` (preview) and `bh_pilot_dualdemo_live_main` (live);
   the live URL serves the live DB, the **preview URL keeps serving** its own DB
   (preview survived promote). Same image, same `MAIN_URL` key → different DSN
   per channel. **Isolation proven on real Postgres.**
3. Edit app → `deploy_beam` (v2) to preview: preview serves v2, **production
   stays v1** (the "iterate after shipping" use case). Re-promote → production
   rolls forward to v2, the live DB is **reused** (no third DB; production data
   preserved); stable URL repointed (zero-downtime).
4. `rollback to_version=2` → production back to v1, **preview still v2**
   (production rollback leaves the preview channel alone). Default `rollback`
   (no version) was cleanly guarded ("already serving production").

**Fixed (channel-aware rollback target).** The MCP `rollback` tool's default
target picker was channel-naive — it picked the preceding *version* across both
channels, so for a promoted beam it resolved to the current live release
(orchestrator-guarded: "already serving production") or a preview build, never a
valid prior production release. Fix: each `Release` now records the channel it
served (`releases.channel`, migration `0008`; deploy mints preview, promote mints
live), and `pickRollbackTarget` considers ONLY prior live releases — default =
most recent live release that isn't currently serving; `to_version` matches
within live history. **Verified live:** after promote (v2), a `rollback` with no
`to_version` rolled production back to v1 automatically (previously errored).

## Audit retention (checkpoint-anchored pruning) — 2026-06-17

The hash-chained audit log is append-only (deleting rows breaks Verify), so
bounded growth is achieved by a **checkpoint-anchored prune**: record the cut
seq + chain hash, delete through it, and Verify resumes from the latest
checkpoint (migration `0009`, `internal/audit/prune.go`).

**Verified live** against the real 214-event lab log:
- `prune-audit -keep 40 -dry-run` → "would prune 174 of 214".
- `prune-audit -keep 40` → "pruned 174 … surviving chain verified ✓"; 40 remain;
  `audit_checkpoints` row through_seq=174.
- Re-prune `-keep 40` → "pruned 0 … verified ✓" (idempotent — the prune is NOT a
  chain event, so KeepLast stays exact).
- A fresh audited action (a real `promote_to_live`) appended across the
  checkpoint and the chain kept verifying (Verify resumes at the anchor, then
  walks the survivors + new events).
- Unit: `TestPruneThenUncheckpointedDeletionStillDetected` — a raw `DELETE` of a
  survivor with no checkpoint is still caught by Verify (seq gap / prev_hash).

Manual: `beamhalld admin prune-audit -keep-days N|-keep N [-dry-run]`. Auto:
opt-in `BEAMHALL_AUDIT_RETENTION_DAYS` (prune on boot + daily). No SIEM export in
this build — pruned events are gone; the checkpoint records when/who/how many.

## From-scratch MCP-driven pilot + first public releases — 2026-06-21

A full bare-host → live-beam run **driven over MCP**, from a clean Proxmox
snapshot, simulating a first-time IT admin. Produced `docs/getting-started.md`
(the IT play) and shipped the first public releases. Bugs/gaps caught (each is a
"the documented streamlined path didn't exist / didn't work" finding that no unit
test could surface):

- **No release pipeline (FIXED, v0.1.0).** `install.sh` only took a *local* binary
  path; `.goreleaser.yaml` was draft-only; no tag/release/CI existed — so the
  public install story ("`curl … install.sh | bash`") was impossible. Added
  `.github/workflows/release.yml` (tag-triggered GoReleaser → published assets +
  `checksums.txt`), an `install.sh` **GitHub-release fetch path** (resolve latest
  or `--version`, download by arch, **verify checksum**; local path stays the dev
  fast-path), and flipped goreleaser to publish-on-tag. Dogfooded: `curl|bash`
  installed `beamhalld 0.1.0`, `/healthz` ok.
- **`admin_create_beamhall` created a ZERO-quota, unusable workspace (FIXED).** A
  workspace made over MCP got `ResourceQuota{}` → every `create_beam` failed
  `max_beams 0 of 0`. Quota is baked into the immutable SecurityContext at create
  and there is **no edit path** (no `admin_set_quota`), so the workspace was
  permanently dead. Fix: default `5 beams / 1 live / 2 db` + optional
  `max_beams/max_live_slots/max_databases` overrides, mirroring the Admin console.
  **Gotcha:** the live-slot gate reads `EffectiveLiveSlotLimit =
  min(beamhalls.live_slot_limit, quota_json.MaxLiveSlots)` — **two** places
  (a column *and* the JSON), both set from `spec.LiveSlots`/`spec.Quota`. The MCP
  fix sets `LiveSlots: q.MaxLiveSlots` so both move together; the pre-fix pilot
  workspace needed both patched to promote.
- **Bundled IdP wasn't a real one-liner (FIXED, v0.1.1).** `setup-bundled-idp.sh`
  reads two sibling files (`realm-template.json`, `beamhall-keycloak.service`) via
  `$HERE`, and `install.sh`'s post-install hint pointed at a **repo-relative path**
  that doesn't exist after a `curl|bash` install. Fix: the script **self-fetches**
  its siblings from `BEAMHALL_REF` when run without a checkout; the install hint now
  prints the `curl|bash` one-liner pinned to the installed tag; the release archive
  bundles the keycloak assets.
- **`admin:it` over a real agent client (FIXED — role-gated admin, v0.1.2).**
  `claude mcp add` has no OAuth-scope flag and requests only the *advertised*
  scopes — `admin:it` is hidden by design — so a normal browser-OAuth connection
  couldn't obtain it. Fix: Beamhall now derives IT-admin from the `admin:it` scope
  **OR** a configurable realm role (`BEAMHALL_OAUTH_ADMIN_ROLE`, default
  `beamhall-it`); the verifier extracts `realm_access.roles` into the token info,
  and `resolveActor` accepts either at the gate and the PEP-bypass. The bundled
  realm gained the `beamhall-it` role + a public **`beamhall-admin-agent`** client
  (full capability scopes by default + a realm-roles mapper); the role is assigned
  to `it-admin`. Lab-verified live: `it-admin` via `beamhall-admin-agent` (role,
  **no `admin:it` scope**) → `admin_*` works; `builder` via the same client →
  `insufficient_scope: requires IT-admin (the "admin:it" scope or the "beamhall-it"
  role)`. The role is user-gated in the IdP, so an ungated client can't manufacture
  admin. Header-token path (ROPC `admin:it`) and the Admin console still work.
  Unit-tested (`TestITAdminViaRealmRole`, `TestNonAdminRoleDoesNotElevate`). For an
  existing persistent IdP, add the role+client+assignment via the Admin REST (the
  realm import only seeds a fresh install). See `docs/getting-started.md` Part 3B.

**runsc money-shot re-confirmed on the freshly installed v0.1.1 appliance:** the
beam ran `runtime=runsc`, kernel `4.19.0-gvisor`, read-only rootfs, all caps
dropped, no-new-privileges, on a per-workspace bridge; managed Postgres reachable
by name; sealed-secret greeting + live counter worked. Builder self-promote denied
by role; IT promote → stable live URL with a separate live DB. Releases: **v0.1.0**
(install path) and **v0.1.1** (usable MCP workspaces + one-liner bundled IdP),
both public, checksum-verified.
