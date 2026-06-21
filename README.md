<div align="center">

# Beamhall

**Agent-built apps, infrastructure included.**

_The self-hosted backplane for internal apps your AI agents build — they inherit
compute, data, secrets, identity, and secure connectivity instead of wiring it._

[Website](https://beamhall.com) · [Security](https://beamhall.com/#security) · [Threat model](docs/threat-model.md) · [Roadmap](https://beamhall.com/#roadmap)

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8.svg)
![Status](https://img.shields.io/badge/status-pre--1.0%20%C2%B7%20validated-orange.svg)

</div>

---

Beamhall is a **self-hosted application backplane** built on
[MCP](https://modelcontextprotocol.io). AI coding agents (Claude Code first) build
and deploy internal apps — **beams** — by intent alone. Each beam **inherits
everything it needs to run** — compute, data, secrets, identity, and secure
connectivity to your internal systems — as managed capabilities from Beamhall. The
agent never provisions, configures, or holds credentials for any of it.

```
AI agent  ──intent──►  Beamhall backplane  ──provisions──►  your beam
(no infra access)      runtime · data · secrets ·           inherits it all,
                       identity · connectors                 governed + audited
```

The agent asks for a capability — a database, a secret, user authentication, a
connection to the ERP — and Beamhall provisions it behind policy, handing back a
handle, never the wiring.

## Why Beamhall

- **Apps inherit their infrastructure.** A beam gets a hardened runtime, a managed
  database, and secrets today — with end-user **identity** and secure **connectors**
  to internal systems (ERP, integrations) on the near-term roadmap — each
  provisioned by Beamhall under policy and audited. The agent declares the need; it
  never sees a credential, an endpoint, or a config file.
- **A reliable path, not improvised infrastructure.** Ask a typical agent to deploy
  and it improvises — GitHub Actions, Fly.io, Neon, a guessed Dockerfile, a
  half-remembered cloud CLI. Beamhall gives it one documented tool surface and a
  built-in knowledge base, so it ships the same known-good, governed way every time
  — and nothing leaves your environment.
- **IT decides where apps run.** A private VM, a dedicated VPC, or fully on-prem,
  per workspace — for heavy-compliance or strictly-internal workloads. The gateway
  is the single ingress and egress is default-deny, so there is no cloud security
  group or load balancer to misconfigure into accidental public access.
- **No raw credential reaches the agent.** A consequence of the model: there is no
  `get_secret` tool, `set_secret` is write-only, and `create_database` returns a key
  and a file path, never a connection string.

## Security properties

- **No raw credential reaches the agent.** No `get_secret` tool; `set_secret` is
  write-only; `create_database` returns a key and a file path, never a connection
  string.
- **One audited policy point.** Every action passes a single backplane Policy
  Enforcement Point and is recorded on a **hash-chained, append-only audit log**,
  verified at boot.
- **Immutable hardening baseline.** cap-drop ALL, no-new-privileges, read-only
  rootfs, seccomp + AppArmor, cgroup v2 ceilings, userns-remap — chosen by IT,
  unchangeable by the agent, re-asserted on every deploy.
- **Default-deny egress.** Per-workspace bridge with an always-deny set (cloud
  metadata, link-local, host, management subnet). The agent has no tool to widen
  it.
- **Stronger isolation on demand.** Flip one field to run a workspace under
  **gVisor (`runsc`)** — a userspace kernel that keeps workloads off the host
  kernel, no KVM required. A Firecracker microVM tier is the documented upgrade
  path.
- **Proven, not asserted.** A negative-security suite (`TestAgentCannot`) makes a
  builder holding *every* scope attempt to read secrets, escape its workspace,
  mutate its posture, and exfiltrate data — and proves each attempt fails.

The full, honest treatment — including the **residual risks Beamhall does not
eliminate** — is in [`docs/threat-model.md`](docs/threat-model.md) and on the
[website](https://beamhall.com/security/threat-model/).

## Status

The entire MUST-HAVE security surface is **built and validated end-to-end**,
including a from-scratch install driven entirely by an agent over MCP, on both the
hardened `runc` and gVisor `runsc` tiers. Beamhall is **pre-1.0**; the next
milestone is validation with design-partner deployments. See
[`docs/STATUS.md`](docs/STATUS.md) for the authoritative status and
[the roadmap](https://beamhall.com/roadmap/) for what's planned.

## Build

Requires **Go 1.26+**.

```sh
go build ./...
go vet ./...
go test -race ./...
```

Integration tests (Docker, root, a hardened runtime) are gated behind
`BEAMHALL_DOCKER_IT=1` and run against a Linux test appliance — see
[`docs/STATUS.md`](docs/STATUS.md).

## Documentation

| Doc | What it is |
|---|---|
| [`docs/PLAN.md`](docs/PLAN.md) | The design contract: architecture, security model, scope, decisions. |
| [`docs/STATUS.md`](docs/STATUS.md) | Living status: what's built, package layout, how to run things. |
| [`docs/threat-model.md`](docs/threat-model.md) | The security/sign-off artifact: attack → mitigation → residual → test. |
| [`website/`](website/) | The public site (Astro + Starlight → Cloudflare Pages). |

## Project layout

```
cmd/beamhalld/      the single-binary appliance (MCP + backplane + admin)
internal/domain/    entities + Beam lifecycle FSM (pure)
internal/driver/    RuntimeDriver interface + Docker impl (runc / gVisor runsc)
internal/egress/    iptables DOCKER-USER egress reconciler (default-deny)
internal/scheduler/ durable preview-pause scheduler
internal/gateway/   Caddy Admin-API gateway client
internal/store/     SQLite control-plane store (sqlc)
internal/secret/    age secret vault (write-only) + log scrubber
internal/audit/     hash-chained append-only audit log
internal/policy/    Policy Enforcement Point (role/action matrix, quota gates)
internal/orch/      orchestrator: the lifecycle reconciler behind the PEP
internal/build/     source → image pipeline (Cloud Native Buildpacks)
internal/resource/  managed-resource provisioners (Postgres)
internal/auth/      OAuth resource server (JWKS / iss / aud / scope validation)
internal/mcp/       agent-facing MCP server (the fixed tool surface)
internal/web/       IT Admin console (OIDC)
internal/gitserver/ git smart-HTTP push transport
website/            marketing + documentation site
docs/               PLAN.md, STATUS.md, threat-model.md, and more
```

## Contributing

Contributions are welcome — please read [`CONTRIBUTING.md`](CONTRIBUTING.md) first,
especially the note on the two stable seams (the `RuntimeDriver` interface and the
MCP tool contract). Found a security issue? See [`SECURITY.md`](SECURITY.md) — do
**not** open a public issue. Participation is governed by our
[Code of Conduct](CODE_OF_CONDUCT.md).

## License

[Apache License 2.0](LICENSE). © 2026 The Beamhall Authors.
