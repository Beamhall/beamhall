# Beamhall — agent guide

Beamhall is a self-hosted, **MCP-controlled infrastructure backplane** (Go single
binary) that lets AI agents safely build and deploy internal beams inside a
company-controlled environment, with **no raw credentials** ever reaching the
agent. Module `github.com/Beamhall/beamhall` (Go 1.26).

## Start here (cold start — read before doing anything)
1. **`docs/STATUS.md`** — the source of truth for *progress*: what's done, what's
   next, lab access, and exact test commands. (The in-session task list does NOT
   persist between sessions; STATUS.md does.)
2. **`docs/PLAN.md`** — the *design contract*: architecture, security model, MVP
   scope, phased plan, locked decisions, and findings baked in.
3. **`docs/lab-phase0-validation.md`** — hardware evidence + bugs the lab caught.
4. **`docs/threat-model.md`** — customer-facing security doc; every mitigation
   cites a test/lab finding (the regulated sign-off artifact).

## Build & test
- `go build ./... && go vet ./... && go test -race ./...`
- Integration tests are gated by `BEAMHALL_DOCKER_IT=1` and run on the lab VM
  (cross-compile `GOOS=linux GOARCH=amd64 go test -c`, `scp`, run as root). See
  each `*_integration_test.go` header and `docs/STATUS.md`.

## Test appliance (standing integration target)
A private VM is the standing integration target — `ssh root@$BEAMHALL_TEST_HOST`
(key auth, full root). The concrete address is kept out of this public repo (in
the maintainer's private ops notes), not committed. Provisioned by
`scripts/lab-bootstrap.sh`: Docker 29 + userns-remap, gVisor `runsc`, pack, Caddy,
plus the `bh-smoke-beam` test image.

## Conventions
- Git: feature branch → `git merge --ff-only` into `main` → push. **No PRs**
  (operator preference). Commit email `marcosmachado@gmail.com`. Never add AI
  attribution to commits/PRs.
- Keep the two stable seams stable: the `RuntimeDriver` interface and the MCP tool
  contract (PLAN §5.3, §5.7). Runtime is Docker-only behind the driver; gVisor
  `runsc` is a `runtime_class`, not a new driver (PLAN §3).

## Keep docs current — REQUIRED
Docs are part of "done." A change isn't complete until the relevant doc reflects
it. Whenever you change code/design or learn something, update:
- **`docs/STATUS.md`** — status, the next-steps list, package layout, and any
  decision. This is what the next agent reads first.
- **`docs/lab-phase0-validation.md`** — append every new lab finding, **gotcha**,
  or bug (with the fix and why it was invisible to unit tests).
- **`docs/PLAN.md`** — reflect any design/scope change, last-minute decision, or
  resolved open question (PLAN §10).

Prefer a short pointer/bullet over prose — enough for the next agent to follow a
coherent train of thought, not a re-explanation of how everything works.
