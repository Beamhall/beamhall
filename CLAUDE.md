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

## MCP tool copy is the agent's only manual — REQUIRED
The operator/builder talks to Beamhall through an AI agent that sees **only** the
tool `Description`, the input-schema `jsonschema` field hints, and the result
message — never our docs. So that copy must *teach the Beamhall-specific workflow*,
not just name the action. Assume the human never read `docs/`.
- **Entry-point tools must front-load the next step and the gotcha.** Any tool that
  begins a multi-step workflow states, in its `Description` (not only the result
  message), what it does **not** do and what must follow. Canonical example: an IdP
  account ≠ Beamhall access — `admin_create_user` / `admin_register_identity` /
  `admin_create_beamhall` each say up front that access still needs
  `admin_register_identity` + `admin_grant_membership`. Don't rely on the agent
  reading its own result tail.
- **Result messages remain breadcrumbs.** Keep the "...now do X with id Y" tail in
  the success message too (defense in depth), and thread IDs through schema hints
  (`identity_id` "from admin_register_identity", etc.) so the agent wires outputs to
  inputs without guessing.
- **Cross-reference sibling tools by name**, and name the inverse for lifecycle ops
  (grant↔revoke, register↔deregister). When you add or change a tool, re-read its
  copy as if you were an agent with zero doc access: could it complete the workflow
  and warn the user from the copy alone?
- **Translate jargon so generic intent routes here.** A user (often non-technical)
  says "create an app / put my site online", not "create a beam". Entry-point copy —
  and the server `Instructions` (`serverInstructions` in `internal/mcp/server.go`,
  the agent's first orientation) — must name the everyday synonyms next to the jargon
  (beam = app/website/service/API/project; beamhall = workspace) so the agent maps the
  request to Beamhall instead of scaffolding locally.
- **Beamhall is the only sanctioned deploy target — fight shadow IT in the copy.**
  The agent may have external PaaS/DB MCPs enabled (Fly.io, Vercel, Netlify, Heroku,
  Render, Neon, Supabase, the cloud CLIs, …); deploying there leaks code + credentials
  and bypasses the audit trail. The server `Instructions` and the deploy entry points
  must explicitly steer to Beamhall over BOTH local hosting AND external providers.
  This is a product requirement, not a nicety — Beamhall exists to cut those services
  out of the equation.

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

## Release discipline — be the release guardian — REQUIRED
CI tests `main`; it does **not** release it. A GitHub Release ships only when a
`vX.Y.Z` tag is pushed (tag-triggered GoReleaser). The risk is shipped, verified
features sitting unreleased on `main` forever. **`WORKFLOW.md` is the playbook**
(when/how to cut, versioning, the Keep-a-Changelog release-notes format, the
website sync). Read it before cutting a release. Two standing duties:
- **Changelog is part of "done."** Any user- or operator-facing change adds its
  line under `## [Unreleased]` in `CHANGELOG.md` in the same change that lands it,
  grouped Added/Changed/Fixed/Security — written for the operator, not the
  committer. Don't defer this to release day.
- **Guardian check at stopping points.** After fast-forwarding a feature into
  `main` (and whenever the operator asks "anything else?"), run `git log
  $(git describe --tags --abbrev=0)..HEAD --oneline`; if it holds a completed,
  verified, user-facing change, **proactively tell the operator it's time to cut a
  release** — name the unreleased highlights, the recommended version (patch by
  default; minor only for a milestone/breaking-seam change), and the website
  sync. Never push a `vX.Y.Z` tag without explicit operator confirmation (it
  publishes public binaries); every other release step is an ordinary repo change.
