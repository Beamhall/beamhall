# Contributing to Beamhall

Thanks for your interest in Beamhall. It is a security-sensitive project — an
infrastructure backplane that deliberately stands between an untrusted AI agent
and real infrastructure — so contributions are reviewed with that lens. This
guide explains how to get a change in.

## Before you start

- **Found a security vulnerability?** Do **not** open a public issue. Follow the
  responsible-disclosure process in [`SECURITY.md`](SECURITY.md).
- **Have a feature idea or a question?** Open a GitHub Discussion or an issue
  first so we can agree on the approach before you write code. For anything that
  touches the security model, this is required — see "The two stable seams" below.

## Development setup

Beamhall is a single Go binary. You need **Go 1.26+**.

```sh
git clone https://github.com/Beamhall/beamhall.git
cd beamhall
go build ./...
go vet ./...
go test ./...
```

The full gate that every change must pass:

```sh
go build ./... && go vet ./... && go test -race ./...
gofmt -l .   # must print nothing (excluding generated code under internal/store/db/)
```

Some tests are **integration tests** that require a Linux host with Docker, root,
and a hardened runtime. They are gated behind `BEAMHALL_DOCKER_IT=1` and are not
run by the default `go test`. See `docs/STATUS.md` for how they are run against a
test appliance. A unit-test-only change does not need them, but a change to the
driver, egress, gateway, or end-to-end flow does.

## The two stable seams — handle with care

Two interfaces are deliberately stable; changing them affects security and
compatibility, and they get extra scrutiny:

1. The **`RuntimeDriver` interface** (`internal/driver`) — the boundary the Docker
   runtime sits behind (and a future Firecracker driver will sit behind).
2. The **MCP tool contract** (`internal/mcp`) — the fixed surface the agent sees.

If your change adds, removes, or alters an agent-facing tool, or weakens any part
of the hardening baseline, egress model, or audit chain, **open an issue first.**
A PR that quietly widens the agent's blast radius will not be merged.

## Coding conventions

- Write code that reads like the surrounding code — match the existing naming,
  structure, and comment density.
- Keep the documentation current. A change isn't complete until the relevant doc
  reflects it:
  - `docs/STATUS.md` — status, package layout, decisions (read first by the next
    contributor).
  - `docs/PLAN.md` — design/scope changes.
  - `docs/threat-model.md` — any change touching the security posture, with the
    mitigation cited to a test.
  - The website under `website/` if a public-facing security claim changes.
- The store layer uses [sqlc](https://sqlc.dev). Regenerate with
  `cd internal/store && go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1 generate`
  after editing `queries/*.sql`. Keep query files ASCII-only.

## Tests are part of the change

Beamhall's security claims are backed by tests — most notably the
negative-security suite (`internal/e2e/TestAgentCannot`), where the agent holds
every scope and still cannot escape its boundary. If you change the security
surface, add or update the test that proves the new behavior. A claim without a
test is not a claim.

## Commits and pull requests

- Keep commits focused and the message descriptive of *what changed and why*.
- Open a pull request against `main`. Describe the change, the motivation, and how
  you verified it (which tests, and whether integration tests were run).
- By contributing, you agree your contribution is licensed under the project's
  [Apache-2.0 license](LICENSE).

## Code of conduct

Participation in this project is governed by the
[Code of Conduct](CODE_OF_CONDUCT.md).
