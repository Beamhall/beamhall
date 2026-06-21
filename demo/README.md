# Beamhall canonical demo

The one-command "watch Beamhall work" story: an AI agent, holding only a scoped
OAuth token and **never a raw credential**, builds and operates a real internal
beam — a small request tracker backed by a managed Postgres database.

It exercises the whole product (PLAN §7) against a *running appliance* through
the real MCP tool contract:

```
create_beam → set_secret → create_database → deploy_beam (preview URL)
→ show_logs (secret scrubbed) → promote denied for the builder (PEP)
→ promote as IT (live URL) → deploy v2 → rollback to v1
```

## What's here

| File | Role |
|---|---|
| `beam-app/` | The internal tool the agent ships — a Node app, **no Dockerfile** (buildpacks detect Node). Reads a write-only secret from `/run/secrets/API_TOKEN` and a managed DB DSN from `/run/secrets/MAIN_URL`. |
| `run-demo.sh` | Runs **on the appliance host**: does the IT setup (`beamhalld admin bootstrap` + `register-identity`), mints tokens from the IdP, then runs the agent flow. |
| `cmd/bh-demo` | The agent driver (built from the repo). Drives the MCP flow with narration. |

## Run it

On a host with `beamhalld` running and an IdP configured (the lab uses
`bh-devidp`):

```sh
# build the agent driver and the appliance binary
GOOS=linux GOARCH=amd64 go build -o /tmp/bh-demo   ./cmd/bh-demo
GOOS=linux GOARCH=amd64 go build -o /tmp/beamhalld ./cmd/beamhalld   # gains `admin`

# on the host:
BH_DEMO=/tmp/bh-demo BEAMHALLD=/usr/local/bin/beamhalld \
BEAMHALL_DATA_DIR=/var/lib/beamhall BEAMHALL_BASE_DOMAIN=<base-domain> \
  bash demo/run-demo.sh
```

For a real IdP (not the lab `bh-devidp`), mint the two tokens however that IdP
issues them and pass `BUILDER_TOKEN=… IT_TOKEN=…`; everything else is the same.
If the beam hostnames aren't resolvable from where you run it, pass the agent
driver `-gateway 127.0.0.1:80` (or `:443`) to probe through the gateway with a
`Host` header.

## What it proves

- **No raw credentials reach the agent.** The secret and the database DSN arrive
  as *files inside the workload*; the agent only ever sends a secret in and gets
  a key reference back. `show_logs` returns the boot line with the token
  `***REDACTED***`.
- **Real managed database.** `/api/status` reports `"database":"ready"` and the
  page's request counter increments on each visit — live Postgres writes from
  inside a cap-dropped, read-only-rootfs, egress-denied container.
- **Promotion is governed.** The builder holds the `beams:promote` scope yet is
  denied — the policy enforcement point requires an IT role. An `admin:it`
  operator promotes to the stable live URL.
- **Releases are reversible.** A v2 deploy followed by a one-call `rollback`
  returns the live URL to v1.

## Sample output

```
[4] deploy_beam
    source tarball → buildpacks (no Dockerfile) → hardened run → preview URL
    → preview URL: https://<id>.preview.<base-domain>
    ✓ live, HTTP 200 via the gateway
[5] show_logs
    | booted release=v1; api token is ***REDACTED***
    ✓ secret scrubbed from logs
[6] promote_to_live (as the builder)
    ✓ denied by the policy enforcement point: role "builder" does not grant "promote_to_live"
[7] promote_to_live (as IT)
    → LIVE URL: https://tracker.demo.<base-domain>
    ✓ live, HTTP 200 via the gateway
✓ demo complete — an agent built, shipped, and operated an internal beam with no raw credentials.
```
