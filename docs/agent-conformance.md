# Agent-conformance suite — exercising Beamhall the way agents use it

Beamhall is MCP-first: builders and IT operators drive it entirely over MCP. This
suite proves the two properties that matter for a regulated sign-off, **as a real
agent would hit them**, by running four authenticated personas against the
`beamhall.internal` appliance:

1. **Environment isolation** — a builder in one workspace cannot see or touch
   another, enforced server-side per token.
2. **Four-eyes / separation of duties** — a sensitive admin action (or a live
   promotion) needs a *different* operator to approve; nobody approves their own.

Both are enforced by Beamhall on the server, keyed on the token's resolved
identity (`req.RequestedBy == actor.ID`; membership lookups). So the only faithful
test is **distinct authenticated identities** — not one shared admin token.

## The idea: one authenticated MCP channel per identity

Claude Code subagents share the parent session's MCP connections, so isolation
can't come from the agent layer. Instead each persona gets **its own stdio MCP
proxy** (`bh-mcp-proxy.py`) that mints and auto-refreshes that identity's OAuth
token (ROPC against the bundled Keycloak) and bridges Claude Code ⇄ Beamhall's
Streamable-HTTP MCP endpoint. The four proxies are registered as four servers in
`.mcp.json`; each persona subagent (`.claude/agents/bh-*.md`) is pinned by its
`tools:` allowlist to its own server. Real isolation is the distinct tokens; the
allowlist just keeps each agent's channel and context clean.

```
 main session (conductor)
   ├─ Agent: bh-admin-alice   → mcp__bh-admin-alice__*   → proxy(admin-alice)   ┐
   ├─ Agent: bh-admin-bob     → mcp__bh-admin-bob__*     → proxy(admin-bob)     │ ROPC, distinct
   ├─ Agent: bh-builder-carol → mcp__bh-builder-carol__* → proxy(builder-carol) │ tokens → distinct
   └─ Agent: bh-builder-dave  → mcp__bh-builder-dave__*  → proxy(builder-dave)  ┘ actor.ID server-side
                                          └────────────→ https://beamhall.internal/mcp
```

## The four personas

| Persona (subagent) | IdP subject | Elevation | Workspace |
|---|---|---|---|
| `bh-admin-alice` | `admin-alice` | `beamhall-it` realm role | none (role is the bypass); default four-eyes **requester** |
| `bh-admin-bob` | `admin-bob` | `beamhall-it` realm role | none; default four-eyes **approver** |
| `bh-builder-carol` | `builder-carol` | capability scopes only | **team-blue** |
| `bh-builder-dave` | `builder-dave` | capability scopes only | **team-green** |

Admins elevate via the realm **role**, not a scope — the public `beamhall-admin-agent`
ROPC client cannot obtain the hidden `admin:it` scope. Builders use `beamhall-agent`.
Both public clients ROPC with no client secret.

## Setup

```sh
# 1. Provision the four identities + two workspaces (idempotent; runs over SSH to
#    the appliance, writes the gitignored scripts/agent-conformance/.env).
scripts/agent-conformance/provision.sh

# 2. Restart Claude Code (or reconnect MCP) so the four .mcp.json servers attach.
#    They appear as bh-admin-alice / bh-admin-bob / bh-builder-carol / bh-builder-dave,
#    and the persona subagents become callable via the Agent tool.

# 3. Smoke-check the channels (admins must see admin_*, builders must not):
scripts/agent-conformance/verify.sh
```

`provision.sh` requires: SSH to the appliance (`root@10.255.255.153`, override with
`BEAMHALL_APPLIANCE`), and the gateway CA on the Mac (`BH_CA`, default
`/Users/mmachado/Scratch/.beamhall-gateway-ca.crt`). Passwords are generated on the
appliance and returned over the encrypted SSH channel into the local gitignored
`.env` only.

## Driving the suite — two ways

- **Agentic (the real thing):** the conductor dispatches a persona subagent via the
  Agent tool with a concrete instruction; the subagent acts through its own channel
  and returns a structured `RESULT:` block. This is how you exercise "the agentic
  side" — each persona is a real authenticated client. Requires step 2 (restart).
- **One-shot (no restart):** `scripts/agent-conformance/bh-call.sh <user> <tool> '<json>'`
  drives a persona's proxy directly. Handy for scripted checks and for the scenarios
  below before/without a Claude restart. Example:
  `bh-call.sh builder-carol create_beam '{"beamhall":"team-blue","slug":"app","display_name":"App","runtime_hint":"node"}'`.

## Scenario matrix

Sequence: **gates off** → a, a′, d, e1, e3 → `gates.sh on` → b1, b2, b3, c →
`gates.sh off` → e2, f. The conductor passes each filer's `request_id` to the approver.

| # | Scenario | Personas | Gate | Expected |
|---|---|---|---|---|
| a | Isolation: Carol works in team-blue, then tries team-green | carol | off | team-blue ok; team-green `denied … no membership`; team-green absent from `list_beams` |
| a′ | Isolation mirror: Dave tries team-blue | dave | off | symmetric `denied … no membership` |
| d | Full builder lifecycle in team-blue | carol | off | create_beam → deploy_beam → show_logs/metrics → set_secret → pause/resume → (promote) → rollback → archive |
| e1 | Builder sees no admin surface | carol | off | zero `admin_*` in her menu |
| e3 | Secret not readable back | carol | off | `set_secret` ok; no read tool; value never echoed |
| b1 | Admin four-eyes, happy path | bob files `admin_set_security_context`(team-blue→runsc), alice approves | on | filed (not executed); alice (≠ requester) executes |
| b2 | Self-approval refused | alice files, alice approves own | on | `the requester cannot approve their own sensitive action (four-eyes)` |
| b3 | Different operator completes it | bob approves alice's b2 request | on | executes; pending queue empties |
| c | Promotion four-eyes | carol `promote_to_live` files a request, an admin `approve_promotion` | on | filed with request_id; a different operator promotes to live |
| e2 | Suspended workspace denies all | alice `admin_update_beamhall status=suspended`, carol acts, alice re-activates | off | Carol denied while suspended; restored after |
| f | Audit chain records everything | alice `admin_query_audit` + `admin_verify_audit_chain` | off | chain intact; denials + four-eyes pairs present |

### Verified live (2026-06-23, appliance v0.1.11)

Isolation, admin four-eyes, state-driven menu filtering, and the audit trail were
run end-to-end through the four proxies:

- **Isolation:** `denied "create_beam": no membership in this beamhall` for carol→team-green
  and dave→team-blue; each `list_beams` shows only the owner's workspace.
- **Menu filtering:** builders see 16 builder tools, **0** `admin_*`; admins see
  `admin_*` and the count tracks appliance state live — **30 with gates off → 35 when the
  sensitive tier is on → 30 again when off** (backup/upgrade tools stay hidden, as configured).
- **Four-eyes:** bob files → alice approves (executes); alice approves her own →
  refused with the four-eyes message; bob then approves → executes; queue empties.
- **Audit:** `audit chain VERIFIED — intact`; the tail shows the two isolation
  denials and the request/approve pairs, each against a distinct `actor` ID.

The full builder lifecycle (d) and promotion four-eyes (c) involve a real
build/deploy (git push or a tarball) and are best run agentically per the runbook.

## Gates (reversible)

```sh
scripts/agent-conformance/gates.sh on       # BEAMHALL_IDP_SENSITIVE_ADMIN=on + BEAMHALL_PROMOTE_APPROVAL=on, restart
scripts/agent-conformance/gates.sh off       # back to shipped defaults
scripts/agent-conformance/gates.sh status
```

Each change backs up `beamhall.env` (timestamped) first. The restart is the only
disruptive step (seconds; running beams unaffected). Wrap the four-eyes scenarios
with `on`, then `off`.

**Restart resilience.** A gate toggle (and a self-upgrade) restarts `beamhalld`,
which invalidates every open `Mcp-Session-Id` — the server then returns **HTTP 404**
to any client still holding the old session. `bh-mcp-proxy.py` recovers
automatically: on a 404 it drops the session, re-handshakes, retries, and emits a
`tools/list_changed` so Claude Code re-lists (picking up the now-visible sensitive
tools). Caveat: an *already-running* proxy started with an older build can't recover
— if you toggle gates mid-session and the persona subagents then return HTTP 404 or
a stale menu, `/mcp` reconnect (or a Claude restart) respawns the proxies with the
current code and a fresh session. The no-restart `bh-call.sh` path is immune (fresh
process per call).

## Teardown

```sh
scripts/agent-conformance/teardown.sh   # deletes the four IdP users + local .env
```

team-blue/team-green and the Beamhall identity rows are left intact-but-inert (no
token can resolve to a deleted IdP user) and are reused idempotently on the next
`provision.sh`. To also archive the workspaces / deregister the identities, the
conductor calls `admin_update_beamhall(status=archived)` + `admin_deregister_identity`
over MCP as a persona.

## Files

- `scripts/agent-conformance/bh-mcp-proxy.py` — per-identity stdio↔HTTP MCP proxy.
- `scripts/agent-conformance/{lib.sh,provision.sh,verify.sh,gates.sh,teardown.sh,bh-call.sh}` — harness.
- `scripts/agent-conformance/auth-isolation.sh` — proves provisioned-auth (PLAN §5.10) audience
  isolation end-to-end: a beam's own OIDC-client token is **401'd by `/mcp`** (with a positive
  control), plus the provision→show→archive-reclaim lifecycle and the group allowlist.
- `scripts/agent-conformance/env.example` — secrets template (the real `.env` is gitignored).
- `.mcp.json` — the four persona servers.
- `.claude/agents/bh-{admin-alice,admin-bob,builder-carol,builder-dave}.md` — the personas.

## Stronger isolation (optional): Apple `container`

For OS-level separation or to run the four personas as fully parallel real
clients, each proxy can run inside its own Apple `container` Linux VM (installed,
v1.0.0). Cost: each container has its own network namespace, so it needs
`10.255.255.153 beamhall.internal idp.beamhall.internal` injected (its `/etc/hosts`
or the lab resolver) and the gateway CA mounted + trusted inside. Since isolation
is already enforced server-side by token identity, this is a hardening/parallelism
tier only — the native multi-proxy suite is the primary path. A future
`scripts/agent-conformance/container/` variant would carry the Dockerfile-equivalent
+ a host-routing/CA-mount wrapper.

## Insights — how to exercise the agentic side well

- **Trust the server, not the client.** The strong guarantees (isolation, four-eyes)
  live in Beamhall and are keyed on the resolved identity. The harness's job is to
  present *genuinely distinct identities*; the proxies do exactly that and nothing
  more. Don't try to enforce isolation in the agent layer — prove the server does.
- **A refusal is a PASS.** Most of the value is in negative space: cross-workspace
  denials, self-approval refusals, hidden admin tools. The personas are told to
  *attempt* forbidden actions and quote the exact refusal as evidence.
- **The menu is a feature to test, not just a convenience.** Per-caller `tools/list`
  filtering is itself a security-relevant surface (a builder's context never sees the
  ~30 `admin_*` tools; sensitive tools appear only when their gate is on). `verify.sh`
  and scenario e1 assert it; we watched it change live with the gate.
- **Distinct identities are cheap and high-signal.** Two admins + two builders is the
  minimum to prove both separation-of-duties and isolation; the audit chain then ties
  every action to a distinct `actor` ID, which is the regulated artifact.
- **Keep provisioning out-of-band.** The first IT identity/role can't be minted by the
  `admin_*` tools (chicken-and-egg) and realm-role assignment has no MCP/CLI path —
  so `provision.sh` uses Keycloak Admin REST + `beamhalld admin`, and reserves the
  MCP admin tools for the agents *under test*.

## Troubleshooting

- **`verify.sh` says "tools/list returned nothing"** — usually the token mint failed.
  Check `scripts/agent-conformance/.env` exists (run `provision.sh`) and that the
  IdP user's profile is complete: a user created via Admin REST without
  `firstName`/`lastName` triggers Keycloak's "Account is not fully set up" and ROPC
  returns HTTP 400. `provision.sh` sets a complete profile + clears required actions;
  re-run it if you created users by hand.
- **Admin persona sees 0 `admin_*`** — the `beamhall-it` realm role didn't land. Re-run
  `provision.sh` (it re-asserts the role) and confirm with `verify.sh admin-alice`.
- **Proxy `missing required env BH_SCOPE`** — you ran the proxy without the `.mcp.json`
  env; use `bh-call.sh`/`verify.sh` (they source `lib.sh`) or set the `BH_*` vars.
