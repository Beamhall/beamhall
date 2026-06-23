---
name: bh-conformance
description: Run the Beamhall agent-conformance matrix — dispatch the four authenticated personas (bh-admin-alice/-bob, bh-builder-carol/-dave) to prove environment isolation and four-eyes over MCP, then aggregate their structured results into one PASS/FAIL summary. Use when asked to run/validate the conformance suite or test Beamhall's isolation/four-eyes end-to-end.
---

# Beamhall agent-conformance conductor

You are the **conductor**. You orchestrate the four persona subagents; you do not
talk to Beamhall directly. Full reference: `docs/agent-conformance.md`.

## Preconditions
1. `scripts/agent-conformance/.env` exists — else run `scripts/agent-conformance/provision.sh` (Bash) first.
2. The four `.mcp.json` servers are connected (a Claude Code restart attaches them).
   If the persona subagents or their `mcp__bh-*__*` tools aren't available, tell the
   user to restart Claude Code, or fall back to `scripts/agent-conformance/bh-call.sh`
   for a no-restart dry run.

## Run order (toggle the appliance gates around the four-eyes block)
Dispatch each persona with the Agent tool (`subagent_type` = the persona name) and a
concrete instruction. Collect each persona's `RESULT:` block. Pass each filer's
`request_id` into the approver's instruction.

1. **Gates off** (`scripts/agent-conformance/gates.sh off` via Bash if unsure):
   - **a** `bh-builder-carol`: act in team-blue (list_beams, create_beam), then attempt
     team-green (create_beam, show_logs) — expect `no membership` denials.
   - **a′** `bh-builder-dave`: mirror — act in team-green, attempt team-blue.
   - **e1** `bh-builder-carol`: report whether any `admin_*` tools are in her menu (expect none).
   - **e3** `bh-builder-carol`: set_secret in team-blue, then confirm no read-back tool exists.
   - **d** `bh-builder-carol`: full lifecycle in team-blue (create→deploy→logs/metrics→
     pause/resume→rollback→archive). Deploy needs real source — use `get_repo` + a tiny
     push or a small tarball; if deploy isn't feasible in the run, report the lifecycle up
     to the point reached and mark the rest SKIPPED (don't fake it).
2. **Gates on** (`scripts/agent-conformance/gates.sh on`):
   - **b1** `bh-admin-bob`: file `admin_set_security_context(slug=team-blue, runtime_class=runsc)`;
     capture request_id. Then `bh-admin-alice`: `admin_list_pending_requests` →
     `admin_approve_request(request_id)` (expect executes).
   - **b2** `bh-admin-alice`: file `admin_set_security_context(slug=team-green, runtime_class=runsc)`;
     capture request_id; then attempt `admin_approve_request` on her own (expect four-eyes refusal).
   - **b3** `bh-admin-bob`: `admin_approve_request(request_id from b2)` (expect executes).
   - **c** `bh-builder-carol`: `promote_to_live` a deployed team-blue beam (expect a pending
     request_id); then `bh-admin-alice`: `list_pending_promotions` → `approve_promotion`.
     If no beam is deployed, mark c SKIPPED with the reason.
   - Revert: have bob file + alice approve `runtime_class=runc` for team-blue and team-green.
3. **Gates off** (`scripts/agent-conformance/gates.sh off`):
   - **e2** `bh-admin-alice`: `admin_update_beamhall(slug=team-blue, status=suspended)`; then
     `bh-builder-carol`: attempt create_beam/list_beams in team-blue (expect denied/suspended);
     then `bh-admin-alice`: `admin_update_beamhall(status=active)` to restore.
   - **f** `bh-admin-alice`: `admin_verify_audit_chain` (expect intact) and `admin_query_audit`
     to confirm the denials + four-eyes pairs are recorded against distinct actor IDs.

## Output
A single table: scenario → personas → expected → actual (from each `RESULT:` block) →
PASS/FAIL. A correctly-refused action is a PASS — cite the refusal text. Note any SKIPPED
scenarios and why. End by confirming gates are off and (if asked) running teardown.
