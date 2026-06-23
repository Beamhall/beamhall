#!/usr/bin/env bash
# One-shot: call a single MCP tool AS a persona, driving that persona's proxy
# directly (no Claude Code restart needed). Handy for the runbook, smoke checks,
# and scripted scenarios.
#
#   scripts/agent-conformance/bh-call.sh <idp-username> <tool> '<json-args>'
#   scripts/agent-conformance/bh-call.sh admin-alice admin_list_beamhalls '{}'
#   scripts/agent-conformance/bh-call.sh builder-carol list_beams '{}'
#
# Exit status is 0 even on a tool-level refusal (a refusal is often the expected
# result in conformance tests) — read the printed TOOL ERROR / text.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"

u="${1:?usage: bh-call.sh <username> <tool> [json-args]}"
tool="${2:?missing tool name}"
args="${3:-}"; [ -n "$args" ] || args='{}'
client="$(client_for "$u")"
[ -f "$ENV_LOCAL" ] || die "no secrets file at $ENV_LOCAL — run provision.sh first"

call=$(jq -cn --arg n "$tool" --argjson a "$args" '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:$n,arguments:$a}}')
{
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"bh-call","version":"0"}}}'
  printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  printf '%s\n' "$call"
} | BH_USER="$u" BH_CLIENT_ID="$client" BH_SCOPE="$CAP_SCOPE" \
      BH_ISSUER="$ISSUER" BH_MCP_URL="$MCP_URL" BH_CA="$CA" BH_ENV_FILE="$ENV_LOCAL" \
      python3 "$PROXY" 2>/dev/null \
  | jq -rs '.[] | select(.id==2) |
      if .error then "RPC ERROR: \(.error.message)"
      else (.result // {} |
        (if .isError then "TOOL ERROR:\n" else "" end)
        + ([ (.content // [])[] | select(.type=="text") | .text ] | join("\n"))
        + (if .structuredContent then "\n[structured] " + (.structuredContent|tojson) else "" end))
      end'
