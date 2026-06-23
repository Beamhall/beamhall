#!/usr/bin/env bash
# Smoke-verify each persona's MCP channel by driving the proxy directly:
# initialize + tools/list, then assert the menu matches the identity
# (admins must see admin_* tools; builders must see none). Catches a missed
# beamhall-it role assignment or a broken token path before the full run.
#
#   scripts/agent-conformance/verify.sh            # all four personas
#   scripts/agent-conformance/verify.sh admin-alice
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"

[ -f "$ENV_LOCAL" ] || die "no secrets file at $ENV_LOCAL — run provision.sh first"

targets=("$@"); [ ${#targets[@]} -gt 0 ] || targets=("${ALL_USERS[@]}")

list_tools() {  # <username> -> tool names on stdout (one per line)
  local u="$1" client; client="$(client_for "$u")"
  {
    printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"verify","version":"0"}}}'
    printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
    printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
  } | BH_USER="$u" BH_CLIENT_ID="$client" BH_SCOPE="$CAP_SCOPE" \
        BH_ISSUER="$ISSUER" BH_MCP_URL="$MCP_URL" BH_CA="$CA" BH_ENV_FILE="$ENV_LOCAL" \
        python3 "$PROXY" 2>/dev/null \
    | jq -rs '.[] | select(.id==2) | (.result.tools // [])[] | .name'
}

rc=0
for u in "${targets[@]}"; do
  names="$(list_tools "$u" || true)"
  total=$(printf '%s\n' "$names" | grep -c . || true)
  admin=$(printf '%s\n' "$names" | grep -c '^admin_' || true)
  if [ "$total" -eq 0 ]; then
    warn "$u: tools/list returned nothing (provisioning/connectivity?)"; rc=1; continue
  fi
  if is_admin "$u"; then
    if [ "$admin" -gt 0 ]; then ok "$u: sees $admin admin_* tools (of $total) — IT elevation OK"
    else warn "$u: NO admin_* tools — beamhall-it role likely not applied"; rc=1; fi
  else
    if [ "$admin" -eq 0 ]; then ok "$u: $total builder tools, 0 admin_* — correctly unprivileged"
    else warn "$u: sees $admin admin_* tools — should see none!"; rc=1; fi
  fi
done
exit $rc
