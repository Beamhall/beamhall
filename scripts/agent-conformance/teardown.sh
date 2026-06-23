#!/usr/bin/env bash
# Remove the conformance personas. Deletes the four bundled-IdP accounts (so none
# can authenticate again) and removes the local secrets file. Never touches the
# seed it-admin/builder accounts or the pilot workspace.
#
#   scripts/agent-conformance/teardown.sh
#
# Beamhall identity rows + team-blue/team-green are left intact-but-inert (no
# token can resolve to a deleted IdP user); they are reused idempotently on the
# next provision.sh. To also archive the workspaces / deregister the identities,
# the conductor calls admin_update_beamhall(status=archived) +
# admin_deregister_identity over MCP (see docs/agent-conformance.md).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"

say "Removing conformance IdP users from $APPLIANCE …"

REMOTE='
set -euo pipefail
ENVFILE=/etc/beamhall/beamhall.env
KC=$(sed -n "s#^BEAMHALL_IDP_ADMIN_URL=##p" "$ENVFILE" | tail -1)
REALM=$(sed -n "s#^BEAMHALL_IDP_ADMIN_REALM=##p" "$ENVFILE" | tail -1)
CID=$(sed -n "s#^BEAMHALL_IDP_ADMIN_CLIENT_ID=##p" "$ENVFILE" | tail -1)
SEC=$(sed -n "s/^BEAMHALL_IDP_ADMIN_CLIENT_SECRET=//p" "$ENVFILE" | tail -1)
TOK=$(curl -fsS "$KC/realms/$REALM/protocol/openid-connect/token" \
  -d grant_type=client_credentials -d client_id="$CID" -d client_secret="$SEC" | jq -r .access_token)
AUTH="Authorization: Bearer $TOK"
for u in "$@"; do
  uid=$(curl -fsS -H "$AUTH" "$KC/admin/realms/$REALM/users?username=$u&exact=true" | jq -r ".[0].id // empty")
  if [ -n "$uid" ]; then
    curl -fsS -X DELETE -H "$AUTH" "$KC/admin/realms/$REALM/users/$uid" && echo "  deleted IdP user $u" >&2
  else
    echo "  IdP user $u not present" >&2
  fi
done
'

printf '%s' "$REMOTE" | "${SSH[@]}" bash -s -- "${ALL_USERS[@]}"

rm -f "$ENV_LOCAL" && ok "removed local secrets $ENV_LOCAL" || true
ok "teardown complete (team-blue/team-green left inert; reused on next provision)."
