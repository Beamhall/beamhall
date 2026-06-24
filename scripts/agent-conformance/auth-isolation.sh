#!/usr/bin/env bash
# Prove the provisioned-auth (PLAN §5.10) audience-isolation invariant end-to-end,
# the way it gates the regulated sign-off: a token minted for a beam's OWN OIDC
# client must be REJECTED (401) by /mcp, so an app token can never be replayed
# against the Beamhall backplane. Also exercises the lifecycle: provision_auth →
# show_auth → archive reclaims the client.
#
#   scripts/agent-conformance/auth-isolation.sh [beam-slug]
#
# Requires: the appliance running a beamhalld with provisioned-auth, the four
# personas provisioned (provision.sh), and the gateway CA on the Mac (BH_CA).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"

BEAM="${1:-authcheck}"
WS="$WORKSPACE_BLUE"          # team-blue (builder-carol owns it)
BUILDER="builder-carol"
AUDIENCE="https://beamhall.internal/mcp"   # BEAMHALL_OAUTH_AUDIENCE on the appliance
CLIENT_ID="beam-${WS}-${BEAM}-preview"

[ -f "$ENV_LOCAL" ] || die "no secrets file at $ENV_LOCAL — run provision.sh first"
CAROL_PW="$(awk -F= -v u="$BUILDER" '$1==u{print $2}' "$ENV_LOCAL")"
[ -n "$CAROL_PW" ] || die "no password for $BUILDER in $ENV_LOCAL"

call() { "$HERE/bh-call.sh" "$@"; }

say "1. Builder $BUILDER provisions company sign-in for $WS/$BEAM"
call "$BUILDER" create_beam "{\"beamhall\":\"$WS\",\"slug\":\"$BEAM\",\"display_name\":\"Auth Check\",\"runtime_hint\":\"node\"}" >/dev/null 2>&1 || true
prov="$(call "$BUILDER" provision_auth "{\"beamhall\":\"$WS\",\"beam\":\"$BEAM\"}" 2>/dev/null || true)"
printf '%s\n' "$prov" | grep -q 'OIDC_CLIENT_SECRET' || die "provision_auth did not return the OIDC keys:\n$prov"
ok "provision_auth returned the OIDC key set (no secret value)"

say "2. Mint a token for the beam's OWN OIDC client (Keycloak-side, on the appliance)"
# Keycloak is loopback-only on the appliance, so the client lookup + ROPC run
# there (mirrors provision.sh). The app client has directAccessGrants OFF; we
# enable it just long enough to mint a representative token, then revert.
REMOTE='
set -euo pipefail
CLIENT_ID="$1"; AUD="$2"; CUSER="$3"; CPW="$4"
ENVFILE=/etc/beamhall/beamhall.env
KC=$(sed -n "s#^BEAMHALL_IDP_ADMIN_URL=##p" "$ENVFILE" | tail -1)
REALM=$(sed -n "s#^BEAMHALL_IDP_ADMIN_REALM=##p" "$ENVFILE" | tail -1)
CID=$(sed -n "s#^BEAMHALL_IDP_ADMIN_CLIENT_ID=##p" "$ENVFILE" | tail -1)
SEC=$(sed -n "s/^BEAMHALL_IDP_ADMIN_CLIENT_SECRET=//p" "$ENVFILE" | tail -1)
TOK=$(curl -fsS "$KC/realms/$REALM/protocol/openid-connect/token" \
  -d grant_type=client_credentials -d client_id="$CID" -d client_secret="$SEC" | jq -r .access_token)
AUTH="Authorization: Bearer $TOK"
UUID=$(curl -fsS -H "$AUTH" "$KC/admin/realms/$REALM/clients?clientId=$CLIENT_ID" | jq -r ".[0].id // empty")
[ -n "$UUID" ] || { echo "APP_CLIENT_MISSING" >&2; exit 1; }
echo "UUID $UUID"
SECRET=$(curl -fsS -H "$AUTH" "$KC/admin/realms/$REALM/clients/$UUID/client-secret" | jq -r .value)
# Post-assert: the effective token mappers must NOT inject the Beamhall resource URI.
if curl -fsS -H "$AUTH" "$KC/admin/realms/$REALM/clients/$UUID/evaluate-scopes/protocol-mappers?scope=openid" \
   | jq -e --arg aud "$AUD" "any(.[]; .protocolMapper==\"oidc-audience-mapper\" and .config[\"included.custom.audience\"]==\$aud)" >/dev/null; then
  echo "AUDBAD"
else
  echo "AUDOK"
fi
# Temporarily allow direct grants to mint a representative app-audience token.
curl -fsS -X PUT -H "$AUTH" -H "Content-Type: application/json" \
  "$KC/admin/realms/$REALM/clients/$UUID" -d "{\"directAccessGrantsEnabled\":true}" >/dev/null
APPTOK=$(curl -fsS "$KC/realms/$REALM/protocol/openid-connect/token" \
  -d grant_type=password -d client_id="$CLIENT_ID" -d client_secret="$SECRET" \
  -d username="$CUSER" -d password="$CPW" -d scope=openid | jq -r .access_token)
curl -fsS -X PUT -H "$AUTH" -H "Content-Type: application/json" \
  "$KC/admin/realms/$REALM/clients/$UUID" -d "{\"directAccessGrantsEnabled\":false}" >/dev/null
[ -n "$APPTOK" ] && [ "$APPTOK" != null ] || { echo "ROPC_FAILED" >&2; exit 1; }
echo "APP_TOKEN $APPTOK"
'
out="$(printf '%s' "$REMOTE" | "${SSH[@]}" bash -s -- "$CLIENT_ID" "$AUDIENCE" "$BUILDER" "$CAROL_PW")"
case "$out" in *AUDOK*) ok "effective mappers exclude the Beamhall resource URI (audience isolation in Keycloak)";;
  *) die "app client injects the Beamhall resource URI into its token — audience isolation BROKEN";; esac
APP_TOKEN="$(printf '%s\n' "$out" | awk '/^APP_TOKEN /{print $2}')"
[ -n "$APP_TOKEN" ] || die "could not mint an app-client token for the probe"

say "3. The app-client token must be REJECTED by /mcp (no backplane replay)"
init='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"isocheck","version":"0"}}}'
code="$(curl -s -o /dev/null -w '%{http_code}' --cacert "$CA" "$MCP_URL" \
  -H "Authorization: Bearer $APP_TOKEN" -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" -d "$init")"
[ "$code" = "401" ] || die "app token got HTTP $code from /mcp, expected 401 — AUDIENCE ISOLATION FAILED"
ok "app-client token rejected with HTTP 401 — cannot reach the backplane"

say "4. Positive control: a correctly-scoped builder token IS accepted by /mcp"
good="$(curl -fsS --cacert "$CA" "$ISSUER/protocol/openid-connect/token" \
  -d grant_type=password -d client_id="$BUILDER_CLIENT" -d username="$BUILDER" \
  -d "password=$CAROL_PW" -d "scope=openid $CAP_SCOPE" | jq -r .access_token)"
gcode="$(curl -s -o /dev/null -w '%{http_code}' --cacert "$CA" "$MCP_URL" \
  -H "Authorization: Bearer $good" -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" -d "$init")"
[ "$gcode" != "401" ] || die "correctly-scoped token also got 401 — the probe is wrong, not the isolation"
ok "correctly-scoped token accepted (HTTP $gcode) — the 401 above is specifically the audience gate"

say "5. show_auth reports the wiring (no secret value)"
call "$BUILDER" show_auth "{\"beamhall\":\"$WS\",\"beam\":\"$BEAM\"}" 2>/dev/null | grep -qi 'client_id' \
  && ok "show_auth lists the client wiring" || warn "show_auth did not list a client (check provisioning)"

say "6. archive reclaims the OIDC client (no orphan)"
call "$BUILDER" archive_beam "{\"beamhall\":\"$WS\",\"beam\":\"$BEAM\"}" >/dev/null 2>&1 || true
gone="$(printf '%s' '
set -euo pipefail
ENVFILE=/etc/beamhall/beamhall.env
KC=$(sed -n "s#^BEAMHALL_IDP_ADMIN_URL=##p" "$ENVFILE" | tail -1)
REALM=$(sed -n "s#^BEAMHALL_IDP_ADMIN_REALM=##p" "$ENVFILE" | tail -1)
CID=$(sed -n "s#^BEAMHALL_IDP_ADMIN_CLIENT_ID=##p" "$ENVFILE" | tail -1)
SEC=$(sed -n "s/^BEAMHALL_IDP_ADMIN_CLIENT_SECRET=//p" "$ENVFILE" | tail -1)
TOK=$(curl -fsS "$KC/realms/$REALM/protocol/openid-connect/token" -d grant_type=client_credentials -d client_id="$CID" -d client_secret="$SEC" | jq -r .access_token)
n=$(curl -fsS -H "Authorization: Bearer $TOK" "$KC/admin/realms/$REALM/clients?clientId=$1" | jq "length")
[ "$n" = "0" ] && echo GONE || echo PRESENT
' | "${SSH[@]}" bash -s -- "$CLIENT_ID")"
[ "$gone" = "GONE" ] && ok "OIDC client deleted on archive (no orphan)" || warn "OIDC client still present after archive: $gone"

printf '\n\033[32m✓ provisioned-auth audience isolation verified end-to-end\033[0m\n'
