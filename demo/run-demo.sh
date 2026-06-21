#!/usr/bin/env bash
# Beamhall canonical demo — runs ON the appliance host. It does the IT setup
# (beamhalld admin bootstrap) and then runs the agent flow (bh-demo) end-to-end:
# create_beam → set_secret → create_database → deploy → preview → scrubbed logs
# → promote denied → promote as IT → v2 + rollback.
#
# Prereqs on the host: beamhalld running with an IdP configured, bh-demo on PATH
# (or next to this script), and the demo/beam-app source tree. For the lab the
# IdP is bh-devidp; for a real IdP, mint the two tokens however that IdP issues
# them and pass them in via BUILDER_TOKEN / IT_TOKEN.
set -euo pipefail

ENDPOINT="${ENDPOINT:-http://127.0.0.1:8443/mcp}"
IDP="${IDP:-http://127.0.0.1:9081}"          # bh-devidp (lab). Ignored if tokens are supplied.
ISSUER="${ISSUER:-$IDP}"
BEAMHALL="${BEAMHALL:-demo}"
BEAM="${BEAM:-tracker}"
BUILDER_SUB="${BUILDER_SUB:-agent}"
IT_SUB="${IT_SUB:-it}"
BEAMHALLD="${BEAMHALLD:-/usr/local/bin/beamhalld}"
HERE="$(cd "$(dirname "$0")" && pwd)"
BH_DEMO="${BH_DEMO:-$(command -v bh-demo || echo "$HERE/bh-demo")}"
APP_DIR="${APP_DIR:-$HERE/beam-app}"

BUILDER_SCOPES="beams:write beams:deploy beams:operate beams:promote secrets:write resources:write logs:read"
IT_SCOPES="admin:it beams:promote"

mint() { # sub, scopes(space-sep)
  curl -fsS "$IDP/mint?sub=$1&scopes=$(echo "$2" | tr ' ' ',')&ttl=1h"
}

BUILDER_TOKEN="${BUILDER_TOKEN:-$(mint "$BUILDER_SUB" "$BUILDER_SCOPES")}"
IT_TOKEN="${IT_TOKEN:-$(mint "$IT_SUB" "$IT_SCOPES")}"

echo "== IT setup: bootstrap the beamhall and grant the agent =="
sudo "$BEAMHALLD" admin bootstrap \
  -beamhall "$BEAMHALL" -display "Demo workspace" \
  -issuer "$ISSUER" -subject "$BUILDER_SUB" -email "$BUILDER_SUB@demo.test" \
  -role builder -runtime runc

# The IT operator needs a registered identity too (admin:it still audits against
# a known identity); it needs no membership — the scope is the bypass.
sudo "$BEAMHALLD" admin register-identity \
  -issuer "$ISSUER" -subject "$IT_SUB" -email "$IT_SUB@demo.test"

echo
echo "== agent flow =="
"$BH_DEMO" -endpoint "$ENDPOINT" -token "$BUILDER_TOKEN" -it-token "$IT_TOKEN" \
  -beamhall "$BEAMHALL" -beam "$BEAM" -app "$APP_DIR"
