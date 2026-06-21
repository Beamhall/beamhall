#!/usr/bin/env bash
# Turnkey bundled-IdP setup for a Beamhall PILOT: brings up a pre-configured
# Keycloak (fronted by the Beamhall gateway), wires beamhalld to trust it, and
# registers the seed identities — so an evaluator gets a working Admin console +
# agent flow without touching their corporate IdP. Swap to a real IdP for
# production (docs/idp-setup.md).
#
#   sudo BASE_DOMAIN=beamhall.acme.internal bash packaging/keycloak/setup-bundled-idp.sh
#
# Idempotent-ish: re-running re-renders the realm and restarts the IdP.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }

BASE_DOMAIN="${BASE_DOMAIN:?set BASE_DOMAIN to the appliance base domain}"
SCHEME="${SCHEME:-https}"                       # http for an internal pilot (gateway TLS-off); https with real DNS
KC_PORT="${KC_PORT:-8090}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ENVFILE="${ENVFILE:-/etc/beamhall/beamhall.env}"
BEAMHALLD="${BEAMHALLD:-/usr/local/bin/beamhalld}"

IDP_HOST="idp.${BASE_DOMAIN}"
ISSUER="${SCHEME}://${IDP_HOST}/realms/beamhall"
AUDIENCE="${SCHEME}://${BASE_DOMAIN}/mcp"
ADMIN_REDIRECT="${SCHEME}://${BASE_DOMAIN}/admin/callback"

# openssl rand: no pipe, so safe under `set -o pipefail` (a tr|head -c gen trips
# SIGPIPE and aborts the script). hex output is fine for secrets/passwords.
command -v envsubst >/dev/null 2>&1 || { echo "== install envsubst (gettext-base) =="; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq gettext-base >/dev/null; }

gen() { openssl rand -hex "${1:-16}"; }
ADMIN_SECRET="$(gen 24)"; BUILDER_PASSWORD="$(gen 10)"; IT_PASSWORD="$(gen 10)"
KC_ADMIN_PASSWORD="$(gen 12)"

echo "== render realm =="
install -d -m 0750 -o root -g beamhall /etc/beamhall/keycloak
export AUDIENCE ADMIN_REDIRECT ADMIN_SECRET BUILDER_PASSWORD IT_PASSWORD
envsubst '${AUDIENCE} ${ADMIN_REDIRECT} ${ADMIN_SECRET} ${BUILDER_PASSWORD} ${IT_PASSWORD}' \
  < "$HERE/realm-template.json" > /etc/beamhall/keycloak/realm.json
# 0644: the Keycloak container runs as a non-root (userns-remapped) uid and must
# read this bind-mounted import file. These are regenerated pilot-grade creds on
# a single-tenant appliance; production uses a real IdP (no bundled realm).
chmod 0644 /etc/beamhall/keycloak/realm.json

echo "== install + start the bundled Keycloak unit =="
sed -e "s#\${KC_HOSTNAME}#${SCHEME}://${IDP_HOST}#" -e "s#\${KC_ADMIN_PASSWORD}#${KC_ADMIN_PASSWORD}#" \
  "$HERE/beamhall-keycloak.service" > /etc/systemd/system/beamhall-keycloak.service
systemctl daemon-reload
systemctl enable beamhall-keycloak >/dev/null 2>&1 || true
# restart (not just enable --now): a re-run must re-import the freshly rendered
# realm even when Keycloak is already running.
systemctl restart beamhall-keycloak

echo "== wire beamhalld to the bundled IdP =="
# strip prior OAuth/admin/bundled lines, then append
sed -i '/^BEAMHALL_OAUTH_/d;/^BEAMHALL_ADMIN_CLIENT/d;/^BEAMHALL_BUNDLED_IDP_/d' "$ENVFILE"
cat >>"$ENVFILE" <<EOF
BEAMHALL_OAUTH_ISSUER=${ISSUER}
BEAMHALL_OAUTH_AUDIENCE=${AUDIENCE}
BEAMHALL_ADMIN_CLIENT_ID=beamhall-admin
BEAMHALL_ADMIN_CLIENT_SECRET=${ADMIN_SECRET}
BEAMHALL_BUNDLED_IDP_UPSTREAM=127.0.0.1:${KC_PORT}
EOF

echo "== wait for the IdP to answer through the gateway =="
# beamhalld must resolve ${IDP_HOST} to the gateway; for a single-host pilot, a
# hosts entry is the simplest (real DNS in production).
grep -q "$IDP_HOST" /etc/hosts || echo "127.0.0.1 ${IDP_HOST}" >>/etc/hosts
systemctl restart beamhalld
for i in $(seq 1 40); do
  curl -fsS "${ISSUER}/.well-known/openid-configuration" >/dev/null 2>&1 && break || sleep 3
done

echo "== register the seed identities in Beamhall =="
export BEAMHALL_DATA_DIR="${BEAMHALL_DATA_DIR:-/var/lib/beamhall}" BEAMHALL_BASE_DOMAIN="$BASE_DOMAIN"
"$BEAMHALLD" admin register-identity -issuer "$ISSUER" -subject it-admin   -email it-admin@beamhall.pilot   || true
"$BEAMHALLD" admin bootstrap -beamhall pilot -display "Pilot workspace" \
  -issuer "$ISSUER" -subject builder -email builder@beamhall.pilot -role builder -runtime runc || true

cat <<EOF

================ bundled IdP ready (PILOT) ================
Admin console : ${SCHEME}://${BASE_DOMAIN}/admin   (log in as it-admin / ${IT_PASSWORD})
IdP issuer    : ${ISSUER}
Agent client  : beamhall-agent (public, PKCE)   user: builder / ${BUILDER_PASSWORD}
Keycloak admin: ${SCHEME}://${IDP_HOST}  (admin / ${KC_ADMIN_PASSWORD})

Give an employee this command to connect their agent (uses the pre-registered
agent client — no dynamic client registration needed):
  claude mcp add --transport http --client-id beamhall-agent beamhall ${SCHEME}://${BASE_DOMAIN}/mcp
  (then authenticate and sign in as builder / ${BUILDER_PASSWORD})

Secrets were generated and written to ${ENVFILE}. SAVE the passwords above.
This is an evaluation IdP — for production, point Beamhall at your own IdP
(docs/idp-setup.md) and disable beamhall-keycloak.service.
===========================================================
EOF
