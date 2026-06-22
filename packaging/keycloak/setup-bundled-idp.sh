#!/usr/bin/env bash
# Turnkey bundled-IdP setup for a Beamhall PILOT: brings up a pre-configured
# Keycloak (fronted by the Beamhall gateway), wires beamhalld to trust it, and
# registers the seed identities — so an evaluator gets a working Admin console +
# agent flow without touching their corporate IdP. Swap to a real IdP for
# production (docs/idp-setup.md).
#
#   # from a checkout:
#   sudo BASE_DOMAIN=beamhall.acme.internal bash packaging/keycloak/setup-bundled-idp.sh
#   # or streamlined (no checkout) — the script self-fetches its sibling files:
#   curl -fsSL https://raw.githubusercontent.com/Beamhall/beamhall/<tag>/packaging/keycloak/setup-bundled-idp.sh \
#     | sudo BASE_DOMAIN=beamhall.acme.internal BEAMHALL_REF=<tag> bash
#
# Persistent: Keycloak state lives in the named volume beamhall-keycloak-data, so
# users/groups/config created at runtime in the console survive reboots. The realm
# is seeded ONCE on first install; a re-run preserves the persistent state (it does
# NOT regenerate secrets or re-import the realm — the printed values wouldn't match
# what's persisted). To wipe and re-seed from scratch, re-run with RESET=1.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }

BASE_DOMAIN="${BASE_DOMAIN:?set BASE_DOMAIN to the appliance base domain}"
SCHEME="${SCHEME:-https}"                       # http for an internal pilot (gateway TLS-off); https with real DNS
KC_PORT="${KC_PORT:-8090}"
HERE="$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo .)"
ENVFILE="${ENVFILE:-/etc/beamhall/beamhall.env}"
BEAMHALLD="${BEAMHALLD:-/usr/local/bin/beamhalld}"

# Sibling files this script reads. When run via `curl | bash` (no checkout),
# fetch them from the same ref so the bundled IdP is a true one-liner.
REPO_SLUG="${BEAMHALL_REPO:-Beamhall/beamhall}"
BEAMHALL_REF="${BEAMHALL_REF:-main}"
_need_fetch=0
for _f in realm-template.json beamhall-keycloak.service; do
  [ -f "$HERE/$_f" ] || _need_fetch=1
done
if [ "$_need_fetch" = 1 ]; then
  HERE="$(mktemp -d)"
  for _f in realm-template.json beamhall-keycloak.service; do
    curl -fsSL "https://raw.githubusercontent.com/${REPO_SLUG}/${BEAMHALL_REF}/packaging/keycloak/${_f}" -o "$HERE/$_f" \
      || { echo "could not fetch ${_f} from ${REPO_SLUG}@${BEAMHALL_REF}"; exit 1; }
  done
  echo "fetched bundled-IdP assets from ${REPO_SLUG}@${BEAMHALL_REF}"
fi

IDP_HOST="idp.${BASE_DOMAIN}"
ISSUER="${SCHEME}://${IDP_HOST}/realms/beamhall"
AUDIENCE="${SCHEME}://${BASE_DOMAIN}/mcp"
ADMIN_REDIRECT="${SCHEME}://${BASE_DOMAIN}/admin/callback"

# openssl rand: no pipe, so safe under `set -o pipefail` (a tr|head -c gen trips
# SIGPIPE and aborts the script). hex output is fine for secrets/passwords.
command -v envsubst >/dev/null 2>&1 || { echo "== install envsubst (gettext-base) =="; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq gettext-base >/dev/null; }

gen() { openssl rand -hex "${1:-16}"; }

VOLUME="beamhall-keycloak-data"

# RESET=1: destroy all persistent runtime identity state, then proceed as a fresh
# first install (regenerate secrets + re-seed the realm).
if [ "${RESET:-0}" = "1" ]; then
  echo "!! RESET=1 — destroying the Keycloak container and the persistent volume"
  echo "!! ${VOLUME}. ALL runtime identity state (users/groups/config created in"
  echo "!! the console) will be LOST and the realm re-seeded from scratch."
  docker rm -f beamhall-keycloak >/dev/null 2>&1 || true
  docker volume rm "$VOLUME" >/dev/null 2>&1 || true
fi

# First install vs re-run over existing persistent state. The named volume is the
# signal: if it exists, the realm + admin password already live inside it and must
# NOT be regenerated/re-imported (the printed values would silently desync).
if docker volume inspect "$VOLUME" >/dev/null 2>&1; then
  FIRST_INSTALL=0
else
  FIRST_INSTALL=1
fi

if [ "$FIRST_INSTALL" = "1" ]; then
  ADMIN_SECRET="$(gen 24)"; BUILDER_PASSWORD="$(gen 10)"; IT_PASSWORD="$(gen 10)"
  KC_ADMIN_PASSWORD="$(gen 12)"
  # Service-account secret the backplane uses to administer the realm (admin_* IdP
  # tools). Beamhall holds it; agents never do.
  IDP_ADMIN_SECRET="$(gen 24)"

  echo "== render realm (first install — seeding) =="
  install -d -m 0750 -o root -g beamhall /etc/beamhall/keycloak
  export AUDIENCE ADMIN_REDIRECT ADMIN_SECRET BUILDER_PASSWORD IT_PASSWORD IDP_ADMIN_SECRET
  envsubst '${AUDIENCE} ${ADMIN_REDIRECT} ${ADMIN_SECRET} ${BUILDER_PASSWORD} ${IT_PASSWORD} ${IDP_ADMIN_SECRET}' \
    < "$HERE/realm-template.json" > /etc/beamhall/keycloak/realm.json
  # 0644: the Keycloak container runs as a non-root (userns-remapped) uid and must
  # read this bind-mounted import file. These are regenerated pilot-grade creds on
  # a single-tenant appliance; production uses a real IdP (no bundled realm).
  chmod 0644 /etc/beamhall/keycloak/realm.json
else
  echo "== existing persistent state detected — preserving realm + secrets =="
  # Reuse the beamhall-admin OIDC client secret already persisted in the realm
  # (and recorded in beamhall.env). Regenerating it here would desync from the
  # persisted realm. KC_ADMIN_PASSWORD is only used to render the unit's bootstrap
  # vars on first boot; Keycloak ignores it once the admin user exists, so a
  # rendered placeholder is harmless on a re-run.
  ADMIN_SECRET="$(sed -n 's/^BEAMHALL_ADMIN_CLIENT_SECRET=//p' "$ENVFILE" 2>/dev/null | tail -n1)"
  [ -n "$ADMIN_SECRET" ] || { echo "no BEAMHALL_ADMIN_CLIENT_SECRET in $ENVFILE — run RESET=1 to re-seed"; exit 1; }
  IDP_ADMIN_SECRET="$(sed -n 's/^BEAMHALL_IDP_ADMIN_CLIENT_SECRET=//p' "$ENVFILE" 2>/dev/null | tail -n1)"
  [ -n "$IDP_ADMIN_SECRET" ] || { echo "no BEAMHALL_IDP_ADMIN_CLIENT_SECRET in $ENVFILE — run RESET=1 to re-seed"; exit 1; }
  KC_ADMIN_PASSWORD="$(gen 12)"
fi

echo "== install + start the bundled Keycloak unit =="
sed -e "s#\${KC_HOSTNAME}#${SCHEME}://${IDP_HOST}#" -e "s#\${KC_ADMIN_PASSWORD}#${KC_ADMIN_PASSWORD}#" \
  "$HERE/beamhall-keycloak.service" > /etc/systemd/system/beamhall-keycloak.service
systemctl daemon-reload
systemctl enable beamhall-keycloak >/dev/null 2>&1 || true
# restart (not just enable --now): re-render the unit and pick up changes. State
# is persistent (named volume), so the realm is seeded once on first boot and NOT
# re-imported on restart — a re-run preserves runtime identity state.
systemctl restart beamhall-keycloak

echo "== wire beamhalld to the bundled IdP =="
# strip prior OAuth/admin/bundled/idp-admin lines, then append
sed -i '/^BEAMHALL_OAUTH_/d;/^BEAMHALL_ADMIN_CLIENT/d;/^BEAMHALL_BUNDLED_IDP_/d;/^BEAMHALL_IDP_ADMIN_/d' "$ENVFILE"
cat >>"$ENVFILE" <<EOF
BEAMHALL_OAUTH_ISSUER=${ISSUER}
BEAMHALL_OAUTH_AUDIENCE=${AUDIENCE}
BEAMHALL_ADMIN_CLIENT_ID=beamhall-admin
BEAMHALL_ADMIN_CLIENT_SECRET=${ADMIN_SECRET}
BEAMHALL_BUNDLED_IDP_UPSTREAM=127.0.0.1:${KC_PORT}
BEAMHALL_IDP_ADMIN_URL=http://127.0.0.1:${KC_PORT}
BEAMHALL_IDP_ADMIN_REALM=beamhall
BEAMHALL_IDP_ADMIN_CLIENT_ID=beamhall-idp-admin
BEAMHALL_IDP_ADMIN_CLIENT_SECRET=${IDP_ADMIN_SECRET}
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

if [ "$FIRST_INSTALL" = "1" ]; then
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

For an IT operator to administer over MCP (the admin_* tools), use the admin
client — IT-admin is gated by the 'beamhall-it' realm role (it-admin has it):
  claude mcp add --transport http --client-id beamhall-admin-agent beamhall-admin ${SCHEME}://${BASE_DOMAIN}/mcp
  (sign in as it-admin / ${IT_PASSWORD})

Secrets were generated and written to ${ENVFILE}. SAVE the passwords above.
Identity state is PERSISTENT (named volume ${VOLUME}): users/groups/config you
create in the console survive restarts and reboots.

IdP administration over MCP is ENABLED: an it-admin agent can run the admin_*
tools (create users/groups, onboard people, list identities) without opening the
Keycloak console. Directory federation (admin_federate_directory) is the
SENSITIVE tier: it files a request a DIFFERENT it-admin must approve (four-eyes)
before it takes effect, and is OFF by default — set BEAMHALL_IDP_SENSITIVE_ADMIN=on
in ${ENVFILE} to permit it (it changes who can sign in to the whole appliance).
This is an evaluation IdP — for production, point Beamhall at your own IdP
(docs/idp-setup.md) and disable beamhall-keycloak.service.
===========================================================
EOF
else
cat <<EOF

================ bundled IdP re-wired (PILOT) ================
IdP issuer    : ${ISSUER}
Existing persistent state was PRESERVED — the realm and the seed passwords were
NOT regenerated (they live in the named volume ${VOLUME} and the values printed
on first install still apply). The systemd unit and ${ENVFILE} were re-rendered.

Manage users/groups/config via the Keycloak admin console
(${SCHEME}://${IDP_HOST}) or the Beamhall admin tools.

To WIPE all runtime identity state and re-seed from scratch, re-run with RESET=1:
  sudo RESET=1 BASE_DOMAIN=${BASE_DOMAIN} bash packaging/keycloak/setup-bundled-idp.sh
=============================================================
EOF
fi
