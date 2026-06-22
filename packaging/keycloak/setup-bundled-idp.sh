#!/usr/bin/env bash
# Bundled-IdP wizard for a Beamhall PILOT: brings up a pre-configured Keycloak
# (fronted by the Beamhall gateway), wires beamhalld to trust it, seeds users and
# the admin client/role, and registers the seed identities — a working Admin
# console + agent flow without touching a corporate IdP. For production, point
# Beamhall at your own IdP (https://github.com/Beamhall/beamhall/blob/main/docs/idp-setup.md).
#
#   curl -fsSL https://github.com/Beamhall/beamhall/releases/latest/download/setup-bundled-idp.sh \
#     | sudo BASE_DOMAIN=beamhall.acme.internal bash
#
# Interactive by default (prompts read /dev/tty); BEAMHALL_YES=1 / no tty auto-
# confirms. Persistent: Keycloak state lives in the named volume
# beamhall-keycloak-data; the realm is seeded once and survives reboots. RESET=1
# wipes and re-seeds.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }

BASE_DOMAIN="${BASE_DOMAIN:?set BASE_DOMAIN to the appliance base domain}"
SCHEME="${SCHEME:-https}"
KC_PORT="${KC_PORT:-8090}"
HERE="$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo .)"
ENVFILE="${ENVFILE:-/etc/beamhall/beamhall.env}"
BEAMHALLD="${BEAMHALLD:-/usr/local/bin/beamhalld}"
REPO_SLUG="${BEAMHALL_REPO:-Beamhall/beamhall}"
BEAMHALL_REF="${BEAMHALL_REF:-}"
VOLUME="beamhall-keycloak-data"

# ---- wizard UI (matches install.sh) ----------------------------------------
if [ -t 1 ]; then
  C_RST=$'\033[0m'; C_B=$'\033[1m'; C_DIM=$'\033[2m'
  C_R=$'\033[31m'; C_G=$'\033[32m'; C_Y=$'\033[33m'; C_C=$'\033[36m'; C_BLU=$'\033[34m'; C_TTY=1
else C_RST=; C_B=; C_DIM=; C_R=; C_G=; C_Y=; C_C=; C_BLU=; C_TTY=0; fi
if [ -e /dev/tty ] && { : >/dev/tty; } 2>/dev/null; then TTY=/dev/tty; else TTY=; BEAMHALL_YES=1; fi
ASSUME_YES="${BEAMHALL_YES:-0}"
_rule() { local n="${1:-72}" i=0; while [ "$i" -lt "$n" ]; do printf '─'; i=$((i+1)); done; }
box() { local col="$1" title="$2"; shift 2
  printf '\n%s┌─ %s%s %s\n' "$col" "$C_B" "$title" "$(printf '%s' "$col")$(_rule $((68 - ${#title})))$C_RST"
  local line; for line in "$@"; do printf '%s│%s %b\n' "$col" "$C_RST" "$line"; done
  printf '%s└%s%s\n' "$col" "$(_rule 70)" "$C_RST"; }
phase() { printf '\n%s%s━━ %s%s\n' "$C_C" "$C_B" "$1" "$C_RST"; }
ok()   { printf '   %s✓%s %s\n' "$C_G" "$C_RST" "$1"; }
note() { printf '   %s•%s %s\n' "$C_Y" "$C_RST" "$1"; }
die()  { printf '\n%s  ✗ %s%s\n' "$C_R$C_B" "$1" "$C_RST" >&2; exit 1; }
run_step() { local label="$1"; shift; local log; log="$(mktemp)"
  if [ "$C_TTY" = 0 ]; then if "$@" </dev/null >"$log" 2>&1; then ok "$label"; rm -f "$log"; return 0
    else printf '   %s✗ %s%s\n' "$C_R" "$label" "$C_RST"; sed 's/^/      /' "$log"; rm -f "$log"; exit 1; fi; fi
  ( "$@" ) </dev/null >"$log" 2>&1 & local pid=$! i=0 sp='|/-\'
  while kill -0 "$pid" 2>/dev/null; do printf '\r   %s%s%s %s ' "$C_C" "${sp:$((i%4)):1}" "$C_RST" "$label"; i=$((i+1)); sleep 0.12; done
  if wait "$pid"; then printf '\r   %s✓%s %s\033[K\n' "$C_G" "$C_RST" "$label"
  else printf '\r   %s✗%s %s\033[K\n' "$C_R" "$C_RST" "$label"; sed 's/^/      /' "$log" | tail -n 25; rm -f "$log"; exit 1; fi; rm -f "$log"; }
spinner_wait() { local label="$1" timeout="$2"; shift 2; local t=0 i=0 sp='|/-\'
  while [ "$t" -lt "$timeout" ]; do
    if "$@" >/dev/null 2>&1; then [ "$C_TTY" = 1 ] && printf '\r'; ok "$label (${t}s)"; return 0; fi
    [ "$C_TTY" = 1 ] && printf '\r   %s%s%s %s … %ss\033[K' "$C_C" "${sp:$((i%4)):1}" "$C_RST" "$label" "$t"
    i=$((i+1)); sleep 1; t=$((t+1)); done
  [ "$C_TTY" = 1 ] && printf '\r'; note "$label — not ready after ${timeout}s"; return 1; }
press_enter() { [ "$ASSUME_YES" = 1 ] && return 0; printf '   %s↵  Press Enter to continue…%s ' "$C_B" "$C_RST"; read -r _ <"$TTY" || true; }
confirm() { [ "$ASSUME_YES" = 1 ] && return 0; local a; printf '   %s%s%s [y/N] ' "$C_B" "$1" "$C_RST"; read -r a <"$TTY" || a=; case "$a" in [Yy]*) return 0;; *) return 1;; esac; }
# Setup checklist: shared with install.sh when chained (BEAMHALL_SETUP_SUMMARY);
# standalone we own + print it ourselves at the end.
SUMMARY="${BEAMHALL_SETUP_SUMMARY:-}"; _OWN_SUMMARY=0
if [ -z "$SUMMARY" ]; then SUMMARY=/root/beamhall-setup.txt; : > "$SUMMARY"; chmod 600 "$SUMMARY" 2>/dev/null || true; _OWN_SUMMARY=1; fi
chk() { printf '%s\n' "$@" >> "$SUMMARY"; }

# ---- self-fetch sibling assets (quiet) -------------------------------------
# NOTE: HERE is set by the caller (in the PARENT shell) before this runs, because
# run_step executes it in a subshell — a HERE assignment here would be lost and
# the later realm render would look in the wrong directory.
_fetch_assets() {
  local f url
  for f in realm-template.json beamhall-keycloak.service; do
    if [ -n "$BEAMHALL_REF" ]; then url="https://raw.githubusercontent.com/${REPO_SLUG}/${BEAMHALL_REF}/packaging/keycloak/${f}"
    else url="https://github.com/${REPO_SLUG}/releases/latest/download/${f}"; fi
    curl -fsSL "$url" -o "$HERE/$f" || return 1
  done
}
_need_fetch=0
for _f in realm-template.json beamhall-keycloak.service; do [ -f "$HERE/$_f" ] || _need_fetch=1; done

IDP_HOST="idp.${BASE_DOMAIN}"
ISSUER="${SCHEME}://${IDP_HOST}/realms/beamhall"
AUDIENCE="${SCHEME}://${BASE_DOMAIN}/mcp"
ADMIN_REDIRECT="${SCHEME}://${BASE_DOMAIN}/admin/callback"
gen() { openssl rand -hex "${1:-16}"; }

# ============================================================================
box "$C_BLU" "Bundled Identity Provider (pilot)" \
  "This sets up a ready-to-use Keycloak so you can evaluate Beamhall without a" \
  "corporate IdP. It seeds an ${C_B}it-admin${C_RST} and a ${C_B}builder${C_RST} account, wires this" \
  "appliance to trust it, and registers their access — fronted by your gateway" \
  "at ${C_B}${SCHEME}://${IDP_HOST}${C_RST}." \
  "" \
  "${C_DIM}Pilot-grade (single-host, embedded DB). For production, point Beamhall at${C_RST}" \
  "${C_DIM}your own IdP. State is persistent across reboots.${C_RST}"
press_enter

command -v envsubst >/dev/null 2>&1 || run_step "Installing envsubst (gettext-base)" bash -c 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq gettext-base'
if [ "$_need_fetch" = 1 ]; then
  HERE="$(mktemp -d)"   # set in the PARENT so _fetch_assets (run in a subshell) and the realm render agree
  run_step "Fetching bundled-IdP assets (${BEAMHALL_REF:-latest release})" _fetch_assets
fi

if [ "${RESET:-0}" = "1" ]; then
  box "$C_Y" "⚠  RESET — wiping all runtime identity state" \
    "This destroys the Keycloak container and the persistent volume ${C_B}${VOLUME}${C_RST}." \
    "ALL users/groups/config you created will be LOST and the realm re-seeded."
  confirm "Really wipe and re-seed?" || die "aborted."
  run_step "Removing Keycloak container + volume" bash -c "docker rm -f beamhall-keycloak >/dev/null 2>&1 || true; docker volume rm '$VOLUME' >/dev/null 2>&1 || true"
fi

if docker volume inspect "$VOLUME" >/dev/null 2>&1; then FIRST_INSTALL=0; else FIRST_INSTALL=1; fi

phase "Realm + credentials"
if [ "$FIRST_INSTALL" = "1" ]; then
  ADMIN_SECRET="$(gen 24)"; BUILDER_PASSWORD="$(gen 10)"; IT_PASSWORD="$(gen 10)"
  KC_ADMIN_PASSWORD="$(gen 12)"; IDP_ADMIN_SECRET="$(gen 24)"
  _render_realm() {
    install -d -m 0750 -o root -g beamhall /etc/beamhall/keycloak
    export AUDIENCE ADMIN_REDIRECT ADMIN_SECRET BUILDER_PASSWORD IT_PASSWORD IDP_ADMIN_SECRET
    envsubst '${AUDIENCE} ${ADMIN_REDIRECT} ${ADMIN_SECRET} ${BUILDER_PASSWORD} ${IT_PASSWORD} ${IDP_ADMIN_SECRET}' \
      < "$HERE/realm-template.json" > /etc/beamhall/keycloak/realm.json
    chmod 0644 /etc/beamhall/keycloak/realm.json
  }
  run_step "Generating credentials + rendering the realm (first install)" _render_realm
else
  ADMIN_SECRET="$(sed -n 's/^BEAMHALL_ADMIN_CLIENT_SECRET=//p' "$ENVFILE" 2>/dev/null | tail -n1)"
  [ -n "$ADMIN_SECRET" ] || die "no BEAMHALL_ADMIN_CLIENT_SECRET in $ENVFILE — run RESET=1 to re-seed"
  IDP_ADMIN_SECRET="$(sed -n 's/^BEAMHALL_IDP_ADMIN_CLIENT_SECRET=//p' "$ENVFILE" 2>/dev/null | tail -n1)"
  [ -n "$IDP_ADMIN_SECRET" ] || die "no BEAMHALL_IDP_ADMIN_CLIENT_SECRET in $ENVFILE — run RESET=1 to re-seed"
  KC_ADMIN_PASSWORD="$(gen 12)"
  ok "existing persistent state detected — preserving realm + secrets"
fi

phase "Bring up Keycloak + wire the appliance"
_start_kc() {
  sed -e "s#\${KC_HOSTNAME}#${SCHEME}://${IDP_HOST}#" -e "s#\${KC_ADMIN_PASSWORD}#${KC_ADMIN_PASSWORD}#" \
    "$HERE/beamhall-keycloak.service" > /etc/systemd/system/beamhall-keycloak.service
  systemctl daemon-reload; systemctl enable beamhall-keycloak >/dev/null 2>&1 || true
  systemctl restart beamhall-keycloak
}
run_step "Installing + starting the Keycloak service" _start_kc

_wire_env() {
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
  grep -q "$IDP_HOST" /etc/hosts || echo "127.0.0.1 ${IDP_HOST}" >>/etc/hosts
  systemctl restart beamhalld
}
run_step "Wiring beamhalld to trust the IdP" _wire_env

phase "Wait for the identity provider"
note "Keycloak's first boot imports the realm — this can take up to ~90s."
spinner_wait "Keycloak answering through the gateway" 120 \
  curl -fsS "${ISSUER}/.well-known/openid-configuration" \
  || die "Keycloak did not come up in time — check: journalctl -u beamhall-keycloak -n 80"

phase "Register the seed identities"
export BEAMHALL_DATA_DIR="${BEAMHALL_DATA_DIR:-/var/lib/beamhall}" BEAMHALL_BASE_DOMAIN="$BASE_DOMAIN"
run_step "Registering it-admin + creating the pilot workspace" bash -c "
  '$BEAMHALLD' admin register-identity -issuer '$ISSUER' -subject it-admin -email it-admin@beamhall.pilot || true
  '$BEAMHALLD' admin bootstrap -beamhall pilot -display 'Pilot workspace' -issuer '$ISSUER' -subject builder -email builder@beamhall.pilot -role builder -runtime runc || true"

# ============================================================================
if [ "$FIRST_INSTALL" = "1" ]; then
  note "credentials generated — they're in your setup checklist (shown once, at the end)"
  chk "" "[ ] SAVE THESE CREDENTIALS  (generated once)" \
       "      Admin console : ${SCHEME}://${BASE_DOMAIN}/admin" \
       "        it-admin    : ${IT_PASSWORD}" \
       "      Builder login : ${BUILDER_PASSWORD}   (user: builder)" \
       "      Keycloak admin: ${SCHEME}://${IDP_HOST}   admin / ${KC_ADMIN_PASSWORD}" \
       "      (client secrets are in ${ENVFILE})" \
       "" \
       "[ ] CONNECT AN AGENT OVER MCP" \
       "      Engineer (builder):" \
       "        claude mcp add --transport http --client-id beamhall-agent beamhall ${SCHEME}://${BASE_DOMAIN}/mcp" \
       "      IT operator (admin — gated by the beamhall-it realm role):" \
       "        claude mcp add --transport http --client-id beamhall-admin-agent beamhall-admin ${SCHEME}://${BASE_DOMAIN}/mcp"
else
  ok "bundled IdP re-wired — existing state preserved (passwords unchanged)"
  chk "" "Bundled IdP re-wired. Passwords are unchanged from first install;" \
       "client secrets live in ${ENVFILE}. Wipe + re-seed: sudo RESET=1 BASE_DOMAIN=${BASE_DOMAIN} bash …"
fi

# Standalone: print the checklist here. Chained (install.sh set the summary
# path): just append — install.sh prints the consolidated checklist at the end.
if [ "$_OWN_SUMMARY" = 1 ]; then
  box "$C_G" "✅  Bundled IdP ready" \
    "MCP + the Admin console are live at ${C_B}${SCHEME}://${BASE_DOMAIN}${C_RST}."
  printf '\n%s%s📋  YOUR TURN — do these now%s %s(saved to %s)%s\n' "$C_Y" "$C_B" "$C_RST" "$C_DIM" "$SUMMARY" "$C_RST"
  cat "$SUMMARY"
else
  ok "bundled IdP ready — credentials are in the final checklist below"
fi
