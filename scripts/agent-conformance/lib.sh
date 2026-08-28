#!/usr/bin/env bash
# Shared config + helpers for the Beamhall agent-conformance suite.
# Sourced by provision.sh / verify.sh / gates.sh / teardown.sh.

set -euo pipefail

# --- appliance + endpoints ---------------------------------------------------
# BEAMHALL_APPLIANCE (ssh target, e.g. root@<appliance-ip>) and BH_CA (path to
# the gateway CA cert on this machine) are deployment-specific: set them in the
# environment or in the gitignored .env alongside this script.
APPLIANCE="${BEAMHALL_APPLIANCE:-${BEAMHALL_TEST_HOST:+root@$BEAMHALL_TEST_HOST}}"
[ -n "$APPLIANCE" ] || { echo "set BEAMHALL_APPLIANCE (ssh target, e.g. root@<appliance-ip>) or BEAMHALL_TEST_HOST" >&2; exit 1; }
ISSUER="${BH_ISSUER:-https://idp.beamhall.internal/realms/beamhall}"
MCP_URL="${BH_MCP_URL:-https://beamhall.internal/mcp}"
CA="${BH_CA:-$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)/gateway-ca.crt}"
ENVFILE_REMOTE="/etc/beamhall/beamhall.env"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
ENV_LOCAL="${BH_ENV_FILE:-$HERE/.env}"           # gitignored secrets file (username=password)
PROXY="$HERE/bh-mcp-proxy.py"

# --- the four personas ------------------------------------------------------
# Admins elevate via the beamhall-it realm role (the public admin client cannot
# obtain the admin:it scope); builders get capability scopes only.
ADMINS=(admin-alice admin-bob)
BUILDERS=(builder-carol builder-dave)
ALL_USERS=("${ADMINS[@]}" "${BUILDERS[@]}")

ADMIN_CLIENT="beamhall-admin-agent"
BUILDER_CLIENT="beamhall-agent"

# Canonical capability scope (must match .mcp.json). beamhall-audience maps the
# aud claim; admin power is the role, not a scope.
CAP_SCOPE="beamhall-audience beamhalls:read beams:write beams:deploy beams:operate beams:promote secrets:write resources:write logs:read metrics:read"

# workspace -> owning builder
WORKSPACE_BLUE="team-blue"
WORKSPACE_GREEN="team-green"
EMAIL_DOMAIN="beamhall.internal"

# --- helpers ----------------------------------------------------------------
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=10 "$APPLIANCE")
remote() { "${SSH[@]}" "$@"; }

say()  { printf '   \033[36m•\033[0m %s\n' "$*"; }
ok()   { printf '   \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '   \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

client_for() { case "$1" in admin-*) echo "$ADMIN_CLIENT";; *) echo "$BUILDER_CLIENT";; esac; }
is_admin()   { case "$1" in admin-*) return 0;; *) return 1;; esac; }
