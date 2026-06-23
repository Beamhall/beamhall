#!/usr/bin/env bash
# Provision the four conformance identities + two workspaces on the appliance.
#
#   scripts/agent-conformance/provision.sh
#
# Idempotent. Creates IdP users admin-alice/admin-bob (with the beamhall-it realm
# role) and builder-carol/builder-dave (no role), gives each a PERMANENT password
# (so headless ROPC works), registers all four Beamhall identities, creates
# team-blue (carol) and team-green (dave) — granting ONLY the owning builder —
# then writes the gitignored secrets file the proxy reads. Re-running rotates the
# passwords and rewrites the secrets file (kept consistent on purpose).
#
# The heavy lifting runs on the appliance (Keycloak is loopback-only there);
# generated passwords come back over the encrypted SSH channel and are written
# only to the local gitignored .env — never to a file on the appliance.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"

A1="${ADMINS[0]}"; A2="${ADMINS[1]}"
BBLUE="${BUILDERS[0]}"; BGREEN="${BUILDERS[1]}"

say "Provisioning conformance identities on $APPLIANCE …"
say "  admins (beamhall-it): $A1, $A2"
say "  builders: $BBLUE → $WORKSPACE_BLUE, $BGREEN → $WORKSPACE_GREEN"

REMOTE='
set -euo pipefail
A1="$1"; A2="$2"; BBLUE="$3"; BGREEN="$4"; WBLUE="$5"; WGREEN="$6"; EDOM="$7"
ENVFILE=/etc/beamhall/beamhall.env
BEAMHALLD=/usr/local/bin/beamhalld
KC=$(sed -n "s#^BEAMHALL_IDP_ADMIN_URL=##p" "$ENVFILE" | tail -1)
REALM=$(sed -n "s#^BEAMHALL_IDP_ADMIN_REALM=##p" "$ENVFILE" | tail -1)
CID=$(sed -n "s#^BEAMHALL_IDP_ADMIN_CLIENT_ID=##p" "$ENVFILE" | tail -1)
SEC=$(sed -n "s/^BEAMHALL_IDP_ADMIN_CLIENT_SECRET=//p" "$ENVFILE" | tail -1)
ISSUER=$(sed -n "s#^BEAMHALL_OAUTH_ISSUER=##p" "$ENVFILE" | tail -1)
[ -n "$KC" ] && [ -n "$SEC" ] && [ -n "$ISSUER" ] || { echo "missing IdP admin config in $ENVFILE" >&2; exit 1; }

TOK=$(curl -fsS "$KC/realms/$REALM/protocol/openid-connect/token" \
  -d grant_type=client_credentials -d client_id="$CID" -d client_secret="$SEC" | jq -r .access_token)
[ -n "$TOK" ] && [ "$TOK" != null ] || { echo "could not obtain Keycloak admin token" >&2; exit 1; }
AUTH="Authorization: Bearer $TOK"
ROLE=$(curl -fsS -H "$AUTH" "$KC/admin/realms/$REALM/roles/beamhall-it")
echo "$ROLE" | jq -e .id >/dev/null || { echo "beamhall-it realm role not found" >&2; exit 1; }

uid_of() { curl -fsS -H "$AUTH" "$KC/admin/realms/$REALM/users?username=$1&exact=true" | jq -r ".[0].id // empty"; }

ensure_user() {  # <username> <admin:yes|no>
  local u="$1" admin="$2" uid pw
  uid=$(uid_of "$u")
  if [ -z "$uid" ]; then
    curl -fsS -X POST -H "$AUTH" -H "Content-Type: application/json" "$KC/admin/realms/$REALM/users" \
      -d "{\"username\":\"$u\",\"email\":\"$u@$EDOM\",\"enabled\":true,\"emailVerified\":true,\"firstName\":\"$u\",\"lastName\":\"conformance\"}" >/dev/null
    uid=$(uid_of "$u")
    echo "  created IdP user $u ($uid)" >&2
  else
    echo "  IdP user $u exists ($uid)" >&2
  fi
  # Complete the profile + clear required actions so headless ROPC works (an
  # incomplete profile triggers "Account is not fully set up"). Idempotent.
  curl -fsS -X PUT -H "$AUTH" -H "Content-Type: application/json" "$KC/admin/realms/$REALM/users/$uid" \
    -d "{\"email\":\"$u@$EDOM\",\"enabled\":true,\"emailVerified\":true,\"firstName\":\"$u\",\"lastName\":\"conformance\",\"requiredActions\":[]}" >/dev/null
  pw=$(openssl rand -hex 12)
  curl -fsS -X PUT -H "$AUTH" -H "Content-Type: application/json" \
    "$KC/admin/realms/$REALM/users/$uid/reset-password" \
    -d "{\"type\":\"password\",\"value\":\"$pw\",\"temporary\":false}"
  if [ "$admin" = yes ]; then
    curl -fsS -X POST -H "$AUTH" -H "Content-Type: application/json" \
      "$KC/admin/realms/$REALM/users/$uid/role-mappings/realm" -d "[$ROLE]" >/dev/null || true
    echo "  assigned beamhall-it to $u" >&2
  fi
  printf "CRED %s %s\n" "$u" "$pw"   # stdout: captured by the Mac
}

ensure_user "$A1" yes
ensure_user "$A2" yes
ensure_user "$BBLUE" no
ensure_user "$BGREEN" no

# Register all four Beamhall identities (admins need a registered identity but no
# membership — the role is the bypass).
for u in "$A1" "$A2" "$BBLUE" "$BGREEN"; do
  "$BEAMHALLD" admin register-identity -issuer "$ISSUER" -subject "$u" -email "$u@$EDOM" >&2 2>&1 || true
done
# Two isolated workspaces, each granting ONLY its owning builder.
"$BEAMHALLD" admin bootstrap -beamhall "$WBLUE"  -display "Team Blue"  -issuer "$ISSUER" -subject "$BBLUE"  -email "$BBLUE@$EDOM"  -role builder -runtime runc >&2 2>&1 || true
"$BEAMHALLD" admin bootstrap -beamhall "$WGREEN" -display "Team Green" -issuer "$ISSUER" -subject "$BGREEN" -email "$BGREEN@$EDOM" -role builder -runtime runc >&2 2>&1 || true
echo "  registered 4 identities; bootstrapped $WBLUE + $WGREEN" >&2
'

creds="$(printf '%s' "$REMOTE" | "${SSH[@]}" bash -s -- \
  "$A1" "$A2" "$BBLUE" "$BGREEN" "$WORKSPACE_BLUE" "$WORKSPACE_GREEN" "$EMAIL_DOMAIN")"

n=$(printf '%s\n' "$creds" | grep -c '^CRED ' || true)
[ "$n" -eq 4 ] || die "expected 4 credentials back, got $n"

umask 077
{
  echo "# Beamhall agent-conformance secrets — generated by provision.sh. GITIGNORED."
  echo "# Format: <idp-username>=<password>, read by bh-mcp-proxy.py."
  printf '%s\n' "$creds" | awk '/^CRED /{print $2"="$3}'
} > "$ENV_LOCAL"
chmod 600 "$ENV_LOCAL"
ok "wrote $n credentials to $ENV_LOCAL (chmod 600, gitignored)"

say "Verifying token elevation (admins see admin_*, builders don't) …"
"$HERE/verify.sh" || die "verification failed — see above"
ok "provisioning complete. Restart Claude Code to connect the four MCP servers."
