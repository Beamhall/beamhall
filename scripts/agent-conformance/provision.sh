#!/usr/bin/env bash
# Provision the six conformance identities + two workspaces on the appliance.
#
#   scripts/agent-conformance/provision.sh
#
# Idempotent. Creates IdP users admin-alice/admin-bob (with the beamhall-it realm
# role), builder-carol/builder-dave (no role), and user-erin/user-frank (the
# using tier: an IdP account only — deliberately NOT registered as Beamhall
# identities and granted NO membership, so a conformance run proves user
# auto-registration on their first beams:use call). Gives each a PERMANENT
# password (so headless ROPC works), registers the admin/builder identities,
# creates team-blue (carol) and team-green (dave) — granting ONLY the owning
# builder — then writes the gitignored secrets file the proxy reads. Re-running
# rotates the passwords and rewrites the secrets file (kept consistent on purpose).
#
# The heavy lifting runs on the appliance (Keycloak is loopback-only there);
# generated passwords come back over the encrypted SSH channel and are written
# only to the local gitignored .env — never to a file on the appliance. It also
# fetches the appliance's install-generated gateway CA into the local gitignored
# gateway-ca.crt so the proxies can verify TLS (nothing cert-like is shipped).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"

A1="${ADMINS[0]}"; A2="${ADMINS[1]}"
BBLUE="${BUILDERS[0]}"; BGREEN="${BUILDERS[1]}"
UERIN="${USERS[0]}"; UFRANK="${USERS[1]}"

say "Provisioning conformance identities on $APPLIANCE …"
say "  admins (beamhall-it): $A1, $A2"
say "  builders: $BBLUE → $WORKSPACE_BLUE, $BGREEN → $WORKSPACE_GREEN"
say "  users (beams:use, no membership): $UERIN, $UFRANK"

REMOTE='
set -euo pipefail
A1="$1"; A2="$2"; BBLUE="$3"; BGREEN="$4"; UERIN="$5"; UFRANK="$6"; WBLUE="$7"; WGREEN="$8"; EDOM="$9"
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
ensure_user "$UERIN" no
ensure_user "$UFRANK" no

# Register the admin/builder Beamhall identities (admins need a registered
# identity but no membership — the role is the bypass). The user personas are
# deliberately NOT registered: their first beams:use call must auto-register
# them (BEAMHALL_USER_AUTO_REGISTER), and the conformance run proves it.
for u in "$A1" "$A2" "$BBLUE" "$BGREEN"; do
  "$BEAMHALLD" admin register-identity -issuer "$ISSUER" -subject "$u" -email "$u@$EDOM" >&2 2>&1 || true
done
# Two isolated workspaces, each granting ONLY its owning builder.
"$BEAMHALLD" admin bootstrap -beamhall "$WBLUE"  -display "Team Blue"  -issuer "$ISSUER" -subject "$BBLUE"  -email "$BBLUE@$EDOM"  -role builder -runtime runc >&2 2>&1 || true
"$BEAMHALLD" admin bootstrap -beamhall "$WGREEN" -display "Team Green" -issuer "$ISSUER" -subject "$BGREEN" -email "$BGREEN@$EDOM" -role builder -runtime runc >&2 2>&1 || true
echo "  registered 4 identities (users auto-register on first call); bootstrapped $WBLUE + $WGREEN" >&2
'

creds="$(printf '%s' "$REMOTE" | "${SSH[@]}" bash -s -- \
  "$A1" "$A2" "$BBLUE" "$BGREEN" "$UERIN" "$UFRANK" "$WORKSPACE_BLUE" "$WORKSPACE_GREEN" "$EMAIL_DOMAIN")"

n=$(printf '%s\n' "$creds" | grep -c '^CRED ' || true)
[ "$n" -eq 6 ] || die "expected 6 credentials back, got $n"

umask 077
{
  echo "# Beamhall agent-conformance secrets — generated by provision.sh. GITIGNORED."
  echo "# Format: <idp-username>=<password>, read by bh-mcp-proxy.py."
  printf '%s\n' "$creds" | awk '/^CRED /{print $2"="$3}'
} > "$ENV_LOCAL"
chmod 600 "$ENV_LOCAL"
ok "wrote $n credentials to $ENV_LOCAL (chmod 600, gitignored)"

# Fetch this appliance's gateway CA (generated at install time by Caddy's
# internal PKI, trusted on the appliance by install.sh) into the local
# gitignored path the proxies/scripts default to ($CA, see lib.sh). Idempotent:
# re-running just refreshes the copy.
CA_REMOTE=/usr/local/share/ca-certificates/beamhall-gateway-ca.crt
if "${SSH[@]}" cat "$CA_REMOTE" > "$CA.tmp" 2>/dev/null && [ -s "$CA.tmp" ]; then
  mv "$CA.tmp" "$CA"
  ok "fetched the gateway CA to $CA (gitignored)"
else
  rm -f "$CA.tmp"
  if [ -s "$CA" ]; then
    warn "could not fetch $CA_REMOTE from the appliance — keeping the existing $CA"
  else
    die "no gateway CA at $CA_REMOTE on the appliance (non-internal TLS install?) and no local $CA — set BH_CA to your CA bundle"
  fi
fi

say "Verifying token elevation (admins see admin_*, builders don't, users see only the app tools) …"
"$HERE/verify.sh" || die "verification failed — see above"
ok "provisioning complete. Restart Claude Code to connect the six MCP servers."
