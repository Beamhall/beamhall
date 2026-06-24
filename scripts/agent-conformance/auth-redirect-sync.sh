#!/usr/bin/env bash
# Exercise the provisioned-auth (PLAN §5.10) LIFECYCLE HOOKS end-to-end against
# the live appliance + real Keycloak. auth-isolation.sh proves the load-bearing
# 401; this proves the moving parts that keep sign-in working as a beam's URL
# changes, and that production gets its own mirrored relying party:
#
#   provision_auth         → preview OIDC client, EMPTY redirect allowlist (no host yet)
#   deploy_beam            → finalizeActiveRelease syncs preview redirects to host H1
#   admin_set_auth_groups  → IT curates the group allowlist on the (preview) client
#   pause_preview          → redirect allowlist EMPTIED (the paused URL is dead)
#   resume_preview         → new host H2 (rotation), redirects re-synced to H2
#   promote_to_live (IT)   → mirrorLiveAuthClient mints a DISTINCT live client
#                            (own secret, own audience, stable live host) and
#                            CARRIES the group allowlist to production
#   destroy_beam (IT)      → reclaims BOTH channel clients (no orphans)
#
# Each step is verified by reading the client back from Keycloak's Admin REST
# (loopback on the appliance, same bootstrap as auth-isolation.sh) — so the
# assertions are against the real IdP, not the backplane's own view.
#
#   scripts/agent-conformance/auth-redirect-sync.sh [beam-slug]
#
# Requires: a beamhalld with provisioned-auth, the four personas (provision.sh),
# the gateway CA on the Mac (BH_CA), and a free live slot in team-blue. The beam
# is deployed by PINNING an already-built team-blue image (no pack build needed —
# the redirect-sync hooks fire on route/host assignment, not on what the app does).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"

BEAM="${1:-authsync}"
WS="$WORKSPACE_BLUE"            # team-blue (builder-carol owns it)
BUILDER="builder-carol"
ADMIN="admin-alice"            # IT: promotes + destroys + curates groups
GROUP="hr"                     # the curated allowlist group (created if absent)
BASE_DOMAIN="beamhall.internal"
AUDIENCE="https://beamhall.internal/mcp"   # BEAMHALL_OAUTH_AUDIENCE (the forbidden aud)

PREVIEW_CLIENT="beam-${WS}-${BEAM}-preview"
LIVE_CLIENT="beam-${WS}-${BEAM}-live"
LIVE_HOST="${BEAM}.${WS}.${BASE_DOMAIN}"   # liveHost(beamSlug, hallSlug) is deterministic

# An already-built, secret-free Node image in this hall (serves on $PORT, boots
# clean). Resolve its digest from the loopback registry so the pin is immutable.
REG_HOST="127.0.0.1:5000"
REPO_PATH="${WS}/blue-web"
IMG_REPO="${REG_HOST}/${REPO_PATH}"

call() { "$HERE/bh-call.sh" "$@"; }

# --- Keycloak inspector: print a client's live shape, fields one per line ----
# Reuses the bundled-IdP admin creds from the appliance env (loopback only).
KC_INSPECT='
set -euo pipefail
CLIENT_ID="$1"
ENVFILE=/etc/beamhall/beamhall.env
KC=$(sed -n "s#^BEAMHALL_IDP_ADMIN_URL=##p" "$ENVFILE" | tail -1)
REALM=$(sed -n "s#^BEAMHALL_IDP_ADMIN_REALM=##p" "$ENVFILE" | tail -1)
CID=$(sed -n "s#^BEAMHALL_IDP_ADMIN_CLIENT_ID=##p" "$ENVFILE" | tail -1)
SEC=$(sed -n "s/^BEAMHALL_IDP_ADMIN_CLIENT_SECRET=//p" "$ENVFILE" | tail -1)
TOK=$(curl -fsS "$KC/realms/$REALM/protocol/openid-connect/token" \
  -d grant_type=client_credentials -d client_id="$CID" -d client_secret="$SEC" | jq -r .access_token)
AUTH="Authorization: Bearer $TOK"
J=$(curl -fsS -H "$AUTH" "$KC/admin/realms/$REALM/clients?clientId=$CLIENT_ID")
[ "$(printf "%s" "$J" | jq "length")" != "0" ] || { echo "EXISTS=no"; exit 0; }
echo "EXISTS=yes"
UUID=$(printf "%s" "$J" | jq -r ".[0].id")
printf "REDIRECTS=%s\n" "$(printf "%s" "$J" | jq -r "(.[0].redirectUris//[])|sort|join(\",\")")"
printf "ORIGINS=%s\n"   "$(printf "%s" "$J" | jq -r "(.[0].webOrigins//[])|sort|join(\",\")")"
# Audience the client injects (must equal the OWN clientId, never AUD). Read the
# client-level protocol mappers directly — our audience mapper is on the client,
# not on a shared scope (so evaluate-scopes does not surface it).
printf "AUD=%s\n" "$(curl -fsS -H "$AUTH" \
  "$KC/admin/realms/$REALM/clients/$UUID/protocol-mappers/models" \
  | jq -r "[.[]|select(.protocolMapper==\"oidc-audience-mapper\")
            |(.config[\"included.client.audience\"]//.config[\"included.custom.audience\"])]
           |map(select(.!=null))|unique|join(\",\")")"
# Hash the secret so we can prove preview/live differ WITHOUT exfiltrating it.
printf "SECRETHASH=%s\n" "$(curl -fsS -H "$AUTH" \
  "$KC/admin/realms/$REALM/clients/$UUID/client-secret" | jq -r .value | sha256sum | cut -c1-16)"
# The group allowlist is implemented as per-group client roles on the client.
printf "ROLES=%s\n" "$(curl -fsS -H "$AUTH" \
  "$KC/admin/realms/$REALM/clients/$UUID/roles" | jq -r "[.[].name]|sort|join(\",\")")"
'
inspect() { printf '%s' "$KC_INSPECT" | "${SSH[@]}" bash -s -- "$1" 2>/dev/null; }
field()   { printf '%s\n' "$1" | sed -n "s/^$2=//p" | head -1; }
host_in() { printf '%s\n' "$1" | tr ',' '\n' | sed -nE 's#^https?://([^/]+)/.*#\1#p' | head -1; }

# beam_host <preview|live>: the host the gateway actually serves the beam on,
# read from list_beams (independent of the auth subsystem — ties Keycloak to the
# real route).
beam_host() {
  call "$BUILDER" list_beams '{}' 2>/dev/null | sed -n 's/^\[structured\] //p' \
    | jq -r --arg b "$BEAM" --arg c "$1" \
        '.beamhalls[]?.beams[]? | select(.beam==$b)
         | (if $c=="live" then .live_url else .preview_url end) // ""' 2>/dev/null \
    | sed -E 's#^https?://([^/]+).*#\1#' | head -1
}

[ -f "$ENV_LOCAL" ] || die "no secrets file at $ENV_LOCAL — run provision.sh first"

printf '\n\033[1mProvisioned-auth lifecycle pass — %s/%s\033[0m\n\n' "$WS" "$BEAM"

# --- 0. Resolve the pinned image digest -------------------------------------
say "0. Resolve a build-free image to deploy ($IMG_REPO)"
TAG="$("${SSH[@]}" "curl -fsS http://${REG_HOST}/v2/${REPO_PATH}/tags/list" 2>/dev/null \
        | jq -r '.tags[0] // empty' || true)"
[ -n "$TAG" ] || die "no built image in the registry for $REPO_PATH — deploy blue-web first, or adapt REPO_PATH"
DIGEST="$("${SSH[@]}" "curl -fsS -o /dev/null -D - -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' http://${REG_HOST}/v2/${REPO_PATH}/manifests/${TAG}" 2>/dev/null \
        | tr -d '\r' | awk 'tolower($1)=="docker-content-digest:"{print $2}' || true)"
[ -n "$DIGEST" ] || die "could not resolve the manifest digest for $REPO_PATH:$TAG"
IMG_DIGEST="${IMG_REPO}@${DIGEST}"
ok "pinning $IMG_DIGEST"

# --- 1. provision_auth (before any deploy) ----------------------------------
say "1. Builder provisions company sign-in — BEFORE the first deploy"
call "$BUILDER" create_beam "{\"beamhall\":\"$WS\",\"slug\":\"$BEAM\",\"display_name\":\"Auth Sync\",\"runtime_hint\":\"node\"}" >/dev/null 2>&1 || true
prov="$(call "$BUILDER" provision_auth "{\"beamhall\":\"$WS\",\"beam\":\"$BEAM\"}" 2>/dev/null || true)"
printf '%s\n' "$prov" | grep -q 'OIDC_CLIENT_SECRET' || die "provision_auth did not return the OIDC keys:\n$prov"
ok "provision_auth returned the key set (no secret value)"

p="$(inspect "$PREVIEW_CLIENT")"
[ "$(field "$p" EXISTS)" = "yes" ]  || die "preview client $PREVIEW_CLIENT was not created in Keycloak"
[ -z "$(field "$p" REDIRECTS)" ]    || die "preview client has redirects before any deploy: $(field "$p" REDIRECTS)"
[ "$(field "$p" AUD)" = "$PREVIEW_CLIENT" ] || die "preview audience is $(field "$p" AUD), expected own id $PREVIEW_CLIENT"
case "$(field "$p" AUD)" in *"$AUDIENCE"*) die "preview token would carry the Beamhall resource URI — isolation broken";; esac
ok "preview client exists, EMPTY redirect allowlist, audience = own id (not the backplane URI)"

# --- 2. deploy → redirects sync to the live host ----------------------------
say "2. Deploy (pinned image) — finalizeActiveRelease must sync preview redirects"
dep="$(call "$BUILDER" deploy_beam "{\"beamhall\":\"$WS\",\"beam\":\"$BEAM\",\"image_ref\":\"$IMG_REPO\",\"image_digest\":\"$IMG_DIGEST\"}" 2>/dev/null || true)"
printf '%s\n' "$dep" | grep -qiE 'preview|https://' || warn "deploy result had no URL:\n$dep"
H1="$(beam_host preview)"
[ -n "$H1" ] || die "beam has no preview host after deploy — deploy likely failed:\n$dep"
p="$(inspect "$PREVIEW_CLIENT")"
RD="$(field "$p" REDIRECTS)"; OR="$(field "$p" ORIGINS)"
[ "$(host_in "$RD")" = "$H1" ] || die "preview redirects point at $(host_in "$RD"), gateway serves $H1 — sync failed"
printf '%s' "$RD" | grep -q "https://$H1/auth/callback" || die "missing /auth/callback redirect for $H1"
printf '%s' "$RD" | grep -q "https://$H1/callback"      || die "missing /callback redirect for $H1"
[ "$OR" = "https://$H1" ] || die "preview web-origin is '$OR', expected https://$H1"
ok "preview redirects + web-origin synced to the live host ($H1)"

# --- 3. IT curates the group allowlist --------------------------------------
say "3. IT curates the group allowlist ($GROUP) on the beam's sign-in"
call "$ADMIN" admin_create_group "{\"name\":\"$GROUP\"}" >/dev/null 2>&1 || true
grp="$(call "$ADMIN" admin_set_auth_groups "{\"beamhall\":\"$WS\",\"beam\":\"$BEAM\",\"groups\":[\"$GROUP\"]}" 2>/dev/null || true)"
printf '%s\n' "$grp" | grep -qiv 'error' || warn "admin_set_auth_groups reported: $grp"
p="$(inspect "$PREVIEW_CLIENT")"
case ",$(field "$p" ROLES)," in *",$GROUP,"*) ok "preview client carries the '$GROUP' allowlist role";;
  *) die "preview client roles = '$(field "$p" ROLES)', expected to include $GROUP";; esac

# --- 4. pause → allowlist emptied -------------------------------------------
say "4. Pause — the dead preview URL's redirects must be cleared"
call "$BUILDER" pause_preview "{\"beamhall\":\"$WS\",\"beam\":\"$BEAM\"}" >/dev/null 2>&1 || true
p="$(inspect "$PREVIEW_CLIENT")"
[ -z "$(field "$p" REDIRECTS)" ] || die "redirects survived pause: $(field "$p" REDIRECTS)"
[ -z "$(field "$p" ORIGINS)" ]   || die "web-origins survived pause: $(field "$p" ORIGINS)"
ok "redirect allowlist emptied on pause"

# --- 5. resume → new host, redirects re-synced (rotation) -------------------
say "5. Resume — a NEW host is minted and redirects re-synced to it"
call "$BUILDER" resume_preview "{\"beamhall\":\"$WS\",\"beam\":\"$BEAM\"}" >/dev/null 2>&1 || true
H2="$(beam_host preview)"
[ -n "$H2" ] || die "no preview host after resume"
[ "$H2" != "$H1" ] || die "resume did NOT rotate the host ($H2) — the stale-URL property is broken"
p="$(inspect "$PREVIEW_CLIENT")"
[ "$(host_in "$(field "$p" REDIRECTS)")" = "$H2" ] || die "redirects point at $(host_in "$(field "$p" REDIRECTS)"), resumed host is $H2"
ok "host rotated ($H1 → $H2) and redirects re-synced to the new host (no redeploy)"

# --- 6. promote → live client mirrored, distinct, group carried -------------
say "6. Promote to live (IT) — mirrorLiveAuthClient mints production's own client"
PRE_SECRET="$(field "$(inspect "$PREVIEW_CLIENT")" SECRETHASH)"
promo="$(call "$ADMIN" promote_to_live "{\"beamhall\":\"$WS\",\"beam\":\"$BEAM\"}" 2>/dev/null || true)"
printf '%s\n' "$promo" | grep -qiv 'error\|denied' || warn "promote reported: $promo"
l="$(inspect "$LIVE_CLIENT")"
[ "$(field "$l" EXISTS)" = "yes" ] || die "live client $LIVE_CLIENT was not mirrored on promote:\n$promo"
LH="$(beam_host live)"
[ "$LH" = "$LIVE_HOST" ] || warn "list_beams live host '$LH' != expected $LIVE_HOST"
[ "$(host_in "$(field "$l" REDIRECTS)")" = "$LIVE_HOST" ] || die "live redirects point at $(host_in "$(field "$l" REDIRECTS)"), expected $LIVE_HOST"
[ "$(field "$l" AUD)" = "$LIVE_CLIENT" ] || die "live audience is $(field "$l" AUD), expected own id $LIVE_CLIENT"
case "$(field "$l" AUD)" in *"$AUDIENCE"*) die "live token would carry the Beamhall resource URI — isolation broken";; esac
[ "$(field "$l" SECRETHASH)" != "$PRE_SECRET" ] || die "live client shares the preview secret — credentials NOT isolated"
case ",$(field "$l" ROLES)," in *",$GROUP,"*) ok2group=1;; *) ok2group=0;; esac
[ "$ok2group" = "1" ] || die "live client did not inherit the '$GROUP' allowlist (carry-to-live failed): roles=$(field "$l" ROLES)"
ok "live client mirrored: stable host $LIVE_HOST, own audience, DISTINCT secret, '$GROUP' allowlist carried"

# --- 7. destroy → both clients reclaimed ------------------------------------
say "7. Destroy (IT) — both channel clients must be reclaimed (no orphans)"
call "$ADMIN" destroy_beam "{\"beamhall\":\"$WS\",\"beam\":\"$BEAM\"}" >/dev/null 2>&1 || true
[ "$(field "$(inspect "$PREVIEW_CLIENT")" EXISTS)" = "no" ] || die "preview client orphaned after destroy"
[ "$(field "$(inspect "$LIVE_CLIENT")" EXISTS)" = "no" ]    || die "live client orphaned after destroy"
ok "both preview and live OIDC clients deleted on destroy"

printf '\n\033[32m✓ provisioned-auth lifecycle verified live: deploy/pause/resume sync, live mirror + carry, reclaim\033[0m\n'
