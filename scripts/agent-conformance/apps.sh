#!/usr/bin/env bash
# Exercise the using tier (agent-facing apps) end-to-end against the live
# appliance:
#
#   builder-carol create_beam (with description)  → the app to publish
#   user-erin list_apps (first call)              → auto-registers her identity
#   admin_set_app_audience (identities:[erin])    → publish to erin alone
#   user-erin list_apps / describe_app            → sees it (unpromoted → "not live yet")
#   user-frank list_apps / describe_app           → does NOT see it; uniform refusal, no leak
#   user-erin create_beam / admin_set_app_audience→ DENIED (tier boundary)
#   admin_set_app_audience clear                  → unpublished for everyone
#   group path (bundled IdP): finance group       → erin (member) sees, frank doesn't
#
#   scripts/agent-conformance/apps.sh
#
# Requires: the six personas (provision.sh). Pure MCP — nothing runs on the
# appliance. The app is never deployed: publishing an unpromoted app is legal
# and shows to users as "not live yet" (the live-URL path is covered by the e2e
# suite, which can deploy).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"
call() { "$HERE/bh-call.sh" "$@"; }

ADMIN="admin-alice"
APP="staff-handbook"

# --- 0. baseline: the app exists and is unpublished ---------------------------
say "0. builder-carol registers the app (idempotent); ensure unpublished"
r="$(call builder-carol create_beam "{\"beamhall\":\"$WORKSPACE_BLUE\",\"slug\":\"$APP\",\"display_name\":\"Staff Handbook\",\"description\":\"Company policies and how-tos for every employee\"}" 2>/dev/null)"
echo "$r" | grep -qi "created\|already\|conflict\|exists" || die "create_beam failed: $r"
call "$ADMIN" admin_set_app_audience "{\"beamhall\":\"$WORKSPACE_BLUE\",\"beam\":\"$APP\",\"clear\":true}" >/dev/null 2>&1 || true
ok "app $APP registered in $WORKSPACE_BLUE, unpublished"

# --- 1. erin's first call auto-registers her ----------------------------------
say "1. user-erin list_apps (first call — auto-registration)"
e="$(call user-erin list_apps '{}' 2>/dev/null)"
echo "$e" | grep -qi "published to you" || die "erin's list_apps failed (auto-register broken?): $e"
echo "$e" | grep -q "$APP" && die "unpublished app already visible: $e"
ok "erin's channel works; unpublished app not listed"

# --- 2. IT publishes to erin alone --------------------------------------------
say "2. admin_set_app_audience (identities:[erin])"
ids="$(call "$ADMIN" admin_list_identities '{}' 2>/dev/null)"
ERIN_ID="$(printf '%s\n' "$ids" | grep "subject=user-erin" | awk '{print $2}' | head -1)"
[ -n "$ERIN_ID" ] || die "user-erin has no registered identity (auto-register failed): $ids"
p="$(call "$ADMIN" admin_set_app_audience "{\"beamhall\":\"$WORKSPACE_BLUE\",\"beam\":\"$APP\",\"identities\":[\"$ERIN_ID\"]}" 2>/dev/null)"
echo "$p" | grep -qi "published to" || die "publish failed: $p"
ok "published to erin (identity $ERIN_ID)"

# --- 3. erin sees it; unpromoted shows as not-live ----------------------------
say "3. user-erin list_apps + describe_app → visible, 'not live yet'"
e="$(call user-erin list_apps '{}' 2>/dev/null)"
echo "$e" | grep -q "$APP" || die "published app missing from erin's list: $e"
echo "$e" | grep -qi "not live yet" || die "unpromoted app should show 'not live yet': $e"
d="$(call user-erin describe_app "{\"app\":\"$APP\"}" 2>/dev/null)"
echo "$d" | grep -q "Company policies" || die "description missing from describe_app: $d"
echo "$d" | grep -q "$WORKSPACE_BLUE" || die "owning workspace missing: $d"
ok "erin sees the app with its description and owner"

# --- 4. frank is outside the audience -----------------------------------------
# bh-call.sh exits 0 even on a tool-level refusal — assert on the reply text.
say "4. user-frank → not listed; uniform refusal with no leak"
f="$(call user-frank list_apps '{}' 2>/dev/null)"
echo "$f" | grep -q "$APP" && die "audience isolation broken — frank sees $APP: $f"
fd="$(call user-frank describe_app "{\"app\":\"$APP\"}" 2>/dev/null)"
echo "$fd" | grep -qi "no app named" || die "expected the uniform refusal: $fd"
echo "$fd" | grep -q "$WORKSPACE_BLUE\|https://" && die "refusal leaks workspace/URL: $fd"
ok "frank: not listed, uniform refusal, nothing leaked"

# --- 5. the tier boundary -------------------------------------------------------
say "5. denials: user cannot build or publish"
b="$(call user-erin create_beam "{\"beamhall\":\"$WORKSPACE_BLUE\",\"slug\":\"nope\"}" 2>/dev/null)"
echo "$b" | grep -qi "TOOL ERROR\|insufficient_scope\|denied\|unknown tool\|not found" || die "erin reached create_beam: $b"
a="$(call user-erin admin_set_app_audience "{\"beamhall\":\"$WORKSPACE_BLUE\",\"beam\":\"$APP\",\"everyone\":true}" 2>/dev/null)"
echo "$a" | grep -qi "TOOL ERROR\|insufficient_scope\|denied\|unknown tool\|not found" || die "erin reached admin_set_app_audience: $a"
ok "erin → create_beam / admin_set_app_audience: denied"

# --- 6. unpublish removes it everywhere ---------------------------------------
say "6. admin_set_app_audience clear → gone from erin's list"
call "$ADMIN" admin_set_app_audience "{\"beamhall\":\"$WORKSPACE_BLUE\",\"beam\":\"$APP\",\"clear\":true}" >/dev/null 2>&1 \
  || die "clear failed"
e2="$(call user-erin list_apps '{}' 2>/dev/null)"
echo "$e2" | grep -q "$APP" && die "unpublished app still listed for erin: $e2"
ok "unpublished; erin no longer sees it"

# --- 7. group audience (bundled IdP) ------------------------------------------
say "7. group audience: finance → erin (member) sees, frank doesn't"
g="$(call "$ADMIN" admin_create_group '{"name":"finance"}' 2>/dev/null)"
if echo "$g" | grep -qi "TOOL ERROR\|not available\|BYO"; then
  warn "bundled-IdP group tools unavailable — skipping the group-audience path"
else
  gid="$(printf '%s\n' "$g" | grep -o '"group_id":"[^"]*"' | head -1 | cut -d'"' -f4)"
  if [ -z "$gid" ]; then
    lg="$(call "$ADMIN" admin_list_groups '{}' 2>/dev/null)"
    gid="$(printf '%s\n' "$lg" | grep -i finance | grep -o '[0-9a-f-]\{36\}' | head -1)"
  fi
  [ -n "$gid" ] || die "could not resolve the finance group id: $g"
  uid="$(call "$ADMIN" admin_list_users '{"query":"user-erin"}' 2>/dev/null | grep -o '[0-9a-f-]\{36\}' | head -1)"
  [ -n "$uid" ] || die "could not resolve user-erin's IdP user id"
  call "$ADMIN" admin_add_user_to_group "{\"user_id\":\"$uid\",\"group_id\":\"$gid\"}" >/dev/null 2>&1 || true
  call "$ADMIN" admin_set_app_audience "{\"beamhall\":\"$WORKSPACE_BLUE\",\"beam\":\"$APP\",\"groups\":[\"finance\"]}" >/dev/null 2>&1 \
    || die "group publish failed"
  eg="$(call user-erin list_apps '{}' 2>/dev/null)"
  echo "$eg" | grep -q "$APP" || die "finance member erin does not see the group-published app: $eg"
  fg="$(call user-frank list_apps '{}' 2>/dev/null)"
  echo "$fg" | grep -q "$APP" && die "non-member frank sees the group-published app: $fg"
  call "$ADMIN" admin_set_app_audience "{\"beamhall\":\"$WORKSPACE_BLUE\",\"beam\":\"$APP\",\"clear\":true}" >/dev/null 2>&1 || true
  ok "group audience: erin in, frank out (cleared after)"
fi

# --- 8. app tools (stage 2): not-live copy, tier boundary, update_beam --------
# The full brokered-invoke path needs a deployed app and lives in the e2e suite
# (TestAppToolsEndToEnd); here we prove the copy and the tier boundary pure-MCP.
say "8. use_app on an unpromoted app; tier boundary; update_beam"
call "$ADMIN" admin_set_app_audience "{\"beamhall\":\"$WORKSPACE_BLUE\",\"beam\":\"$APP\",\"identities\":[\"$ERIN_ID\"]}" >/dev/null 2>&1 \
  || die "republish failed"
u="$(call user-erin use_app "{\"app\":\"$APP\"}" 2>/dev/null)"
echo "$u" | grep -qi "not live yet" || die "use_app on an unpromoted app should say 'not live yet': $u"
fu="$(call user-frank use_app "{\"app\":\"$APP\"}" 2>/dev/null)"
echo "$fu" | grep -qi "no app named" || die "frank's use_app should get the uniform refusal: $fu"
echo "$fu" | grep -q "$WORKSPACE_BLUE\|https://" && die "use_app refusal leaks workspace/URL: $fu"
tb="$(call user-erin try_beam_tool "{\"beamhall\":\"$WORKSPACE_BLUE\",\"beam\":\"$APP\"}" 2>/dev/null)"
echo "$tb" | grep -qi "TOOL ERROR\|insufficient_scope\|denied\|unknown tool\|not found" || die "erin reached try_beam_tool: $tb"
ub="$(call builder-carol update_beam "{\"beamhall\":\"$WORKSPACE_BLUE\",\"beam\":\"$APP\",\"description\":\"Conformance-updated description\"}" 2>/dev/null)"
echo "$ub" | grep -qi "updated" || die "update_beam failed: $ub"
ed="$(call user-erin describe_app "{\"app\":\"$APP\"}" 2>/dev/null)"
echo "$ed" | grep -q "Conformance-updated description" || die "describe_app did not pick up update_beam: $ed"
call builder-carol update_beam "{\"beamhall\":\"$WORKSPACE_BLUE\",\"beam\":\"$APP\",\"description\":\"Company policies and how-tos for every employee\"}" >/dev/null 2>&1 || true
call "$ADMIN" admin_set_app_audience "{\"beamhall\":\"$WORKSPACE_BLUE\",\"beam\":\"$APP\",\"clear\":true}" >/dev/null 2>&1 || true
ok "not-live copy, uniform use_app refusal, tier denial, update_beam round trip (restored + cleared)"

printf '\n\033[32m✓ apps (using tier) conformance PASSED\033[0m\n'
echo "Note: the app $APP stays registered (unpublished) in $WORKSPACE_BLUE."
