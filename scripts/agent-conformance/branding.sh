#!/usr/bin/env bash
# Exercise company branding end-to-end against the live appliance:
#
#   admin_set_branding (IT, no beamhall)  → facility-wide default + a logo
#   admin_set_branding (IT, team-blue)    → per-team primary-colour override
#   show_branding (carol, team-blue)      → merged view (blue primary over facility)
#   show_branding (dave, team-green)      → pure facility values (scope=facility)
#   show_branding (carol, team-green)     → DENIED (membership isolation)
#   admin_set_branding (carol)            → DENIED (separation of duties)
#   curl css_url + logo_url ($BH_CA)      → the gateway serves the public assets
#   admin_set_branding clear (team-blue)  → falls back to the facility default
#
#   scripts/agent-conformance/branding.sh
#
# Requires: the four personas (provision.sh) and the gateway CA on this
# machine (BH_CA). Pure MCP + HTTPS — nothing runs on the appliance.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"
call() { "$HERE/bh-call.sh" "$@"; }

ADMIN="admin-alice"
TMP="${TMPDIR:-/tmp}/bh-branding-$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

# A tiny valid-enough PNG (signature + padding) for the logo upload.
printf '\x89PNG\r\n\x1a\nconformance-logo' > "$TMP/logo.png"
LOGO_B64="$(base64 < "$TMP/logo.png" | tr -d '\n')"

# --- 1. IT sets the facility default (with logo) ------------------------------
say "1. admin_set_branding (facility-wide default)"
r="$(call "$ADMIN" admin_set_branding "{\"primary_color\":\"#112233\",\"secondary_color\":\"#445566\",\"header_html\":\"<div>ACME</div>\",\"logo_png_base64\":\"$LOGO_B64\"}" 2>/dev/null)"
echo "$r" | grep -qi "company-wide default" || die "facility set failed: $r"
ok "facility default set (logo uploaded)"

# --- 2. IT overrides team-blue's primary --------------------------------------
say "2. admin_set_branding (team-blue override)"
call "$ADMIN" admin_set_branding "{\"beamhall\":\"$WORKSPACE_BLUE\",\"primary_color\":\"#AABBCC\"}" >/dev/null 2>&1 \
  || die "team-blue override failed"
ok "team-blue overrides primary_color"

# --- 3. carol reads the merged view -------------------------------------------
say "3. show_branding (carol, team-blue) → merged"
b="$(call builder-carol show_branding "{\"beamhall\":\"$WORKSPACE_BLUE\"}" 2>/dev/null)"
echo "$b" | grep -q "#AABBCC" || die "override primary missing: $b"
echo "$b" | grep -q "#445566" || die "facility secondary did not fall through: $b"
CSS_URL="$(echo "$b" | grep -o 'https://[^" ]*/brand\.css' | head -1)"
LOGO_URL="$(echo "$b" | grep -o 'https://[^" ]*/logo-[0-9a-f]*\.png' | head -1)"
[ -n "$CSS_URL" ] && [ -n "$LOGO_URL" ] || die "branding URLs missing: $b"
ok "merged: blue primary over facility fields; URLs returned"

# --- 4. dave reads pure facility values ---------------------------------------
say "4. show_branding (dave, team-green) → facility"
g="$(call builder-dave show_branding "{\"beamhall\":\"$WORKSPACE_GREEN\"}" 2>/dev/null)"
echo "$g" | grep -q "#112233" || die "team-green should inherit the facility primary: $g"
echo "$g" | grep -q "#AABBCC" && die "team-blue's override leaked into team-green: $g"
ok "team-green inherits the facility default"

# --- 5. isolation + separation of duties --------------------------------------
# bh-call.sh exits 0 even on a tool-level refusal — assert on the refusal text.
say "5. denials: cross-hall read, builder write"
iso="$(call builder-carol show_branding "{\"beamhall\":\"$WORKSPACE_GREEN\"}" 2>/dev/null)"
echo "$iso" | grep -qi "TOOL ERROR\|denied" || die "carol read team-green's branding (isolation broken): $iso"
echo "$iso" | grep -q "#112233" && die "team-green's values leaked to carol: $iso"
ok "carol → team-green branding: denied"
sod="$(call builder-carol admin_set_branding '{"primary_color":"#000000"}' 2>/dev/null)"
echo "$sod" | grep -qi "TOOL ERROR\|insufficient_scope\|denied" || die "carol set branding (separation of duties broken): $sod"
ok "carol → admin_set_branding: denied"

# --- 6. the gateway serves the public assets ----------------------------------
say "6. public assets over the gateway"
css="$(curl -fsS --cacert "$CA" "$CSS_URL")" || die "brand.css not served: $CSS_URL"
echo "$css" | grep -q -- "--brand-primary:#AABBCC;" || die "brand.css wrong palette: $css"
curl -fsS --cacert "$CA" "$LOGO_URL" -o "$TMP/served.png" || die "logo not served: $LOGO_URL"
# LC_ALL=C: the PNG signature byte 0x89 makes BSD grep treat the input as
# invalid text and miss the match under a UTF-8 locale.
head -c 4 "$TMP/served.png" | LC_ALL=C grep -q "PNG" || die "served logo is not a PNG"
ok "brand.css + logo live at their public URLs"

# --- 7. clearing the override falls back --------------------------------------
say "7. admin_set_branding clear (team-blue) → inherits facility"
call "$ADMIN" admin_set_branding "{\"beamhall\":\"$WORKSPACE_BLUE\",\"clear\":true}" >/dev/null 2>&1 \
  || die "clear failed"
b2="$(call builder-carol show_branding "{\"beamhall\":\"$WORKSPACE_BLUE\"}" 2>/dev/null)"
echo "$b2" | grep -q "#112233" || die "team-blue did not fall back to the facility default: $b2"
css2="$(curl -fsS --cacert "$CA" "$CSS_URL")" || die "brand.css gone after clear"
echo "$css2" | grep -q -- "--brand-primary:#112233;" || die "hot-linked stylesheet did not follow the clear: $css2"
ok "override cleared; stylesheet followed with no redeploy"

printf '\n\033[32m✓ branding conformance PASSED\033[0m\n'
echo "Note: leave the facility default in place or clear it with:"
echo "  bh-call.sh admin-alice admin_set_branding '{\"clear\":true}'"
