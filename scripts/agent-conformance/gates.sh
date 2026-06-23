#!/usr/bin/env bash
# Reversibly toggle the appliance four-eyes gates for the conformance run, then
# restore. Backs up beamhall.env (timestamped) before each change.
#
#   scripts/agent-conformance/gates.sh on       # sensitive tier + promote approval ON
#   scripts/agent-conformance/gates.sh off       # back to the shipped defaults (both off)
#   scripts/agent-conformance/gates.sh status
#
# Wrap the four-eyes scenarios (b1/b2/b3/c) with `on`, then `off`. The restart is
# the only disruptive step (a few seconds; running beams are unaffected).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"

action="${1:-status}"

REMOTE='
set -euo pipefail
ACTION="$1"
ENVFILE=/etc/beamhall/beamhall.env
K1=BEAMHALL_IDP_SENSITIVE_ADMIN
K2=BEAMHALL_PROMOTE_APPROVAL
cur() { sed -n "s/^$1=//p" "$ENVFILE" | tail -1; }
case "$ACTION" in
  status)
    echo "$K1=$(cur $K1 | sed "s/^$/<unset (off)>/")"
    echo "$K2=$(cur $K2 | sed "s/^$/<unset (off)>/")"
    echo "beamhalld: $(systemctl is-active beamhalld)"
    exit 0 ;;
  on)  val=on ;;
  off) val=off ;;
  *) echo "usage: gates.sh on|off|status" >&2; exit 2 ;;
esac
cp "$ENVFILE" "$ENVFILE.bak.$(date +%s)"
sed -i "/^$K1=/d;/^$K2=/d" "$ENVFILE"
printf "%s=%s\n%s=%s\n" "$K1" "$val" "$K2" "$val" >> "$ENVFILE"
systemctl restart beamhalld
for _ in $(seq 1 20); do [ "$(systemctl is-active beamhalld)" = active ] && break; sleep 0.5; done
echo "gates → $val   ($K1=$(cur $K1), $K2=$(cur $K2));  beamhalld $(systemctl is-active beamhalld)"
'

printf '%s' "$REMOTE" | "${SSH[@]}" bash -s -- "$action"
