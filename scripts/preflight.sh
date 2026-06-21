#!/usr/bin/env bash
# Beamhall appliance preflight — verifies the host meets the hardened-Docker
# baseline (docs/PLAN.md §2, §3, §7 supported-systems matrix) BEFORE installing
# beamhalld. Targets Ubuntu 24.04 LTS / Debian 12. Run as root on the target VM:
#
#   sudo bash scripts/preflight.sh            # baseline (runc tier)
#   BEAMHALL_REQUIRE_RUNSC=1 sudo bash scripts/preflight.sh   # also require gVisor
#
# Exit code 0 = ready; non-zero = at least one hard check failed.
set -u

# --- config / thresholds ----------------------------------------------------
MIN_KERNEL="5.2"           # cgroup v2 unified + namespace baseline
MIN_RUNC="1.2.8"           # patched for the Nov-2025 runC CVEs
HTTPS_PORT="${BEAMHALL_HTTPS_PORT:-8443}"
SUBID_USER="${BEAMHALL_SUBID_USER:-dockermap}"
REQUIRE_RUNSC="${BEAMHALL_REQUIRE_RUNSC:-0}"   # 1 = fail if gVisor runsc absent

fail=0
warn=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; fail=$((fail+1)); }
note() { printf '  \033[33mWARN\033[0m  %s\n' "$1"; warn=$((warn+1)); }

# version_ge A B  -> true if A >= B (dotted numeric compare)
version_ge() {
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}

echo "Beamhall preflight ($(date -u '+%Y-%m-%dT%H:%M:%SZ'))"
echo "host: $(uname -srm)  ${NAME:-}${VERSION_ID:+ }${VERSION_ID:-}"
[ -r /etc/os-release ] && . /etc/os-release
echo

# --- 1. OS ------------------------------------------------------------------
case "${ID:-}:${VERSION_ID:-}" in
  ubuntu:24.04|ubuntu:24.10|ubuntu:25.*|ubuntu:26.*|debian:12|debian:13)
    pass "supported OS: ${PRETTY_NAME:-$ID $VERSION_ID}" ;;
  *)
    note "untested OS '${PRETTY_NAME:-unknown}'; supported: Ubuntu 24.04 LTS, Debian 12" ;;
esac

# --- 2. kernel >= MIN_KERNEL ------------------------------------------------
kver="$(uname -r | sed -E 's/^([0-9]+\.[0-9]+).*/\1/')"
if version_ge "$kver" "$MIN_KERNEL"; then
  pass "kernel $(uname -r) >= $MIN_KERNEL"
else
  bad "kernel $(uname -r) < $MIN_KERNEL"
fi

# --- 3. cgroup v2 unified hierarchy (avoids CVE-2022-0492) ------------------
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
  pass "cgroup v2 unified hierarchy active"
else
  bad "cgroup v2 not active (found cgroup v1 or hybrid). Boot with systemd.unified_cgroup_hierarchy=1"
fi

# --- 4. /etc/subuid + /etc/subgid for userns-remap (dockermap) --------------
check_subid() {
  local file="$1"
  if [ -r "$file" ] && grep -qE "^(${SUBID_USER}|dockremap):" "$file"; then
    pass "$file has a userns-remap range for '${SUBID_USER}'/dockremap"
  else
    bad "$file missing a subuid/subgid range for userns-remap user '${SUBID_USER}'"
  fi
}
check_subid /etc/subuid
check_subid /etc/subgid

# --- 5. Docker present, daemon up, userns-remap enabled ---------------------
if command -v docker >/dev/null 2>&1; then
  pass "docker present: $(docker --version 2>/dev/null)"
  if docker info >/dev/null 2>&1; then
    pass "docker daemon reachable"
    sec="$(docker info --format '{{range .SecurityOptions}}{{println .}}{{end}}' 2>/dev/null)"
    if printf '%s' "$sec" | grep -q 'userns'; then
      pass "userns-remap enabled on the daemon"
    else
      bad "userns-remap NOT enabled (set \"userns-remap\": \"${SUBID_USER}\" in /etc/docker/daemon.json)"
    fi
  else
    bad "docker daemon not reachable (is it running / are you root?)"
  fi
else
  bad "docker not installed"
fi

# --- 6. runc >= MIN_RUNC ----------------------------------------------------
if command -v runc >/dev/null 2>&1; then
  rver="$(runc --version 2>/dev/null | sed -nE 's/^runc version ([0-9.]+).*/\1/p' | head -n1)"
  if [ -n "$rver" ] && version_ge "$rver" "$MIN_RUNC"; then
    pass "runc $rver >= $MIN_RUNC"
  else
    bad "runc ${rver:-unknown} < $MIN_RUNC (patched for 2025-26 runC CVEs)"
  fi
else
  bad "runc not found on PATH"
fi

# --- 7. gVisor runsc (regulated tier) ---------------------------------------
if command -v runsc >/dev/null 2>&1; then
  rsver="$(runsc --version 2>/dev/null | sed -nE 's/^runsc version (.*)/\1/p' | head -n1)"
  pass "gVisor runsc present: ${rsver:-unknown}"
  if docker info --format '{{range $k,$v := .Runtimes}}{{println $k}}{{end}}' 2>/dev/null | grep -qx 'runsc'; then
    pass "runsc registered as a Docker runtime"
  else
    note "runsc installed but NOT registered with dockerd (run: runsc install && systemctl restart docker)"
  fi
else
  if [ "$REQUIRE_RUNSC" = "1" ]; then
    bad "gVisor runsc required (BEAMHALL_REQUIRE_RUNSC=1) but not installed"
  else
    note "gVisor runsc not installed (needed only for the regulated runtime tier)"
  fi
fi

# --- 8. inbound HTTPS port free ---------------------------------------------
if command -v ss >/dev/null 2>&1; then
  if ss -ltnH "( sport = :${HTTPS_PORT} )" 2>/dev/null | grep -q ":${HTTPS_PORT}"; then
    bad "port ${HTTPS_PORT} already in use (beamhalld needs one inbound HTTPS port)"
  else
    pass "inbound HTTPS port ${HTTPS_PORT} is free"
  fi
else
  note "ss not available; could not verify port ${HTTPS_PORT}"
fi

# --- summary ----------------------------------------------------------------
echo
if [ "$fail" -eq 0 ]; then
  echo "preflight OK (${warn} warning(s)). Host is ready for beamhalld."
  exit 0
else
  echo "preflight FAILED: ${fail} hard check(s), ${warn} warning(s). Resolve the FAIL items above."
  exit 1
fi
