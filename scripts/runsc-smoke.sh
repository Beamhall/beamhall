#!/usr/bin/env bash
# Phase-0 gate (docs/PLAN.md §3.4, §8): prove a REAL beam survives the full
# hardened-Docker profile under BOTH runc and gVisor runsc. Run on the target
# Linux VM after preflight passes.
#
# Point it at a Paketo-buildpack-built image for the true gate; it defaults to a
# small Paketo Node sample so the script is runnable out of the box:
#
#   IMAGE=my-registry/request-tracker@sha256:... bash scripts/runsc-smoke.sh
#
# The profile below mirrors the SecurityContext the Docker driver will apply:
# cap-drop ALL (+NET_BIND_SERVICE), no-new-privileges, read-only rootfs,
# tmpfs /tmp, pids/mem limits. Exit 0 only if the beam serves HTTP under every
# available runtime.
set -u

IMAGE="${IMAGE:-paketobuildpacks/run-jammy-tiny:latest}"   # replace with a built beam image for the real gate
APP_PORT="${APP_PORT:-8080}"
HEALTH_PATH="${HEALTH_PATH:-/}"
WAIT_SECS="${WAIT_SECS:-15}"

# Hardening flags = the SecurityContext baseline applied to every workload.
HARDENING=(
  --cap-drop ALL
  --cap-add NET_BIND_SERVICE
  --security-opt no-new-privileges
  --read-only
  --tmpfs /tmp:rw,nosuid,nodev
  --pids-limit 256
  --memory 512m
)

fail=0
runtimes=(runc)
if docker info --format '{{range $k,$v := .Runtimes}}{{println $k}}{{end}}' 2>/dev/null | grep -qx runsc; then
  runtimes+=(runsc)
else
  echo "note: runsc not registered with dockerd; testing runc only"
fi

smoke_one() {
  local rt="$1" name="bh-smoke-${1}-$$"
  echo "── runtime: ${rt} ───────────────────────────────"
  docker rm -f "$name" >/dev/null 2>&1 || true
  if ! docker run -d --name "$name" --runtime "$rt" "${HARDENING[@]}" \
        -p 127.0.0.1:0:"${APP_PORT}" "$IMAGE" >/dev/null 2>&1; then
    echo "  FAIL  container did not start under ${rt}"
    docker logs "$name" 2>&1 | tail -n 20 | sed 's/^/    | /'
    docker rm -f "$name" >/dev/null 2>&1 || true
    return 1
  fi

  local hostport
  hostport="$(docker port "$name" "${APP_PORT}/tcp" 2>/dev/null | head -n1 | sed -E 's/.*:([0-9]+)$/\1/')"
  local ok=1 i
  for ((i=0; i<WAIT_SECS; i++)); do
    if [ -n "$hostport" ] && curl -fsS "http://127.0.0.1:${hostport}${HEALTH_PATH}" >/dev/null 2>&1; then
      ok=0; break
    fi
    # container may have exited under the hardening profile — surface it early
    if [ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" != "true" ]; then
      break
    fi
    sleep 1
  done

  if [ "$ok" -eq 0 ]; then
    echo "  PASS  beam served HTTP under ${rt} with the full hardening profile"
  else
    echo "  FAIL  beam did not serve HTTP under ${rt} within ${WAIT_SECS}s"
    echo "        (common causes: writes outside tmpfs vs --read-only, bind to a privileged port,"
    echo "         or a syscall unsupported by gVisor — exactly what Phase-0 must surface)"
    docker logs "$name" 2>&1 | tail -n 30 | sed 's/^/    | /'
    fail=1
  fi
  docker rm -f "$name" >/dev/null 2>&1 || true
}

for rt in "${runtimes[@]}"; do
  smoke_one "$rt"
done

echo
if [ "$fail" -eq 0 ]; then
  echo "runsc-smoke OK: beam survives the hardening profile under: ${runtimes[*]}"
  exit 0
else
  echo "runsc-smoke FAILED — see FAIL lines above. This is the Phase-0 de-risk signal, not a flake."
  exit 1
fi
