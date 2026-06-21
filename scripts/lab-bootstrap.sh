#!/usr/bin/env bash
# One-time lab bootstrap for the Beamhall hardened-Docker baseline. Run as root
# on the appliance/lab VM (Ubuntu 24.04+/26.04). Idempotent: safe to re-run.
#
#   sudo bash scripts/lab-bootstrap.sh
#
# Installs and configures the runtime baseline from docs/PLAN.md §3/§7:
#   - Docker engine + runc (>= 1.2.8) from the distro repo
#   - userns-remap = default (auto-creates dockremap + subuid/subgid ranges)
#   - gVisor runsc registered as a Docker runtime (the regulated tier)
#   - the invoking user added to the docker group (so testing needs no sudo)
#   - the pack CLI (Cloud Native Buildpacks), best-effort
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "must run as root (use sudo)"; exit 1; }

# Who should get docker-group + own the daemon? The sudo invoker, else 'mmachado'.
TARGET_USER="${SUDO_USER:-mmachado}"
ARCH="$(uname -m)"
log() { printf '\n\033[1;36m== %s\033[0m\n' "$1"; }

log "1/6 Install Docker engine + runc"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq docker.io runc curl ca-certificates jq python3 >/dev/null
docker --version
runc --version | head -1

log "2/6 Install gVisor (runsc) ${ARCH}"
if ! command -v runsc >/dev/null 2>&1; then
  base="https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH}"
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  ( cd "$tmp"
    curl -fsSL -O "${base}/runsc" -O "${base}/runsc.sha512" \
                -O "${base}/containerd-shim-runsc-v1" -O "${base}/containerd-shim-runsc-v1.sha512"
    sha512sum -c runsc.sha512 containerd-shim-runsc-v1.sha512
    chmod a+rx runsc containerd-shim-runsc-v1
    mv runsc containerd-shim-runsc-v1 /usr/local/bin/ )
fi
runsc --version | head -1

log "3/6 Configure dockerd: userns-remap=default + runsc runtime"
mkdir -p /etc/docker
# Merge our keys into any existing daemon.json without clobbering other settings.
python3 - <<'PY'
import json, os
p = "/etc/docker/daemon.json"
cfg = {}
if os.path.exists(p):
    try:
        with open(p) as f:
            cfg = json.load(f) or {}
    except Exception:
        cfg = {}
cfg["userns-remap"] = "default"
cfg.setdefault("runtimes", {})["runsc"] = {"path": "/usr/local/bin/runsc"}
with open(p, "w") as f:
    json.dump(cfg, f, indent=2)
print(json.dumps(cfg, indent=2))
PY

log "4/6 Restart dockerd and wait for readiness"
systemctl enable --now docker >/dev/null 2>&1 || true
systemctl restart docker
for i in $(seq 1 20); do docker info >/dev/null 2>&1 && break; sleep 1; done
docker info --format 'server={{.ServerVersion}} cgroup={{.CgroupVersion}}'
echo -n "security: "; docker info --format '{{range .SecurityOptions}}{{.}} {{end}}'; echo
echo -n "runtimes: "; docker info --format '{{range $k,$v := .Runtimes}}{{$k}} {{end}}'; echo
grep -qE '^dockremap:' /etc/subuid && echo "subuid: dockremap range present" || echo "subuid: MISSING dockremap"

log "5/6 Add ${TARGET_USER} to the docker group"
groupadd -f docker
usermod -aG docker "${TARGET_USER}"
echo "added ${TARGET_USER} to docker group (effective on next login)"

log "6/6 Install pack CLI (Cloud Native Buildpacks), best-effort"
if ! command -v pack >/dev/null 2>&1; then
  ptag="$(curl -fsSL https://api.github.com/repos/buildpacks/pack/releases/latest | jq -r .tag_name 2>/dev/null || echo)"
  if [ -n "${ptag}" ] && [ "${ptag}" != "null" ]; then
    case "$ARCH" in x86_64) pa=linux ;; aarch64) pa=linux-arm64 ;; *) pa=linux ;; esac
    if curl -fsSL "https://github.com/buildpacks/pack/releases/download/${ptag}/pack-${ptag}-${pa}.tgz" \
         | tar -xz -C /usr/local/bin pack 2>/dev/null; then
      echo "pack ${ptag} installed"
    else
      echo "pack download failed (non-fatal; needed only for the buildpack gate)"
    fi
  else
    echo "could not resolve latest pack release (non-fatal)"
  fi
fi
command -v pack >/dev/null 2>&1 && pack version || true

log "7/10 Install Caddy (gateway)"
if ! command -v caddy >/dev/null 2>&1; then
  curl -fsSL "https://caddyserver.com/api/download?os=linux&arch=${ARCH/x86_64/amd64}" -o /usr/local/bin/caddy \
    && chmod +x /usr/local/bin/caddy && echo "caddy installed" \
    || echo "caddy download failed (non-fatal)"
fi
command -v caddy >/dev/null 2>&1 && caddy version || true

log "8/10 Dedicated build daemon (non-remapped; CNB builds only — PLAN §4)"
# The buildpack lifecycle cannot run on the userns-remapped runtime daemon
# (lab finding). Builds run on this separate daemon and --publish to the
# internal registry; the runtime daemon only pulls pinned digests. Its own
# config file keeps it from inheriting /etc/docker/daemon.json (which would
# re-enable userns-remap); no bridge/iptables — the lifecycle runs
# --network host and must never fight the egress chains.
cat > /etc/docker/daemon-build.json <<'EOF'
{
  "bridge": "none",
  "iptables": false
}
EOF
cat > /etc/systemd/system/docker-build.service <<'EOF'
[Unit]
Description=Beamhall build daemon (non-remapped; CNB builds only, never workloads)
After=network-online.target docker.service
Wants=network-online.target

[Service]
ExecStart=/usr/bin/dockerd --config-file /etc/docker/daemon-build.json -H unix:///run/docker-build.sock --data-root /var/lib/docker-build --exec-root /run/docker-build --pidfile /run/docker-build.pid
Restart=on-failure
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now docker-build.service
sleep 3
docker -H unix:///run/docker-build.sock info >/dev/null 2>&1 && echo "build daemon up" \
  || echo "build daemon failed to start (check journalctl -u docker-build)"
# Seed the Paketo builder/run images from the runtime daemon if it has them
# (saves a 3.7 GB download); first pack build pulls them otherwise.
if docker image inspect paketobuildpacks/builder-jammy-base:latest >/dev/null 2>&1 \
   && ! docker -H unix:///run/docker-build.sock image inspect paketobuildpacks/builder-jammy-base:latest >/dev/null 2>&1; then
  echo "seeding Paketo builder images into the build daemon..."
  docker save paketobuildpacks/builder-jammy-base:latest paketobuildpacks/run-jammy-base:latest \
    | docker -H unix:///run/docker-build.sock load
fi

log "9/10 Internal registry (loopback only — build publishes, runtime pulls)"
docker network inspect bh-registry-net >/dev/null 2>&1 || docker network create bh-registry-net
if ! docker ps --format '{{.Names}}' | grep -qx bh-registry; then
  docker rm -f bh-registry >/dev/null 2>&1 || true
  docker run -d --restart=always --name bh-registry --network bh-registry-net \
    -p 127.0.0.1:5000:5000 registry:2
fi
sleep 2
curl -fsS http://127.0.0.1:5000/v2/ >/dev/null && echo "registry v2 OK on 127.0.0.1:5000" \
  || echo "registry not responding (non-fatal; needed for the build pipeline)"

log "10/10 Appliance Postgres (db-per-beam scoped roles — PLAN §6)"
# Admin on loopback 127.0.0.1:5433 (backplane only); beams reach the server as
# bh-postgres:5432 on whichever Beamhall network the provisioner attaches it
# to. The fixed admin password is LAB-ONLY — the production appliance
# generates its own and feeds it via systemd LoadCredential.
docker network inspect bh-postgres-net >/dev/null 2>&1 || docker network create bh-postgres-net
if ! docker ps --format '{{.Names}}' | grep -qx bh-postgres; then
  docker rm -f bh-postgres >/dev/null 2>&1 || true
  docker run -d --restart=always --name bh-postgres --network bh-postgres-net \
    -p 127.0.0.1:5433:5432 -e POSTGRES_PASSWORD=beamhall-lab-admin postgres:17-alpine
fi
sleep 5
docker exec bh-postgres pg_isready -U postgres >/dev/null 2>&1 && echo "postgres OK (admin 127.0.0.1:5433)" \
  || echo "postgres not ready (non-fatal; needed for create_database)"

echo
echo "DONE. Log out/in (or reconnect over SSH) so the docker group applies, then:"
echo "  bash scripts/preflight.sh && bash scripts/runsc-smoke.sh"
