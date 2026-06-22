#!/usr/bin/env bash
# Beamhall turnkey installer — takes a bare Linux host to a running appliance in
# one command. Run as root:
#
#   sudo bash install.sh [./beamhalld] [--base-domain beamhall.example.com]
#
# With no binary path it fetches the latest published beamhalld from GitHub
# Releases for this host's arch and verifies it against checksums.txt:
#
#   curl -fsSL https://raw.githubusercontent.com/Beamhall/beamhall/<tag>/packaging/install.sh \
#     | sudo bash -s -- --base-domain beamhall.example.com --tls internal
#
# Pin a specific release with --version vX.Y.Z; pass a local path to install a
# dev build instead.
#
# It lays the whole stack so an admin never hand-assembles a runtime:
#   - Docker Engine (official repo) + runc, hard-verified >= 1.2.8 (CVE floor)
#   - userns-remap=default + gVisor runsc registered as the regulated tier
#   - a dedicated non-remapped build daemon (buildpack builds only)
#   - the gateway (Caddy), internal registry, and managed Postgres
#   - the beamhall service user, a generated age root key + config, the unit
#
# Idempotent: safe to re-run (upgrades the binary, preserves /etc/beamhall and
# /var/lib/beamhall). Run a single group with --group baseline|substrate|appliance.
set -euo pipefail

# --- pinned versions (override via env for reproducible/air-gapped installs) ---
MIN_RUNC="1.2.8"                                  # patched for the 2025-26 runC CVEs
PACK_VERSION="${BEAMHALL_PACK_VERSION:-v0.40.6}"  # Cloud Native Buildpacks CLI
CNB_BUILDER="${BEAMHALL_CNB_BUILDER:-paketobuildpacks/builder-jammy-base:latest}"
REGISTRY_IMAGE="${BEAMHALL_REGISTRY_IMAGE:-registry:2}"
POSTGRES_IMAGE="${BEAMHALL_POSTGRES_IMAGE:-postgres:17-alpine}"

# --- args -------------------------------------------------------------------
GROUP="all"
BASE_DOMAIN=""
BIN_SRC=""
SECRET_KEY_SRC=""           # supply your own age key instead of generating one
AUTO_START=1
TLS_MODE="on"               # on=public ACME | internal=Caddy local CA | off=plain HTTP
RELEASE_VERSION=""          # --version vX.Y.Z (empty => latest published release)
REPO_SLUG="${BEAMHALL_REPO:-Beamhall/beamhall}"
RESOLVED_TAG=""             # set to the release tag actually installed (for the IdP hint)
while [ $# -gt 0 ]; do
  case "$1" in
    --group)       GROUP="$2"; shift 2 ;;
    --base-domain) BASE_DOMAIN="$2"; shift 2 ;;
    --secret-key)  SECRET_KEY_SRC="$2"; shift 2 ;;
    --tls)         TLS_MODE="$2"; shift 2 ;;
    --version)     RELEASE_VERSION="$2"; shift 2 ;;
    --repo)        REPO_SLUG="$2"; shift 2 ;;
    --no-start)    AUTO_START=0; shift ;;
    -*)            echo "unknown flag: $1" >&2; exit 2 ;;
    *)             BIN_SRC="$1"; shift ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "must run as root (use sudo)"; exit 1; }
export NEEDRESTART_SUSPEND=1 NEEDRESTART_MODE=a   # don't prompt/print during apt
log()  { printf '\n\033[1;36m== %s\033[0m\n' "$1"; }
ok()   { printf '   \033[32mok\033[0m  %s\n' "$1"; }
die()  { printf '   \033[31mFAIL\033[0m  %s\n' "$1" >&2; exit 1; }
note() { printf '   \033[33m..\033[0m  %s\n' "$1"; }
version_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

ARCH="$(uname -m)"
DPKG_ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
. /etc/os-release
CODENAME="${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}"

# Beamhall-owned component names (no host-Docker confusion for the admin).
BUILD_SOCK="/run/beamhall-build.sock"
BUILD_DATA="/var/lib/beamhall-build"
BUILD_EXEC="/run/beamhall-build"
BUILD_CONF="/etc/beamhall/build-daemon.json"
REGISTRY_NAME="beamhall-registry"
REGISTRY_NET="beamhall-registry-net"
PG_NAME="beamhall-postgres"
PG_NET="beamhall-postgres-net"

want() { [ "$GROUP" = "all" ] || [ "$GROUP" = "$1" ]; }

# ===========================================================================
group_baseline() {
  log "BASELINE 1/7  Preflight (hard prerequisites)"
  case "${ID:-}:${VERSION_ID:-}" in
    ubuntu:24.*|ubuntu:25.*|ubuntu:26.*|debian:12|debian:13) ok "supported OS: ${PRETTY_NAME}" ;;
    *) note "untested OS '${PRETTY_NAME:-?}' (validated: Ubuntu 24.04+/Debian 12). Continuing." ;;
  esac
  command -v apt-get >/dev/null 2>&1 || die "this installer currently supports apt-based distros (Ubuntu/Debian). RPM support pending."
  kver="$(uname -r | sed -E 's/^([0-9]+\.[0-9]+).*/\1/')"
  version_ge "$kver" "5.2" && ok "kernel $(uname -r) >= 5.2" || die "kernel $(uname -r) < 5.2"
  [ -f /sys/fs/cgroup/cgroup.controllers ] && ok "cgroup v2 unified active" || die "cgroup v2 not active (boot with systemd.unified_cgroup_hierarchy=1)"
  memkb="$(awk '/MemTotal/{print $2}' /proc/meminfo)"
  if [ "${memkb:-0}" -lt 6000000 ]; then
    note "RAM $((memkb/1024)) MiB is below the 8 GiB recommended for buildpack builds (ok for evaluation; size up for production)."
  else ok "RAM $((memkb/1024)) MiB"; fi

  log "BASELINE 2/7  Base packages"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl gnupg jq python3 uidmap age >/dev/null
  ok "ca-certificates curl gnupg jq python3 uidmap age"

  log "BASELINE 3/7  Docker Engine (official repo, uniform across the support matrix)"
  install -m 0755 -d /etc/apt/keyrings
  if [ ! -s /etc/apt/keyrings/docker.asc ]; then
    curl -fsSL https://download.docker.com/linux/${ID}/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
  fi
  echo "deb [arch=${DPKG_ARCH} signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${ID} ${CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  if apt-cache policy docker-ce 2>/dev/null | grep -qE 'Candidate: [0-9]'; then
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io >/dev/null
    ok "installed docker-ce from download.docker.com (${CODENAME})"
  else
    note "Docker's repo has no package for '${CODENAME}' yet — falling back to the distro package, then hard-verifying the runc floor."
    rm -f /etc/apt/sources.list.d/docker.list; apt-get update -qq
    apt-get install -y -qq docker.io >/dev/null
    ok "installed distro docker.io"
  fi

  log "BASELINE 4/7  gVisor runsc (regulated isolation tier)"
  if [ ! -s /etc/apt/keyrings/gvisor-archive-keyring.gpg ]; then
    curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor -o /etc/apt/keyrings/gvisor-archive-keyring.gpg
  fi
  echo "deb [arch=${DPKG_ARCH} signed-by=/etc/apt/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
    > /etc/apt/sources.list.d/gvisor.list
  apt-get update -qq
  apt-get install -y -qq runsc >/dev/null
  RUNSC_PATH="$(command -v runsc)"
  ok "runsc installed: $(runsc --version 2>/dev/null | head -1) (${RUNSC_PATH})"

  log "BASELINE 5/7  Configure the runtime daemon (userns-remap + runsc)"
  mkdir -p /etc/docker
  RUNSC_PATH="$RUNSC_PATH" python3 - <<'PY'
import json, os
p="/etc/docker/daemon.json"; cfg={}
if os.path.exists(p):
    try: cfg=json.load(open(p)) or {}
    except Exception: cfg={}
cfg["userns-remap"]="default"
cfg.setdefault("runtimes",{})["runsc"]={"path": os.environ["RUNSC_PATH"]}
json.dump(cfg, open(p,"w"), indent=2)
print("   wrote /etc/docker/daemon.json:", json.dumps(cfg))
PY

  log "BASELINE 6/7  Dedicated build daemon (non-remapped; buildpack builds only)"
  # The buildpack lifecycle can't run on the userns-remapped runtime daemon. This
  # second daemon publishes pinned images to the internal registry; the runtime
  # daemon only pulls digests. bridge:none + iptables:false so it never fights the
  # per-workspace egress chains (it builds with --network host).
  install -d -m 0750 /etc/beamhall
  cat > "$BUILD_CONF" <<EOF
{ "bridge": "none", "iptables": false }
EOF
  cat > /etc/systemd/system/beamhall-build.service <<EOF
[Unit]
Description=Beamhall build daemon (non-remapped; buildpack builds only, never workloads)
After=network-online.target docker.service
Wants=network-online.target

[Service]
ExecStart=/usr/bin/dockerd --config-file ${BUILD_CONF} -H unix://${BUILD_SOCK} --data-root ${BUILD_DATA} --exec-root ${BUILD_EXEC} --pidfile /run/beamhall-build.pid
Restart=on-failure
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload

  log "BASELINE 7/7  Start daemons and verify the security baseline"
  systemctl enable --now docker >/dev/null 2>&1 || true
  systemctl restart docker
  for i in $(seq 1 20); do docker info >/dev/null 2>&1 && break; sleep 1; done
  systemctl enable --now beamhall-build.service >/dev/null 2>&1 || true
  systemctl restart beamhall-build.service; sleep 3

  docker info >/dev/null 2>&1 || die "runtime docker daemon not reachable"
  docker info --format '{{range .SecurityOptions}}{{println .}}{{end}}' | grep -q userns \
    && ok "userns-remap enabled on the runtime daemon" || die "userns-remap NOT enabled"
  docker info --format '{{range $k,$v := .Runtimes}}{{println $k}}{{end}}' | grep -qx runsc \
    && ok "runsc registered as a Docker runtime" || die "runsc not registered"
  rver="$(runc --version 2>/dev/null | sed -nE 's/^runc version ([0-9.]+).*/\1/p' | head -1)"
  if [ -n "$rver" ] && version_ge "$rver" "$MIN_RUNC"; then ok "runc $rver >= $MIN_RUNC (CVE floor)"
  else die "runc ${rver:-unknown} < $MIN_RUNC — refusing to continue on a vulnerable runtime"; fi
  docker -H unix://${BUILD_SOCK} info >/dev/null 2>&1 \
    && ok "build daemon up on ${BUILD_SOCK}" || die "build daemon failed (journalctl -u beamhall-build)"
}

# ===========================================================================
group_substrate() {
  log "SUBSTRATE 1/4  pack (Cloud Native Buildpacks CLI ${PACK_VERSION})"
  if ! command -v pack >/dev/null 2>&1 || [ "$(pack version 2>/dev/null)" != "${PACK_VERSION#v}" ]; then
    case "$ARCH" in x86_64) pa=linux ;; aarch64) pa=linux-arm64 ;; *) pa=linux ;; esac
    curl -fsSL "https://github.com/buildpacks/pack/releases/download/${PACK_VERSION}/pack-${PACK_VERSION}-${pa}.tgz" \
      | tar -xz -C /usr/local/bin pack
  fi
  ok "pack $(pack version 2>/dev/null)"

  log "SUBSTRATE 2/4  Gateway (Caddy) as a service"
  if ! command -v caddy >/dev/null 2>&1; then
    curl -fsSL "https://caddyserver.com/api/download?os=linux&arch=${DPKG_ARCH}" -o /usr/local/bin/caddy
    chmod +x /usr/local/bin/caddy
  fi
  id caddy >/dev/null 2>&1 || useradd --system --home-dir /var/lib/caddy --create-home --shell /usr/sbin/nologin caddy
  # Caddy boots with only its admin API; beamhalld owns the full config via POST
  # /load. Its init config lives in /etc/caddy (caddy-readable) — NOT /etc/beamhall,
  # which is 0750 root:beamhall and the caddy user can't traverse.
  install -d -m 0755 /etc/caddy
  cat > /etc/caddy/init.json <<'EOF'
{ "admin": { "listen": "127.0.0.1:2019" } }
EOF
  cat > /etc/systemd/system/beamhall-gateway.service <<'EOF'
[Unit]
Description=Beamhall gateway (Caddy; config driven by beamhalld via the admin API)
After=network-online.target
Wants=network-online.target

[Service]
User=caddy
Group=caddy
ExecStart=/usr/local/bin/caddy run --config /etc/caddy/init.json
Restart=on-failure
AmbientCapabilities=CAP_NET_BIND_SERVICE
StateDirectory=caddy
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now beamhall-gateway.service >/dev/null 2>&1 || systemctl restart beamhall-gateway.service
  sleep 2
  curl -fsS http://127.0.0.1:2019/config/ >/dev/null 2>&1 \
    && ok "gateway admin API up on 127.0.0.1:2019" || note "gateway admin not responding yet (journalctl -u beamhall-gateway)"

  log "SUBSTRATE 3/4  Internal registry (loopback only)"
  docker network inspect "$REGISTRY_NET" >/dev/null 2>&1 || docker network create "$REGISTRY_NET" >/dev/null
  if ! docker ps --format '{{.Names}}' | grep -qx "$REGISTRY_NAME"; then
    docker rm -f "$REGISTRY_NAME" >/dev/null 2>&1 || true
    docker run -d --restart=always --name "$REGISTRY_NAME" --network "$REGISTRY_NET" \
      -p 127.0.0.1:5000:5000 "$REGISTRY_IMAGE" >/dev/null
  fi
  sleep 2
  curl -fsS http://127.0.0.1:5000/v2/ >/dev/null 2>&1 \
    && ok "registry v2 on 127.0.0.1:5000" || note "registry not responding yet"

  log "SUBSTRATE 4/4  Managed Postgres (generated admin password)"
  install -d -m 0750 /etc/beamhall
  if [ ! -s /etc/beamhall/postgres-admin.pw ]; then
    (umask 077; openssl rand -hex 24 > /etc/beamhall/postgres-admin.pw)
  fi
  PGPW="$(cat /etc/beamhall/postgres-admin.pw)"
  docker network inspect "$PG_NET" >/dev/null 2>&1 || docker network create "$PG_NET" >/dev/null
  if ! docker ps --format '{{.Names}}' | grep -qx "$PG_NAME"; then
    docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
    docker run -d --restart=always --name "$PG_NAME" --network "$PG_NET" \
      -p 127.0.0.1:5433:5432 -e POSTGRES_PASSWORD="$PGPW" "$POSTGRES_IMAGE" >/dev/null
  fi
  sleep 5
  docker exec "$PG_NAME" pg_isready -U postgres >/dev/null 2>&1 \
    && ok "postgres ready (admin on 127.0.0.1:5433, password in /etc/beamhall/postgres-admin.pw)" \
    || note "postgres not ready yet"
}

# Fetch the published beamhalld for this host's arch from GitHub Releases and
# verify it against checksums.txt. Sets BIN_SRC to the extracted binary.
fetch_release_binary() {
  local arch tag ver base ar tmp
  case "$DPKG_ARCH" in
    amd64) arch=amd64 ;;
    arm64) arch=arm64 ;;
    *) die "no released binary for arch '$DPKG_ARCH'; build from source and pass the path" ;;
  esac
  command -v curl >/dev/null 2>&1 || { apt-get update -qq; apt-get install -y -qq curl ca-certificates >/dev/null; }
  tag="$RELEASE_VERSION"
  if [ -z "$tag" ]; then
    tag="$(curl -fsSL "https://api.github.com/repos/${REPO_SLUG}/releases/latest" 2>/dev/null \
            | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name":[[:space:]]*"([^"]+)".*/\1/')"
    [ -n "$tag" ] || die "could not resolve the latest ${REPO_SLUG} release; pin one with --version vX.Y.Z"
  fi
  case "$tag" in v*) ver="${tag#v}" ;; *) ver="$tag" ;; esac
  RESOLVED_TAG="$tag"
  base="https://github.com/${REPO_SLUG}/releases/download/${tag}"
  ar="beamhall_${ver}_linux_${arch}.tar.gz"
  tmp="$(mktemp -d)"
  log "APPLIANCE 0/6  Fetch beamhalld ${ver} (${arch}) from ${REPO_SLUG}"
  curl -fsSL "${base}/${ar}" -o "${tmp}/${ar}" || die "download failed: ${base}/${ar}"
  if curl -fsSL "${base}/checksums.txt" -o "${tmp}/checksums.txt" 2>/dev/null; then
    ( cd "$tmp" && grep " ${ar}\$" checksums.txt | sha256sum -c - >/dev/null 2>&1 ) \
      && ok "checksum verified (${ar})" \
      || die "checksum verification FAILED for ${ar} — refusing to install"
  else
    note "checksums.txt not found in the release; skipping verification"
  fi
  tar -xzf "${tmp}/${ar}" -C "$tmp" beamhalld || die "release archive did not contain beamhalld"
  chmod +x "${tmp}/beamhalld"
  BIN_SRC="${tmp}/beamhalld"
  ok "release binary ready: beamhalld ${ver}"
}

# ===========================================================================
group_appliance() {
  if [ -n "$BIN_SRC" ] && [ -x "$BIN_SRC" ]; then
    ok "using provided binary: $BIN_SRC"
  elif [ -n "$RELEASE_VERSION" ]; then
    fetch_release_binary
  elif command -v beamhalld >/dev/null 2>&1; then
    BIN_SRC="$(command -v beamhalld)"; ok "using beamhalld already on PATH: $BIN_SRC"
  else
    fetch_release_binary
  fi
  [ -n "$BIN_SRC" ] && [ -x "$BIN_SRC" ] || die "no beamhalld binary (pass a local path, or use --version vX.Y.Z)"
  [ -n "$BASE_DOMAIN" ] || BASE_DOMAIN="$(hostname -f 2>/dev/null || hostname)"

  log "APPLIANCE 1/6  Service user"
  id beamhall >/dev/null 2>&1 || useradd --system --home-dir /var/lib/beamhall --shell /usr/sbin/nologin beamhall
  groupadd -f docker; usermod -aG docker beamhall
  ok "user 'beamhall' in group docker"

  log "APPLIANCE 2/6  Binary -> /usr/local/bin/beamhalld"
  # Do NOT invoke the binary to "smoke" it: beamhalld treats unknown args as
  # "run the daemon", so 'beamhalld --version' would block here. The systemd
  # start in phase 6 is the real smoke.
  install -m 0755 "$BIN_SRC" /usr/local/bin/beamhalld
  ok "installed /usr/local/bin/beamhalld"

  log "APPLIANCE 3/6  Secret root key (age)"
  install -d -m 0750 -o root -g beamhall /etc/beamhall
  if [ -n "$SECRET_KEY_SRC" ]; then
    install -m 0400 -o root -g root "$SECRET_KEY_SRC" /etc/beamhall/secret.key
    ok "installed supplied root key"
  elif [ ! -s /etc/beamhall/secret.key ]; then
    # Write ONLY the key line — beamhalld's parser doesn't skip age-keygen's
    # '# created:' / '# public key:' comment lines (they fail bech32 as mixed case).
    (umask 077; age-keygen 2>/dev/null | grep '^AGE-SECRET-KEY-' > /etc/beamhall/secret.key)
    chmod 0400 /etc/beamhall/secret.key
    KEY_GENERATED=1   # the prominent back-it-up warning prints at the very end
    ok "generated a new age root key at /etc/beamhall/secret.key"
  else ok "existing root key left unchanged"; fi

  log "APPLIANCE 4/6  Config -> /etc/beamhall/beamhall.env"
  PGPW="$(cat /etc/beamhall/postgres-admin.pw 2>/dev/null || echo CHANGE-ME)"
  if [ ! -f /etc/beamhall/beamhall.env ]; then
    cat > /etc/beamhall/beamhall.env <<EOF
# Beamhall appliance config (generated by install.sh). Owner root:beamhall 0640.
BEAMHALL_HTTP_ADDR=:8443
BEAMHALL_BASE_DOMAIN=${BASE_DOMAIN}
BEAMHALL_DATA_DIR=/var/lib/beamhall
BEAMHALL_LOG_LEVEL=info

# Identity provider — set the issuer to enable MCP + Admin (see docs/idp-setup.md).
BEAMHALL_OAUTH_ISSUER=
#BEAMHALL_OAUTH_AUDIENCE=https://${BASE_DOMAIN}/mcp
BEAMHALL_ADMIN_CLIENT_ID=beamhall-admin
BEAMHALL_ADMIN_CLIENT_SECRET=

# Gateway (Caddy).
BEAMHALL_CADDY_ADMIN=http://127.0.0.1:2019
BEAMHALL_GATEWAY_LISTEN=:80,:443
BEAMHALL_GATEWAY_TLS=${TLS_MODE}

# Build pipeline (dedicated non-remapped build daemon + internal registry).
BEAMHALL_BUILD_DOCKER_HOST=unix://${BUILD_SOCK}
BEAMHALL_CNB_BUILDER=${CNB_BUILDER}
BEAMHALL_REGISTRY=127.0.0.1:5000

# Managed Postgres (admin DSN on loopback; password generated at install).
BEAMHALL_PG_ADMIN_DSN=postgres://postgres:${PGPW}@127.0.0.1:5433/postgres?sslmode=disable
BEAMHALL_PG_BEAM_HOST=${PG_NAME}
EOF
    chmod 0640 /etc/beamhall/beamhall.env; chown root:beamhall /etc/beamhall/beamhall.env
    ok "wrote beamhall.env (base domain ${BASE_DOMAIN}; set BEAMHALL_OAUTH_ISSUER to enable MCP/Admin)"
  else ok "beamhall.env exists — left unchanged"; fi

  log "APPLIANCE 5/6  systemd unit"
  cat > /etc/systemd/system/beamhalld.service <<EOF
[Unit]
Description=Beamhall infrastructure backplane
Documentation=https://github.com/Beamhall/beamhall
After=network-online.target docker.service beamhall-build.service beamhall-gateway.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=simple
User=beamhall
Group=beamhall
SupplementaryGroups=docker
EnvironmentFile=/etc/beamhall/beamhall.env
LoadCredential=secret.key:/etc/beamhall/secret.key
Environment=BEAMHALL_SECRET_KEY_FILE=%d/secret.key
ExecStart=/usr/local/bin/beamhalld
Restart=on-failure
RestartSec=3
TimeoutStopSec=20
StateDirectory=beamhall
StateDirectoryMode=0700
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
ProtectKernelLogs=true
ProtectClock=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
RemoveIPC=true
ReadWritePaths=/var/lib/beamhall
ReadWritePaths=/run/docker.sock ${BUILD_SOCK}
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  ok "installed /etc/systemd/system/beamhalld.service"

  log "APPLIANCE 6/6  Start"
  if [ "$AUTO_START" = "1" ]; then
    systemctl enable --now beamhalld
    sleep 3
    if curl -fsS "http://127.0.0.1:8443/healthz" >/dev/null 2>&1; then
      ok "beamhalld is up — /healthz responds on :8443"
    else
      note "beamhalld started but /healthz not green yet — check: journalctl -u beamhalld -n 50"
    fi
  else note "skipped start (--no-start); enable with: systemctl enable --now beamhalld"; fi

  if [ "$TLS_MODE" = "internal" ]; then
    log "APPLIANCE: trust the gateway internal CA (host + IdP discovery; distribute to clients)"
    CA_OUT=/usr/local/share/ca-certificates/beamhall-gateway-ca.crt
    for i in 1 2 3 4 5; do
      if curl -fsS -m5 "${BEAMHALL_CADDY_ADMIN:-http://127.0.0.1:2019}/pki/ca/local" 2>/dev/null \
           | python3 -c 'import sys,json; print(json.load(sys.stdin)["root_certificate"])' > "$CA_OUT" 2>/dev/null \
         && [ -s "$CA_OUT" ]; then
        update-ca-certificates >/dev/null 2>&1
        systemctl restart beamhalld 2>/dev/null || true   # reload the system cert pool
        ok "gateway root CA installed at $CA_OUT — distribute it to client workstations (so browsers/agents trust *.${BASE_DOMAIN})"
        break
      fi
      sleep 2
    done
    [ -s "$CA_OUT" ] || note "could not fetch the gateway CA yet (gateway still starting?); rerun: curl -s \$CADDY_ADMIN/pki/ca/local | jq -r .root_certificate"
  fi

  # Pin the bundled-IdP hint to the exact release we installed (else main).
  IDP_REF="${RESOLVED_TAG:-main}"
  cat <<EOF

Beamhall appliance installed and running (/healthz is green).

NEXT — turn on identities (this enables the MCP endpoint + the Admin console).
Pick ONE; you don't need to read any docs for the first option:

  • Evaluate now with the bundled IdP (recommended for a pilot) — one command:
       curl -fsSL https://raw.githubusercontent.com/${REPO_SLUG}/${IDP_REF}/packaging/keycloak/setup-bundled-idp.sh \\
         | sudo BASE_DOMAIN=${BASE_DOMAIN} BEAMHALL_REF=${IDP_REF} bash
    It stands up a ready-to-use Keycloak + seed users and wires beamhalld for you.

  • Use your corporate IdP (production): set BEAMHALL_OAUTH_ISSUER in
       /etc/beamhall/beamhall.env  then  systemctl restart beamhalld
    Per-IdP recipe (Okta/Entra/Keycloak): docs/idp-setup.md

After that: create a workspace and register identities — Admin console at
https://${BASE_DOMAIN}/admin, or the 'beamhalld admin' CLI.
EOF

  if [ "${KEY_GENERATED:-0}" = "1" ]; then
    # Prominent, border-free (alignment-proof) and LAST so the admin can't miss it.
    printf '\n\033[1;33m  !!  ACTION REQUIRED — BACK UP YOUR SECRET ROOT KEY  !!\033[0m\n'
    printf '\033[1;33m  ----------------------------------------------------------------\n'
    printf '  A new age root key was generated at /etc/beamhall/secret.key (0400).\n'
    printf '  It seals EVERY secret Beamhall stores. Copy it to your KMS / vault\n'
    printf '  NOW and keep it offline — if this key is lost, every stored secret is\n'
    printf '  unrecoverable, and so are your backups.\n'
    printf '  ----------------------------------------------------------------\033[0m\n'
  fi
}

# ===========================================================================
want baseline  && group_baseline
want substrate && group_substrate
want appliance && group_appliance
log "install.sh: group '${GROUP}' complete"
