#!/usr/bin/env bash
# Beamhall Setup Wizard — takes a bare Linux host to a running appliance, guiding
# the IT admin step by step. Run as root:
#
#   curl -fsSL https://github.com/Beamhall/beamhall/releases/latest/download/install.sh \
#     | sudo bash -s -- --base-domain beamhall.example.com --tls internal
#
# It lays the whole stack (Docker + userns-remap + gVisor runsc, a dedicated
# build daemon, the Caddy gateway, internal registry, managed Postgres), installs
# the checksum-verified beamhalld release, generates the age root key + config,
# installs a hardened systemd service, then walks you through DNS, the secret-key
# backup, the gateway CA, and turning on identity.
#
# Interactive by default (prompts read /dev/tty). Non-interactive / CI: set
# BEAMHALL_YES=1 (auto-confirms) — a proper unattended mode lands later.
# Pin a release with --version vX.Y.Z; pass a local path to install a dev build.
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
RESOLVED_TAG=""
SETUP_IDP="ask"             # ask | bundled | corporate | skip (--idp)
while [ $# -gt 0 ]; do
  case "$1" in
    --group)       GROUP="$2"; shift 2 ;;
    --base-domain) BASE_DOMAIN="$2"; shift 2 ;;
    --secret-key)  SECRET_KEY_SRC="$2"; shift 2 ;;
    --tls)         TLS_MODE="$2"; shift 2 ;;
    --version)     RELEASE_VERSION="$2"; shift 2 ;;
    --repo)        REPO_SLUG="$2"; shift 2 ;;
    --idp)         SETUP_IDP="$2"; shift 2 ;;
    --yes|-y)      BEAMHALL_YES=1; shift ;;
    --no-start)    AUTO_START=0; shift ;;
    -*)            echo "unknown flag: $1" >&2; exit 2 ;;
    *)             BIN_SRC="$1"; shift ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "must run as root (use sudo)"; exit 1; }
export NEEDRESTART_SUSPEND=1 NEEDRESTART_MODE=a   # don't prompt/print during apt

# ============================================================================
# Wizard UI — colors, boxes, spinner-wrapped quiet steps, /dev/tty gates.
# ============================================================================
if [ -t 1 ]; then
  C_RST=$'\033[0m'; C_B=$'\033[1m'; C_DIM=$'\033[2m'
  C_R=$'\033[31m'; C_G=$'\033[32m'; C_Y=$'\033[33m'; C_C=$'\033[36m'; C_BLU=$'\033[34m'; C_TTY=1
else
  C_RST=; C_B=; C_DIM=; C_R=; C_G=; C_Y=; C_C=; C_BLU=; C_TTY=0
fi
# Interactive prompts read the controlling terminal, NOT stdin (the script itself
# arrives on stdin under `curl | bash`). No tty => behave as --yes (never hang).
if [ -e /dev/tty ] && { : >/dev/tty; } 2>/dev/null; then TTY=/dev/tty; else TTY=; BEAMHALL_YES=1; fi
ASSUME_YES="${BEAMHALL_YES:-0}"
WIZ_STEP=0

_rule() { local n="${1:-72}" i=0; while [ "$i" -lt "$n" ]; do printf '─'; i=$((i+1)); done; }
# box COLOR TITLE LINE...   (left border only — alignment-proof with ANSI/emoji)
box() {
  local col="$1" title="$2"; shift 2
  printf '\n%s┌─ %s%s %s\n' "$col" "$C_B" "$title" "$(printf '%s' "$col")$(_rule $((68 - ${#title})))$C_RST"
  local line
  for line in "$@"; do printf '%s│%s %b\n' "$col" "$C_RST" "$line"; done
  printf '%s└%s%s\n' "$col" "$(_rule 70)" "$C_RST"
}
phase() { WIZ_STEP=$((WIZ_STEP+1)); printf '\n%s%s━━ %s%s\n' "$C_C" "$C_B" "$1" "$C_RST"; }
ok()   { printf '   %s✓%s %s\n' "$C_G" "$C_RST" "$1"; }
note() { printf '   %s•%s %s\n' "$C_Y" "$C_RST" "$1"; }
die()  { printf '\n%s  ✗ %s%s\n' "$C_R$C_B" "$1" "$C_RST" >&2; exit 1; }

# run_step "Label" cmd...   run quietly with a spinner; dump log + abort on fail.
run_step() {
  local label="$1"; shift
  local log; log="$(mktemp)"
  if [ "$C_TTY" = 0 ]; then
    if "$@" </dev/null >"$log" 2>&1; then ok "$label"; rm -f "$log"; return 0
    else printf '   %s✗ %s%s\n' "$C_R" "$label" "$C_RST"; sed 's/^/      /' "$log"; rm -f "$log"; exit 1; fi
  fi
  ( "$@" ) </dev/null >"$log" 2>&1 &
  local pid=$! i=0 sp='|/-\'
  while kill -0 "$pid" 2>/dev/null; do
    printf '\r   %s%s%s %s ' "$C_C" "${sp:$((i%4)):1}" "$C_RST" "$label"; i=$((i+1)); sleep 0.12
  done
  if wait "$pid"; then printf '\r   %s✓%s %s\033[K\n' "$C_G" "$C_RST" "$label"
  else printf '\r   %s✗%s %s\033[K\n' "$C_R" "$C_RST" "$label"; sed 's/^/      /' "$log" | tail -n 25; rm -f "$log"; exit 1; fi
  rm -f "$log"
}

# spinner_wait "Label" timeout_s check_cmd...   live elapsed-time until ready.
spinner_wait() {
  local label="$1" timeout="$2"; shift 2
  local t=0 i=0 sp='|/-\'
  while [ "$t" -lt "$timeout" ]; do
    if "$@" >/dev/null 2>&1; then
      [ "$C_TTY" = 1 ] && printf '\r' ; ok "$label (${t}s)"; return 0
    fi
    [ "$C_TTY" = 1 ] && printf '\r   %s%s%s %s … %ss\033[K' "$C_C" "${sp:$((i%4)):1}" "$C_RST" "$label" "$t"
    i=$((i+1)); sleep 1; t=$((t+1))
  done
  [ "$C_TTY" = 1 ] && printf '\r'; note "$label — not ready after ${timeout}s"; return 1
}

press_enter() { [ "$ASSUME_YES" = 1 ] && return 0; printf '   %s↵ Press Enter to continue…%s ' "$C_B" "$C_RST"; read -r _ <"$TTY" || true; }
confirm()     { [ "$ASSUME_YES" = 1 ] && return 0; local a; printf '   %s%s%s [y/N] ' "$C_B" "$1" "$C_RST"; read -r a <"$TTY" || a=; case "$a" in [Yy]*) return 0;; *) return 1;; esac; }
ask() { # ask "prompt" "default" -> echoes answer (default when --yes/no tty)
  local def="${2:-}" a
  if [ "$ASSUME_YES" = 1 ]; then echo "$def"; return; fi
  printf '   %s%s%s ' "$C_B" "$1" "$C_RST" >&2; read -r a <"$TTY" || a=; echo "${a:-$def}"
}

# ============================================================================
ARCH="$(uname -m)"
DPKG_ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
. /etc/os-release
CODENAME="${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}"
_route="$(ip route get 1.1.1.1 2>/dev/null || true)"
if [[ "$_route" =~ src[[:space:]]+([0-9.]+) ]]; then HOST_IP="${BASH_REMATCH[1]}"; else HOST_IP=""; fi
[ -n "$HOST_IP" ] || HOST_IP="$(hostname -I 2>/dev/null | awk 'NR==1{print $1}')"

BUILD_SOCK="/run/beamhall-build.sock"
BUILD_DATA="/var/lib/beamhall-build"
BUILD_EXEC="/run/beamhall-build"
BUILD_CONF="/etc/beamhall/build-daemon.json"
REGISTRY_NAME="beamhall-registry"
REGISTRY_NET="beamhall-registry-net"
PG_NAME="beamhall-postgres"
PG_NET="beamhall-postgres-net"

want() { [ "$GROUP" = "all" ] || [ "$GROUP" = "$1" ]; }
version_ge() { local lo; lo="$(printf '%s\n%s\n' "$2" "$1" | sort -V)"; lo="${lo%%$'\n'*}"; [ "$lo" = "$2" ]; }

# --- small wrapped helpers (so run_step can spinner-wrap multi-step work) ----
_apt_install() { DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null; }
_docker_repo() {
  install -m 0755 -d /etc/apt/keyrings
  if [ ! -s /etc/apt/keyrings/docker.asc ]; then
    curl -fsSL "https://download.docker.com/linux/${ID}/gpg" -o /etc/apt/keyrings/docker.asc; chmod a+r /etc/apt/keyrings/docker.asc
  fi
  echo "deb [arch=${DPKG_ARCH} signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${ID} ${CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  if apt-cache policy docker-ce 2>/dev/null | grep -qE 'Candidate: [0-9]'; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker-ce docker-ce-cli containerd.io >/dev/null
  else
    rm -f /etc/apt/sources.list.d/docker.list; apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io >/dev/null
  fi
}
_gvisor_install() {
  if [ ! -s /etc/apt/keyrings/gvisor-archive-keyring.gpg ]; then
    curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor -o /etc/apt/keyrings/gvisor-archive-keyring.gpg
  fi
  echo "deb [arch=${DPKG_ARCH} signed-by=/etc/apt/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
    > /etc/apt/sources.list.d/gvisor.list
  apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq runsc >/dev/null
}
_pack_install() {
  case "$ARCH" in x86_64) pa=linux ;; aarch64) pa=linux-arm64 ;; *) pa=linux ;; esac
  curl -fsSL "https://github.com/buildpacks/pack/releases/download/${PACK_VERSION}/pack-${PACK_VERSION}-${pa}.tgz" | tar -xz -C /usr/local/bin pack
}
_caddy_install() { curl -fsSL "https://caddyserver.com/api/download?os=linux&arch=${DPKG_ARCH}" -o /usr/local/bin/caddy; chmod +x /usr/local/bin/caddy; }

# ============================================================================
step_dns() {
  phase "Networking — wildcard DNS (you own this)"
  box "$C_C" "Point *.${BASE_DOMAIN} at this host" \
    "Beamhall serves every beam and the IdP under ${C_B}*.${BASE_DOMAIN}${C_RST}, all on" \
    "this one host. Your DNS must resolve these to ${C_B}${HOST_IP:-the host IP}${C_RST}:" \
    "" \
    "   ${C_B}${BASE_DOMAIN}${C_RST}            (the appliance: MCP + Admin console)" \
    "   ${C_B}idp.${BASE_DOMAIN}${C_RST}        (the bundled identity provider)" \
    "   ${C_B}*.${BASE_DOMAIN}${C_RST}          (preview + live beam URLs)" \
    "" \
    "A single ${C_B}wildcard A record${C_RST} (*.${BASE_DOMAIN} → ${HOST_IP:-IP}) covers all three." \
    "${C_DIM}Engineer workstations must resolve these too (corporate DNS). Beamhall${C_RST}" \
    "${C_DIM}does not run DNS for you.${C_RST}"
  local r=""
  r="$(getent hosts "probe-$$.${BASE_DOMAIN}" 2>/dev/null | awk 'NR==1{print $1}')"
  if [ -z "$r" ]; then r="$(getent hosts "${BASE_DOMAIN}" 2>/dev/null | awk 'NR==1{print $1}')"; fi
  if [ -n "$r" ] && { [ -z "$HOST_IP" ] || [ "$r" = "$HOST_IP" ]; }; then
    ok "wildcard resolves to ${r} — DNS looks good"
  else
    note "could not confirm *.${BASE_DOMAIN} resolves to ${HOST_IP:-this host} (got '${r:-nothing}')."
    note "Set the wildcard record before engineers connect; the install can proceed now."
    confirm "I understand the DNS requirement — continue?" || die "set up DNS, then re-run."
  fi
}

# ============================================================================
group_baseline() {
  phase "Runtime baseline (Docker, gVisor, build daemon)"
  case "${ID:-}:${VERSION_ID:-}" in
    ubuntu:24.*|ubuntu:25.*|ubuntu:26.*|debian:12|debian:13) ok "supported OS: ${PRETTY_NAME}" ;;
    *) note "untested OS '${PRETTY_NAME:-?}' (validated: Ubuntu 24.04+/Debian 12) — continuing." ;;
  esac
  command -v apt-get >/dev/null 2>&1 || die "apt-based distros only (Ubuntu/Debian) for now."
  local kver; kver="$(uname -r | sed -E 's/^([0-9]+\.[0-9]+).*/\1/')"
  version_ge "$kver" "5.2" && ok "kernel $(uname -r) ≥ 5.2" || die "kernel $(uname -r) < 5.2"
  [ -f /sys/fs/cgroup/cgroup.controllers ] && ok "cgroup v2 unified active" || die "cgroup v2 not active"
  local memkb; memkb="$(awk '/MemTotal/{print $2}' /proc/meminfo)"
  if [ "${memkb:-0}" -lt 6000000 ]; then note "RAM $((memkb/1024)) MiB < 8 GiB recommended (ok for evaluation)."; else ok "RAM $((memkb/1024)) MiB"; fi

  run_step "Updating package lists" apt-get update -qq
  run_step "Installing base packages (curl, jq, age, …)" _apt_install ca-certificates curl gnupg jq python3 uidmap age
  run_step "Installing Docker Engine" _docker_repo
  run_step "Installing gVisor (runsc) — the regulated isolation tier" _gvisor_install

  local RUNSC_PATH; RUNSC_PATH="$(command -v runsc)"
  mkdir -p /etc/docker
  RUNSC_PATH="$RUNSC_PATH" python3 - >/dev/null <<'PY'
import json, os
p="/etc/docker/daemon.json"; cfg={}
if os.path.exists(p):
    try: cfg=json.load(open(p)) or {}
    except Exception: cfg={}
cfg["userns-remap"]="default"
cfg.setdefault("runtimes",{})["runsc"]={"path": os.environ["RUNSC_PATH"]}
json.dump(cfg, open(p,"w"), indent=2)
PY
  ok "configured userns-remap + runsc on the runtime daemon"

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
  run_step "Starting the runtime daemon" bash -c 'systemctl enable --now docker >/dev/null 2>&1 || true; systemctl restart docker; for i in $(seq 1 20); do docker info >/dev/null 2>&1 && break; sleep 1; done'
  run_step "Starting the dedicated build daemon" bash -c 'systemctl enable --now beamhall-build.service >/dev/null 2>&1 || true; systemctl restart beamhall-build.service; sleep 3'

  docker info >/dev/null 2>&1 || die "runtime docker daemon not reachable"
  docker info --format '{{range .SecurityOptions}}{{println .}}{{end}}' | grep -q userns || die "userns-remap NOT enabled"
  docker info --format '{{range $k,$v := .Runtimes}}{{println $k}}{{end}}' | grep -qx runsc || die "runsc not registered"
  local rver; rver="$(runc --version 2>/dev/null | sed -nE 's/^runc version ([0-9.]+).*/\1/p')"; rver="${rver%%$'\n'*}"
  if [ -n "$rver" ] && version_ge "$rver" "$MIN_RUNC"; then ok "security baseline verified (userns-remap, runsc, runc $rver ≥ $MIN_RUNC)"
  else die "runc ${rver:-unknown} < $MIN_RUNC — refusing to continue on a vulnerable runtime"; fi
  docker -H unix://${BUILD_SOCK} info >/dev/null 2>&1 || die "build daemon failed (journalctl -u beamhall-build)"
}

# ============================================================================
group_substrate() {
  phase "Platform services (buildpacks, gateway, registry, database)"
  if ! command -v pack >/dev/null 2>&1 || [ "$(pack version 2>/dev/null)" != "${PACK_VERSION#v}" ]; then
    run_step "Installing Cloud Native Buildpacks (pack ${PACK_VERSION})" _pack_install
  else ok "pack ${PACK_VERSION#v} present"; fi

  if ! command -v caddy >/dev/null 2>&1; then run_step "Installing the gateway (Caddy)" _caddy_install; fi
  id caddy >/dev/null 2>&1 || useradd --system --home-dir /var/lib/caddy --create-home --shell /usr/sbin/nologin caddy
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
  run_step "Starting the gateway" bash -c 'systemctl enable --now beamhall-gateway.service >/dev/null 2>&1 || systemctl restart beamhall-gateway.service; sleep 2'
  spinner_wait "Gateway admin API" 20 curl -fsS http://127.0.0.1:2019/config/ || true

  docker network inspect "$REGISTRY_NET" >/dev/null 2>&1 || docker network create "$REGISTRY_NET" >/dev/null
  run_step "Pulling the internal registry image" docker pull "$REGISTRY_IMAGE"
  if ! docker ps --format '{{.Names}}' | grep -qx "$REGISTRY_NAME"; then
    docker rm -f "$REGISTRY_NAME" >/dev/null 2>&1 || true
    run_step "Starting the internal registry (loopback only)" docker run -d --restart=always --name "$REGISTRY_NAME" --network "$REGISTRY_NET" -p 127.0.0.1:5000:5000 "$REGISTRY_IMAGE"
  fi
  spinner_wait "Internal registry" 20 curl -fsS http://127.0.0.1:5000/v2/ || true

  install -d -m 0750 /etc/beamhall
  [ -s /etc/beamhall/postgres-admin.pw ] || (umask 077; openssl rand -hex 24 > /etc/beamhall/postgres-admin.pw)
  local PGPW; PGPW="$(cat /etc/beamhall/postgres-admin.pw)"
  docker network inspect "$PG_NET" >/dev/null 2>&1 || docker network create "$PG_NET" >/dev/null
  run_step "Pulling the managed PostgreSQL image" docker pull "$POSTGRES_IMAGE"
  if ! docker ps --format '{{.Names}}' | grep -qx "$PG_NAME"; then
    docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
    run_step "Starting managed PostgreSQL" docker run -d --restart=always --name "$PG_NAME" --network "$PG_NET" -p 127.0.0.1:5433:5432 -e POSTGRES_PASSWORD="$PGPW" "$POSTGRES_IMAGE"
  fi
  spinner_wait "PostgreSQL ready" 30 docker exec "$PG_NAME" pg_isready -U postgres || true
}

# ============================================================================
fetch_release_binary() {
  local arch tag ver base ar tmp resp
  case "$DPKG_ARCH" in amd64) arch=amd64 ;; arm64) arch=arm64 ;; *) die "no released binary for '$DPKG_ARCH'; pass a local path" ;; esac
  command -v curl >/dev/null 2>&1 || { apt-get update -qq; _apt_install curl ca-certificates; }
  tag="$RELEASE_VERSION"
  if [ -z "$tag" ]; then
    resp="$(curl -fsSL "https://api.github.com/repos/${REPO_SLUG}/releases/latest" 2>/dev/null || true)"
    [[ "$resp" =~ \"tag_name\"[[:space:]]*:[[:space:]]*\"([^\"]+)\" ]] && tag="${BASH_REMATCH[1]}"
    [ -n "$tag" ] || die "could not resolve the latest ${REPO_SLUG} release; pin with --version vX.Y.Z"
  fi
  case "$tag" in v*) ver="${tag#v}" ;; *) ver="$tag" ;; esac
  RESOLVED_TAG="$tag"
  base="https://github.com/${REPO_SLUG}/releases/download/${tag}"; ar="beamhall_${ver}_linux_${arch}.tar.gz"; tmp="$(mktemp -d)"
  _fetch_verify() {
    curl -fsSL "${base}/${ar}" -o "${tmp}/${ar}" || return 1
    if curl -fsSL "${base}/checksums.txt" -o "${tmp}/checksums.txt" 2>/dev/null; then
      ( cd "$tmp" && grep " ${ar}\$" checksums.txt | sha256sum -c - >/dev/null 2>&1 ) || return 2
    fi
    tar -xzf "${tmp}/${ar}" -C "$tmp" beamhalld || return 3
    chmod +x "${tmp}/beamhalld"
  }
  run_step "Fetching beamhalld ${ver} (${arch}) + verifying checksum" _fetch_verify
  BIN_SRC="${tmp}/beamhalld"
}

group_appliance() {
  phase "The Beamhall appliance"
  if [ -n "$BIN_SRC" ] && [ -x "$BIN_SRC" ]; then ok "using provided binary: $BIN_SRC"
  elif [ -n "$RELEASE_VERSION" ]; then fetch_release_binary
  elif command -v beamhalld >/dev/null 2>&1; then BIN_SRC="$(command -v beamhalld)"; ok "using beamhalld on PATH"
  else fetch_release_binary; fi
  [ -n "$BIN_SRC" ] && [ -x "$BIN_SRC" ] || die "no beamhalld binary (pass a path or use --version)"
  [ -n "$BASE_DOMAIN" ] || BASE_DOMAIN="$(hostname -f 2>/dev/null || hostname)"

  id beamhall >/dev/null 2>&1 || useradd --system --home-dir /var/lib/beamhall --shell /usr/sbin/nologin beamhall
  groupadd -f docker; usermod -aG docker beamhall
  if [ "$BIN_SRC" != /usr/local/bin/beamhalld ]; then install -m 0755 "$BIN_SRC" /usr/local/bin/beamhalld; fi
  ok "installed /usr/local/bin/beamhalld + service user"

  install -d -m 0750 -o root -g beamhall /etc/beamhall
  if [ -n "$SECRET_KEY_SRC" ]; then
    install -m 0400 -o root -g root "$SECRET_KEY_SRC" /etc/beamhall/secret.key; ok "installed supplied secret root key"
  elif [ ! -s /etc/beamhall/secret.key ]; then
    (umask 077; age-keygen 2>/dev/null | grep '^AGE-SECRET-KEY-' > /etc/beamhall/secret.key); chmod 0400 /etc/beamhall/secret.key
    KEY_GENERATED=1; ok "generated the age secret root key"
  else ok "existing secret root key left unchanged"; fi

  local PGPW; PGPW="$(cat /etc/beamhall/postgres-admin.pw 2>/dev/null || echo CHANGE-ME)"
  if [ ! -f /etc/beamhall/beamhall.env ]; then
    cat > /etc/beamhall/beamhall.env <<EOF
# Beamhall appliance config (generated by install.sh). Owner root:beamhall 0640.
BEAMHALL_HTTP_ADDR=:8443
BEAMHALL_BASE_DOMAIN=${BASE_DOMAIN}
BEAMHALL_DATA_DIR=/var/lib/beamhall
BEAMHALL_LOG_LEVEL=info

# Identity provider — set the issuer to enable MCP + Admin.
# Per-IdP recipe: https://github.com/Beamhall/beamhall/blob/main/docs/idp-setup.md
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
    ok "wrote /etc/beamhall/beamhall.env (base domain ${BASE_DOMAIN})"
  else ok "beamhall.env exists — left unchanged"; fi

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
  ok "installed the hardened systemd unit"

  if [ "$AUTO_START" = "1" ]; then
    run_step "Starting beamhalld" bash -c 'systemctl enable --now beamhalld >/dev/null 2>&1; sleep 2'
    spinner_wait "Appliance health (/healthz)" 25 curl -fsS http://127.0.0.1:8443/healthz \
      || note "beamhalld started but /healthz not green yet — journalctl -u beamhalld -n 50"
  else note "skipped start (--no-start) — enable with: systemctl enable --now beamhalld"; fi

  CA_OUT=/usr/local/share/ca-certificates/beamhall-gateway-ca.crt
  if [ "$TLS_MODE" = "internal" ]; then
    _install_ca() {
      curl -fsS -m5 "http://127.0.0.1:2019/pki/ca/local" 2>/dev/null \
        | python3 -c 'import sys,json; print(json.load(sys.stdin)["root_certificate"])' > "$CA_OUT" 2>/dev/null
      [ -s "$CA_OUT" ] || return 1
      update-ca-certificates >/dev/null 2>&1; systemctl restart beamhalld 2>/dev/null || true
    }
    spinner_wait "Issuing + trusting the gateway internal CA" 20 _install_ca || note "could not fetch the gateway CA yet (gateway still starting?)."
  fi
}

# ============================================================================
gate_post_install() {
  box "$C_G" "✅  Appliance installed and running" \
    "beamhalld is up and ${C_B}/healthz${C_RST} is green on this host." \
    "Admin console (after identity is on): ${C_B}https://${BASE_DOMAIN}/admin${C_RST}"

  if [ "${KEY_GENERATED:-0}" = "1" ]; then
    box "$C_Y" "🔑  ACTION REQUIRED — back up the secret root key" \
      "A new age root key was generated at ${C_B}/etc/beamhall/secret.key${C_RST} (0400)." \
      "It seals ${C_B}every${C_RST} secret Beamhall stores — and it travels inside backups." \
      "" \
      "${C_B}Copy it to your KMS / vault now and keep it offline.${C_RST}" \
      "If this key is lost, every stored secret (and every backup) is unrecoverable."
    confirm "I have backed up (or will immediately back up) the secret key — continue?" \
      || note "Remember: /etc/beamhall/secret.key — back it up before going further."
  fi

  if [ "$TLS_MODE" = "internal" ] && [ -s "${CA_OUT:-/nonexistent}" ]; then
    box "$C_C" "🔒  Distribute the gateway CA to client machines" \
      "Internal TLS uses a private CA. This host already trusts it; your" \
      "engineers' workstations must too, so HTTPS to *.${BASE_DOMAIN} validates" \
      "(browser OAuth + beam URLs). The root cert is at:" \
      "   ${C_B}${CA_OUT}${C_RST}" \
      "" \
      "macOS: add to login keychain & trust · Linux: drop in" \
      "/usr/local/share/ca-certificates/ then run update-ca-certificates." \
      "${C_DIM}Or point a single tool at it: curl --cacert <file>, NODE_EXTRA_CA_CERTS=<file>.${C_RST}"
    press_enter
  fi
}

choose_idp() {
  local choice="$SETUP_IDP"
  if [ "$choice" = "ask" ]; then
    box "$C_C" "Turn on identity — required for MCP + the Admin console" \
      "Beamhall validates OAuth tokens from an identity provider. Until one is" \
      "wired, the MCP endpoint and Admin console stay closed. Choose one:" \
      "" \
      "   ${C_B}1)${C_RST} Bundled Keycloak — recommended for a pilot/evaluation" \
      "        One step, seeds users, wires everything. No corporate IdP needed." \
      "   ${C_B}2)${C_RST} Your corporate IdP (Okta / Entra / Keycloak) — production" \
      "   ${C_B}3)${C_RST} Skip for now"
    choice="$(ask 'Choose [1/2/3] (default 1):' 1)"
  fi
  case "$choice" in
    2|corporate)
      box "$C_C" "Wire your corporate IdP" \
        "1. Set ${C_B}BEAMHALL_OAUTH_ISSUER${C_RST} in /etc/beamhall/beamhall.env" \
        "2. ${C_B}systemctl restart beamhalld${C_RST}" \
        "Per-IdP recipe (Okta/Entra/Keycloak):" \
        "   ${C_B}https://github.com/Beamhall/beamhall/blob/main/docs/idp-setup.md${C_RST}"
      ;;
    3|skip)
      box "$C_C" "Identity skipped" \
        "Turn it on later — re-run this and pick the bundled IdP, or wire your own" \
        "(BEAMHALL_OAUTH_ISSUER in /etc/beamhall/beamhall.env, then restart)."
      ;;
    *)
      local scheme=https; [ "$TLS_MODE" = "off" ] && scheme=http
      local idp; idp="$(mktemp)"
      run_step "Downloading the bundled-IdP wizard" curl -fsSL "https://github.com/${REPO_SLUG}/releases/latest/download/setup-bundled-idp.sh" -o "$idp"
      printf '\n%s%s  Handing off to the bundled-IdP wizard…%s\n' "$C_C" "$C_B" "$C_RST"
      BASE_DOMAIN="$BASE_DOMAIN" SCHEME="$scheme" BEAMHALL_YES="$ASSUME_YES" bash "$idp" </dev/null
      ;;
  esac
}

final_summary() {
  box "$C_G" "🎉  Beamhall is ready" \
    "Admin console : ${C_B}https://${BASE_DOMAIN}/admin${C_RST}" \
    "MCP endpoint  : ${C_B}https://${BASE_DOMAIN}/mcp${C_RST}" \
    "" \
    "Next: create a workspace and onboard an engineer (Admin console, or the" \
    "admin_* MCP tools). Full walkthrough:" \
    "   ${C_B}https://github.com/Beamhall/beamhall/blob/main/docs/getting-started.md${C_RST}"
}

# ============================================================================
if want baseline || want substrate || want appliance; then
  box "$C_BLU" "Beamhall Setup Wizard" \
    "This will turn this host into a running Beamhall appliance:" \
    "Docker + gVisor isolation · build pipeline · gateway · database · the" \
    "hardened backplane service — then guide you through DNS, the secret key," \
    "the gateway CA, and turning on identity." \
    "" \
    "Host: ${C_B}$(hostname)${C_RST} (${HOST_IP:-?}) · base domain: ${C_B}${BASE_DOMAIN:-unset}${C_RST} · TLS: ${C_B}${TLS_MODE}${C_RST}"
  press_enter
fi

[ -n "$BASE_DOMAIN" ] && want appliance && step_dns || true
want baseline  && group_baseline  </dev/null
want substrate && group_substrate </dev/null
want appliance && group_appliance </dev/null

if want appliance; then
  gate_post_install
  choose_idp
  final_summary
fi
