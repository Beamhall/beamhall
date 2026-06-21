#!/usr/bin/env bash
# Load an offline image bundle (scripts/airgap-bundle.sh) onto an AIR-GAPPED
# Beamhall host. The CNB builder + run images must land in the dedicated BUILD
# daemon (pack runs there); the IdP/support images land in the runtime daemon.
# Then point Beamhall at them with the printed env so pack stops reaching the
# internet (PLAN §10, docs/air-gapped.md).
#
#   sudo bash scripts/airgap-load.sh beamhall-airgap-bundle.tar.gz
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }

BUNDLE="${1:?usage: airgap-load.sh <bundle.tar.gz>}"
BUILD_SOCK="${BEAMHALL_BUILD_DOCKER_HOST:-unix:///run/docker-build.sock}"
BUILDER="${BEAMHALL_CNB_BUILDER:-paketobuildpacks/builder-jammy-base:latest}"

echo "== load into the BUILD daemon ($BUILD_SOCK) — builder + run images =="
gunzip -c "$BUNDLE" | docker -H "$BUILD_SOCK" load

echo "== load into the runtime daemon — IdP + support images =="
gunzip -c "$BUNDLE" | docker load

echo "== verify the CNB builder is present in the build daemon =="
if docker -H "$BUILD_SOCK" image inspect "$BUILDER" >/dev/null 2>&1; then
  echo "  OK: $BUILDER"
else
  echo "  !! $BUILDER not found in the build daemon — set BEAMHALL_CNB_BUILDER to a"
  echo "     ref that IS in the bundle (see the .images.txt manifest)."
fi

cat <<EOF

Loaded. Add to /etc/beamhall/beamhall.env so builds use the local images:

  BEAMHALL_PACK_PULL_POLICY=if-not-present
  # BEAMHALL_CNB_BUILDER / BEAMHALL_CNB_RUN_IMAGE only if you retagged the images.

Then restart beamhalld and run a test deploy. The runtime daemon pulls only
pinned digests from the internal registry, so no further internet access is
needed for deploys. (npm/pip and similar package fetches during a beam build are
a separate concern — point them at your internal mirrors.)
EOF
