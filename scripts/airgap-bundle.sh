#!/usr/bin/env bash
# Build an offline image bundle for an air-gapped Beamhall (PLAN §10). Run on a
# CONNECTED machine; it pulls the container images the appliance would otherwise
# fetch from the internet and `docker save`s them into one tarball you carry to
# the air-gapped host and load with scripts/airgap-load.sh.
#
#   bash scripts/airgap-bundle.sh [out.tar.gz]
#
# Override the image set with IMAGES="a b c". The defaults are the build
# pipeline's Cloud Native Buildpacks builder + run image (the real blocker for
# offline builds) plus the bundled-IdP and support images.
set -euo pipefail

OUT="${1:-beamhall-airgap-bundle.tar.gz}"
IMAGES="${IMAGES:-\
paketobuildpacks/builder-jammy-base:latest \
paketobuildpacks/run-jammy-base:latest \
quay.io/keycloak/keycloak:26.0 \
postgres:17-alpine \
registry:2}"

echo "== pulling images =="
for img in $IMAGES; do
  echo "  $img"
  docker pull -q "$img" >/dev/null
done

echo "== saving -> $OUT =="
# shellcheck disable=SC2086
docker save $IMAGES | gzip > "$OUT"

# A manifest of exactly what's inside, so the load side can verify + the operator
# knows the refs to configure.
printf '%s\n' $IMAGES > "${OUT%.tar.gz}.images.txt"

echo
echo "bundle: $OUT ($(du -h "$OUT" | cut -f1))"
echo "images: ${OUT%.tar.gz}.images.txt"
echo "Carry both to the air-gapped host and run scripts/airgap-load.sh."
