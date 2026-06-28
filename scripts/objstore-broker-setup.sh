#!/usr/bin/env bash
# Stand up the shared bh-objstore broker (PLAN §5.11 facility brokers / §5.13
# object storage) on a Beamhall appliance. Run ON the appliance (root). This is
# the MINIMUM to make object storage available — and it works out of the box: the
# broker boots a LOCAL disk backend, so beams can provision_object_store with no
# external account. An IT admin can later switch the backend to the company's S3,
# at runtime, with the MCP tool admin_set_object_store_provider (the endpoint +
# credential are held + persisted by the broker, never here).
#
# `install.sh` already does this on a fresh install; use this script to (re)stand
# up the broker on a hand-wired appliance, or with --lab-minio to add a local
# MinIO to exercise FORWARD mode (then point admin_set_object_store_provider at it).
#
# Usage:  objstore-broker-setup.sh [--lab-minio]
#
# Prints the BEAMHALL_OBJSTORE_* plumbing block to add to /etc/beamhall/beamhall.env
# (control URL/token + beam host), then restart beamhalld.
set -euo pipefail

BEAMHALLD="${BEAMHALLD:-/usr/local/bin/beamhalld}"
WORKDIR="${WORKDIR:-/root/lab-objstore}"
LAB_MINIO=0
while [ $# -gt 0 ]; do
  case "$1" in
    --lab-minio) LAB_MINIO=1; shift;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

[ -x "$BEAMHALLD" ] || { echo "beamhalld not found at $BEAMHALLD" >&2; exit 1; }
command -v docker >/dev/null || { echo "docker required" >&2; exit 1; }
mkdir -p "$WORKDIR"; cd "$WORKDIR"

[ -s /etc/beamhall/objstore-control.token ] 2>/dev/null || { mkdir -p /etc/beamhall; (umask 077; openssl rand -hex 24 > /etc/beamhall/objstore-control.token); } 2>/dev/null || true
TOKEN="$(cat /etc/beamhall/objstore-control.token 2>/dev/null || openssl rand -hex 24)"

# --- broker image: the beamhalld binary in object-store-relay mode (scratch) ---
cp -f "$BEAMHALLD" "$WORKDIR/beamhalld"
printf 'FROM scratch\nCOPY beamhalld /beamhalld\nENTRYPOINT ["/beamhalld","object-store-relay"]\n' > Dockerfile.relay
docker build -q -t bh-objstore-img:lab -f Dockerfile.relay . >/dev/null
echo "✓ built bh-objstore image"

docker network create objstore-egress-net 2>/dev/null || true
docker volume create bh-objstore-data >/dev/null 2>&1 || true

# --- optional lab MinIO (a test external-S3 target for the forward backend) ----
if [ "$LAB_MINIO" = 1 ]; then
  docker rm -f objstore-minio >/dev/null 2>&1 || true
  docker run -d --name objstore-minio --network objstore-egress-net --restart unless-stopped \
    -e MINIO_ROOT_USER=labkey -e MINIO_ROOT_PASSWORD=labsecret123 \
    minio/minio server /data >/dev/null
  # Create the company bucket the broker forwards into.
  sleep 2
  docker run --rm --network objstore-egress-net --entrypoint sh minio/mc -c \
    'mc alias set lab http://objstore-minio:9000 labkey labsecret123 && mc mb -p lab/company-bucket' >/dev/null 2>&1 || true
  echo "✓ lab MinIO running on objstore-egress-net (point admin_set_object_store_provider at endpoint objstore-minio:9000, bucket company-bucket, key labkey/labsecret123, force_path_style=true, use_ssl=false)"
fi

# --- broker container (local backend by default — set external via MCP) --------
docker rm -f bh-objstore >/dev/null 2>&1 || true
docker run -d --name bh-objstore --network objstore-egress-net --restart unless-stopped \
  -p 127.0.0.1:9001:9001 -v bh-objstore-data:/data \
  -e BEAMHALL_OBJSTORE_CONTROL_TOKEN="$TOKEN" -e BEAMHALL_OBJSTORE_S3_ADDR=:9000 \
  -e BEAMHALL_OBJSTORE_CONTROL_ADDR=:9001 -e BEAMHALL_OBJSTORE_STATE_DIR=/data bh-objstore-img:lab >/dev/null
echo "✓ bh-objstore broker running (control on 127.0.0.1:9001; local disk backend; switch to external S3 via admin_set_object_store_provider)"

cat <<EOF

Add to /etc/beamhall/beamhall.env (if not already present), then: systemctl restart beamhalld

# --- object-store broker (provision_object_store) ---
BEAMHALL_OBJSTORE_CONTROL_URL=http://127.0.0.1:9001
BEAMHALL_OBJSTORE_CONTROL_TOKEN=$TOKEN
BEAMHALL_OBJSTORE_BEAM_HOST=bh-objstore

Object storage is ON by default (local disk backend). To back it with the company S3:
  admin_set_object_store_provider {"endpoint":"s3.yourprovider.com","bucket":"your-bucket","access_key":"...","secret_key":"...","force_path_style":true}
EOF
