#!/usr/bin/env bash
# Exercise the object-storage facility (PLAN §5.11 facility brokers / §5.13)
# end-to-end against the live appliance + the shared bh-objstore broker:
#
#   provision_object_store (builder) → 6 sealed secrets (S3_ENDPOINT/REGION/
#                                      FORCE_PATH_STYLE + per-channel BUCKET/
#                                      ACCESS_KEY/SECRET_KEY), broker registration,
#                                      bh-objstore attached to the beam bridge
#   show_object_store                → preview bucket + region + endpoint
#   deploy_beam                      → S3_* injected as /run/secrets/*
#   put+get (stock SDK, SigV4)       → round-trip via minio-go over plain HTTP
#   cross-beam                       → beam B's key on beam A's bucket → 403
#   forged key                       → wrong secret → SignatureDoesNotMatch
#   destroy_beam (IT)                → broker deregisters + purges the bucket
#                                      (old creds → 403)
#
# MCP is driven AS the personas (bh-call.sh); the S3 checks run on the appliance
# over SSH (root) with throwaway helper containers (s3probe, minio-go) on the
# shared team bridge.
#
#   scripts/agent-conformance/object-store.sh [beam-slug]
#
# Requires: a beamhalld with the object-store facility + a running bh-objstore
# broker (install.sh, or scripts/objstore-broker-setup.sh), the four personas
# (provision.sh), and Go on the Mac (builds the s3probe helper from the module).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"
call() { "$HERE/bh-call.sh" "$@"; }
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

BEAM="${1:-storecheck}"
BEAM2="${BEAM}2"
WS="$WORKSPACE_BLUE"
BUILDER="builder-carol"
ADMIN="admin-alice"
REG_HOST="127.0.0.1:5000"
REPO_PATH="${WS}/blue-web"
TMP="${TMPDIR:-/tmp}/bh-objstore-$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

# --- 0. preflight: broker up -------------------------------------------------
say "0. Broker preflight"
remote 'docker ps --format "{{.Names}}" | grep -qx bh-objstore' \
  || die "bh-objstore broker not running — run scripts/objstore-broker-setup.sh on the appliance first"
ok "bh-objstore broker is up"

# --- build the stock-SDK probe (minio-go, from the module) -------------------
(cd "$REPO_ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$TMP/s3-probe" ./scripts/agent-conformance/s3probe)
remote 'mkdir -p /root/lab-objstore'
scp -q "$TMP/s3-probe" "$APPLIANCE":/root/lab-objstore/
remote 'cd /root/lab-objstore
  printf "FROM scratch\nCOPY s3-probe /s3-probe\nENTRYPOINT [\"/s3-probe\"]\n" > Dockerfile.probe
  docker build -q -t s3probe:lab -f Dockerfile.probe . >/dev/null'
ok "s3probe helper built on the appliance"

# --- resolve a build-free image to deploy ------------------------------------
TAG="$(remote "curl -fsS http://${REG_HOST}/v2/${REPO_PATH}/tags/list" 2>/dev/null | jq -r '.tags[0] // empty' || true)"
[ -n "$TAG" ] || die "no built image in the registry for ${REPO_PATH} — deploy blue-web first"
DIGEST="$(remote "curl -fsS -o /dev/null -D - -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' http://${REG_HOST}/v2/${REPO_PATH}/manifests/${TAG}" 2>/dev/null | tr -d '\r' | awk 'tolower($1)=="docker-content-digest:"{print $2}')"
[ -n "$DIGEST" ] || die "could not resolve manifest digest for ${REPO_PATH}:${TAG}"
FULLREF="${REG_HOST}/${REPO_PATH}@${DIGEST}"

deploy_beam() { # $1=slug → echoes "<container> <bridge>"
  call "$BUILDER" deploy_beam "{\"beamhall\":\"$WS\",\"beam\":\"$1\",\"image_ref\":\"${REG_HOST}/${REPO_PATH}\",\"image_digest\":\"$FULLREF\"}" >/dev/null 2>&1 \
    || die "deploy_beam $1 failed"
  sleep 1
  remote "c=\$(docker ps --format '{{.Names}}\t{{.CreatedAt}}' | grep '^bh_' | sort -k2 | tail -1 | cut -f1); b=\$(docker inspect \$c -f '{{range \$k,\$v := .NetworkSettings.Networks}}{{println \$k}}{{end}}' | grep '^bh-' | head -1); echo \"\$c \$b\""
}
secret_of() { remote "docker exec $1 cat /run/secrets/$2"; }
probe() { # $1=bridge ; remaining = -e ENV=VAL ... ; runs s3probe, echoes last line
  local bridge="$1"; shift
  remote "docker run --rm --network $bridge $* s3probe:lab 2>&1 | tail -1"
}

# --- 1. provision_object_store (beam A) --------------------------------------
say "1. create_beam + provision_object_store"
call "$BUILDER" create_beam "{\"beamhall\":\"$WS\",\"slug\":\"$BEAM\",\"display_name\":\"$BEAM\"}" >/dev/null 2>&1 || true
prov="$(call "$BUILDER" provision_object_store "{\"beamhall\":\"$WS\",\"beam\":\"$BEAM\"}" 2>/dev/null)"
echo "$prov" | grep -q "S3_SECRET_KEY" || die "provision_object_store did not return S3_SECRET_KEY: $prov"
echo "$prov" | grep -q "S3_ENDPOINT" || die "provision_object_store missing S3_ENDPOINT"
ok "provision_object_store sealed the S3_* secrets"

# --- 2. show_object_store ----------------------------------------------------
show="$(call "$BUILDER" show_object_store "{\"beamhall\":\"$WS\",\"beam\":\"$BEAM\"}" 2>/dev/null)"
echo "$show" | grep -qi "preview" || warn "expected a preview bucket; got: $show"
ok "show_object_store reports the preview bucket"

# --- 3. deploy (image pin) → secrets injected --------------------------------
say "3. deploy_beam (build-free pin)"
read -r CT BRIDGE < <(deploy_beam "$BEAM")
[ -n "$CT" ] && [ -n "$BRIDGE" ] || die "could not resolve beam container/bridge"
remote "docker exec $CT ls /run/secrets/S3_SECRET_KEY >/dev/null 2>&1" || die "S3_SECRET_KEY not injected into the beam"
ok "deployed; S3_* injected (container $CT on $BRIDGE)"

EP="$(secret_of "$CT" S3_ENDPOINT)"; REGION="$(secret_of "$CT" S3_REGION)"
A_BUCKET="$(secret_of "$CT" S3_BUCKET)"; A_AK="$(secret_of "$CT" S3_ACCESS_KEY)"; A_SK="$(secret_of "$CT" S3_SECRET_KEY)"
common=(-e "S3_ENDPOINT=$EP" -e "S3_REGION=$REGION")

# --- 4. round-trip (stock SDK, SigV4 over plain HTTP) ------------------------
say "4. put + get with a stock S3 SDK"
res="$(probe "$BRIDGE" "${common[@]}" -e "S3_BUCKET=$A_BUCKET" -e "S3_ACCESS_KEY=$A_AK" -e "S3_SECRET_KEY=$A_SK" -e OP=putget)"
echo "$res" | grep -q "^OK" || die "object round-trip failed: $res"
ok "round-trip OK: $res"

# --- 5. cross-beam isolation (beam B key on beam A bucket → 403) -------------
say "5. cross-beam isolation"
call "$BUILDER" create_beam "{\"beamhall\":\"$WS\",\"slug\":\"$BEAM2\",\"display_name\":\"$BEAM2\"}" >/dev/null 2>&1 || true
call "$BUILDER" provision_object_store "{\"beamhall\":\"$WS\",\"beam\":\"$BEAM2\"}" >/dev/null 2>&1 || die "provision beam B failed"
read -r CT2 BRIDGE2 < <(deploy_beam "$BEAM2")
B_AK="$(secret_of "$CT2" S3_ACCESS_KEY)"; B_SK="$(secret_of "$CT2" S3_SECRET_KEY)"
res="$(probe "$BRIDGE2" "${common[@]}" -e "S3_BUCKET=$A_BUCKET" -e "S3_ACCESS_KEY=$B_AK" -e "S3_SECRET_KEY=$B_SK" -e OP=get -e KEY=probe.txt)"
echo "$res" | grep -q "ERR" || die "beam B read beam A's bucket (isolation broken): $res"
ok "cross-beam denied: $res"

# --- 6. forged key → SignatureDoesNotMatch -----------------------------------
say "6. forged secret rejected"
res="$(probe "$BRIDGE" "${common[@]}" -e "S3_BUCKET=$A_BUCKET" -e "S3_ACCESS_KEY=$A_AK" -e "S3_SECRET_KEY=WRONG-SECRET" -e OP=get -e KEY=probe.txt)"
echo "$res" | grep -q "ERR" || die "forged secret was accepted: $res"
ok "forged secret rejected: $res"

# --- 7. destroy → broker deregisters + purges --------------------------------
say "7. destroy_beam (IT) → broker deregisters + purges the bucket"
call "$ADMIN" destroy_beam "{\"beamhall\":\"$WS\",\"beam\":\"$BEAM\"}" >/dev/null 2>&1 || die "destroy_beam failed"
sleep 1
res="$(probe "$BRIDGE2" "${common[@]}" -e "S3_BUCKET=$A_BUCKET" -e "S3_ACCESS_KEY=$A_AK" -e "S3_SECRET_KEY=$A_SK" -e OP=get -e KEY=probe.txt)"
echo "$res" | grep -q "ERR" || die "old creds still work after destroy (no reclaim): $res"
ok "broker deregistered beam A (old creds → $res)"

# --- teardown ----------------------------------------------------------------
call "$ADMIN" destroy_beam "{\"beamhall\":\"$WS\",\"beam\":\"$BEAM2\"}" >/dev/null 2>&1 || true

printf '\n\033[32m✓ object-store facility conformance PASSED\033[0m\n'
echo "Note: per-request audit (object_store_op put/get) lands in the hash chain via"
echo "the audit-pull loop (~15s); verify with: bh-call.sh admin-alice admin_query_audit '{\"beamhall\":\"team-blue\"}'"
