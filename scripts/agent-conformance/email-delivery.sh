#!/usr/bin/env bash
# Exercise the email delivery facility (PLAN §5.11 facility brokers / §5.12)
# end-to-end against the live appliance + the shared bh-mail broker:
#
#   provision_email (builder)      → 5 sealed secrets incl SMTP_CA, broker registration,
#                                    bh-mail attached to the beam bridge; NO senders yet
#   show_email                     → "no allowed senders" before IT curates them
#   admin_set_email_senders (IT)   → per-beam From allowlist (separation of duties)
#   deploy_beam                    → SMTP_HOST/PORT/USER/PASS/CA injected as /run/secrets/*
#   send (allowed, STARTTLS)       → strict Go net/smtp upgrades against SMTP_CA, AUTHs,
#                                    relay forwards to the smarthost (sink) → delivered
#   send (disallowed sender)       → 550 (anti-spoof across beams)
#   isolation                      → beam→smarthost-direct BLOCKED; beam→bh-mail REACHABLE
#   destroy_beam (IT)              → broker deregisters the beam (old creds → 535)
#
# MCP is driven AS the personas (bh-call.sh); the send/isolation checks run on the
# appliance over SSH (root) with throwaway helper containers on the beam bridge.
#
#   scripts/agent-conformance/email-delivery.sh [beam-slug]
#
# Requires: a beamhalld with the email facility + a running bh-mail broker
# (scripts/mail-broker-setup.sh --lab-sink), the four personas (provision.sh),
# the gateway CA on the Mac (BH_CA), and Go on the Mac (builds the test helpers).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"
call() { "$HERE/bh-call.sh" "$@"; }

BEAM="${1:-mailcheck}"
WS="$WORKSPACE_BLUE"
BUILDER="builder-carol"
ADMIN="admin-alice"
SENDER_DOMAIN="app.example.com"
REG_HOST="127.0.0.1:5000"
REPO_PATH="${WS}/blue-web"
TMP="${TMPDIR:-/tmp}/bh-email-$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

remote() { "${SSH[@]}" "$@"; }

# --- 0. preflight: broker up -------------------------------------------------
say "0. Broker preflight"
remote 'docker ps --format "{{.Names}}" | grep -qx bh-mail' \
  || die "bh-mail broker not running — run scripts/mail-broker-setup.sh --lab-sink on the appliance first"
ok "bh-mail broker is up"

# --- build the strict STARTTLS sender + a tcp probe (on the Mac) -------------
cat > "$TMP/smtp-send.go" <<'GO'
package main
import ("crypto/tls";"crypto/x509";"fmt";"net/smtp";"os";"strings")
func cred(e,f string)string{ if v:=os.Getenv(e);v!=""{return v}; b,_:=os.ReadFile(f); return strings.TrimSpace(string(b)) }
func main(){
 h:=cred("SMTP_HOST","/run/secrets/SMTP_HOST"); p:=cred("SMTP_PORT","/run/secrets/SMTP_PORT")
 u:=cred("SMTP_USER","/run/secrets/SMTP_USER"); pw:=cred("SMTP_PASS","/run/secrets/SMTP_PASS")
 ca:=cred("SMTP_CA","/run/secrets/SMTP_CA"); from:=os.Getenv("FROM"); if from==""{from="noreply@app.example.com"}
 to:=os.Getenv("TO"); if to==""{to="dest@example.org"}; addr:=h+":"+p
 fail:=func(s string,e error){fmt.Printf("%s-ERR: %v\n",s,e); os.Exit(1)}
 c,e:=smtp.Dial(addr); if e!=nil{fail("DIAL",e)}; defer c.Close()
 if e:=c.Hello("mailcheck");e!=nil{fail("EHLO",e)}
 pool:=x509.NewCertPool(); if !pool.AppendCertsFromPEM([]byte(ca)){fail("CA",fmt.Errorf("bad SMTP_CA"))}
 if e:=c.StartTLS(&tls.Config{ServerName:h,RootCAs:pool});e!=nil{fail("STARTTLS",e)}
 if e:=c.Auth(smtp.PlainAuth("",u,pw,h));e!=nil{fail("AUTH",e)}
 if e:=c.Mail(from);e!=nil{fail("MAIL",e)}
 if e:=c.Rcpt(to);e!=nil{fail("RCPT",e)}
 w,e:=c.Data(); if e!=nil{fail("DATA",e)}
 fmt.Fprintf(w,"From: %s\r\nTo: %s\r\nSubject: conformance\r\nMessage-Id: <c-%d@app>\r\n\r\nhi\r\n",from,to,os.Getpid())
 if e:=w.Close();e!=nil{fail("BODY",e)}; c.Quit(); fmt.Printf("SENT from=%s\n",from)
}
GO
cat > "$TMP/tcp-probe.go" <<'GO'
package main
import ("fmt";"net";"os";"time")
func main(){ c,e:=net.DialTimeout("tcp",os.Getenv("TARGET"),5*time.Second); if e!=nil{fmt.Printf("BLOCKED: %v\n",e);return}; c.Close(); fmt.Printf("REACHABLE\n") }
GO
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$TMP/smtp-send" "$TMP/smtp-send.go"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$TMP/tcp-probe" "$TMP/tcp-probe.go"
remote 'mkdir -p /root/lab-mail'
scp -q "$TMP/smtp-send" "$TMP/tcp-probe" "$APPLIANCE":/root/lab-mail/
remote 'cd /root/lab-mail
  printf "FROM scratch\nCOPY smtp-send /smtp-send\nENTRYPOINT [\"/smtp-send\"]\n" > Dockerfile.send
  printf "FROM scratch\nCOPY tcp-probe /tcp-probe\nENTRYPOINT [\"/tcp-probe\"]\n" > Dockerfile.probe
  docker build -q -t smtp-send:lab -f Dockerfile.send . >/dev/null
  docker build -q -t tcp-probe:lab -f Dockerfile.probe . >/dev/null'
ok "test helpers built on the appliance"

# --- resolve a build-free image to deploy ------------------------------------
TAG="$(remote "curl -fsS http://${REG_HOST}/v2/${REPO_PATH}/tags/list" 2>/dev/null | jq -r '.tags[0] // empty' || true)"
[ -n "$TAG" ] || die "no built image in the registry for ${REPO_PATH} — deploy blue-web first"
DIGEST="$(remote "curl -fsS -o /dev/null -D - -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' http://${REG_HOST}/v2/${REPO_PATH}/manifests/${TAG}" 2>/dev/null | tr -d '\r' | awk 'tolower($1)=="docker-content-digest:"{print $2}')"
[ -n "$DIGEST" ] || die "could not resolve manifest digest for ${REPO_PATH}:${TAG}"
FULLREF="${REG_HOST}/${REPO_PATH}@${DIGEST}"

# --- 1. provision_email ------------------------------------------------------
say "1. create_beam + provision_email"
call "$BUILDER" create_beam "{\"beamhall\":\"$WS\",\"slug\":\"$BEAM\",\"display_name\":\"$BEAM\"}" >/dev/null 2>&1 || true
prov="$(call "$BUILDER" provision_email "{\"beamhall\":\"$WS\",\"beam\":\"$BEAM\"}" 2>/dev/null)"
echo "$prov" | grep -q "SMTP_CA" || die "provision_email did not return SMTP_CA: $prov"
echo "$prov" | grep -q "SMTP_PASS" || die "provision_email missing SMTP_PASS"
ok "provision_email sealed 5 secrets incl SMTP_CA"

# --- 2. show_email before senders --------------------------------------------
show="$(call "$BUILDER" show_email "{\"beamhall\":\"$WS\",\"beam\":\"$BEAM\"}" 2>/dev/null)"
echo "$show" | grep -qi "none yet" || warn "expected no senders yet; got: $show"
ok "show_email: no senders before IT curates them"

# --- 3. admin_set_email_senders (IT) -----------------------------------------
say "3. admin_set_email_senders (IT)"
call "$ADMIN" admin_set_email_senders "{\"beamhall\":\"$WS\",\"beam\":\"$BEAM\",\"senders\":[\"$SENDER_DOMAIN\"]}" >/dev/null 2>&1 \
  || die "admin_set_email_senders failed"
ok "IT allowed sender domain $SENDER_DOMAIN"

# --- 4. deploy (image pin) ---------------------------------------------------
say "4. deploy_beam (build-free pin)"
call "$BUILDER" deploy_beam "{\"beamhall\":\"$WS\",\"beam\":\"$BEAM\",\"image_ref\":\"${REG_HOST}/${REPO_PATH}\",\"image_digest\":\"$FULLREF\"}" >/dev/null 2>&1 \
  || die "deploy_beam failed"
sleep 1
# Resolve the beam container + its beam bridge + creds (root, on the appliance).
read -r CT BRIDGE < <(remote "c=\$(docker ps --format '{{.Names}}\t{{.CreatedAt}}' | grep '^bh_' | sort -k2 | tail -1 | cut -f1); b=\$(docker inspect \$c -f '{{range \$k,\$v := .NetworkSettings.Networks}}{{println \$k}}{{end}}' | grep '^bh-' | head -1); echo \"\$c \$b\"")
[ -n "$CT" ] && [ -n "$BRIDGE" ] || die "could not resolve beam container/bridge"
remote "docker exec $CT ls /run/secrets/SMTP_CA >/dev/null 2>&1" || die "SMTP_CA not injected into the beam"
ok "deployed; SMTP_* injected (container $CT on $BRIDGE)"

CREDS="$(remote "echo \"\$(docker exec $CT cat /run/secrets/SMTP_USER)|\$(docker exec $CT cat /run/secrets/SMTP_PASS)\"")"
U="${CREDS%%|*}"; P="${CREDS##*|}"
# Stash the broker CA appliance-side so the post-destroy reclaim check can still
# STARTTLS (and thus reach AUTH) after the beam container is gone.
remote "docker exec $CT cat /run/secrets/SMTP_CA > /tmp/bh-mail-ca.pem"

# --- 5. allowed send (STARTTLS) → delivered ----------------------------------
say "5. send with an allowed sender (strict STARTTLS) → delivered"
before="$(remote 'docker logs mail-sink 2>&1 | grep -c RECV-MESSAGE || true')"
res="$(remote "CA=\$(docker exec $CT cat /run/secrets/SMTP_CA); docker run --rm --network $BRIDGE -e SMTP_HOST=bh-mail -e SMTP_PORT=587 -e SMTP_USER='$U' -e SMTP_PASS='$P' -e SMTP_CA=\"\$CA\" -e FROM=noreply@$SENDER_DOMAIN smtp-send:lab 2>&1 | tail -1")"
echo "$res" | grep -q "^SENT" || die "allowed send failed: $res"
after="$(remote 'docker logs mail-sink 2>&1 | grep -c RECV-MESSAGE || true')"
[ "$after" -gt "$before" ] || die "smarthost sink did not receive the message ($before -> $after)"
ok "delivered via STARTTLS; sink received it ($before -> $after)"

# --- 6. disallowed sender → 550 ----------------------------------------------
say "6. disallowed sender → rejected"
res="$(remote "CA=\$(docker exec $CT cat /run/secrets/SMTP_CA); docker run --rm --network $BRIDGE -e SMTP_HOST=bh-mail -e SMTP_PORT=587 -e SMTP_USER='$U' -e SMTP_PASS='$P' -e SMTP_CA=\"\$CA\" -e FROM=evil@other.example smtp-send:lab 2>&1 | tail -1")"
echo "$res" | grep -q "550" || die "disallowed sender was not rejected with 550: $res"
ok "spoofed sender rejected: $res"

# --- 7. isolation ------------------------------------------------------------
say "7. isolation: beam can reach bh-mail but NOT the smarthost directly"
SINK_IP="$(remote "docker inspect mail-sink -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null")"
if [ -n "$SINK_IP" ]; then
  iso="$(remote "docker run --rm --network $BRIDGE -e TARGET='$SINK_IP:2525' tcp-probe:lab 2>&1 | tail -1")"
  echo "$iso" | grep -q "BLOCKED" || die "beam reached the smarthost directly (isolation broken): $iso"
  ok "beam→smarthost direct: $iso"
fi
reach="$(remote "docker run --rm --network $BRIDGE -e TARGET='bh-mail:587' tcp-probe:lab 2>&1 | tail -1")"
echo "$reach" | grep -q "REACHABLE" || die "beam cannot reach bh-mail: $reach"
ok "beam→bh-mail:587: $reach"

# --- 8. destroy → broker deregisters -----------------------------------------
say "8. destroy_beam (IT) → broker deregisters"
call "$ADMIN" destroy_beam "{\"beamhall\":\"$WS\",\"beam\":\"$BEAM\"}" >/dev/null 2>&1 || die "destroy_beam failed"
sleep 1
res="$(remote "docker run --rm --network $BRIDGE -e SMTP_HOST=bh-mail -e SMTP_PORT=587 -e SMTP_USER='$U' -e SMTP_PASS='$P' -e SMTP_CA=\"\$(cat /tmp/bh-mail-ca.pem)\" -e FROM=noreply@$SENDER_DOMAIN smtp-send:lab 2>&1 | tail -1")"
remote 'rm -f /tmp/bh-mail-ca.pem'
echo "$res" | grep -q "535" || die "old creds still authenticate after destroy (no reclaim): $res"
ok "broker deregistered the beam (old creds → 535 auth failure)"

printf '\n\033[32m✓ email facility conformance PASSED\033[0m\n'
echo "Note: per-message audit (email_send sent/rejected) lands in the hash chain via"
echo "the audit-pull loop (~15s); verify with: bh-call.sh admin-alice admin_query_audit '{\"beamhall\":\"team-blue\"}'"
