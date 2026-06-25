#!/usr/bin/env bash
# Stand up the shared bh-mail email broker (PLAN §5.11 facility brokers / §5.12)
# on a Beamhall appliance. Run ON the appliance (root). This is the MINIMUM to
# make the email facility configurable — it does NOT set a provider. An IT admin
# turns email on later, at runtime, with the MCP tool admin_set_email_provider
# (the smarthost + credential are held + persisted by the broker, never here).
#
# `install.sh` already does this on a fresh install; use this script to (re)stand
# up the broker on a hand-wired appliance, or with --lab-sink to add a local SMTP
# capture sink for testing (then point admin_set_email_provider at mail-sink:2525).
#
# Usage:  mail-broker-setup.sh [--lab-sink]
#
# Prints the BEAMHALL_MAIL_* plumbing block to add to /etc/beamhall/beamhall.env
# (control URL/token + beam host — no provider), then restart beamhalld.
set -euo pipefail

BEAMHALLD="${BEAMHALLD:-/usr/local/bin/beamhalld}"
WORKDIR="${WORKDIR:-/root/lab-mail}"
LAB_SINK=0
while [ $# -gt 0 ]; do
  case "$1" in
    --lab-sink) LAB_SINK=1; shift;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

[ -x "$BEAMHALLD" ] || { echo "beamhalld not found at $BEAMHALLD" >&2; exit 1; }
command -v docker >/dev/null || { echo "docker required" >&2; exit 1; }
mkdir -p "$WORKDIR"; cd "$WORKDIR"

[ -s /etc/beamhall/mail-control.token ] 2>/dev/null || { mkdir -p /etc/beamhall; (umask 077; openssl rand -hex 24 > /etc/beamhall/mail-control.token); } 2>/dev/null || true
TOKEN="$(cat /etc/beamhall/mail-control.token 2>/dev/null || openssl rand -hex 24)"

# --- broker image: the beamhalld binary in mail-relay mode (scratch) ----------
cp -f "$BEAMHALLD" "$WORKDIR/beamhalld"
printf 'FROM scratch\nCOPY beamhalld /beamhalld\nENTRYPOINT ["/beamhalld","mail-relay"]\n' > Dockerfile.relay
docker build -q -t bh-mail-img:lab -f Dockerfile.relay . >/dev/null
echo "✓ built bh-mail image"

docker network create mail-egress-net 2>/dev/null || true
docker volume create bh-mail-tls >/dev/null 2>&1 || true

# --- optional lab sink (a test capture target for admin_set_email_provider) ---
if [ "$LAB_SINK" = 1 ]; then
  cat > sink.go <<'GO'
package main
import ("bufio";"log";"net";"os";"strings")
func main(){ a:=os.Getenv("SINK_ADDR"); if a==""{a=":2525"}; ln,e:=net.Listen("tcp",a); if e!=nil{log.Fatal(e)}; log.Printf("sink on %s",a); for{c,e:=ln.Accept(); if e!=nil{continue}; go h(c)} }
func h(c net.Conn){ defer c.Close(); r:=bufio.NewReader(c); w:=bufio.NewWriter(c); rep:=func(s string){w.WriteString(s+"\r\n");w.Flush()}; rep("220 sink"); var f,t string
 for{ l,e:=r.ReadString('\n'); if e!=nil{return}; u:=strings.ToUpper(strings.TrimRight(l,"\r\n"))
  switch{ case strings.HasPrefix(u,"EHLO"),strings.HasPrefix(u,"HELO"): rep("250 sink")
   case strings.HasPrefix(u,"MAIL FROM"): f=strings.TrimRight(l,"\r\n"); rep("250 ok")
   case strings.HasPrefix(u,"RCPT TO"): t=strings.TrimRight(l,"\r\n"); rep("250 ok")
   case u=="DATA": rep("354 go"); n:=0; for{d,e:=r.ReadString('\n'); if e!=nil{return}; if d==".\r\n"||d==".\n"{break}; n+=len(d)}; log.Printf("RECV-MESSAGE from=%q rcpt=%q bytes=%d",f,t,n); rep("250 queued")
   case u=="RSET": f,t="",""; rep("250 ok"); case u=="QUIT": rep("221 bye"); return; default: rep("250 ok") } } }
GO
  printf 'FROM scratch\nCOPY mail-sink /mail-sink\nENTRYPOINT ["/mail-sink"]\n' > Dockerfile.sink
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o mail-sink sink.go 2>/dev/null \
    || docker run --rm -v "$WORKDIR":/w -w /w golang:1.26 sh -c 'CGO_ENABLED=0 go build -o mail-sink sink.go'
  docker build -q -t mail-sink:lab -f Dockerfile.sink . >/dev/null
  docker rm -f mail-sink >/dev/null 2>&1 || true
  docker run -d --name mail-sink --network mail-egress-net --restart unless-stopped mail-sink:lab >/dev/null
  echo "✓ lab sink running on mail-egress-net (point admin_set_email_provider at mail-sink:2525, starttls=false)"
fi

# --- broker container (no provider — set via MCP) -----------------------------
docker rm -f bh-mail >/dev/null 2>&1 || true
docker run -d --name bh-mail --network mail-egress-net --restart unless-stopped \
  -p 127.0.0.1:2526:2526 -v bh-mail-tls:/tls \
  -e BEAMHALL_MAIL_CONTROL_TOKEN="$TOKEN" -e BEAMHALL_MAIL_SMTP_ADDR=:587 \
  -e BEAMHALL_MAIL_CONTROL_ADDR=:2526 -e BEAMHALL_MAIL_BEAM_HOST=bh-mail \
  -e BEAMHALL_MAIL_TLS_DIR=/tls bh-mail-img:lab >/dev/null
echo "✓ bh-mail broker running (control on 127.0.0.1:2526; provider set later via admin_set_email_provider)"

cat <<EOF

Add to /etc/beamhall/beamhall.env (if not already present), then: systemctl restart beamhalld

# --- email broker (provision_email) ---
BEAMHALL_MAIL_CONTROL_URL=http://127.0.0.1:2526
BEAMHALL_MAIL_CONTROL_TOKEN=$TOKEN
BEAMHALL_MAIL_BEAM_HOST=bh-mail

Then an IT admin turns email ON over MCP:
  admin_set_email_provider {"smarthost":"smtp.yourprovider.com:587","username":"...","password":"..."}
EOF
