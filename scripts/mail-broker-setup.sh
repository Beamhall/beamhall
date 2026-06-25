#!/usr/bin/env bash
# Stand up the shared bh-mail email broker (PLAN §5.11 facility brokers / §5.12)
# on a Beamhall appliance. Run this ON the appliance (root). It is the bootstrap
# wiring for the email facility — the production installer will fold this in; for
# now it reproduces the lab topology from the installed beamhalld binary.
#
# The broker is the beamhalld binary in `mail-relay` mode, run as a container
# attached to a dedicated egress network (for its outbound to the smarthost) and,
# at provision time, to each beam bridge (beamhalld does that). Beams reach it as
# `bh-mail:587` (Docker DNS) — never the host, no beam-bridge egress hole. The
# control port is published on host loopback for beamhalld to drive.
#
# Usage:
#   mail-broker-setup.sh --smarthost host:port [--user U --pass P] [--lab-sink]
#   --lab-sink   also run a local SMTP sink (a test stand-in) and point the
#                broker at it instead of --smarthost (for lab verification).
#
# Prints the BEAMHALL_MAIL_* block to add to /etc/beamhall/beamhall.env, then
# restart beamhalld.
set -euo pipefail

BEAMHALLD="${BEAMHALLD:-/usr/local/bin/beamhalld}"
WORKDIR="${WORKDIR:-/root/lab-mail}"
SMARTHOST=""; SMUSER=""; SMPASS=""; LAB_SINK=0
while [ $# -gt 0 ]; do
  case "$1" in
    --smarthost) SMARTHOST="$2"; shift 2;;
    --user) SMUSER="$2"; shift 2;;
    --pass) SMPASS="$2"; shift 2;;
    --lab-sink) LAB_SINK=1; shift;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

[ -x "$BEAMHALLD" ] || { echo "beamhalld not found at $BEAMHALLD" >&2; exit 1; }
command -v docker >/dev/null || { echo "docker required" >&2; exit 1; }
mkdir -p "$WORKDIR"; cd "$WORKDIR"

TOKEN="$(openssl rand -hex 24)"

# --- broker image: the beamhalld binary in mail-relay mode (scratch) ----------
cp -f "$BEAMHALLD" "$WORKDIR/beamhalld"
cat > Dockerfile.relay <<EOF
FROM scratch
COPY beamhalld /beamhalld
ENTRYPOINT ["/beamhalld","mail-relay"]
EOF
docker build -q -t bh-mail-img:lab -f Dockerfile.relay . >/dev/null
echo "✓ built bh-mail image"

docker network create mail-egress-net 2>/dev/null || true

# --- optional lab sink (test stand-in for the external smarthost) -------------
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
  cat > Dockerfile.sink <<EOF
FROM scratch
COPY mail-sink /mail-sink
ENTRYPOINT ["/mail-sink"]
EOF
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o mail-sink sink.go 2>/dev/null \
    || docker run --rm -v "$WORKDIR":/w -w /w golang:1.26 sh -c 'CGO_ENABLED=0 go build -o mail-sink sink.go'
  docker build -q -t mail-sink:lab -f Dockerfile.sink . >/dev/null
  docker rm -f mail-sink >/dev/null 2>&1 || true
  docker run -d --name mail-sink --network mail-egress-net --restart unless-stopped mail-sink:lab >/dev/null
  SMARTHOST="mail-sink:2525"; SMUSER=""; SMPASS=""
  echo "✓ lab sink running (smarthost=$SMARTHOST)"
fi

[ -n "$SMARTHOST" ] || { echo "need --smarthost host:port (or --lab-sink)" >&2; exit 2; }

# --- broker container ---------------------------------------------------------
docker rm -f bh-mail >/dev/null 2>&1 || true
docker volume create bh-mail-tls >/dev/null
docker run -d --name bh-mail --network mail-egress-net --restart unless-stopped \
  -p 127.0.0.1:2526:2526 -v bh-mail-tls:/tls \
  -e BEAMHALL_MAIL_CONTROL_TOKEN="$TOKEN" -e BEAMHALL_MAIL_SMTP_ADDR=:587 \
  -e BEAMHALL_MAIL_CONTROL_ADDR=:2526 -e BEAMHALL_MAIL_BEAM_HOST=bh-mail \
  -e BEAMHALL_MAIL_TLS_DIR=/tls bh-mail-img:lab >/dev/null
echo "✓ bh-mail broker running (control on 127.0.0.1:2526, STARTTLS cert in volume bh-mail-tls)"

cat <<EOF

Add to /etc/beamhall/beamhall.env, then: systemctl restart beamhalld

# --- email facility ---
BEAMHALL_MAIL_CONTROL_URL=http://127.0.0.1:2526
BEAMHALL_MAIL_CONTROL_TOKEN=$TOKEN
BEAMHALL_MAIL_BEAM_HOST=bh-mail
BEAMHALL_MAIL_BEAM_PORT=587
BEAMHALL_MAIL_SMARTHOST=$SMARTHOST
$( [ -n "$SMUSER" ] && echo "BEAMHALL_MAIL_USERNAME=$SMUSER" )
$( [ -n "$SMPASS" ] && echo "BEAMHALL_MAIL_PASSWORD=$SMPASS" )
$( [ "$LAB_SINK" = 1 ] && echo "BEAMHALL_MAIL_STARTTLS=off  # the lab sink is plaintext; real providers use STARTTLS (default on)" )
EOF
