#!/usr/bin/env python3
"""Beamhall per-identity MCP proxy (Python stdlib only).

A persistent **stdio MCP server** for Claude Code that bridges to Beamhall's
Streamable-HTTP MCP endpoint as ONE authenticated identity. Claude Code spawns
one of these per persona (see ../../.mcp.json); each mints and auto-refreshes its
own OAuth token (ROPC against the bundled Keycloak), so every persona reaches
Beamhall as a distinct registered identity — which is what makes the
environment-isolation and four-eyes conformance tests meaningful (the appliance
enforces both server-side, keyed on the token's resolved actor).

It is a thin evolution of the one-shot ../../  (../bhmcp.py) pilot driver: it reuses
the same ROPC mint, the same Streamable-HTTP handshake, and the same SSE/JSON
response parsing, wrapped in a stdin/stdout JSON-RPC pump with token refresh.

Configuration (all via env, set per-server in .mcp.json — NO secrets here):
  BH_USER        IdP username / subject (e.g. admin-alice)            [required]
  BH_CLIENT_ID   ROPC client (beamhall-admin-agent | beamhall-agent)  [required]
  BH_SCOPE       space-separated capability scopes (audience included)[required]
  BH_ISSUER      https://idp.beamhall.internal/realms/beamhall        [required]
  BH_MCP_URL     https://beamhall.internal/mcp                        [required]
  BH_CA          path to the gateway internal CA cert                 [required]
  BH_ENV_FILE    path to the gitignored secrets file (default: ./.env next to this script)
  BH_PASS        password override (else looked up in BH_ENV_FILE by BH_USER)
  BH_CLIENT_SECRET  optional confidential-client secret (public clients need none)

The secrets file (BH_ENV_FILE) is plain `username=password` lines, gitignored.
Diagnostics go to stderr; stdout carries ONLY the MCP protocol.
"""
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

PROTOCOL_VERSION = "2025-06-18"


def log(*a):
    print("[bh-mcp-proxy:%s]" % os.environ.get("BH_USER", "?"), *a, file=sys.stderr, flush=True)


def _require(name):
    v = os.environ.get(name)
    if not v:
        log("FATAL: missing required env", name)
        sys.exit(2)
    return v


def _load_secret(env_file, user):
    """Resolve the identity's password: BH_PASS wins, else a `user=pass` line."""
    if os.environ.get("BH_PASS"):
        return os.environ["BH_PASS"]
    try:
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                if k.strip() == user:
                    return v.strip()
    except FileNotFoundError:
        log("secrets file not found yet:", env_file, "(run provision.sh)")
    return None


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
USER = _require("BH_USER")
CLIENT_ID = _require("BH_CLIENT_ID")
SCOPE = _require("BH_SCOPE")
ISSUER = _require("BH_ISSUER")
MCP_URL = _require("BH_MCP_URL")
CA = _require("BH_CA")
ENV_FILE = os.environ.get("BH_ENV_FILE") or os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
CLIENT_SECRET = os.environ.get("BH_CLIENT_SECRET")
CTX = ssl.create_default_context(cafile=CA)


def _http(url, data=None, headers=None):
    req = urllib.request.Request(url, data=data, headers=headers or {},
                                 method="POST" if data is not None else "GET")
    return urllib.request.urlopen(req, context=CTX, timeout=600)


# ---------------------------------------------------------------------------
# Token lifecycle — ROPC mint with re-mint near expiry / on 401. We hold the
# password, so a fresh password grant is simpler and more robust than juggling
# refresh tokens; access tokens are ~1h, re-minting is cheap.
# ---------------------------------------------------------------------------
class TokenSource:
    def __init__(self):
        self.access = None
        self.exp = 0.0

    def mint(self):
        pw = _load_secret(ENV_FILE, USER)
        if not pw:
            raise RuntimeError("no password for %s (set BH_PASS or add to %s)" % (USER, ENV_FILE))
        form = {"grant_type": "password", "client_id": CLIENT_ID,
                "username": USER, "password": pw, "scope": "openid " + SCOPE}
        if CLIENT_SECRET:
            form["client_secret"] = CLIENT_SECRET
        r = _http(ISSUER + "/protocol/openid-connect/token",
                  data=urllib.parse.urlencode(form).encode(),
                  headers={"Content-Type": "application/x-www-form-urlencoded"})
        tok = json.load(r)
        self.access = tok["access_token"]
        self.exp = time.time() + max(30, int(tok.get("expires_in", 300)) - 60)
        log("minted token for", USER, "(expires in ~%ds)" % int(self.exp - time.time()))
        return self.access

    def bearer(self):
        if not self.access or time.time() >= self.exp:
            self.mint()
        return self.access

    def force_remint(self):
        self.access = None
        return self.bearer()


# ---------------------------------------------------------------------------
# Upstream Streamable-HTTP MCP client (mirrors ../bhmcp.py Client + _parse)
# ---------------------------------------------------------------------------
def _parse(resp, want_id):
    ctype = resp.headers.get("Content-Type", "")
    sid = resp.headers.get("Mcp-Session-Id")
    raw = resp.read().decode()
    objs = []
    if "text/event-stream" in ctype:
        for line in raw.splitlines():
            if line.startswith("data:"):
                try:
                    objs.append(json.loads(line[5:].strip()))
                except Exception:
                    pass
    elif raw.strip():
        objs.append(json.loads(raw))
    for o in objs:
        if o.get("id") == want_id:
            return o, sid
    return (objs[-1] if objs else None), sid


class Upstream:
    def __init__(self, ts):
        self.ts = ts
        self.sid = None
        self._id = 0

    def _headers(self):
        h = {"Authorization": "Bearer " + self.ts.bearer(),
             "Content-Type": "application/json",
             "Accept": "application/json, text/event-stream"}
        if self.sid:
            h["Mcp-Session-Id"] = self.sid
        return h

    def _post(self, body, want_id, notif):
        resp = _http(MCP_URL, data=json.dumps(body).encode(), headers=self._headers())
        if notif:
            resp.read()
            return None
        obj, sid = _parse(resp, want_id)
        if sid and not self.sid:
            self.sid = sid
        return obj

    def call(self, method, params=None, notif=False):
        """One request/response (or fire-and-forget notification) to Beamhall,
        with a single re-auth+resession retry on a 401."""
        body = {"jsonrpc": "2.0", "method": method}
        want = None
        if not notif:
            self._id += 1
            want = self._id
            body["id"] = want
        if params is not None:
            body["params"] = params
        try:
            return self._post(body, want, notif)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                log("upstream", e.code, "— re-minting + re-handshaking")
                self.ts.force_remint()
                self.sid = None
                self._handshake()
                return self._post(body, want, notif)
            raise

    def _handshake(self):
        body = {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
            "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
            "clientInfo": {"name": "beamhall-conformance-proxy", "version": "0.1.0"}}}
        resp = _http(MCP_URL, data=json.dumps(body).encode(), headers=self._headers())
        obj, sid = _parse(resp, 0)
        if sid:
            self.sid = sid
        # notifications/initialized (no reply)
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"}, None, True)
        return obj

    def initialize(self):
        return self._handshake()


# ---------------------------------------------------------------------------
# stdio JSON-RPC pump
# ---------------------------------------------------------------------------
def _err(mid, code, message):
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def _synthetic_init():
    # Lets Claude Code register the server even before provisioning/connectivity;
    # tools/list and tools/call then surface the real upstream error per call.
    return {"protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": True}},
            "serverInfo": {"name": "beamhall-proxy:%s" % USER, "version": "0.1.0"}}


def main():
    ts = TokenSource()
    up = Upstream(ts)
    out = sys.stdout

    def emit(obj):
        if obj is None:
            return
        out.write(json.dumps(obj) + "\n")
        out.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception as e:
            emit(_err(None, -32700, "parse error: %s" % e))
            continue

        method = msg.get("method")
        mid = msg.get("id")
        try:
            if method == "initialize":
                try:
                    init = up.initialize()
                    result = init.get("result") if init else None
                    if not result:
                        result = _synthetic_init()
                except Exception as e:
                    log("upstream initialize failed (%s) — serving synthetic init" % e)
                    result = _synthetic_init()
                emit({"jsonrpc": "2.0", "id": mid, "result": result})
            elif method == "notifications/initialized":
                # already sent to Beamhall during initialize(); swallow.
                continue
            elif mid is None:
                # client -> server notification: forward, no reply expected.
                up.call(method, msg.get("params"), notif=True)
            else:
                obj = up.call(method, msg.get("params"))
                if obj is None:
                    emit(_err(mid, -32603, "no response from Beamhall"))
                elif "error" in obj:
                    emit({"jsonrpc": "2.0", "id": mid, "error": obj["error"]})
                else:
                    emit({"jsonrpc": "2.0", "id": mid, "result": obj.get("result", {})})
        except urllib.error.HTTPError as e:
            emit(_err(mid, -32001, "Beamhall HTTP %s: %s" % (e.code, e.reason)))
        except Exception as e:
            emit(_err(mid, -32001, "proxy error: %s" % e))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
