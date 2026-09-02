package e2e

// Lab test for beam-to-beam (PLAN §5.15 stage 3): IT grants one app permission
// to call another app's tools ACROSS beamhalls; the calling workload reaches
// only the backplane relay (its bridge gateway, the one deliberate hole in
// the host guard), authenticates with its injected key, and the target — the
// stage-2 toolbox app, verifying the assertion for real — hears
// caller_type=beam from verified claims. The same run proves the tightened
// bridge: a sibling workload on the caller's own bridge no longer answers a
// direct dial, while the hall's Postgres broker still does.
//
//	BEAMHALL_DOCKER_IT=1 /tmp/e2e.test -test.v -test.run TestBeamToBeamEndToEnd
import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Beamhall/beamhall/internal/domain"
)

// ledgerAppJS is the TARGET: the stage-2 toolbox app with caller_type echoed —
// dependency-free Node, verifying the ES256 assertion against the injected
// JWKS on every request.
const ledgerAppJS = `
const http = require("http");
const crypto = require("crypto");
const fs = require("fs");

const conf = JSON.parse(fs.readFileSync("/run/beamhall/assertion.json", "utf8"));
const key = crypto.createPublicKey({ key: conf.jwks.keys[0], format: "jwk" });

function verify(req, wantTool) {
  const tok = req.headers["beamhall-assertion"];
  if (!tok) return null;
  const parts = tok.split(".");
  if (parts.length !== 3) return null;
  const data = Buffer.from(parts[0] + "." + parts[1]);
  const sig = Buffer.from(parts[2], "base64url");
  if (!crypto.verify("sha256", data, { key, dsaEncoding: "ieee-p1363" }, sig)) return null;
  const c = JSON.parse(Buffer.from(parts[1], "base64url").toString());
  if (c.iss !== conf.issuer || c.aud !== conf.audience) return null;
  if (!c.exp || c.exp < Date.now() / 1000) return null;
  if ((c.tool || "") !== wantTool) return null;
  return c;
}

const menu = { version: 1, tools: [
  { name: "whoami", description: "who is calling", input_schema: { type: "object" } },
  { name: "add", description: "add two numbers",
    input_schema: { type: "object", properties: { a: { type: "number" }, b: { type: "number" } } } },
]};

http.createServer((req, res) => {
  if (req.url === "/") { res.end(JSON.stringify({ ok: true, app: "ledger" })); return; }
  if (!req.url.startsWith("/.beamhall/tools")) { res.statusCode = 404; res.end("not found"); return; }
  const name = req.url === "/.beamhall/tools" ? "" : req.url.slice("/.beamhall/tools/".length);
  const claims = verify(req, name);
  if (!claims) { res.statusCode = 401; res.end("unauthorized"); return; }
  res.setHeader("content-type", "application/json");
  if (name === "") { res.end(JSON.stringify(menu)); return; }
  let body = "";
  req.on("data", (c) => body += c);
  req.on("end", () => {
    if (name === "whoami") {
      res.end(JSON.stringify({ ok: true, sub: claims.sub, caller_type: claims.caller_type,
        email: claims.email, channel: claims.channel, tool: claims.tool }));
    } else if (name === "add") {
      const a = JSON.parse(body || "{}");
      res.end(JSON.stringify({ ok: true, sum: (a.a || 0) + (a.b || 0) }));
    } else { res.statusCode = 404; res.end("no such tool"); }
  });
}).listen(process.env.PORT || 8080);
`

// callerAppJS is the SOURCE: on GET /c2c-report it exercises the relay from
// inside the workload — c2c.json + key, peers list, menu, invoke — and probes
// the tightened bridge (a sibling from its /etc/hosts snapshot must not
// answer; the Postgres broker must).
const callerAppJS = `
const http = require("http"), fs = require("fs"), net = require("net");

function readConf() {
  try {
    const conf = JSON.parse(fs.readFileSync("/run/beamhall/c2c.json", "utf8"));
    conf.key = fs.readFileSync(conf.key_file, "utf8").trim();
    return conf;
  } catch (e) { return null; }
}
function relay(conf, method, path, body) {
  return new Promise((resolve) => {
    const u = new URL(conf.endpoint + path);
    const r = http.request({ host: u.hostname, port: u.port, path: u.pathname, method,
      headers: { "Beamhall-C2C-Key": conf.key, "content-type": "application/json" }, timeout: 8000 },
      res => { let b = ""; res.on("data", c => b += c); res.on("end", () => {
        let parsed = null; try { parsed = JSON.parse(b); } catch (e) {}
        resolve({ status: res.statusCode, json: parsed, raw: b.slice(0, 200) });
      }); });
    r.on("timeout", () => r.destroy(new Error("timeout")));
    r.on("error", e => resolve({ status: 0, raw: String(e.code || e.message) }));
    if (body) r.write(body);
    r.end();
  });
}
function tcpProbe(host, port) {
  // Short and parallel-friendly: a DROPPED SYN answers nothing, so the
  // timeout IS the blocked signal — and the whole report must finish inside
  // the harness curl's 3s budget.
  return new Promise((resolve) => {
    const s = net.connect({ host, port, timeout: 1500 });
    s.on("connect", () => { s.destroy(); resolve("open"); });
    s.on("timeout", () => { s.destroy(); resolve("blocked (timeout)"); });
    s.on("error", (e) => resolve("blocked (" + (e.code || e.message) + ")"));
  });
}
function hostsNames() {
  // Same-network peers snapshotted into /etc/hosts at deploy: workload
  // containers are bh_<beam>-<hex>; the Postgres broker's name varies by
  // install, so find it by substring instead of hardcoding.
  const out = { siblings: [], postgres: null };
  for (const line of fs.readFileSync("/etc/hosts", "utf8").split("\n")) {
    const f = line.trim().split(/\s+/);
    if (f.length < 2) continue;
    if (f[1].startsWith("bh_")) out.siblings.push(f[1]);
    else if (f[1].includes("postgres")) out.postgres = f[1];
  }
  return out;
}

http.createServer(async (req, res) => {
  if (req.url === "/") { res.end(JSON.stringify({ ok: true, app: "caller" })); return; }
  if (req.url !== "/c2c-report") { res.statusCode = 404; res.end("not found"); return; }
  const report = { has_c2c_json: false, peers: [], menu_tools: [] };
  const known = hostsNames();
  const probes = Promise.all([
    known.siblings.length ? tcpProbe(known.siblings[0], 8080) : Promise.resolve("no-sibling-known"),
    known.postgres ? tcpProbe(known.postgres, 5432) : Promise.resolve("no-broker-known"),
  ]);
  const conf = readConf();
  if (conf) {
    report.has_c2c_json = true;
    const peers = await relay(conf, "GET", "/c2c/v1/peers");
    report.peers_status = peers.status;
    if (peers.json && peers.json.peers) {
      for (const p of peers.json.peers) report.peers.push(p.workspace + "/" + p.app);
    }
    const menu = await relay(conf, "GET", "/c2c/v1/peer/fort/ledger/tools");
    report.menu_status = menu.status;
    if (menu.json && menu.json.tools) {
      for (const tl of menu.json.tools) report.menu_tools.push(tl.name);
    }
    const who = await relay(conf, "POST", "/c2c/v1/peer/fort/ledger/tools/whoami", "{}");
    report.whoami_status = who.status;
    report.whoami = who.json;
    const add = await relay(conf, "POST", "/c2c/v1/peer/fort/ledger/tools/add", JSON.stringify({ a: 3, b: 4 }));
    report.add_status = add.status;
    report.add_sum = add.json && add.json.sum;
  }
  const dials = await probes;
  report.sibling_dial = dials[0];
  report.postgres_dial = dials[1];
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify(report));
}).listen(process.env.PORT || 8080);
`

type c2cReport struct {
	HasC2CJSON   bool     `json:"has_c2c_json"`
	Peers        []string `json:"peers"`
	PeersStatus  int      `json:"peers_status"`
	MenuTools    []string `json:"menu_tools"`
	MenuStatus   int      `json:"menu_status"`
	WhoamiStatus int      `json:"whoami_status"`
	Whoami       struct {
		Sub        string `json:"sub"`
		CallerType string `json:"caller_type"`
		Email      string `json:"email"`
		Channel    string `json:"channel"`
	} `json:"whoami"`
	AddStatus    int     `json:"add_status"`
	AddSum       float64 `json:"add_sum"`
	SiblingDial  string  `json:"sibling_dial"`
	PostgresDial string  `json:"postgres_dial"`
}

func TestBeamToBeamEndToEnd(t *testing.T) {
	if os.Getenv("BEAMHALL_DOCKER_IT") != "1" {
		t.Skip("set BEAMHALL_DOCKER_IT=1 to run the beam-to-beam suite")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	a := launchAppliance(t, ctx)
	it := a.connect("e2e-it", "beamhalls:read beams:write beams:deploy beams:operate beams:promote admin:it", nil)
	builder := a.connect("e2e-builder", "beamhalls:read beams:write beams:deploy beams:operate resources:write", nil)

	// --- the TARGET: fort/ledger, deployed and promoted by IT (cross-hall) --
	callTool(ctx, t, it, "create_beam", map[string]any{"beamhall": "fort", "slug": "ledger"}, false)
	callTool(ctx, t, it, "deploy_beam", map[string]any{
		"beamhall": "fort", "beam": "ledger",
		"source_tarball": tarGz(t, map[string]string{
			"package.json": `{ "name": "ledger", "version": "1.0.0", "main": "app.js", "scripts": { "start": "node app.js" } }`,
			"app.js":       ledgerAppJS,
		})}, false)
	res, _ := callTool(ctx, t, it, "promote_to_live", map[string]any{"beamhall": "fort", "beam": "ledger"}, false)
	_ = res

	// --- a sibling on the caller's own bridge (buddy), with a database so
	// the Postgres broker attaches to the e2e bridge --------------------------
	callTool(ctx, t, builder, "create_beam", map[string]any{"beamhall": "e2e", "slug": "buddy"}, false)
	callTool(ctx, t, builder, "create_database", map[string]any{"beamhall": "e2e", "beam": "buddy", "name": "main"}, false)
	callTool(ctx, t, builder, "deploy_beam", map[string]any{
		"beamhall": "e2e", "beam": "buddy",
		"source_tarball": tarGz(t, map[string]string{
			"package.json": `{ "name": "buddy", "version": "1.0.0", "main": "app.js", "scripts": { "start": "node app.js" } }`,
			"app.js":       `require("http").createServer((q, s) => s.end(JSON.stringify({ok:true}))).listen(process.env.PORT || 8080);`,
		})}, false)

	// --- grant BEFORE the caller's deploy, so one deploy carries the key ----
	callTool(ctx, t, builder, "create_beam", map[string]any{"beamhall": "e2e", "slug": "caller"}, false)
	_, txt := callTool(ctx, t, it, "admin_set_beam_peers", map[string]any{
		"beamhall": "e2e", "beam": "caller", "peers": []any{"fort/ledger"}}, false)
	if !strings.Contains(txt, "deploy_beam ONCE") || !strings.Contains(txt, "fort/ledger") {
		t.Fatalf("grant copy must front-load the redeploy: %q", txt)
	}

	res, _ = callTool(ctx, t, builder, "deploy_beam", map[string]any{
		"beamhall": "e2e", "beam": "caller",
		"source_tarball": tarGz(t, map[string]string{
			"package.json": `{ "name": "caller", "version": "1.0.0", "main": "app.js", "scripts": { "start": "node app.js" } }`,
			"app.js":       callerAppJS,
		})}, false)
	callerURL := structuredURL(t, res)
	curlHost(t, callerURL, 200) // wait for the route

	// --- the in-workload proof ----------------------------------------------
	status, body := curlPath(t, callerURL, "/c2c-report")
	if status != 200 {
		t.Fatalf("/c2c-report: %d %s", status, body)
	}
	var rep c2cReport
	if err := json.Unmarshal([]byte(body), &rep); err != nil {
		t.Fatalf("report is not JSON: %v\n%s", err, body)
	}
	if !rep.HasC2CJSON {
		t.Fatalf("the workload found no /run/beamhall/c2c.json:\n%s", body)
	}
	if len(rep.Peers) != 1 || rep.Peers[0] != "fort/ledger" {
		t.Fatalf("peers = %v", rep.Peers)
	}
	if rep.MenuStatus != 200 || !strings.Contains(strings.Join(rep.MenuTools, ","), "whoami") {
		t.Fatalf("menu: %d %v", rep.MenuStatus, rep.MenuTools)
	}
	if rep.WhoamiStatus != 200 || rep.Whoami.CallerType != "beam" || rep.Whoami.Channel != "live" ||
		rep.Whoami.Sub == "" || rep.Whoami.Email != "" {
		t.Fatalf("whoami claims (verified in-app): %+v (status %d)", rep.Whoami, rep.WhoamiStatus)
	}
	if rep.AddStatus != 200 || rep.AddSum != 7 {
		t.Fatalf("add: %d sum=%v", rep.AddStatus, rep.AddSum)
	}
	// The tightened bridge: the sibling's own port no longer answers a direct
	// dial (its name came from the caller's /etc/hosts snapshot), while the
	// hall's Postgres broker still does.
	if !strings.HasPrefix(rep.SiblingDial, "blocked") {
		t.Fatalf("sibling direct dial must be blocked, got %q", rep.SiblingDial)
	}
	if rep.PostgresDial != "open" {
		t.Fatalf("the Postgres broker must stay reachable, got %q", rep.PostgresDial)
	}
	t.Logf("in-workload: relay menu+invoke OK (caller_type=beam, sub=%s), sibling %q, broker %q",
		rep.Whoami.Sub, rep.SiblingDial, rep.PostgresDial)

	// --- builder visibility --------------------------------------------------
	_, txt = callTool(ctx, t, builder, "show_beam_peers", map[string]any{"beamhall": "e2e", "beam": "caller"}, false)
	if !strings.Contains(txt, "fort/ledger") || !strings.Contains(txt, "holds the relay credential") {
		t.Fatalf("show_beam_peers = %q", txt)
	}

	// --- revocation bites on the next call ----------------------------------
	callTool(ctx, t, it, "admin_set_beam_peers", map[string]any{
		"beamhall": "e2e", "beam": "caller", "clear": true}, false)
	status, body = curlPath(t, callerURL, "/c2c-report")
	if status != 200 {
		t.Fatalf("/c2c-report after revoke: %d %s", status, body)
	}
	var rev c2cReport
	if err := json.Unmarshal([]byte(body), &rev); err != nil {
		t.Fatalf("report is not JSON: %v\n%s", err, body)
	}
	if len(rev.Peers) != 0 || rev.WhoamiStatus == 200 || rev.MenuStatus == 200 {
		t.Fatalf("revocation did not bite: peers=%v menu=%d whoami=%d", rev.Peers, rev.MenuStatus, rev.WhoamiStatus)
	}

	// --- audit shape ---------------------------------------------------------
	a.stop()
	st, issues, events := openAndVerifyAudit(t, a.dataDir)
	defer st.Close()
	if len(issues) > 0 {
		t.Fatalf("audit chain violations: %+v", issues)
	}
	var allows, denies, grants int
	for _, ev := range events {
		switch ev.Event.Action {
		case "use_peer_tool":
			if !strings.HasPrefix(string(ev.Event.ActorID), "beam:") {
				t.Errorf("use_peer_tool actor = %q, want beam:<id>", ev.Event.ActorID)
			}
			if ev.Event.Decision == domain.DecisionAllow {
				allows++
			} else {
				denies++
			}
		case "admin_set_beam_peers":
			grants++
		}
	}
	if allows < 3 || denies < 2 || grants < 2 {
		t.Fatalf("audit shape: %d allows (want >=3: menu+whoami+add), %d denies (want >=2: post-revoke), %d grant events (want 2)", allows, denies, grants)
	}
	t.Logf("audit chain verified: %d relayed allows, %d denies, %d grant writes", allows, denies, grants)
}
