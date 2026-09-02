package e2e

// Lab test for app tools (PLAN §5.15 stage 2): a builder ships an app that
// serves the app-tools contract and VERIFIES the backplane-signed assertion
// for real (ES256 via the injected /run/beamhall/assertion.json — no
// dependencies, Node's crypto verifies raw r||s signatures with
// dsaEncoding ieee-p1363). The builder tests it on the preview channel with
// try_beam_tool, IT promotes + publishes, and a user's own agent calls it
// with use_app — the app hears who the caller is from verified claims. The
// contract endpoints sit on the app's public origin, so the test also proves
// a request WITHOUT an assertion is refused by the app itself.
//
//	BEAMHALL_DOCKER_IT=1 /tmp/e2e.test -test.v -test.run TestAppToolsEndToEnd
import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

const toolboxAppJS = `
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
  if (req.url === "/") { res.end(JSON.stringify({ ok: true, app: "toolbox" })); return; }
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
      res.end(JSON.stringify({ ok: true, sub: claims.sub, email: claims.email,
        groups: claims.groups, channel: claims.channel, tool: claims.tool }));
    } else if (name === "add") {
      const a = JSON.parse(body || "{}");
      res.end(JSON.stringify({ ok: true, sum: (a.a || 0) + (a.b || 0) }));
    } else { res.statusCode = 404; res.end("no such tool"); }
  });
}).listen(process.env.PORT || 8080);
`

func TestAppToolsEndToEnd(t *testing.T) {
	if os.Getenv("BEAMHALL_DOCKER_IT") != "1" {
		t.Skip("set BEAMHALL_DOCKER_IT=1 to run the app-tools suite")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	a := launchAppliance(t, ctx)
	it := a.connect("e2e-it", "beams:promote admin:it", nil)
	builder := a.connect("e2e-builder", "beamhalls:read beams:write beams:deploy beams:operate", nil)

	// 1. Builder ships the tool-serving app.
	callTool(ctx, t, builder, "create_beam", map[string]any{
		"beamhall": "e2e", "slug": "toolbox", "runtime_hint": "node",
		"description": "Does things for employees"}, false)
	app := tarGz(t, map[string]string{
		"package.json": `{ "name": "toolbox", "version": "1.0.0", "main": "app.js", "scripts": { "start": "node app.js" } }`,
		"app.js":       toolboxAppJS,
	})
	callTool(ctx, t, builder, "deploy_beam",
		map[string]any{"beamhall": "e2e", "beam": "toolbox", "source_tarball": app}, false)

	// 2. The builder tests the tools on the PREVIEW channel, pre-promotion.
	_, txt := callTool(ctx, t, builder, "try_beam_tool",
		map[string]any{"beamhall": "e2e", "beam": "toolbox"}, false)
	if !strings.Contains(txt, "whoami") || !strings.Contains(txt, "PREVIEW") {
		t.Fatalf("try_beam_tool menu = %q", txt)
	}
	_, txt = callTool(ctx, t, builder, "try_beam_tool", map[string]any{
		"beamhall": "e2e", "beam": "toolbox", "tool": "whoami"}, false)
	if !strings.Contains(txt, `"channel":"preview"`) || !strings.Contains(txt, `"ok":true`) {
		t.Fatalf("preview whoami = %q (the app only answers a VERIFIED preview assertion)", txt)
	}

	// 3. IT promotes; erin's first contact auto-registers her (with a groups
	// claim, so the group reaches the app later); IT publishes to her.
	itRes, _ := callTool(ctx, t, it, "promote_to_live",
		map[string]any{"beamhall": "e2e", "beam": "toolbox"}, false)
	liveURL := structuredURL(t, itRes)
	erin := a.connectAs("e2e-erin", "beams:use", []string{"finance"}, nil)
	callTool(ctx, t, erin, "list_apps", nil, false)
	res, _ := callTool(ctx, t, it, "admin_list_identities", nil, false)
	idents, _ := res.StructuredContent.(map[string]any)
	var erinID string
	if list, ok := idents["identities"].([]any); ok {
		for _, raw := range list {
			m, _ := raw.(map[string]any)
			if m["subject"] == "e2e-erin" {
				erinID, _ = m["identity_id"].(string)
			}
		}
	}
	if erinID == "" {
		t.Fatalf("e2e-erin was not auto-registered: %#v", res.StructuredContent)
	}
	callTool(ctx, t, it, "admin_set_app_audience", map[string]any{
		"beamhall": "e2e", "beam": "toolbox", "identities": []string{erinID}}, false)

	// 4. Discovery advertises the capability: the deploy-time probe stamped
	// the live release, so describe_app says so without touching the app.
	_, txt = callTool(ctx, t, erin, "describe_app", map[string]any{"app": "toolbox"}, false)
	if !strings.Contains(txt, "Agent tools: yes") {
		t.Fatalf("describe_app should advertise agent tools: %q", txt)
	}
	_, txt = callTool(ctx, t, erin, "list_apps", nil, false)
	if !strings.Contains(txt, "offers agent tools") {
		t.Fatalf("list_apps should flag the tools: %q", txt)
	}

	// 5. Erin's agent uses the app: menu, then two invocations. The app
	// answers only because the assertion VERIFIES and carries her identity.
	_, txt = callTool(ctx, t, erin, "use_app", map[string]any{"app": "toolbox"}, false)
	if !strings.Contains(txt, "whoami") || !strings.Contains(txt, "add two numbers") {
		t.Fatalf("use_app menu = %q", txt)
	}
	_, txt = callTool(ctx, t, erin, "use_app", map[string]any{
		"app": "toolbox", "tool": "whoami"}, false)
	for _, want := range []string{`"sub":"` + erinID + `"`, `"channel":"live"`, `"groups":["finance"]`} {
		if !strings.Contains(txt, want) {
			t.Fatalf("whoami result missing %s: %q", want, txt)
		}
	}
	_, txt = callTool(ctx, t, erin, "use_app", map[string]any{
		"app": "toolbox", "tool": "add", "arguments": map[string]any{"a": 3, "b": 4}}, false)
	if !strings.Contains(txt, `"sum":7`) {
		t.Fatalf("add result = %q", txt)
	}

	// 6. Frank (out of audience): byte-uniform, leak-free refusal.
	frank := a.connect("e2e-frank", "beams:use", nil)
	_, txt = callTool(ctx, t, frank, "use_app", map[string]any{"app": "toolbox"}, true)
	if !strings.Contains(txt, "no app named") {
		t.Fatalf("want the uniform refusal, got %q", txt)
	}
	if strings.Contains(txt, "e2e") || strings.Contains(txt, "https://") {
		t.Fatalf("refusal leaks detail: %q", txt)
	}

	// 7. The contract endpoints sit on the app's PUBLIC origin: without an
	// assertion the app itself must refuse (the injected JWKS is the gate).
	if status, body := curlPath(t, liveURL, "/.beamhall/tools"); status != 401 {
		t.Fatalf("bare manifest request: want the app's own 401, got %d: %q", status, body)
	}

	// 8. The audit chain carries the brokered calls (menu + 2 invokes for
	// erin, 1 deny for frank) with the beam pinned, and the builder's tests
	// as PEP decision/outcome pairs.
	a.stop()
	st, issues, events := openAndVerifyAudit(t, a.dataDir)
	defer st.Close()
	if len(issues) != 0 {
		t.Fatalf("audit chain issues: %+v", issues)
	}
	var useOK, useDeny, tryEvents int
	for _, rec := range events {
		switch rec.Event.Action {
		case "use_app":
			if rec.Event.ResultStatus == "ok" {
				useOK++
				if rec.Event.BeamID == "" {
					t.Errorf("use_app event missing beam id: %+v", rec.Event)
				}
				if d := rec.Event.RequestDigest; d != "menu" && !strings.HasPrefix(d, "tool=") {
					t.Errorf("use_app digest = %q", d)
				}
			} else {
				useDeny++
			}
		case "try_beam_tool":
			tryEvents++
		}
	}
	if useOK != 3 || useDeny != 1 || tryEvents < 2 {
		t.Fatalf("audit shape: use_ok=%d use_deny=%d try=%d", useOK, useDeny, tryEvents)
	}
}
