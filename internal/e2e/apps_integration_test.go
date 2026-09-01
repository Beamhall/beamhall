package e2e

// Lab test for the using tier (agent-facing apps): a builder ships an app, IT
// publishes it to an audience, and a user's own agent — a token with only
// beams:use, no membership anywhere — discovers it, gets the real live URL,
// and is auto-registered on first contact. The out-of-audience user sees
// nothing and gets the uniform (leak-free) refusal.
//
//	BEAMHALL_DOCKER_IT=1 /tmp/e2e.test -test.v -test.run TestUserTierEndToEnd
import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestUserTierEndToEnd(t *testing.T) {
	if os.Getenv("BEAMHALL_DOCKER_IT") != "1" {
		t.Skip("set BEAMHALL_DOCKER_IT=1 to run the user-tier suite")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	a := launchAppliance(t, ctx)
	it := a.connect("e2e-it", "beams:promote admin:it", nil)
	builder := a.connect("e2e-builder", "beamhalls:read beams:write beams:deploy", nil)

	// 1. Builder ships an app (with a user-facing description); IT promotes it.
	callTool(ctx, t, builder, "create_beam", map[string]any{
		"beamhall": "e2e", "slug": "handbook", "runtime_hint": "node",
		"description": "Company policies and how-tos"}, false)
	app := tarGz(t, map[string]string{
		"package.json": `{ "name": "handbook", "version": "1.0.0", "main": "app.js", "scripts": { "start": "node app.js" } }`,
		// curlHost's beam-answered marker is a JSON body carrying "ok":true.
		"app.js": `require("http").createServer((q, s) => s.end(JSON.stringify({ ok: true, app: "handbook" })))
  .listen(process.env.PORT || 8080);`,
	})
	callTool(ctx, t, builder, "deploy_beam",
		map[string]any{"beamhall": "e2e", "beam": "handbook", "source_tarball": app}, false)
	itRes, _ := callTool(ctx, t, it, "promote_to_live",
		map[string]any{"beamhall": "e2e", "beam": "handbook"}, false)
	liveURL := structuredURL(t, itRes)

	// 2. Erin's very first contact: a valid beams:use token with NO identity
	// row. list_apps must auto-register her and answer (empty — nothing is
	// published yet), not refuse.
	erin := a.connect("e2e-erin", "beams:use", nil)
	_, txt := callTool(ctx, t, erin, "list_apps", nil, false)
	if !strings.Contains(txt, "No apps are published to you yet") {
		t.Fatalf("pre-publish list_apps = %q", txt)
	}

	// 3. IT publishes to erin alone (her identity id from the registry).
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
		"beamhall": "e2e", "beam": "handbook", "identities": []string{erinID}}, false)

	// 4. Erin discovers the app with its real live URL, and the URL serves.
	_, txt = callTool(ctx, t, erin, "list_apps", nil, false)
	if !strings.Contains(txt, "handbook") || !strings.Contains(txt, liveURL) {
		t.Fatalf("erin's list_apps = %q (want handbook + %s)", txt, liveURL)
	}
	res, txt = callTool(ctx, t, erin, "describe_app", map[string]any{"app": "handbook"}, false)
	if !strings.Contains(txt, "Company policies") || !strings.Contains(txt, liveURL) {
		t.Fatalf("describe_app = %q", txt)
	}
	if body := curlHost(t, liveURL, 200); !strings.Contains(body, `"app":"handbook"`) {
		t.Fatalf("live URL does not serve the app: %q", body)
	}

	// 5. Frank (out of the audience): empty list, and the refusal must be
	// uniform — no workspace or URL may leak through it.
	frank := a.connect("e2e-frank", "beams:use", nil)
	_, txt = callTool(ctx, t, frank, "list_apps", nil, false)
	if strings.Contains(txt, "handbook") {
		t.Fatalf("audience isolation broken — frank sees the app: %q", txt)
	}
	_, txt = callTool(ctx, t, frank, "describe_app", map[string]any{"app": "handbook"}, true)
	if !strings.Contains(txt, "no app named") {
		t.Fatalf("want the uniform refusal, got %q", txt)
	}
	if strings.Contains(txt, "e2e") || strings.Contains(txt, "https://") {
		t.Fatalf("refusal leaks detail: %q", txt)
	}

	// 6. The tier boundary: a beams:use token reaches no build or admin tool.
	_, txt = callTool(ctx, t, erin, "create_beam",
		map[string]any{"beamhall": "e2e", "slug": "nope"}, true)
	if !strings.Contains(txt, "insufficient_scope") {
		t.Fatalf("create_beam refusal = %q", txt)
	}
	callTool(ctx, t, erin, "admin_set_app_audience",
		map[string]any{"beamhall": "e2e", "beam": "handbook", "everyone": true}, true)

	// 7. Group audience: publish to finance; a finance-group token sees it,
	// erin (no longer in the identity list, no group) loses it.
	callTool(ctx, t, it, "admin_set_app_audience", map[string]any{
		"beamhall": "e2e", "beam": "handbook", "groups": []string{"finance"}}, false)
	fin := a.connectAs("e2e-frank", "beams:use", []string{"finance"}, nil)
	_, txt = callTool(ctx, t, fin, "list_apps", nil, false)
	if !strings.Contains(txt, "handbook") {
		t.Fatalf("finance member does not see the group-published app: %q", txt)
	}
	_, txt = callTool(ctx, t, erin, "list_apps", nil, false)
	if strings.Contains(txt, "handbook") {
		t.Fatalf("re-publish replaced the audience; erin should be out: %q", txt)
	}

	// 8. Unpublish: gone for everyone, immediately.
	callTool(ctx, t, it, "admin_set_app_audience", map[string]any{
		"beamhall": "e2e", "beam": "handbook", "clear": true}, false)
	_, txt = callTool(ctx, t, fin, "list_apps", nil, false)
	if strings.Contains(txt, "handbook") {
		t.Fatalf("unpublished app still listed: %q", txt)
	}

	// 9. The audit chain: intact, carries the publish + auto-registrations,
	// and no discovery-read events.
	a.stop()
	st, issues, events := openAndVerifyAudit(t, a.dataDir)
	defer st.Close()
	if len(issues) != 0 {
		t.Fatalf("audit chain issues: %+v", issues)
	}
	var publishes, autoRegs, listReads int
	for _, rec := range events {
		switch rec.Event.Action {
		case "admin_set_app_audience":
			publishes++
			if rec.Event.BeamID == "" {
				t.Errorf("publish event missing beam id: %+v", rec.Event)
			}
		case "user_auto_register":
			autoRegs++
		case "list_apps", "describe_app":
			listReads++
		}
	}
	if publishes < 3 || autoRegs < 2 || listReads != 0 {
		t.Fatalf("audit shape: publishes=%d autoRegs=%d listReads=%d", publishes, autoRegs, listReads)
	}
}
