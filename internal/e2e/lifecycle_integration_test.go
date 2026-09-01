package e2e

// Lab test for the lifecycle-completion tools added in Phase 3 item 4:
// show_metrics, rollback (no rebuild), and destroy_beam. Runs the real
// build→deploy path twice to create two versions, rolls back, and destroys.
//
//	BEAMHALL_DOCKER_IT=1 /tmp/e2e.test -test.v -test.run TestLifecycleRollbackDestroy

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func appFor(t *testing.T, marker string) string {
	return tarGz(t, map[string]string{
		"package.json": `{ "name": "life", "version": "1.0.0", "main": "app.js", "scripts": { "start": "node app.js" } }`,
		"app.js": `require("http").createServer((q, s) => {
  s.setHeader("content-type", "application/json");
  s.end(JSON.stringify({ ok: true, marker: "` + marker + `" }));
}).listen(process.env.PORT || 8080);`,
	})
}

func TestLifecycleRollbackDestroy(t *testing.T) {
	if os.Getenv("BEAMHALL_DOCKER_IT") != "1" {
		t.Skip("set BEAMHALL_DOCKER_IT=1 to run the lifecycle suite")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	a := launchAppliance(t, ctx)
	cs := a.connect("e2e-builder", "beams:write beams:deploy beams:operate logs:read metrics:read", nil)

	callTool(ctx, t, cs, "create_beam",
		map[string]any{"beamhall": "e2e", "slug": "life", "runtime_hint": "node"}, false)

	// Version 1.
	r1, _ := callTool(ctx, t, cs, "deploy_beam",
		map[string]any{"beamhall": "e2e", "beam": "life", "source_tarball": appFor(t, "v1")}, false)
	if body := curlHost(t, structuredURL(t, r1), 200); !strings.Contains(body, `"marker":"v1"`) {
		t.Fatalf("v1 not serving: %s", body)
	}

	// show_metrics on the running workload.
	_, m := callTool(ctx, t, cs, "show_metrics", map[string]any{"beamhall": "e2e", "beam": "life"}, false)
	if !strings.Contains(m, "CPU") || !strings.Contains(m, "memory") {
		t.Errorf("metrics text: %s", m)
	}

	// Promote v1 to production (IT — the builder-denial half is covered by the
	// MCP suite): the live channel pins v1 behind the stable hostname.
	itCS := a.connect("e2e-it", "beams:promote beams:write admin:it", nil)
	pr1, _ := callTool(ctx, t, itCS, "promote_to_live",
		map[string]any{"beamhall": "e2e", "beam": "life"}, false)
	liveURL := structuredURL(t, pr1)
	if body := curlHost(t, liveURL, 200); !strings.Contains(body, `"marker":"v1"`) {
		t.Fatalf("live v1 not serving: %s", body)
	}

	// Version 2 supersedes v1 on the PREVIEW channel only — production stays
	// on v1 until re-promoted (dual-channel: iterate after shipping).
	r2, _ := callTool(ctx, t, cs, "deploy_beam",
		map[string]any{"beamhall": "e2e", "beam": "life", "source_tarball": appFor(t, "v2")}, false)
	urlV2 := structuredPreviewURL(t, r2)
	if body := curlHost(t, urlV2, 200); !strings.Contains(body, `"marker":"v2"`) {
		dumpBeamTopology(t)
		t.Fatalf("v2 not serving: %s", body)
	}
	if body := curlHost(t, liveURL, 200); !strings.Contains(body, `"marker":"v1"`) {
		t.Fatalf("live must still serve v1 before re-promote: %s", body)
	}

	// Re-promote pins production to the build the preview runs now (v2).
	callTool(ctx, t, itCS, "promote_to_live",
		map[string]any{"beamhall": "e2e", "beam": "life"}, false)
	if body := curlHost(t, liveURL, 200); !strings.Contains(body, `"marker":"v2"`) {
		t.Fatalf("live v2 not serving after re-promote: %s", body)
	}

	// Roll production back to the prior live release (no rebuild): the stable
	// hostname serves v1 again; the preview channel is unaffected.
	rb, _ := callTool(ctx, t, cs, "rollback", map[string]any{"beamhall": "e2e", "beam": "life"}, false)
	rbURL := structuredURL(t, rb)
	if body := curlHost(t, rbURL, 200); !strings.Contains(body, `"marker":"v1"`) {
		t.Fatalf("rollback did not restore v1: %s", body)
	}
	if body := curlHost(t, urlV2, 200); !strings.Contains(body, `"marker":"v2"`) {
		t.Fatalf("preview must be unaffected by rollback: %s", body)
	}

	// Destroy requires beamhall_admin: the builder is refused (governance),
	// then IT destroys — both channels' workloads and URLs go away.
	callTool(ctx, t, cs, "destroy_beam", map[string]any{"beamhall": "e2e", "beam": "life"}, true)
	if _, txt := callTool(ctx, t, itCS, "destroy_beam",
		map[string]any{"beamhall": "e2e", "beam": "life"}, false); !strings.Contains(txt, "destroyed") {
		t.Fatalf("IT destroy: %s", txt)
	}
	curlHost(t, rbURL, 0) // destroyed live channel no longer answers
	curlHost(t, urlV2, 0) // destroyed preview channel no longer answers

	// The slug is free again.
	if _, txt := callTool(ctx, t, cs, "create_beam",
		map[string]any{"beamhall": "e2e", "slug": "life"}, false); !strings.Contains(txt, "created") {
		t.Fatalf("recreate after destroy: %s", txt)
	}
}
