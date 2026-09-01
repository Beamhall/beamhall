package e2e

// Lab test for company branding: IT defines a facility-wide default plus a
// per-hall override over MCP, the builder reads the merged view, the gateway
// serves the palette stylesheet and logo on the base domain, and a deployed
// workload receives the resolved values as /run/beamhall/brand.json (the
// first real user of the driver's Bindings channel — this is the mount
// proof on real runtimes).
//
//	BEAMHALL_DOCKER_IT=1 /tmp/e2e.test -test.v -test.run TestBrandingEndToEnd
import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestBrandingEndToEnd(t *testing.T) {
	if os.Getenv("BEAMHALL_DOCKER_IT") != "1" {
		t.Skip("set BEAMHALL_DOCKER_IT=1 to run the branding suite")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	a := launchAppliance(t, ctx)
	it := a.connect("e2e-it", "admin:it", nil)
	builder := a.connect("e2e-builder", "beamhalls:read beams:write beams:deploy logs:read", nil)

	logoPNG := append([]byte("\x89PNG\r\n\x1a\n"), []byte("e2e-logo-body")...)

	// IT: facility default (with logo), then a per-hall primary-colour override.
	callTool(ctx, t, it, "admin_set_branding", map[string]any{
		"primary_color": "#112233", "secondary_color": "#445566",
		"header_html":     "<div>ACME</div>",
		"logo_png_base64": base64.StdEncoding.EncodeToString(logoPNG),
	}, false)
	callTool(ctx, t, it, "admin_set_branding", map[string]any{
		"beamhall": "e2e", "primary_color": "#AABBCC",
	}, false)

	// Separation of duties: the builder cannot write branding.
	callTool(ctx, t, builder, "admin_set_branding", map[string]any{"primary_color": "#000"}, true)

	// The builder reads the merged view: hall primary over facility fields.
	res, _ := callTool(ctx, t, builder, "show_branding", map[string]any{"beamhall": "e2e"}, false)
	brand, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("show_branding structured content: %#v", res.StructuredContent)
	}
	if brand["primary_color"] != "#AABBCC" || brand["secondary_color"] != "#445566" ||
		brand["scope"] != "beamhall" {
		t.Fatalf("merged branding = %v", brand)
	}
	cssURL, _ := brand["css_url"].(string)
	logoURL, _ := brand["logo_url"].(string)
	if cssURL == "" || logoURL == "" {
		t.Fatalf("branding URLs missing: %v", brand)
	}
	// Membership isolation: the builder cannot read another hall's branding.
	callTool(ctx, t, builder, "show_branding", map[string]any{"beamhall": "fort"}, true)

	// The gateway serves both public assets on the base domain.
	css := curlBrand(t, cssURL)
	if !strings.Contains(css, "--brand-primary:#AABBCC;") || !strings.Contains(css, "--brand-secondary:#445566;") {
		t.Fatalf("brand.css = %q", css)
	}
	if img := curlBrand(t, logoURL); !strings.HasPrefix(img, "\x89PNG") {
		t.Fatalf("logo bytes = %q", img[:min(len(img), 40)])
	}

	// A deployed workload gets the resolved values mounted at
	// /run/beamhall/brand.json — the app reads and republishes them.
	callTool(ctx, t, builder, "create_beam",
		map[string]any{"beamhall": "e2e", "slug": "branded", "runtime_hint": "node"}, false)
	app := tarGz(t, map[string]string{
		"package.json": `{ "name": "branded", "version": "1.0.0", "main": "app.js", "scripts": { "start": "node app.js" } }`,
		"app.js": `let brand = null;
try { brand = JSON.parse(require("fs").readFileSync("/run/beamhall/brand.json", "utf8")); } catch (e) {}
require("http").createServer((q, s) => {
  s.setHeader("content-type", "application/json");
  s.end(JSON.stringify({ ok: true, brand }));
}).listen(process.env.PORT || 8080);`,
	})
	dep, _ := callTool(ctx, t, builder, "deploy_beam",
		map[string]any{"beamhall": "e2e", "beam": "branded", "source_tarball": app}, false)
	body := curlHost(t, structuredURL(t, dep), 200)
	if !strings.Contains(body, `"primary_color":"#AABBCC"`) || !strings.Contains(body, `"header_html":"<div>ACME</div>"`) {
		t.Fatalf("workload brand.json not mounted/resolved: %s", body)
	}
	if !strings.Contains(body, `"logo_url":"https://`) {
		t.Fatalf("brand.json missing logo url: %s", body)
	}

	// Clearing the override falls back to the facility default...
	callTool(ctx, t, it, "admin_set_branding", map[string]any{"beamhall": "e2e", "clear": true}, false)
	res, _ = callTool(ctx, t, builder, "show_branding", map[string]any{"beamhall": "e2e"}, false)
	brand = res.StructuredContent.(map[string]any)
	if brand["primary_color"] != "#112233" || brand["scope"] != "facility" {
		t.Fatalf("post-clear branding = %v", brand)
	}
	// ...and the hot-linkable stylesheet reflects it without any redeploy.
	if css := curlBrand(t, cssURL); !strings.Contains(css, "--brand-primary:#112233;") {
		t.Fatalf("brand.css after clear = %q", css)
	}
}

// curlBrand fetches a public /brand/ URL through the gateway (Host-header
// routing, like curlHost, but for control-plane assets rather than beams).
func curlBrand(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("brand url %q: %v", rawURL, err)
	}
	client := &http.Client{Timeout: 3 * time.Second}
	var last string
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequest("GET", "http://127.0.0.1:"+gatewayPort+u.Path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = u.Host
		resp, err := client.Do(req)
		if err == nil {
			var buf bytes.Buffer
			buf.ReadFrom(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return buf.String()
			}
			last = fmt.Sprintf("%d: %s", resp.StatusCode, buf.String())
		} else {
			last = err.Error()
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("brand asset %s never served: %s", rawURL, last)
	return ""
}
