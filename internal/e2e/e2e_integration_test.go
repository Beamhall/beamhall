// Package e2e is the lab end-to-end suite: a real beamhalld process driven
// through real MCP tool calls over Streamable HTTP with real OAuth tokens —
// the canonical demo flow (PLAN §7): create_beam → set_secret →
// create_database → deploy_beam (tarball → pack → registry → hardened run)
// → preview URL through Caddy → scrubbed show_logs → pause/resume (new URL)
// → promote denied for the builder (PEP 403) → promote as IT → live URL —
// then the audit chain verifies clean.
//
// Gated on BEAMHALL_DOCKER_IT=1; runs as root on the lab VM. Needs Caddy and
// the build daemon/registry/Postgres from lab-bootstrap.sh:
//
//	GOOS=linux GOARCH=amd64 go build -o /tmp/beamhalld ./cmd/beamhalld
//	GOOS=linux GOARCH=amd64 go test -c ./internal/e2e -o /tmp/e2e.test
//	scp /tmp/beamhalld /tmp/e2e.test root@"$BEAMHALL_TEST_HOST":/tmp/
//	ssh root@"$BEAMHALL_TEST_HOST" 'caddy start 2>/dev/null; BEAMHALL_DOCKER_IT=1 /tmp/e2e.test -test.v'
package e2e

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Beamhall/beamhall/internal/audit"
	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/store"
)

const (
	httpAddr    = "127.0.0.1:18443"
	gatewayPort = "8089"
	audience    = "https://e2e.beamhall.internal/mcp"
	baseDomain  = "e2e.beamhall.internal"
	secretValue = "e2e-super-secret-api-token-value"
)

func TestMCPEndToEnd(t *testing.T) {
	if os.Getenv("BEAMHALL_DOCKER_IT") != "1" {
		t.Skip("set BEAMHALL_DOCKER_IT=1 to run the E2E suite")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	a := launchAppliance(t, ctx)
	dataDir := a.dataDir

	// --- MCP session as the builder ---------------------------------------
	builderScopes := "beams:write beams:deploy beams:operate beams:promote secrets:write resources:write logs:read"
	var progressMu sync.Mutex
	var progressN int
	cs := a.connect("e2e-builder", builderScopes, &sdkmcp.ClientOptions{
		ProgressNotificationHandler: func(_ context.Context, req *sdkmcp.ProgressNotificationClientRequest) {
			progressMu.Lock()
			progressN++
			progressMu.Unlock()
			t.Logf("[progress] %s", req.Params.Message)
		}})

	call := func(name string, args map[string]any, wantErr bool) (*sdkmcp.CallToolResult, string) {
		t.Helper()
		return callTool(ctx, t, cs, name, args, wantErr)
	}

	// 1. create_beam
	call("create_beam", map[string]any{"beamhall": "e2e", "slug": "tracker", "runtime_hint": "node"}, false)

	// 2. set_secret (write-only)
	call("set_secret", map[string]any{"beamhall": "e2e", "beam": "tracker",
		"key": "API_TOKEN", "value": secretValue}, false)

	// 3. create_database → key only, never the DSN
	_, dbText := call("create_database", map[string]any{"beamhall": "e2e", "beam": "tracker", "name": "main"}, false)
	if !strings.Contains(dbText, "/run/secrets/MAIN_URL") || strings.Contains(dbText, "postgres://") {
		t.Fatalf("create_database must reveal the key, not the DSN: %s", dbText)
	}

	// 4. deploy_beam from a source tarball. The app proves the secret files
	// arrived and logs the API token so show_logs scrubbing has a real leak
	// to catch.
	app := tarGz(t, map[string]string{
		"package.json": `{ "name": "e2e-tracker", "version": "1.0.0", "main": "app.js", "scripts": { "start": "node app.js" } }`,
		"app.js": `const http = require("http"), fs = require("fs");
const tok = fs.readFileSync("/run/secrets/API_TOKEN", "utf8");
const hasDB = fs.existsSync("/run/secrets/MAIN_URL");
console.log("booted; api token is " + tok);
http.createServer((req, res) => {
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify({ ok: true, hasDB: hasDB, hasToken: tok.length > 0 }));
}).listen(process.env.PORT || 8080);`,
	})
	res, _ := call("deploy_beam", map[string]any{"beamhall": "e2e", "beam": "tracker", "source_tarball": app}, false)
	previewURL := structuredURL(t, res)
	if !strings.Contains(previewURL, ".preview."+baseDomain) {
		t.Fatalf("deploy did not yield a preview URL: %q", previewURL)
	}
	progressMu.Lock()
	if progressN == 0 {
		t.Error("no build progress notifications received (SSE progress is non-negotiable)")
	}
	progressMu.Unlock()

	// 5. The preview answers through Caddy, with both secret files present.
	body := curlHost(t, previewURL, http.StatusOK)
	if !strings.Contains(body, `"hasDB":true`) || !strings.Contains(body, `"hasToken":true`) {
		t.Fatalf("beam did not see its injected secrets: %s", body)
	}

	// 6. show_logs is scrubbed: the app logged the token; the agent must not
	// see it.
	_, logsText := call("show_logs", map[string]any{"beamhall": "e2e", "beam": "tracker"}, false)
	if strings.Contains(logsText, secretValue) {
		t.Fatal("show_logs leaked a secret value")
	}
	if !strings.Contains(logsText, "***REDACTED***") {
		t.Errorf("scrubber left no mask in logs:\n%s", logsText)
	}
	for _, b := range []byte(logsText) {
		if b < 0x09 { // docker stream-multiplex frame headers, if undemuxed
			t.Fatalf("show_logs contains raw multiplex frame bytes: %q", logsText)
		}
	}

	// 6b. Error UX: a beam that crashes on boot (writes outside tmpfs) must
	// fail the deploy with an actionable diagnosis, not mint a dead URL.
	call("create_beam", map[string]any{"beamhall": "e2e", "slug": "crasher"}, false)
	broken := tarGz(t, map[string]string{
		"package.json": `{ "name": "crasher", "version": "1.0.0", "main": "app.js", "scripts": { "start": "node app.js" } }`,
		"app.js":       `require("fs").writeFileSync("/boom.txt", "x"); // EROFS: rootfs is read-only`,
	})
	_, diag := call("deploy_beam", map[string]any{"beamhall": "e2e", "beam": "crasher", "source_tarball": broken}, true)
	for _, want := range []string{"exited during startup", "/tmp", "EROFS"} {
		if !strings.Contains(diag, want) {
			t.Errorf("crash diagnosis missing %q:\n%s", want, diag)
		}
	}

	// 7. pause retires the URL; resume mints a fresh one.
	call("pause_preview", map[string]any{"beamhall": "e2e", "beam": "tracker"}, false)
	curlHost(t, previewURL, 0 /* anything but 200 */)
	res, _ = call("resume_preview", map[string]any{"beamhall": "e2e", "beam": "tracker"}, false)
	resumedURL := structuredURL(t, res)
	if resumedURL == previewURL {
		t.Fatal("resume_preview reused the old preview URL")
	}
	curlHost(t, resumedURL, http.StatusOK)

	// 8. promote_to_live as the builder: the scope is granted but the role
	// is not — the PEP, not the token, is the authorization point.
	_, denyText := call("promote_to_live", map[string]any{"beamhall": "e2e", "beam": "tracker"}, true)
	if !strings.Contains(denyText, "denied") {
		t.Fatalf("builder promote should be a PEP denial, got: %s", denyText)
	}

	// 9. promote as IT (admin:it bypass, no membership row).
	itCS := a.connect("e2e-it", "beams:promote admin:it", nil)
	itRes, err := itCS.CallTool(ctx, &sdkmcp.CallToolParams{Name: "promote_to_live",
		Arguments: map[string]any{"beamhall": "e2e", "beam": "tracker"}})
	if err != nil {
		t.Fatal(err)
	}
	if itRes.IsError {
		t.Fatalf("IT promote failed: %s", resultText(itRes))
	}
	liveURL := structuredURL(t, itRes)
	if liveURL != "https://tracker.e2e."+baseDomain {
		t.Fatalf("live URL = %q", liveURL)
	}
	curlHost(t, liveURL, http.StatusOK)
	curlHost(t, resumedURL, 0) // promote retires the stale preview URL
	t.Logf("live at %s", liveURL)

	// --- shutdown, then verify the audit chain end to end ------------------
	cs.Close()
	itCS.Close()
	a.stop()
	st2, err := store.Open(context.Background(), filepath.Join(dataDir, "beamhall.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	issues, err := audit.New(st2).Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) > 0 {
		t.Fatalf("audit chain violations after the full flow: %+v", issues)
	}
	events, err := st2.ListAuditEvents(context.Background(), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var sawDeny bool
	for _, ev := range events {
		if ev.Event.Decision == domain.DecisionDeny && ev.Event.Action == "promote_to_live" {
			sawDeny = true
		}
		if strings.Contains(ev.Event.Reason, secretValue) {
			t.Error("audit log contains a secret value")
		}
	}
	if !sawDeny {
		t.Error("the builder's denied promote is missing from the audit chain")
	}
	t.Logf("audit chain verified: %d events, deny recorded, no secrets", len(events))
}

// --- helpers ---------------------------------------------------------------

type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

type testWriter struct {
	t    *testing.T
	name string
}

func (w testWriter) Write(b []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		w.t.Logf("[%s] %s", w.name, line)
	}
	return len(b), nil
}

func waitHealthy(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatal("beamhalld did not become healthy")
}

func resultText(res *sdkmcp.CallToolResult) string {
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*sdkmcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

// structuredURL pulls the url field out of a tool's structured output.
func structuredURL(t *testing.T, res *sdkmcp.CallToolResult) string {
	t.Helper()
	m, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("no structured content: %#v", res.StructuredContent)
	}
	u, _ := m["url"].(string)
	if u == "" {
		t.Fatalf("structured content has no url: %v", m)
	}
	return u
}

// curlHost fetches the gateway with the route hostname as Host header.
// wantStatus 0 means "the beam must no longer answer" — a retired route may
// surface as an error, a non-200, or Caddy's empty unmatched-host 200, but
// never the beam's own body. Retries briefly — route propagation through the
// Caddy admin API is fast but not synchronous. Every request is bounded: a
// paused container freezes its network stack mid-connection, and an unbounded
// client would hang on it forever.
func curlHost(t *testing.T, routeURL string, wantStatus int) string {
	t.Helper()
	host := strings.TrimPrefix(routeURL, "https://")
	client := &http.Client{Timeout: 3 * time.Second}
	var last string
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequest("GET", "http://127.0.0.1:"+gatewayPort+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		resp, err := client.Do(req)
		if err != nil {
			last = err.Error()
			if wantStatus == 0 {
				return "" // dead is dead
			}
		} else {
			var buf bytes.Buffer
			buf.ReadFrom(resp.Body)
			resp.Body.Close()
			body := buf.String()
			last = fmt.Sprintf("%d: %s", resp.StatusCode, body)
			beamAnswered := resp.StatusCode == http.StatusOK && strings.Contains(body, `"ok":true`)
			if wantStatus == 0 && !beamAnswered {
				return body
			}
			if wantStatus != 0 && resp.StatusCode == wantStatus && beamAnswered {
				return body
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("gateway %s: want %d (0 = beam must not answer); last: %s", host, wantStatus, last)
	return ""
}

func tarGz(t *testing.T, files map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

var _ = fmt.Sprintf // keep fmt for quick debug edits on the VM
