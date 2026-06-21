// bh-demo drives the Beamhall canonical demo (PLAN §7) against a running
// appliance through the real MCP tool contract, with human narration. It is the
// "watch Beamhall work" artifact: an agent, holding only a scoped token and
// never a raw credential, builds and ships an internal beam.
//
// Flow: create_beam → set_secret → create_database → deploy_beam (preview URL)
// → show_logs (scrubbed) → promote denied for the builder → promote as IT
// (live URL) → deploy v2 → rollback to v1.
//
// IT setup is a precondition (see demo/run-demo.sh): `beamhalld admin bootstrap`
// creates the beamhall + grants the builder identity. This binary is the agent.
//
//	bh-demo -endpoint http://host:8443/mcp -token <builder-jwt> -it-token <it-jwt> \
//	        -beamhall demo -beam tracker -app demo/beam-app -base-domain <d>
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	var (
		endpoint = flag.String("endpoint", "http://127.0.0.1:8443/mcp", "MCP endpoint")
		token    = flag.String("token", "", "builder access token (beams:* secrets:write resources:write logs:read)")
		itToken  = flag.String("it-token", "", "IT access token (admin:it) for the promote step")
		beamhall = flag.String("beamhall", "demo", "beamhall slug (must be bootstrapped first)")
		beam     = flag.String("beam", "tracker", "beam slug to create")
		appDir   = flag.String("app", "demo/beam-app", "path to the beam source tree")
		rollback = flag.Bool("rollback", true, "include the v2-deploy + rollback chapter")
		gateway  = flag.String("gateway", "", "host:port to reach the gateway directly (e.g. 127.0.0.1:80) when the beam DNS isn't resolvable from here; sends the URL host as a Host header")
	)
	flag.Parse()
	gatewayAddr = *gateway
	if *token == "" {
		fail("missing -token (the builder's access token)")
	}

	ctx := context.Background()
	builder := mustConnect(ctx, *endpoint, *token)
	defer builder.Close()

	step(1, "create_beam", "the agent declares a beam; nothing is exposed to it yet")
	call(ctx, builder, "create_beam", args{"beamhall": *beamhall, "slug": *beam, "runtime_hint": "node"})

	step(2, "set_secret", "IT-grade secret, write-only — the agent sends it but can never read it back")
	call(ctx, builder, "set_secret", args{"beamhall": *beamhall, "beam": *beam,
		"key": "API_TOKEN", "value": "sk-demo-" + stamp()})

	step(3, "create_database", "a managed Postgres DB; the agent gets a secret KEY, never the DSN")
	dbRes := call(ctx, builder, "create_database", args{"beamhall": *beamhall, "beam": *beam, "name": "main"})
	narrate(textOf(dbRes))

	step(4, "deploy_beam", "source tarball → buildpacks (no Dockerfile) → hardened run → preview URL")
	app := tarApp(*appDir, "v1")
	depRes := call(ctx, builder, "deploy_beam", args{"beamhall": *beamhall, "beam": *beam, "source_tarball": app})
	preview := urlOf(depRes)
	fmt.Printf("    → preview URL: %s\n", preview)
	probe(preview)

	step(5, "show_logs", "the app logged its API token on boot; the agent sees it REDACTED")
	logs := textOf(call(ctx, builder, "show_logs", args{"beamhall": *beamhall, "beam": *beam, "tail_lines": 20}))
	narrate(lastLines(logs, 6))
	if strings.Contains(logs, "REDACTED") {
		fmt.Println("    ✓ secret scrubbed from logs")
	}

	step(6, "promote_to_live (as the builder)", "expected to be DENIED — promotion is an IT decision")
	if _, err := tryCall(ctx, builder, "promote_to_live", args{"beamhall": *beamhall, "beam": *beam}); err != nil {
		fmt.Printf("    ✓ denied by the policy enforcement point: %s\n", oneLine(err.Error()))
	} else {
		fmt.Println("    ⚠ promote unexpectedly succeeded for the builder")
	}

	if *itToken != "" {
		step(7, "promote_to_live (as IT)", "the admin:it operator promotes to a stable live URL")
		it := mustConnect(ctx, *endpoint, *itToken)
		defer it.Close()
		liveRes := call(ctx, it, "promote_to_live", args{"beamhall": *beamhall, "beam": *beam})
		fmt.Printf("    → LIVE URL: %s\n", urlOf(liveRes))
		probe(urlOf(liveRes))
	} else {
		fmt.Println("\n[7] promote_to_live (as IT): skipped (no -it-token)")
	}

	if *rollback {
		step(8, "deploy_beam (v2) + rollback", "ship a new release, then roll back to v1 in one call")
		v2 := tarApp(*appDir, "v2")
		r2 := call(ctx, builder, "deploy_beam", args{"beamhall": *beamhall, "beam": *beam, "source_tarball": v2})
		fmt.Printf("    → v2 preview: %s\n", urlOf(r2))
		rb := call(ctx, builder, "rollback", args{"beamhall": *beamhall, "beam": *beam})
		narrate(textOf(rb))
	}

	fmt.Println("\n✓ demo complete — an agent built, shipped, and operated an internal beam with no raw credentials.")
}

// --- MCP plumbing -----------------------------------------------------------

type args = map[string]any

type bearer struct{ tok string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Set("Authorization", "Bearer "+b.tok)
	return http.DefaultTransport.RoundTrip(r)
}

func mustConnect(ctx context.Context, endpoint, tok string) *sdkmcp.ClientSession {
	c := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "bh-demo", Version: "1"}, nil)
	cs, err := c.Connect(ctx, &sdkmcp.StreamableClientTransport{
		Endpoint:   endpoint,
		HTTPClient: &http.Client{Transport: bearer{tok}},
	}, nil)
	if err != nil {
		fail("connect %s: %v", endpoint, err)
	}
	return cs
}

func tryCall(ctx context.Context, cs *sdkmcp.ClientSession, name string, a args) (*sdkmcp.CallToolResult, error) {
	res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{Name: name, Arguments: a})
	if err != nil {
		return nil, err
	}
	if res.IsError {
		return nil, fmt.Errorf("%s", textOf(res))
	}
	return res, nil
}

func call(ctx context.Context, cs *sdkmcp.ClientSession, name string, a args) *sdkmcp.CallToolResult {
	res, err := tryCall(ctx, cs, name, a)
	if err != nil {
		fail("%s: %v", name, err)
	}
	return res
}

// --- helpers ----------------------------------------------------------------

func urlOf(res *sdkmcp.CallToolResult) string {
	if m, ok := res.StructuredContent.(map[string]any); ok {
		if u, _ := m["url"].(string); u != "" {
			return u
		}
	}
	return "(no url)"
}

func textOf(res *sdkmcp.CallToolResult) string {
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*sdkmcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

// tarApp packs the beam source plus a VERSION file (drives the rollback story)
// into a base64 gzip tarball, as deploy_beam expects.
func tarApp(dir, version string) string {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	add := func(name string, body []byte) {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))})
		_, _ = tw.Write(body)
	}
	for _, f := range []string{"package.json", "server.js"} {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			fail("read %s: %v", f, err)
		}
		add(f, b)
	}
	add("VERSION", []byte(version))
	tw.Close()
	gz.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

var gatewayAddr string

// probe fetches the beam through the gateway. When -gateway is set it dials that
// address directly and carries the beam's hostname as the Host header, so the
// demo works even where the beam's DNS isn't resolvable (e.g. from the host
// loopback). It tries plain HTTP too, since the lab may run with gateway TLS off.
func probe(rawurl string) {
	host := strings.TrimPrefix(strings.TrimPrefix(rawurl, "https://"), "http://")
	host = strings.SplitN(host, "/", 2)[0]
	if host == "" {
		return
	}
	cl := &http.Client{Timeout: 8 * time.Second}
	if gatewayAddr != "" {
		cl.Transport = &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, gatewayAddr)
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	for _, scheme := range []string{"https://", "http://"} {
		resp, err := cl.Get(scheme + host)
		if err != nil {
			continue
		}
		resp.Body.Close()
		fmt.Printf("    ✓ live, HTTP %d via the gateway\n", resp.StatusCode)
		return
	}
	fmt.Println("    (beam is up — see the boot logs; gateway probe skipped)")
}

func step(n int, tool, why string) {
	fmt.Printf("\n[%d] %s\n    %s\n", n, tool, why)
}
func narrate(s string) {
	for _, ln := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		fmt.Printf("    | %s\n", ln)
	}
}
func lastLines(s string, n int) string {
	ls := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(ls) > n {
		ls = ls[len(ls)-n:]
	}
	return strings.Join(ls, "\n")
}
func oneLine(s string) string { return strings.SplitN(strings.TrimSpace(s), "\n", 2)[0] }
func stamp() string           { return fmt.Sprintf("%d", time.Now().Unix()) }
func fail(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "bh-demo: "+f+"\n", a...)
	os.Exit(1)
}
