package build

// Lab integration test: the full source→pinned-image→running path on real
// infrastructure — snapshot into a managed repo, `pack` on the dedicated
// non-userns-remapped build daemon, --publish to the loopback registry, then
// the hardened runtime daemon pulls the digest and runs it (PLAN §4/§5.5; the
// lab-verified build-vs-userns constraint).
//
// Requires the lab provisioning from scripts/lab-bootstrap.sh: the
// docker-build.service daemon (unix:///run/docker-build.sock, Paketo builder
// images seeded), the bh-registry container on 127.0.0.1:5000, and pack.
//
//	GOOS=linux GOARCH=amd64 go test -c ./internal/build -o /tmp/build.test
//	scp /tmp/build.test root@"$BEAMHALL_TEST_HOST":/tmp/
//	ssh root@"$BEAMHALL_TEST_HOST" 'BEAMHALL_DOCKER_IT=1 /tmp/build.test -test.v -test.run TestBuildPipelineToRuntime'

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Beamhall/beamhall/internal/driver"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func TestBuildPipelineToRuntime(t *testing.T) {
	if os.Getenv("BEAMHALL_DOCKER_IT") != "1" {
		t.Skip("set BEAMHALL_DOCKER_IT=1 to run the build-pipeline integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	src := t.TempDir()
	writeTree(t, src, map[string]string{
		"app.js": `const http = require("http");
const port = process.env.PORT || 8080;
http.createServer((req, res) => { res.end("beamhall pipeline ok\n"); }).listen(port);`,
		"package.json": `{ "name": "bh-pipe-it", "version": "1.0.0", "main": "app.js", "scripts": { "start": "node app.js" } }`,
	})

	pl := &Pipeline{
		Repos: NewRepos(filepath.Join(t.TempDir(), "repos")),
		Packer: &Packer{
			DockerHost: envOr("BEAMHALL_BUILD_DAEMON", "unix:///run/docker-build.sock"),
			Builder:    envOr("BEAMHALL_CNB_BUILDER", "paketobuildpacks/builder-jammy-base"),
			Registry:   envOr("BEAMHALL_REGISTRY", "127.0.0.1:5000"),
		},
		Logs: testWriter{t},
	}

	res, err := pl.BuildFromDir(ctx, "it", "pipe", src)
	if err != nil {
		t.Fatalf("BuildFromDir: %v", err)
	}
	if len(res.SourceSHA) != 40 || !strings.HasPrefix(res.ImageDigest, "sha256:") {
		t.Fatalf("result = %+v", res)
	}
	t.Logf("built %s from commit %s", res.PullRef, res.SourceSHA[:12])

	// The hardened runtime daemon pulls the pinned digest and runs it.
	drv, err := driver.NewDockerDriver(filepath.Join(t.TempDir(), "secrets"))
	if err != nil {
		t.Fatalf("NewDockerDriver: %v", err)
	}
	const netName = "bh-build-it"
	spec := driver.DeploySpec{
		BeamID:      "build-it",
		BeamhallID:  "it",
		ImageDigest: res.PullRef,
		Port:        8080,
		Network:     driver.NetworkPolicy{BeamhallNetwork: netName, EgressDenyAll: true},
		Security: driver.SecurityProfile{
			RuntimeClass:    driver.RuntimeRunc,
			CapDrop:         []string{"ALL"},
			CapAdd:          []string{"NET_BIND_SERVICE"},
			NoNewPrivileges: true,
			ReadOnlyRootfs:  true,
			Tmpfs:           []string{"/tmp"},
		},
		Resources: driver.ResourceLimits{MemBytes: 512 << 20, PidsMax: 256, CPUQuota: 50000},
	}
	h, err := drv.Deploy(ctx, spec)
	if err != nil {
		t.Fatalf("Deploy (pull from registry): %v", err)
	}
	defer func() {
		_ = drv.Destroy(context.Background(), h)
		_ = drv.RemoveNetwork(context.Background(), netName)
	}()
	if err := drv.Start(ctx, h); err != nil {
		t.Fatalf("Start: %v", err)
	}

	var addr string
	for i := 0; i < 30; i++ {
		st, err := drv.Status(ctx, h)
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		if st.State == driver.WorkloadRunning && st.BackendAddr != "" {
			addr = st.BackendAddr
			break
		}
		time.Sleep(time.Second)
	}
	if addr == "" {
		t.Fatal("no backend address")
	}
	body := httpBody(t, "http://"+addr+"/")
	if !strings.Contains(body, "beamhall pipeline ok") {
		t.Fatalf("body = %q — the source-built image is not what is serving", body)
	}
	t.Logf("source→pack→registry→pull→run verified: %q via %s", strings.TrimSpace(body), addr)
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("pack: %s", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

func httpBody(t *testing.T, url string) string {
	t.Helper()
	c := &http.Client{Timeout: 5 * time.Second}
	var lastErr error
	for i := 0; i < 10; i++ {
		resp, err := c.Get(url)
		if err != nil {
			lastErr = err
			time.Sleep(500 * time.Millisecond)
			continue
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	t.Fatalf("GET %s: %v", url, lastErr)
	return ""
}
