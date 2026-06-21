package driver

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// Integration test for the Docker driver against a REAL hardened daemon.
// Gated on BEAMHALL_DOCKER_IT=1 so it never runs in plain `go test`. Build it
// for the lab and run there:
//
//	GOOS=linux GOARCH=amd64 go test -c ./internal/driver -o /tmp/driver.test
//	scp /tmp/driver.test root@<lab>:/tmp/ && \
//	ssh root@<lab> 'BEAMHALL_DOCKER_IT=1 BEAMHALL_IT_IMAGE=bh-smoke-beam /tmp/driver.test -test.v -test.run TestDockerDriverLifecycle'
//
// It deploys the image under both runc and runsc with the full hardening
// profile and verifies: HTTP via the container's bridge address, secret-file
// injection, that runtime_class actually took effect (gVisor kernel under
// runsc), and pause/resume/stats/logs.
func TestDockerDriverLifecycle(t *testing.T) {
	if os.Getenv("BEAMHALL_DOCKER_IT") != "1" {
		t.Skip("set BEAMHALL_DOCKER_IT=1 to run the Docker integration test")
	}
	image := os.Getenv("BEAMHALL_IT_IMAGE")
	if image == "" {
		image = "bh-smoke-beam"
	}
	d, err := NewDockerDriver("/tmp/bh-it-secrets")
	if err != nil {
		t.Fatalf("driver: %v", err)
	}
	for _, rc := range []RuntimeClass{RuntimeRunc, RuntimeRunsc} {
		t.Run(string(rc), func(t *testing.T) { runOnce(t, d, image, rc) })
	}
}

func runOnce(t *testing.T, d *DockerDriver, image string, rc RuntimeClass) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	net := "bh-it-" + string(rc)
	spec := DeploySpec{
		BeamID:      "it-" + string(rc),
		BeamhallID:  "it",
		ImageDigest: image,
		Port:        8080,
		Network:     NetworkPolicy{BeamhallNetwork: net, EgressDenyAll: true},
		Security: SecurityProfile{
			RuntimeClass:    rc,
			CapDrop:         []string{"ALL"},
			CapAdd:          []string{"NET_BIND_SERVICE"},
			NoNewPrivileges: true,
			ReadOnlyRootfs:  true,
			Tmpfs:           []string{"/tmp"},
		},
		Resources: ResourceLimits{MemBytes: 512 << 20, PidsMax: 256, CPUQuota: 50000},
		Secrets:   []SecretMount{{Key: "probe", MountPath: "/run/secrets/probe", Value: []byte("s3cr3t-" + string(rc))}},
	}

	h, err := d.Deploy(ctx, spec)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	defer func() { _ = d.Destroy(context.Background(), h) }()

	if err := d.Start(ctx, h); err != nil {
		t.Fatalf("start: %v", err)
	}

	// Wait for running + a backend address, then HTTP-probe via the bridge IP.
	var addr string
	for i := 0; i < 30; i++ {
		st, err := d.Status(ctx, h)
		if err != nil {
			t.Fatalf("status: %v", err)
		}
		if st.State == WorkloadRunning && st.BackendAddr != "" {
			addr = st.BackendAddr
			break
		}
		if st.State == WorkloadExited {
			t.Fatalf("container exited early; logs:\n%s", dumpLogs(ctx, d, h))
		}
		time.Sleep(time.Second)
	}
	if addr == "" {
		t.Fatalf("no backend addr; logs:\n%s", dumpLogs(ctx, d, h))
	}

	body := httpGet(t, "http://"+addr+"/")
	if !strings.Contains(body, "beamhall ok") {
		t.Fatalf("unexpected body %q", body)
	}
	t.Logf("[%s] HTTP ok via %s under full hardening profile", rc, addr)

	// Prove runtime_class took effect: gVisor presents a 4.x-gvisor kernel.
	kernel := execOut(ctx, t, d, h, "uname", "-r")
	isGvisor := strings.Contains(strings.ToLower(kernel), "gvisor")
	if rc == RuntimeRunsc && !isGvisor {
		t.Fatalf("expected gVisor kernel under runsc, got %q", kernel)
	}
	if rc == RuntimeRunc && isGvisor {
		t.Fatalf("unexpected gVisor kernel under runc: %q", kernel)
	}
	t.Logf("[%s] in-container kernel: %s", rc, strings.TrimSpace(kernel))

	// Secret file injected and readable (not env, not returned over MCP).
	got := strings.TrimSpace(execOut(ctx, t, d, h, "cat", "/run/secrets/probe"))
	if got != "s3cr3t-"+string(rc) {
		t.Fatalf("secret mismatch: got %q", got)
	}
	t.Logf("[%s] secret injected at /run/secrets/probe", rc)

	// pause -> resume
	if err := d.Pause(ctx, h); err != nil {
		t.Fatalf("pause: %v", err)
	}
	if st, _ := d.Status(ctx, h); st.State != WorkloadPaused {
		t.Fatalf("expected paused, got %s", st.State)
	}
	if err := d.Resume(ctx, h); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if st, _ := d.Status(ctx, h); st.State != WorkloadRunning {
		t.Fatalf("expected running after resume, got %s", st.State)
	}

	// stats + logs sanity
	if s, err := d.Stats(ctx, h); err != nil || s.MemBytes == 0 {
		t.Fatalf("stats: err=%v mem=%d", err, s.MemBytes)
	}
	if lg := dumpLogs(ctx, d, h); !strings.Contains(lg, "listening") {
		t.Logf("[%s] note: logs did not contain 'listening':\n%s", rc, lg)
	}
	t.Logf("[%s] lifecycle PASS", rc)
}

func httpGet(t *testing.T, url string) string {
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

func execOut(ctx context.Context, t *testing.T, d *DockerDriver, h Handle, cmd ...string) string {
	t.Helper()
	var out bytes.Buffer
	if _, err := d.Exec(ctx, h, cmd, ExecStreams{Stdout: &out, Stderr: &out}); err != nil {
		t.Fatalf("exec %v: %v", cmd, err)
	}
	return out.String()
}

func dumpLogs(ctx context.Context, d *DockerDriver, h Handle) string {
	rc, err := d.Logs(ctx, h, LogOptions{TailN: 20})
	if err != nil {
		return "(logs error: " + err.Error() + ")"
	}
	defer rc.Close()
	b, _ := io.ReadAll(rc)
	return string(b)
}
