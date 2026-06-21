package gateway_test

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Beamhall/beamhall/internal/driver"
	"github.com/Beamhall/beamhall/internal/gateway"
)

// Integration test for the Caddy gateway. Gated on BEAMHALL_DOCKER_IT=1; needs a
// running Caddy with its Admin API reachable (BEAMHALL_CADDY_ADMIN, default
// http://localhost:2019) and Docker. Run on the lab (the run script installs +
// starts Caddy):
//
//	GOOS=linux GOARCH=amd64 go test -c ./internal/gateway -o /tmp/gateway.test
//	scp /tmp/gateway.test root@<lab>:/tmp/ && \
//	ssh root@<lab> 'BEAMHALL_DOCKER_IT=1 /tmp/gateway.test -test.v -test.run TestGateway'
//
// It deploys a real backend container, routes a host to it through Caddy, proves
// HTTP reaches the beam, then retires the route and proves it stops.
func TestGatewayRoutesToContainer(t *testing.T) {
	if os.Getenv("BEAMHALL_DOCKER_IT") != "1" {
		t.Skip("set BEAMHALL_DOCKER_IT=1 (root, Caddy running) to run the gateway integration test")
	}
	admin := envOr("BEAMHALL_CADDY_ADMIN", "http://localhost:2019")
	image := envOr("BEAMHALL_IT_IMAGE", "bh-smoke-beam")
	const listen = ":8088"
	const host = "beam.wc.test"

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	d, err := driver.NewDockerDriver("/tmp/bh-gw-secrets")
	if err != nil {
		t.Fatalf("driver: %v", err)
	}
	const netName = "bh-gw-it"
	if err := d.EnsureNetwork(ctx, netName); err != nil {
		t.Fatalf("ensure net: %v", err)
	}
	defer func() { _ = d.RemoveNetwork(context.Background(), netName) }()

	h, err := d.Deploy(ctx, driver.DeploySpec{
		BeamID: "gw-backend", ImageDigest: image, Port: 8080,
		Network:  driver.NetworkPolicy{BeamhallNetwork: netName},
		Security: driver.SecurityProfile{CapDrop: []string{"ALL"}, CapAdd: []string{"NET_BIND_SERVICE"}, NoNewPrivileges: true, ReadOnlyRootfs: true, Tmpfs: []string{"/tmp"}},
	})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	defer func() { _ = d.Destroy(context.Background(), h) }()
	if err := d.Start(ctx, h); err != nil {
		t.Fatalf("start: %v", err)
	}

	var backend string
	for i := 0; i < 30; i++ {
		st, err := d.Status(ctx, h)
		if err != nil {
			t.Fatalf("status: %v", err)
		}
		if st.State == driver.WorkloadRunning && st.BackendAddr != "" {
			backend = st.BackendAddr
			break
		}
		time.Sleep(time.Second)
	}
	if backend == "" {
		t.Fatal("backend never became ready")
	}
	t.Logf("backend: %s", backend)

	g := gateway.New(gateway.WithAdminURL(admin), gateway.WithoutTLS(), gateway.WithListen(listen))
	if err := g.Apply(ctx); err != nil {
		t.Fatalf("apply (bootstrap): %v", err)
	}
	if err := g.Upsert(ctx, gateway.Route{Hostname: host, BackendAddr: backend, Kind: gateway.Live}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// Routed: HTTP through Caddy on :8088 with the Host header reaches the beam.
	if body := getVia(t, "http://127.0.0.1:8088/", host, 15); !strings.Contains(body, "beamhall ok") {
		t.Fatalf("through gateway got %q", body)
	}
	t.Logf("routed: gateway -> %s served the beam", host)

	// Retired: the host no longer proxies to the backend. (Caddy answers an
	// unmatched host with an empty default 200, so we check the body, not the
	// status code.)
	if err := g.Retire(ctx, host); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if body := bodyVia(t, "http://127.0.0.1:8088/", host); strings.Contains(body, "beamhall ok") {
		t.Fatalf("route still served the beam after retire: %q", body)
	}
	t.Logf("retired: gateway no longer routes %s to the beam", host)
}

func getVia(t *testing.T, url, host string, tries int) string {
	t.Helper()
	c := &http.Client{Timeout: 4 * time.Second}
	for i := 0; i < tries; i++ {
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		req.Host = host
		resp, err := c.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return string(b)
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(time.Second)
	}
	return ""
}

func bodyVia(t *testing.T, url, host string) string {
	t.Helper()
	c := &http.Client{Timeout: 4 * time.Second}
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Host = host
	resp, err := c.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
