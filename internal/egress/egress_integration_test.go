package egress_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Beamhall/beamhall/internal/driver"
	"github.com/Beamhall/beamhall/internal/egress"
)

// Integration test for the egress reconciler against real iptables + Docker.
// Gated on BEAMHALL_DOCKER_IT=1 and must run as root on the lab:
//
//	GOOS=linux GOARCH=amd64 go test -c ./internal/egress -o /tmp/egress.test
//	scp /tmp/egress.test root@<lab>:/tmp/ && \
//	ssh root@<lab> 'BEAMHALL_DOCKER_IT=1 /tmp/egress.test -test.v -test.run TestEgress'
//
// It proves the negative-security property: a container on a Beamhall bridge
// reaches the internet by default, is cut off under default-deny (and cannot
// reach cloud metadata), and only the allowlisted CIDR opens back up.
func TestEgressDefaultDenyAndAllowlist(t *testing.T) {
	if os.Getenv("BEAMHALL_DOCKER_IT") != "1" {
		t.Skip("set BEAMHALL_DOCKER_IT=1 (root) to run the egress integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	d, err := driver.NewDockerDriver("/tmp/bh-egress-secrets")
	if err != nil {
		t.Fatalf("driver: %v", err)
	}
	const netName = "bh-egress-it"
	if err := d.EnsureNetwork(ctx, netName); err != nil {
		t.Fatalf("ensure network: %v", err)
	}
	defer func() { _ = d.RemoveNetwork(context.Background(), netName) }()

	bridge, err := d.NetworkBridge(ctx, netName)
	if err != nil {
		t.Fatalf("network bridge: %v", err)
	}
	t.Logf("beamhall bridge: %s", bridge)

	h, err := d.Deploy(ctx, driver.DeploySpec{
		BeamID:      "egress-probe",
		ImageDigest: "busybox",
		Command:     []string{"sleep", "600"},
		Network:     driver.NetworkPolicy{BeamhallNetwork: netName, EgressDenyAll: true},
		Security: driver.SecurityProfile{
			CapDrop: []string{"ALL"}, NoNewPrivileges: true, ReadOnlyRootfs: true, Tmpfs: []string{"/tmp"},
		},
		Resources: driver.ResourceLimits{MemBytes: 128 << 20, PidsMax: 128},
	})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	defer func() { _ = d.Destroy(context.Background(), h) }()
	if err := d.Start(ctx, h); err != nil {
		t.Fatalf("start: %v", err)
	}

	reach := func(ip, port string) bool {
		// nc -w 3 -z: exit 0 == TCP connect succeeded; exit non-zero (after the
		// timeout) == blocked. Verified on the lab against a real DROP rule.
		code, err := d.Exec(ctx, h, []string{"nc", "-w", "3", "-z", ip, port}, driver.ExecStreams{})
		if err != nil {
			t.Fatalf("exec nc %s:%s: %v", ip, port, err)
		}
		return code == 0
	}

	r := egress.New() // built-in always-deny: 169.254.0.0/16 (link-local + metadata)
	t.Cleanup(func() { _ = r.Teardown(context.Background()) })

	// 1. Baseline: egress is open before we program any policy.
	if !reach("1.1.1.1", "443") {
		t.Fatal("expected open egress to 1.1.1.1:443 before reconcile")
	}
	t.Log("baseline: egress open")

	// 2. Default-deny (no allowlist): internet blocked, metadata blocked.
	if err := r.Reconcile(ctx, []egress.Policy{{Bridge: bridge}}); err != nil {
		t.Fatalf("reconcile deny: %v", err)
	}
	if reach("1.1.1.1", "443") {
		t.Fatal("default-deny failed: 1.1.1.1:443 still reachable")
	}
	if reach("169.254.169.254", "80") {
		t.Fatal("metadata reachable under default-deny")
	}
	t.Log("default-deny: internet + metadata blocked")

	// 3. Allowlist 1.1.1.1/32: that destination opens, others stay blocked.
	if err := r.Reconcile(ctx, []egress.Policy{{Bridge: bridge, Allow: []string{"1.1.1.1/32"}}}); err != nil {
		t.Fatalf("reconcile allow: %v", err)
	}
	if !reach("1.1.1.1", "443") {
		t.Fatal("allowlisted 1.1.1.1:443 not reachable")
	}
	if reach("8.8.8.8", "443") {
		t.Fatal("non-allowlisted 8.8.8.8:443 reachable")
	}
	if reach("169.254.169.254", "80") {
		t.Fatal("metadata reachable even with an unrelated allowlist entry")
	}
	t.Log("allowlist: 1.1.1.1 open; 8.8.8.8 + metadata still blocked")
}
