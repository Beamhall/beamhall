package orch

// Lab integration test: the vault→driver junction through the full
// orchestrator path. Each half is verified elsewhere (secret.Inject unit
// tests; the driver's stageSecrets in its own lab test) — this proves their
// composition: a secret written through the write-only vault is decrypted
// backplane-side at deploy time and readable by the real container at
// /run/secrets/<key>, with the whole lifecycle (deploy → pause → resume →
// promote) driven by the orchestrator against the real Docker driver.
//
// Gated on BEAMHALL_DOCKER_IT=1; runs as root on the lab VM:
//
//	GOOS=linux GOARCH=amd64 go test -c ./internal/orch -o /tmp/orch.test
//	scp /tmp/orch.test root@"$BEAMHALL_TEST_HOST":/tmp/
//	ssh root@"$BEAMHALL_TEST_HOST" 'BEAMHALL_DOCKER_IT=1 BEAMHALL_IT_IMAGE=bh-smoke-beam /tmp/orch.test -test.v -test.run TestOrchestratorJunction'

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/Beamhall/beamhall/internal/audit"
	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/driver"
	"github.com/Beamhall/beamhall/internal/policy"
	"github.com/Beamhall/beamhall/internal/scheduler"
	"github.com/Beamhall/beamhall/internal/secret"
	"github.com/Beamhall/beamhall/internal/store"
)

func TestOrchestratorJunctionVaultToContainer(t *testing.T) {
	if os.Getenv("BEAMHALL_DOCKER_IT") != "1" {
		t.Skip("set BEAMHALL_DOCKER_IT=1 to run the orchestrator integration test")
	}
	image := os.Getenv("BEAMHALL_IT_IMAGE")
	if image == "" {
		image = "bh-smoke-beam"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Real store, vault, audit, PEP, scheduler — and the real Docker driver.
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "orch-it.db"))
	if err != nil {
		t.Fatalf("Open store: %v", err)
	}
	defer st.Close()
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	vault := secret.NewVault(key, st)
	alog := audit.New(st)
	pep := policy.New(st, alog)
	drv, err := driver.NewDockerDriver(filepath.Join(t.TempDir(), "secrets"))
	if err != nil {
		t.Fatalf("NewDockerDriver: %v", err)
	}
	gw := newFakeGateway() // the Caddy path has its own lab test; not the junction
	sched := scheduler.New(st.PauseStore(), func(ctx context.Context, beamID string) error { return nil })

	o := New(st, drv, gw, sched, vault, pep, alog, "it.bh.test", WithStartupGrace(500*time.Millisecond))

	bh := &domain.Beamhall{
		Slug: "it", DisplayName: "IT", Status: domain.BeamhallActive,
		NetworkPolicy: domain.NetworkPolicy{EgressMode: domain.EgressDenyAll},
		Quota:         domain.ResourceQuota{MaxBeams: 2, MaxLiveSlots: 1, MaxDBCount: 1},
		LiveSlotLimit: 1,
	}
	sc := &domain.SecurityContext{
		RuntimeClass: domain.RuntimeRunc, CapDrop: []string{"ALL"}, CapAdd: []string{"NET_BIND_SERVICE"},
		NoNewPrivileges: true, ReadOnlyRootfs: true, Tmpfs: []string{"/tmp"},
		CgroupLimits: domain.ResourceLimits{MemBytes: 512 << 20, PidsMax: 256, CPUQuota: 50000},
		Template:     domain.TemplateWebApp,
	}
	if err := st.CreateBeamhall(ctx, bh, sc); err != nil {
		t.Fatal(err)
	}
	ident := &domain.Identity{ExternalSubject: "it-sub", Email: "it@x", DisplayName: "it",
		IdPIssuer: "idp", Status: domain.IdentityActive}
	if err := st.CreateIdentity(ctx, ident); err != nil {
		t.Fatal(err)
	}
	m := &domain.Membership{IdentityID: ident.ID, BeamhallID: bh.ID,
		Role: domain.RoleBeamhallAdmin, GrantedBy: ident.ID}
	if err := st.CreateMembership(ctx, m); err != nil {
		t.Fatal(err)
	}
	actor := Actor{ID: ident.ID}

	// Write the secret through the write-only vault, then deploy.
	const probeValue = "junction-s3cr3t-via-vault"
	beam, err := o.CreateBeam(ctx, actor, bh.ID, "probe", "Probe", "node")
	if err != nil {
		t.Fatalf("CreateBeam: %v", err)
	}
	if err := o.SetSecret(ctx, actor, bh.ID, beam.ID, "PROBE", []byte(probeValue)); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}
	beam, err = o.DeployBeam(ctx, actor, bh.ID, beam.ID, DeployRequest{ImageRef: image, ImageDigest: image})
	if err != nil {
		t.Fatalf("DeployBeam: %v", err)
	}
	rel, err := st.GetRelease(ctx, beam.CurrentReleaseID)
	if err != nil {
		t.Fatal(err)
	}
	h := handleOf(rel)
	defer func() {
		_ = drv.Destroy(context.Background(), h)
		_ = drv.RemoveNetwork(context.Background(), networkName(bh.ID))
	}()

	// THE junction assertion: the container reads the vault-sealed value at
	// /run/secrets/PROBE.
	var out bytes.Buffer
	if _, err := drv.Exec(ctx, h, []string{"cat", "/run/secrets/PROBE"}, driver.ExecStreams{Stdout: &out, Stderr: &out}); err != nil {
		t.Fatalf("exec: %v", err)
	}
	if got := strings.TrimSpace(out.String()); got != probeValue {
		t.Fatalf("in-container secret = %q, want %q", got, probeValue)
	}
	t.Logf("junction OK: vault→Inject→driver→container read %q at /run/secrets/PROBE", probeValue)

	// The beam actually serves on its per-Beamhall bridge.
	status, err := drv.Status(ctx, h)
	if err != nil || status.BackendAddr == "" {
		t.Fatalf("status: %+v err %v", status, err)
	}
	if body := getBody(t, "http://"+status.BackendAddr+"/"); !strings.Contains(body, "beamhall ok") {
		t.Fatalf("body = %q", body)
	}
	t.Logf("HTTP ok via %s", status.BackendAddr)

	// Lifecycle through the orchestrator: pause → resume → promote.
	if err := o.PausePreview(ctx, actor, bh.ID, beam.ID); err != nil {
		t.Fatalf("PausePreview: %v", err)
	}
	if s, _ := drv.Status(ctx, h); s.State != driver.WorkloadPaused {
		t.Fatalf("after pause: %s", s.State)
	}
	if _, err := o.ResumePreview(ctx, actor, bh.ID, beam.ID); err != nil {
		t.Fatalf("ResumePreview: %v", err)
	}
	if s, _ := drv.Status(ctx, h); s.State != driver.WorkloadRunning {
		t.Fatalf("after resume: %s", s.State)
	}
	host, err := o.PromoteToLive(ctx, actor, bh.ID, beam.ID)
	if err != nil {
		t.Fatalf("PromoteToLive: %v", err)
	}
	t.Logf("promoted to %s", host)

	// The audit chain over the whole run verifies.
	if issues, err := alog.Verify(ctx); err != nil || len(issues) > 0 {
		t.Fatalf("audit chain: issues=%v err=%v", issues, err)
	}
	t.Log("audit chain verified over the full lifecycle")
}

func getBody(t *testing.T, url string) string {
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
