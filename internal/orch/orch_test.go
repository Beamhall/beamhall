package orch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/Beamhall/beamhall/internal/audit"
	"github.com/Beamhall/beamhall/internal/build"
	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/driver"
	"github.com/Beamhall/beamhall/internal/gateway"
	"github.com/Beamhall/beamhall/internal/policy"
	"github.com/Beamhall/beamhall/internal/resource"
	"github.com/Beamhall/beamhall/internal/scheduler"
	"github.com/Beamhall/beamhall/internal/secret"
	"github.com/Beamhall/beamhall/internal/store"
)

// fakeDriver records calls and serves canned results. Concurrency-safe so
// -race covers orchestrator/scheduler interleavings.
type fakeDriver struct {
	mu         sync.Mutex
	deploys    []driver.DeploySpec
	started    []string
	paused     []string
	resumed    []string
	stopped    []string
	destroyed  []string
	startErr   error
	logContent string
	exitCode   *int // non-nil: Status reports an exited workload
	stats      driver.Stats
}

func (f *fakeDriver) Name() string { return "fake" }
func (f *fakeDriver) Capabilities() driver.Capabilities {
	return driver.Capabilities{SupportsPause: true}
}
func (f *fakeDriver) Build(ctx context.Context, req driver.BuildRequest, progress chan<- driver.Event) (driver.BuildResult, error) {
	return driver.BuildResult{}, errors.New("fake does not build")
}
func (f *fakeDriver) Deploy(ctx context.Context, spec driver.DeploySpec) (driver.Handle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deploys = append(f.deploys, spec)
	return driver.Handle{DriverName: "fake", Ref: "ctr-" + spec.BeamID + fmt.Sprint(len(f.deploys))}, nil
}
func (f *fakeDriver) Start(ctx context.Context, h driver.Handle) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.startErr != nil {
		return f.startErr
	}
	f.started = append(f.started, h.Ref)
	return nil
}
func (f *fakeDriver) Pause(ctx context.Context, h driver.Handle) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.paused = append(f.paused, h.Ref)
	return nil
}
func (f *fakeDriver) Resume(ctx context.Context, h driver.Handle) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resumed = append(f.resumed, h.Ref)
	return nil
}
func (f *fakeDriver) Stop(ctx context.Context, h driver.Handle, grace time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped = append(f.stopped, h.Ref)
	return nil
}
func (f *fakeDriver) Destroy(ctx context.Context, h driver.Handle) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.destroyed = append(f.destroyed, h.Ref)
	return nil
}
func (f *fakeDriver) Logs(ctx context.Context, h driver.Handle, opts driver.LogOptions) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(f.logContent)), nil
}
func (f *fakeDriver) Stats(ctx context.Context, h driver.Handle) (driver.Stats, error) {
	return f.stats, nil
}
func (f *fakeDriver) Status(ctx context.Context, h driver.Handle) (driver.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.exitCode != nil {
		return driver.Status{State: driver.WorkloadExited, ExitCode: f.exitCode}, nil
	}
	return driver.Status{State: driver.WorkloadRunning, BackendAddr: "172.18.0.9:8080"}, nil
}
func (f *fakeDriver) Exec(ctx context.Context, h driver.Handle, cmd []string, s driver.ExecStreams) (int, error) {
	return 0, errors.New("not in fake")
}

// fakeGateway records the route table mutations.
type fakeGateway struct {
	mu        sync.Mutex
	routes    map[string]gateway.Route
	retired   []string
	upsertErr error // when set, Upsert fails instead of recording the route
}

func newFakeGateway() *fakeGateway { return &fakeGateway{routes: map[string]gateway.Route{}} }

func (g *fakeGateway) Upsert(ctx context.Context, r gateway.Route) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.upsertErr != nil {
		return g.upsertErr
	}
	g.routes[r.Hostname] = r
	return nil
}
func (g *fakeGateway) Retire(ctx context.Context, hostname string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.routes, hostname)
	g.retired = append(g.retired, hostname)
	return nil
}
func (g *fakeGateway) Apply(ctx context.Context) error { return nil }

type world struct {
	o     *Orchestrator
	st    *store.Store
	drv   *fakeDriver
	gw    *fakeGateway
	sched *scheduler.Scheduler
	bh    *domain.Beamhall
	admin Actor
	build Actor // builder-role actor
}

func newWorld(t *testing.T) *world {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "orch.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	bh := &domain.Beamhall{
		Slug: "ops", DisplayName: "Ops", Status: domain.BeamhallActive,
		NetworkPolicy: domain.NetworkPolicy{EgressMode: domain.EgressDenyAll},
		Quota:         domain.ResourceQuota{MaxBeams: 5, MaxLiveSlots: 1, MaxDBCount: 1},
		LiveSlotLimit: 1,
	}
	sc := &domain.SecurityContext{
		RuntimeClass: domain.RuntimeRunsc, CapDrop: []string{"ALL"}, NoNewPrivileges: true,
		ReadOnlyRootfs: true, Tmpfs: []string{"/tmp"}, Template: domain.TemplateWebApp,
		CgroupLimits: domain.ResourceLimits{CPUQuota: 100000, MemBytes: 256 << 20, PidsMax: 128},
	}
	if err := st.CreateBeamhall(ctx, bh, sc); err != nil {
		t.Fatal(err)
	}

	mkActor := func(role domain.MembershipRole) Actor {
		ident := &domain.Identity{ExternalSubject: string(store.NewID()), Email: "u@x",
			DisplayName: "u", IdPIssuer: "idp", Status: domain.IdentityActive}
		if err := st.CreateIdentity(ctx, ident); err != nil {
			t.Fatal(err)
		}
		m := &domain.Membership{IdentityID: ident.ID, BeamhallID: bh.ID, Role: role, GrantedBy: ident.ID}
		if err := st.CreateMembership(ctx, m); err != nil {
			t.Fatal(err)
		}
		return Actor{ID: ident.ID}
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	vault := secret.NewVault(id, st)
	alog := audit.New(st)
	pep := policy.New(st, alog)
	drv := &fakeDriver{}
	gw := newFakeGateway()
	sched := scheduler.New(st.PauseStore(), func(ctx context.Context, beamID string) error { return nil })

	o := New(st, drv, gw, sched, vault, pep, alog, "bh.example",
		WithDefaultPauseAfter(2*time.Hour), WithStartupGrace(5*time.Millisecond),
		WithUserTier(UserTierConfig{AutoRegister: true, GroupAudiences: true}))
	return &world{o: o, st: st, drv: drv, gw: gw, sched: sched, bh: bh,
		admin: mkActor(domain.RoleBeamhallAdmin), build: mkActor(domain.RoleBuilder)}
}

func (w *world) deployed(t *testing.T, slug string) *domain.Beam {
	t.Helper()
	ctx := context.Background()
	beam, err := w.o.CreateBeam(ctx, w.build, w.bh.ID, slug, slug, "", "node")
	if err != nil {
		t.Fatalf("CreateBeam: %v", err)
	}
	beam, err = w.o.DeployBeam(ctx, w.build, w.bh.ID, beam.ID,
		DeployRequest{ImageRef: "reg/beam:1", ImageDigest: "sha256:abc"})
	if err != nil {
		t.Fatalf("DeployBeam: %v", err)
	}
	return beam
}

func (w *world) armedPauses(t *testing.T) []scheduler.ArmedPause {
	t.Helper()
	pauses, err := w.st.PauseStore().Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return pauses
}

func TestDeployHappyPath(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()

	// Two secrets in scope: one beam-scoped, one beamhall-wide.
	beam, err := w.o.CreateBeam(ctx, w.build, w.bh.ID, "tracker", "Tracker", "", "node")
	if err != nil {
		t.Fatalf("CreateBeam: %v", err)
	}
	if err := w.o.SetSecret(ctx, w.build, w.bh.ID, beam.ID, "DATABASE_URL", []byte("postgres://secret-dsn")); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}
	if err := w.o.SetSecret(ctx, w.build, w.bh.ID, "", "SHARED_TOKEN", []byte("hall-wide-value")); err != nil {
		t.Fatalf("SetSecret hall-wide: %v", err)
	}

	beam, err = w.o.DeployBeam(ctx, w.build, w.bh.ID, beam.ID,
		DeployRequest{ImageRef: "reg/tracker:1", ImageDigest: "sha256:abc"})
	if err != nil {
		t.Fatalf("DeployBeam: %v", err)
	}

	if beam.State != domain.StateRunning || beam.Mode != domain.ModePreview {
		t.Fatalf("beam state/mode = %s/%s", beam.State, beam.Mode)
	}
	if beam.CurrentReleaseID == "" {
		t.Fatal("no current release")
	}

	// The driver saw the hardened spec with both decrypted secrets mounted.
	if len(w.drv.deploys) != 1 {
		t.Fatalf("driver deploys = %d", len(w.drv.deploys))
	}
	spec := w.drv.deploys[0]
	if spec.Network.BeamhallNetwork != "bh-"+string(w.bh.ID) || !spec.Network.EgressDenyAll {
		t.Fatalf("network spec = %+v", spec.Network)
	}
	if spec.Security.RuntimeClass != driver.RuntimeRunsc || !spec.Security.ReadOnlyRootfs {
		t.Fatalf("security spec = %+v", spec.Security)
	}
	got := map[string]string{}
	for _, m := range spec.Secrets {
		got[m.MountPath] = string(m.Value)
	}
	if got["/run/secrets/DATABASE_URL"] != "postgres://secret-dsn" ||
		got["/run/secrets/SHARED_TOKEN"] != "hall-wide-value" {
		t.Fatalf("secret mounts = %v", got)
	}

	// Release is active and carries the workload handle.
	rel, err := w.st.GetRelease(ctx, beam.CurrentReleaseID)
	if err != nil || rel.Status != domain.ReleaseActive || rel.Workload.Ref == "" {
		t.Fatalf("release = %+v err %v", rel, err)
	}

	// A preview route exists in the gateway under *.preview.bh.example.
	if len(w.gw.routes) != 1 {
		t.Fatalf("gateway routes = %v", w.gw.routes)
	}
	for host, rt := range w.gw.routes {
		if !strings.Contains(host, ".preview.bh.example") || rt.Kind != gateway.Preview ||
			rt.BackendAddr != "172.18.0.9:8080" {
			t.Fatalf("route = %+v", rt)
		}
	}

	// The pause timer is durably armed.
	pauses := w.armedPauses(t)
	if len(pauses) != 1 || pauses[0].BeamID != string(beam.ID) {
		t.Fatalf("armed pauses = %+v", pauses)
	}

	// Audit: decision+outcome pairs for create, 2x set_secret, deploy = 8.
	recs, err := w.st.ListAuditEvents(ctx, 0, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 8 {
		t.Fatalf("audit events = %d, want 8 (4 ops x decision+outcome)", len(recs))
	}
	last := recs[len(recs)-1].Event
	if last.Action != "deploy_beam" || last.ResultStatus != "ok" {
		t.Fatalf("last audit event = %+v", last)
	}
}

// TestSecretRefsDedupesSharedAndChannelSpecificKey proves the fix: a
// user-set shared secret and a channel-specific secret (a database DSN)
// sharing the same key must not both be injected — every secret mounts to
// /run/secrets/<key> regardless of channel, so two refs with the same key
// would collide on that path. The channel-specific one must win.
func TestSecretRefsDedupesSharedAndChannelSpecificKey(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	prov := &fakeProvisioner{}
	WithDatabaseProvisioner(prov)(w.o)

	beam, err := w.o.CreateBeam(ctx, w.build, w.bh.ID, "tracker", "Tracker", "", "node")
	if err != nil {
		t.Fatalf("CreateBeam: %v", err)
	}
	// A user-set shared secret using the SAME key a "main" database's DSN
	// would use (dbSecretKey("main") == "MAIN_URL").
	if err := w.o.SetSecret(ctx, w.build, w.bh.ID, beam.ID, "MAIN_URL", []byte("manually-set-value")); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}
	if _, err := w.o.CreateDatabase(ctx, w.build, w.bh.ID, beam.ID, "main"); err != nil {
		t.Fatalf("CreateDatabase: %v", err)
	}

	beam, err = w.o.DeployBeam(ctx, w.build, w.bh.ID, beam.ID,
		DeployRequest{ImageRef: "reg/tracker:1", ImageDigest: "sha256:abc"})
	if err != nil {
		t.Fatalf("DeployBeam: %v", err)
	}

	spec := w.drv.deploys[len(w.drv.deploys)-1]
	var matches []driver.SecretMount
	for _, m := range spec.Secrets {
		if m.MountPath == "/run/secrets/MAIN_URL" {
			matches = append(matches, m)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("want exactly one mount at /run/secrets/MAIN_URL (Docker rejects a duplicate target), got %d: %+v", len(matches), matches)
	}
	if !strings.Contains(string(matches[0].Value), "postgres://") {
		t.Fatalf("the channel-specific database DSN should win over the shared secret, got %q", matches[0].Value)
	}
}

func TestDeployStartFailure(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	beam, err := w.o.CreateBeam(ctx, w.build, w.bh.ID, "flaky", "Flaky", "", "node")
	if err != nil {
		t.Fatal(err)
	}
	w.drv.startErr = errors.New("entrypoint crashed")

	_, err = w.o.DeployBeam(ctx, w.build, w.bh.ID, beam.ID,
		DeployRequest{ImageDigest: "sha256:bad"})
	if err == nil || !strings.Contains(err.Error(), "entrypoint crashed") {
		t.Fatalf("deploy err = %v", err)
	}

	got, err := w.st.GetBeam(ctx, beam.ID)
	if err != nil || got.State != domain.StateFailed {
		t.Fatalf("beam after failed start = %s (err %v), want failed", got.State, err)
	}
	recs, _ := w.st.ListAuditEvents(ctx, 0, 20)
	last := recs[len(recs)-1].Event
	if last.ResultStatus != "failed" || !strings.Contains(last.Reason, "entrypoint crashed") {
		t.Fatalf("outcome event = %+v", last)
	}
}

// TestSpawnWorkloadCleansUpOnStartFailure is a regression test:
// once
// drv.Deploy has created a container (with its secrets already staged), a
// later failure in the bring-up sequence (here, drv.Start) must tear that
// container down — not leak it and its staged secret files with nothing
// left referencing them.
func TestSpawnWorkloadCleansUpOnStartFailure(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	beam, err := w.o.CreateBeam(ctx, w.build, w.bh.ID, "flaky", "Flaky", "", "node")
	if err != nil {
		t.Fatal(err)
	}
	w.drv.startErr = errors.New("entrypoint crashed")

	if _, err := w.o.DeployBeam(ctx, w.build, w.bh.ID, beam.ID,
		DeployRequest{ImageDigest: "sha256:bad"}); err == nil {
		t.Fatal("expected the deploy to fail")
	}
	if len(w.drv.deploys) != 1 {
		t.Fatalf("deploys = %d, want exactly 1 (the failed attempt)", len(w.drv.deploys))
	}
	deployedRef := "ctr-" + string(beam.ID) + fmt.Sprint(len(w.drv.deploys))
	if len(w.drv.destroyed) != 1 || w.drv.destroyed[0] != deployedRef {
		t.Fatalf("destroyed = %v, want the failed container %q cleaned up (not leaked)", w.drv.destroyed, deployedRef)
	}
}

func TestPauseRetiresRouteAndResumeMintsNewURL(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	beam := w.deployed(t, "app1")

	var firstHost string
	for h := range w.gw.routes {
		firstHost = h
	}

	if err := w.o.PausePreview(ctx, w.build, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("PausePreview: %v", err)
	}
	if got, _ := w.st.GetBeam(ctx, beam.ID); got.State != domain.StatePaused {
		t.Fatalf("state = %s, want paused", got.State)
	}
	if len(w.drv.paused) != 1 {
		t.Fatal("driver.Pause not called")
	}
	if len(w.gw.routes) != 0 {
		t.Fatalf("paused preview still routed: %v", w.gw.routes)
	}
	if pauses := w.armedPauses(t); len(pauses) != 0 {
		t.Fatalf("timer still armed after manual pause: %+v", pauses)
	}

	host, err := w.o.ResumePreview(ctx, w.build, w.bh.ID, beam.ID)
	if err != nil {
		t.Fatalf("ResumePreview: %v", err)
	}
	if host == firstHost {
		t.Fatal("resume reused the old preview URL; must mint a fresh one")
	}
	if got, _ := w.st.GetBeam(ctx, beam.ID); got.State != domain.StateRunning || got.ResumedAt.IsZero() {
		t.Fatalf("after resume: %+v", got)
	}
	if len(w.drv.resumed) != 1 || len(w.gw.routes) != 1 {
		t.Fatalf("resume effects: resumed=%d routes=%v", len(w.drv.resumed), w.gw.routes)
	}
	if pauses := w.armedPauses(t); len(pauses) != 1 {
		t.Fatal("timer not re-armed after resume")
	}
}

func TestSchedulerPauseFuncPausesViaOrchestrator(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	beam := w.deployed(t, "sleepy")

	// Fire the scheduler's path directly (the loop is not running in tests).
	if err := w.o.PauseFunc()(ctx, string(beam.ID)); err != nil {
		t.Fatalf("PauseFunc: %v", err)
	}
	if got, _ := w.st.GetBeam(ctx, beam.ID); got.State != domain.StatePaused {
		t.Fatalf("state = %s, want paused", got.State)
	}
	// After promote, the preview channel keeps running and still auto-pauses on
	// its timer; the live channel (production) is unaffected.
	live := w.deployed(t, "livebeam")
	if _, err := w.o.PromoteToLive(ctx, w.admin, w.bh.ID, live.ID); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if err := w.o.PauseFunc()(ctx, string(live.ID)); err != nil {
		t.Fatalf("preview pause after promote must succeed: %v", err)
	}
	if got, _ := w.st.GetBeam(ctx, live.ID); got.State != domain.StatePaused || got.LiveState != domain.StateLive {
		t.Fatalf("after preview pause: state=%s live=%s, want paused/live", got.State, got.LiveState)
	}
}

func TestArchivePreviewBuilderSelfServiceLiveGated(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()

	// A builder shelves their own preview beam (rejected idea).
	beam := w.deployed(t, "rejected")
	if err := w.o.ArchiveBeam(ctx, w.build, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("builder archive preview: %v", err)
	}
	got, _ := w.st.GetBeam(ctx, beam.ID)
	if got.Status != domain.BeamArchived {
		t.Fatalf("status = %s, want archived", got.Status)
	}
	// Archived beam frees its slug: the name can be reused.
	if _, err := w.o.CreateBeam(ctx, w.build, w.bh.ID, "rejected", "rejected", "", "node"); err != nil {
		t.Fatalf("re-create archived slug: %v", err)
	}

	// A LIVE beam cannot be archived via the builder path (preview-only); live
	// teardown is IT-gated through destroy_beam.
	live := w.deployed(t, "shipped")
	if _, err := w.o.PromoteToLive(ctx, w.admin, w.bh.ID, live.ID); err != nil {
		t.Fatalf("promote: %v", err)
	}
	err := w.o.ArchiveBeam(ctx, w.build, w.bh.ID, live.ID)
	if err == nil || !strings.Contains(err.Error(), "live") {
		t.Fatalf("archive live beam = %v, want a live-gated refusal", err)
	}
	if got, _ := w.st.GetBeam(ctx, live.ID); got.Status != domain.BeamActive {
		t.Fatalf("live beam status = %s after refused archive, want active", got.Status)
	}
}

func TestPromoteBuilderDeniedAdminAllowed(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	beam := w.deployed(t, "tracker")

	// The demo's 403: builder cannot promote, and the denial is audited.
	_, err := w.o.PromoteToLive(ctx, w.build, w.bh.ID, beam.ID)
	var denial *policy.Denial
	if !errors.As(err, &denial) {
		t.Fatalf("builder promote = %v, want *policy.Denial", err)
	}

	host, err := w.o.PromoteToLive(ctx, w.admin, w.bh.ID, beam.ID)
	if err != nil {
		t.Fatalf("admin promote: %v", err)
	}
	if host != "tracker.ops.bh.example" {
		t.Fatalf("live host = %q", host)
	}
	got, _ := w.st.GetBeam(ctx, beam.ID)
	if got.Mode != domain.ModeLive || got.State != domain.StateRunning {
		t.Fatalf("after promote: mode=%s state=%s, want live/running (preview keeps running)", got.Mode, got.State)
	}
	if got.LiveState != domain.StateLive {
		t.Fatalf("live channel state = %q, want live", got.LiveState)
	}
	if rt, ok := w.gw.routes[host]; !ok || rt.Kind != gateway.Live {
		t.Fatalf("live route missing: %v", w.gw.routes)
	}
	// The preview channel survives promote — the builder keeps iterating on its
	// stable preview URL while production runs the pinned live build.
	if got.PreviewHost == "" {
		t.Fatal("preview host cleared by promote")
	}
	if rt, ok := w.gw.routes[got.PreviewHost]; !ok || rt.Kind != gateway.Preview {
		t.Fatalf("preview route should remain active after promote: %v", w.gw.routes)
	}
	if len(w.gw.routes) != 2 {
		t.Fatalf("want both preview + live routes after promote: %v", w.gw.routes)
	}
	// The preview channel keeps auto-pausing after promote (production never
	// pauses, but the builder's preview still idles out).
	if pauses := w.armedPauses(t); len(pauses) != 1 {
		t.Fatalf("preview pause timer should stay armed after promote, got %d", len(pauses))
	}

	// Slot exhausted: second promote fails with the quota error.
	beam2 := w.deployed(t, "second")
	if _, err := w.o.PromoteToLive(ctx, w.admin, w.bh.ID, beam2.ID); !errors.Is(err, store.ErrQuota) {
		t.Fatalf("second promote = %v, want ErrQuota", err)
	}
}

func TestRedeploySupersedesPreviousRelease(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	beam := w.deployed(t, "app1")
	firstRel := beam.CurrentReleaseID

	beam2, err := w.o.DeployBeam(ctx, w.build, w.bh.ID, beam.ID,
		DeployRequest{ImageRef: "reg/beam:2", ImageDigest: "sha256:def"})
	if err != nil {
		t.Fatalf("redeploy: %v", err)
	}
	if beam2.CurrentReleaseID == firstRel {
		t.Fatal("redeploy did not mint a new release")
	}
	old, err := w.st.GetRelease(ctx, firstRel)
	if err != nil || old.Status != domain.ReleaseSuperseded {
		t.Fatalf("old release = %s (err %v), want superseded", old.Status, err)
	}
	if len(w.drv.destroyed) != 1 {
		t.Fatalf("old workload not destroyed: %v", w.drv.destroyed)
	}
	// Exactly one active route (the new one).
	if len(w.gw.routes) != 1 {
		t.Fatalf("routes after redeploy: %v", w.gw.routes)
	}
	if n, _ := w.st.ListReleasesByBeam(ctx, beam.ID); len(n) != 2 {
		t.Fatalf("releases = %d, want 2 (history retained for rollback)", len(n))
	}
}

// TestRedeployFinalizeFailureLeavesBeamPointingAtNewRelease is a regression
// test: if
// finalizeActiveRelease fails (here, the gateway rejects the route Upsert)
// AFTER the predecessor has already been retired/destroyed, the beam must
// still point CurrentReleaseID at the new (running, active) release — not the
// old one, which no longer has a workload to serve requests from.
func TestRedeployFinalizeFailureLeavesBeamPointingAtNewRelease(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	beam := w.deployed(t, "app1")
	firstRel := beam.CurrentReleaseID

	w.gw.upsertErr = errors.New("caddy admin API unreachable")
	if _, err := w.o.DeployBeam(ctx, w.build, w.bh.ID, beam.ID,
		DeployRequest{ImageRef: "reg/beam:2", ImageDigest: "sha256:def"}); err == nil {
		t.Fatal("expected the redeploy to fail (gateway rejected the route)")
	}
	w.gw.upsertErr = nil

	got, err := w.st.GetBeam(ctx, beam.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.CurrentReleaseID == firstRel {
		t.Fatalf("beam still points at the OLD release %s, which has no workload (retired/destroyed) — every subsequent op on this beam fails confusingly until it's destroyed", firstRel)
	}
	if got.CurrentReleaseID == "" {
		t.Fatal("beam has no CurrentReleaseID at all after the failed finalize")
	}
	newRel, err := w.st.GetRelease(ctx, got.CurrentReleaseID)
	if err != nil {
		t.Fatalf("GetRelease(CurrentReleaseID): %v", err)
	}
	if newRel.Status != domain.ReleaseActive {
		t.Fatalf("beam's CurrentReleaseID release status = %s, want active", newRel.Status)
	}
}

func TestShowLogsScrubsSecrets(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	beam, err := w.o.CreateBeam(ctx, w.build, w.bh.ID, "leaky", "Leaky", "", "node")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.o.SetSecret(ctx, w.build, w.bh.ID, beam.ID, "API_KEY", []byte("super-secret-value")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.o.DeployBeam(ctx, w.build, w.bh.ID, beam.ID, DeployRequest{ImageDigest: "sha256:x"}); err != nil {
		t.Fatal(err)
	}
	w.drv.logContent = "boot ok\nconnecting with key=super-secret-value\ndone\n"

	out, err := w.o.ShowLogs(ctx, w.build, w.bh.ID, beam.ID, driver.LogOptions{})
	if err != nil {
		t.Fatalf("ShowLogs: %v", err)
	}
	if bytes.Contains(out, []byte("super-secret-value")) {
		t.Fatalf("secret leaked through logs: %s", out)
	}
	if !bytes.Contains(out, []byte(secret.Mask)) || !bytes.Contains(out, []byte("boot ok")) {
		t.Fatalf("scrubbed output mangled: %s", out)
	}

	// Viewer can read logs; outsider cannot.
	if _, err := w.o.ShowLogs(ctx, w.admin, w.bh.ID, beam.ID, driver.LogOptions{}); err != nil {
		t.Fatalf("admin ShowLogs: %v", err)
	}
}

func TestBootRestoresRoutes(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.deployed(t, "app1")
	beam2 := w.deployed(t, "app2")
	if _, err := w.o.PromoteToLive(ctx, w.admin, w.bh.ID, beam2.ID); err != nil {
		t.Fatal(err)
	}

	// Simulate restart: empty gateway, then Boot.
	w.gw.routes = map[string]gateway.Route{}
	if err := w.o.Boot(ctx); err != nil {
		t.Fatalf("Boot: %v", err)
	}
	// app1 preview + app2 preview + app2 live are all active: promote adds the
	// live route without retiring app2's preview (the builder keeps iterating).
	if len(w.gw.routes) != 3 {
		t.Fatalf("restored routes = %v", w.gw.routes)
	}
	if rt, ok := w.gw.routes["app2.ops.bh.example"]; !ok || rt.Kind != gateway.Live {
		t.Fatalf("live route not restored: %v", w.gw.routes)
	}
	live, _ := w.st.GetBeam(ctx, beam2.ID)
	if rt, ok := w.gw.routes[live.PreviewHost]; !ok || rt.Kind != gateway.Preview {
		t.Fatalf("app2 preview route not restored after promote: %v", w.gw.routes)
	}
}

// fakeBuilder satisfies Builder with a canned result.
type fakeBuilder struct {
	calls []string // "<hall>/<beam>:<srcDir>"
	res   build.Result
	err   error
}

func (b *fakeBuilder) BuildFromDir(ctx context.Context, hallSlug, beamSlug, srcDir string) (build.Result, error) {
	b.calls = append(b.calls, hallSlug+"/"+beamSlug+":"+srcDir)
	return b.res, b.err
}

func (b *fakeBuilder) BuildFromCommit(ctx context.Context, hallSlug, beamSlug, sha string) (build.Result, error) {
	b.calls = append(b.calls, hallSlug+"/"+beamSlug+"@"+sha)
	return b.res, b.err
}

func TestDeployBeamFromSource(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()

	fb := &fakeBuilder{res: build.Result{
		SourceSHA:   strings.Repeat("a", 40),
		Builder:     "paketobuildpacks/builder-jammy-base",
		ImageRef:    "127.0.0.1:5000/ops/src1:aaaaaaaaaaaa",
		ImageDigest: "sha256:feed",
		PullRef:     "127.0.0.1:5000/ops/src1@sha256:feed",
	}}
	WithBuilder(fb)(w.o)

	beam, err := w.o.CreateBeam(ctx, w.build, w.bh.ID, "src1", "Src1", "", "node")
	if err != nil {
		t.Fatal(err)
	}
	beam, err = w.o.DeployBeamFromSource(ctx, w.build, w.bh.ID, beam.ID, "/tmp/some-src")
	if err != nil {
		t.Fatalf("DeployBeamFromSource: %v", err)
	}
	if beam.State != domain.StateRunning {
		t.Fatalf("state = %s", beam.State)
	}
	if len(fb.calls) != 1 || fb.calls[0] != "ops/src1:/tmp/some-src" {
		t.Fatalf("builder calls = %v", fb.calls)
	}

	// The Build row carries the source pin; the driver deployed the pull ref.
	builds, err := w.st.ListBuildsByBeam(ctx, beam.ID)
	if err != nil || len(builds) != 1 {
		t.Fatalf("builds = %v err %v", builds, err)
	}
	b := builds[0]
	if b.SourceRef != fb.res.SourceSHA || b.SourceKind != domain.SourceManagedGit ||
		b.ImageDigest != "sha256:feed" || b.Builder != fb.res.Builder {
		t.Fatalf("build row = %+v", b)
	}
	if got := w.drv.deploys[len(w.drv.deploys)-1].ImageDigest; got != fb.res.PullRef {
		t.Fatalf("driver image = %q, want pull ref %q", got, fb.res.PullRef)
	}

	// Builder failure lands the beam in failed.
	beam2, err := w.o.CreateBeam(ctx, w.build, w.bh.ID, "src2", "Src2", "", "node")
	if err != nil {
		t.Fatal(err)
	}
	fb.err = errors.New("detect phase found no buildpack")
	if _, err := w.o.DeployBeamFromSource(ctx, w.build, w.bh.ID, beam2.ID, "/tmp/x"); err == nil {
		t.Fatal("want builder error")
	}
	if got, _ := w.st.GetBeam(ctx, beam2.ID); got.State != domain.StateFailed {
		t.Fatalf("state after failed build = %s", got.State)
	}

	// Without a builder configured the path refuses cleanly.
	WithBuilder(nil)(w.o)
	beam3, _ := w.o.CreateBeam(ctx, w.build, w.bh.ID, "src3", "Src3", "", "node")
	if _, err := w.o.DeployBeamFromSource(ctx, w.build, w.bh.ID, beam3.ID, "/tmp/x"); err == nil ||
		!strings.Contains(err.Error(), "no build pipeline") {
		t.Fatalf("want no-pipeline error, got %v", err)
	}
}

// fakeProvisioner satisfies DatabaseProvisioner. Mutex-guarded (like
// fakeDriver/fakeGateway) so concurrency tests exercise a race in the
// orchestrator, not a data race in this test double.
type fakeProvisioner struct {
	mu          sync.Mutex
	provisioned []resource.Request
	dropped     []string
	setErr      bool // makes the vault path fail via an invalid... (unused)
}

func (p *fakeProvisioner) Provision(ctx context.Context, req resource.Request) (resource.Provisioned, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.provisioned = append(p.provisioned, req)
	db := "bh_" + req.BeamhallSlug + "_" + req.BeamSlug + "_" + req.Name
	return resource.Provisioned{
		DSN:      "postgres://" + db + "_rw:pw@bh-postgres:5432/" + db + "?sslmode=disable",
		Database: db,
		Role:     db + "_rw",
	}, nil
}

func (p *fakeProvisioner) Drop(ctx context.Context, pr resource.Provisioned) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dropped = append(p.dropped, pr.Database)
	return nil
}

func TestCreateDatabaseSealsDSNAndInjectsOnDeploy(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	prov := &fakeProvisioner{}
	WithDatabaseProvisioner(prov)(w.o)

	beam, err := w.o.CreateBeam(ctx, w.build, w.bh.ID, "tracker", "Tracker", "", "node")
	if err != nil {
		t.Fatal(err)
	}

	key, err := w.o.CreateDatabase(ctx, w.build, w.bh.ID, beam.ID, "main")
	if err != nil {
		t.Fatalf("CreateDatabase: %v", err)
	}
	if key != "MAIN_URL" {
		t.Fatalf("secret key = %q", key)
	}
	if len(prov.provisioned) != 1 || prov.provisioned[0].Network != "bh-"+string(w.bh.ID) {
		t.Fatalf("provision requests = %+v", prov.provisioned)
	}

	// The DSN is sealed in the vault (metadata exists; value never readable
	// through any API) and the Resource row records the linkage.
	if _, err := w.st.GetSecret(ctx, w.bh.ID, beam.ID, key, domain.ChannelPreview); err != nil {
		t.Fatalf("vault secret metadata missing: %v", err)
	}
	resources, err := w.st.ListResourcesByBeam(ctx, beam.ID)
	if err != nil || len(resources) != 1 {
		t.Fatalf("resources = %v err %v", resources, err)
	}
	r := resources[0]
	if r.Type != domain.ResourceDatabase || r.Status != domain.ResourceReady ||
		r.ConnectionSecretRef.Key != key || r.Spec["database"] != "bh_ops_tracker_main" {
		t.Fatalf("resource row = %+v", r)
	}

	// The DSN never appears in the audit chain.
	recs, _ := w.st.ListAuditEvents(ctx, 0, 50)
	for _, rec := range recs {
		if strings.Contains(rec.Event.Reason, "postgres://") {
			t.Fatalf("DSN leaked into audit event: %+v", rec.Event)
		}
	}

	// Quota: MaxDBCount=1 → second database refused with a QuotaError.
	var qe *policy.QuotaError
	if _, err := w.o.CreateDatabase(ctx, w.build, w.bh.ID, beam.ID, "extra"); !errors.As(err, &qe) {
		t.Fatalf("second database = %v, want *policy.QuotaError", err)
	}

	// The next deploy injects the DSN as a file mount, hands-free.
	if _, err := w.o.DeployBeam(ctx, w.build, w.bh.ID, beam.ID, DeployRequest{ImageDigest: "sha256:x"}); err != nil {
		t.Fatal(err)
	}
	spec := w.drv.deploys[len(w.drv.deploys)-1]
	var dsnMount string
	for _, m := range spec.Secrets {
		if m.MountPath == "/run/secrets/MAIN_URL" {
			dsnMount = string(m.Value)
		}
	}
	if !strings.HasPrefix(dsnMount, "postgres://bh_ops_tracker_main_rw:") {
		t.Fatalf("DSN not injected on deploy: %q (mounts %+v)", dsnMount, spec.Secrets)
	}

	// Without a provisioner the path refuses cleanly.
	WithDatabaseProvisioner(nil)(w.o)
	if _, err := w.o.CreateDatabase(ctx, w.build, w.bh.ID, beam.ID, "x"); err == nil ||
		!strings.Contains(err.Error(), "no database provisioner") {
		t.Fatalf("want no-provisioner error, got %v", err)
	}
}

// TestConcurrentCreateBeamNeverExceedsQuota is a regression test:
// concurrent create_beam calls
// racing for the beamhall's LAST beam slot (MaxBeams=5 in the world fixture)
// must not both succeed — a plain count-then-insert lets both pass the same
// pre-check and together exceed quota. Run with -race.
func TestConcurrentCreateBeamNeverExceedsQuota(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	for i := 0; i < 4; i++ { // MaxBeams=5: fill 4 slots, leaving exactly 1
		if _, err := w.o.CreateBeam(ctx, w.build, w.bh.ID, fmt.Sprintf("filler-%d", i), "", "", "node"); err != nil {
			t.Fatalf("filler CreateBeam %d: %v", i, err)
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	results := make([]error, 2)
	for i := range 2 {
		go func(i int) {
			defer wg.Done()
			_, err := w.o.CreateBeam(ctx, w.build, w.bh.ID, fmt.Sprintf("race-%d", i), "", "", "node")
			results[i] = err
		}(i)
	}
	wg.Wait()

	succeeded := 0
	for _, err := range results {
		if err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("succeeded = %d of 2 concurrent create_beam calls for the last slot (MaxBeams=5), want exactly 1", succeeded)
	}
	n, err := w.st.CountBeamsByBeamhall(ctx, w.bh.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Fatalf("beam count = %d, want exactly 5 (quota exceeded)", n)
	}
}

// TestConcurrentCreateDatabaseNeverExceedsQuota is a regression test:
// two concurrent create_database
// calls racing for the beamhall's LAST db slot (MaxDBCount=1 in the world
// fixture) must not both succeed — a plain count-then-insert lets both pass
// the same pre-check and together exceed quota. Run with -race.
func TestConcurrentCreateDatabaseNeverExceedsQuota(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	prov := &fakeProvisioner{}
	WithDatabaseProvisioner(prov)(w.o)
	beam := w.deployed(t, "tracker")

	var wg sync.WaitGroup
	wg.Add(2)
	results := make([]error, 2)
	for i := range 2 {
		go func(i int) {
			defer wg.Done()
			_, err := w.o.CreateDatabase(ctx, w.build, w.bh.ID, beam.ID, fmt.Sprintf("db%d", i))
			results[i] = err
		}(i)
	}
	wg.Wait()

	succeeded := 0
	for _, err := range results {
		if err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("succeeded = %d of 2 concurrent create_database calls for the last slot (MaxDBCount=1), want exactly 1", succeeded)
	}
	n, err := w.st.CountResourcesByType(ctx, w.bh.ID, domain.ResourceDatabase)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("database resource count = %d, want exactly 1 (quota exceeded)", n)
	}
	// The loser's provisioned database must have been rolled back, not leaked.
	if len(prov.dropped) != 1 {
		t.Fatalf("dropped = %v, want the loser's provisioned database rolled back exactly once", prov.dropped)
	}
}

// create_database is idempotent per (beam,name): a re-call returns the same key
// without re-provisioning — a non-expert agent may call it twice.
func TestCreateDatabaseIdempotent(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	prov := &fakeProvisioner{}
	WithDatabaseProvisioner(prov)(w.o)
	beam, _ := w.o.CreateBeam(ctx, w.build, w.bh.ID, "tracker", "Tracker", "", "node")

	k1, err := w.o.CreateDatabase(ctx, w.build, w.bh.ID, beam.ID, "main")
	if err != nil {
		t.Fatal(err)
	}
	k2, err := w.o.CreateDatabase(ctx, w.build, w.bh.ID, beam.ID, "main")
	if err != nil {
		t.Fatalf("re-calling create_database for the same name must be a no-op: %v", err)
	}
	if k1 != k2 || k2 != "MAIN_URL" {
		t.Fatalf("keys differ: %q vs %q", k1, k2)
	}
	if len(prov.provisioned) != 1 {
		t.Fatalf("provisioned %d times, want 1 (idempotent)", len(prov.provisioned))
	}
}

// Tearing down a beam must reclaim its database (drop the backing db/role and
// free the quota slot), or repeated archive/redeploy cycles exhaust max_db_count.
func TestDestroyReclaimsDatabase(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	prov := &fakeProvisioner{}
	WithDatabaseProvisioner(prov)(w.o)
	beam, _ := w.o.CreateBeam(ctx, w.build, w.bh.ID, "tracker", "Tracker", "", "node")
	if _, err := w.o.CreateDatabase(ctx, w.build, w.bh.ID, beam.ID, "main"); err != nil {
		t.Fatal(err)
	}

	if err := w.o.DestroyBeam(ctx, w.admin, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if len(prov.dropped) != 1 || prov.dropped[0] != "bh_ops_tracker_main" {
		t.Fatalf("backing db not dropped on destroy: %v", prov.dropped)
	}
	if res, _ := w.st.ListResourcesByBeam(ctx, beam.ID); len(res) != 0 {
		t.Fatalf("resource rows after destroy = %d, want 0", len(res))
	}
	if n, _ := w.st.CountResourcesByType(ctx, w.bh.ID, domain.ResourceDatabase); n != 0 {
		t.Fatalf("db quota count after destroy = %d, want 0 (slot reclaimed)", n)
	}
	// The sealed DSN must not survive the beam's destruction as a
	// decryptable orphan.
	if _, err := w.st.GetSecret(ctx, w.bh.ID, beam.ID, "MAIN_URL", domain.ChannelPreview); err == nil {
		t.Fatal("sealed database DSN still present after destroy")
	}
}

// TestDestroySweepsUserSecrets proves the fix: a beam-scoped secret set
// directly via set_secret (no domain.Resource row) must be swept on destroy,
// not left as a decryptable orphan with no way to ever reach or delete it
// again. A beamhall-wide secret (no beam) must survive.
func TestDestroySweepsUserSecrets(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	beam, _ := w.o.CreateBeam(ctx, w.build, w.bh.ID, "tracker", "Tracker", "", "node")

	if err := w.o.SetSecret(ctx, w.build, w.bh.ID, beam.ID, "API_TOKEN", []byte("s3cr3t")); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}
	if err := w.o.SetSecret(ctx, w.build, w.bh.ID, "", "SHARED_KEY", []byte("shared")); err != nil {
		t.Fatalf("SetSecret (beamhall-wide): %v", err)
	}

	if err := w.o.DestroyBeam(ctx, w.admin, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("destroy: %v", err)
	}

	if _, err := w.st.GetSecret(ctx, w.bh.ID, beam.ID, "API_TOKEN", ""); err == nil {
		t.Fatal("beam-scoped user secret still present after destroy")
	}
	if _, err := w.st.GetSecret(ctx, w.bh.ID, "", "SHARED_KEY", ""); err != nil {
		t.Fatalf("beamhall-wide secret was swept by an unrelated beam's destroy: %v", err)
	}
}

// Promote must give the live channel its OWN database under the same app key, so
// production never reads or writes the builder's preview data. The live mirror
// does not count against MaxDBCount (=1 here), and re-promote reuses it so
// production data survives a version bump.
func TestPromoteIsolatesLiveDatabase(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	prov := &fakeProvisioner{}
	WithDatabaseProvisioner(prov)(w.o)

	beam := w.deployed(t, "tracker")
	key, err := w.o.CreateDatabase(ctx, w.build, w.bh.ID, beam.ID, "main")
	if err != nil {
		t.Fatalf("CreateDatabase: %v", err)
	}
	if _, err := w.o.PromoteToLive(ctx, w.admin, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("promote: %v", err)
	}

	// One database per channel, physically distinct.
	preview, _ := w.st.ListResourcesByBeamAndChannel(ctx, beam.ID, domain.ChannelPreview)
	live, _ := w.st.ListResourcesByBeamAndChannel(ctx, beam.ID, domain.ChannelLive)
	if len(preview) != 1 || len(live) != 1 {
		t.Fatalf("channel resource counts: preview=%d live=%d, want 1/1", len(preview), len(live))
	}
	if preview[0].Spec["database"] == live[0].Spec["database"] {
		t.Fatalf("live shares the preview database %q — production is not isolated", live[0].Spec["database"])
	}

	// Same app key, different sealed DSN per channel.
	pv, err := w.st.GetSecret(ctx, w.bh.ID, beam.ID, key, domain.ChannelPreview)
	if err != nil {
		t.Fatalf("preview secret: %v", err)
	}
	lv, err := w.st.GetSecret(ctx, w.bh.ID, beam.ID, key, domain.ChannelLive)
	if err != nil {
		t.Fatalf("live secret: %v", err)
	}
	if pv.ValueRef == lv.ValueRef {
		t.Fatal("preview and live DSNs point at the same ciphertext — not isolated")
	}

	// Re-promote a new build reuses the live database (production data persists).
	if _, err := w.o.DeployBeam(ctx, w.build, w.bh.ID, beam.ID,
		DeployRequest{ImageRef: "reg/beam:2", ImageDigest: "sha256:def"}); err != nil {
		t.Fatalf("redeploy: %v", err)
	}
	if _, err := w.o.PromoteToLive(ctx, w.admin, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("re-promote: %v", err)
	}
	live2, _ := w.st.ListResourcesByBeamAndChannel(ctx, beam.ID, domain.ChannelLive)
	if len(live2) != 1 || live2[0].Spec["database"] != live[0].Spec["database"] {
		t.Fatalf("re-promote did not reuse the live database: %v", live2)
	}

	// Destroy reclaims BOTH channels' databases.
	if err := w.o.DestroyBeam(ctx, w.admin, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if len(prov.dropped) != 2 {
		t.Fatalf("dropped %d databases on destroy, want 2 (preview + live)", len(prov.dropped))
	}
}

// TestRepromoteGatewayFailureLeavesProductionRouteIntact is a regression
// test: a
// re-promote whose gateway Upsert fails must leave the OLD live route active
// (never zero active routes for the stable hostname) and beam.LiveReleaseID
// unchanged — so a restart's boot-route-restore still finds a route to
// program, instead of production 404ing until someone re-promotes.
func TestRepromoteGatewayFailureLeavesProductionRouteIntact(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	beam := w.deployed(t, "tracker")

	if _, err := w.o.PromoteToLive(ctx, w.admin, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("promote v1: %v", err)
	}
	got, _ := w.st.GetBeam(ctx, beam.ID)
	liveRel1 := got.LiveReleaseID
	routes1, err := w.st.ListRoutesByBeam(ctx, beam.ID)
	if err != nil {
		t.Fatal(err)
	}
	var liveRouteID domain.ID
	for _, r := range routes1 {
		if r.Kind == domain.RouteLive && r.Status == domain.RouteActive {
			liveRouteID = r.ID
		}
	}
	if liveRouteID == "" {
		t.Fatal("setup: no active live route after first promote")
	}

	// New preview build, then re-promote — but the gateway rejects the Upsert
	// (a Caddy admin API hiccup).
	if _, err := w.o.DeployBeam(ctx, w.build, w.bh.ID, beam.ID,
		DeployRequest{ImageRef: "reg/beam:2", ImageDigest: "sha256:def"}); err != nil {
		t.Fatalf("redeploy preview: %v", err)
	}
	w.gw.upsertErr = errors.New("caddy admin API unreachable")
	if _, err := w.o.PromoteToLive(ctx, w.admin, w.bh.ID, beam.ID); err == nil {
		t.Fatal("re-promote should have failed when the gateway rejected the Upsert")
	}
	w.gw.upsertErr = nil

	// Production is untouched: same live release, same active route.
	got, _ = w.st.GetBeam(ctx, beam.ID)
	if got.LiveReleaseID != liveRel1 {
		t.Fatalf("live release changed to %s despite a failed re-promote, want unchanged %s", got.LiveReleaseID, liveRel1)
	}
	rt, err := w.st.GetRoute(ctx, liveRouteID)
	if err != nil {
		t.Fatalf("GetRoute: %v", err)
	}
	if rt.Status != domain.RouteActive {
		t.Fatalf("original live route status = %s, want still active (zero-active-route window after a failed re-promote)", rt.Status)
	}
	// Exactly one active route for the live hostname — no orphaned duplicate
	// from a partially-applied swap.
	active := 0
	for _, r := range mustListRoutes(t, w, beam.ID) {
		if r.Kind == domain.RouteLive && r.Status == domain.RouteActive {
			active++
		}
	}
	if active != 1 {
		t.Fatalf("active live routes = %d, want exactly 1", active)
	}
}

func mustListRoutes(t *testing.T, w *world, beamID domain.ID) []domain.Route {
	t.Helper()
	rs, err := w.st.ListRoutesByBeam(context.Background(), beamID)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func TestDeployCrashOnStartupIsDiagnosed(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()

	beam, err := w.o.CreateBeam(ctx, w.build, w.bh.ID, "crasher", "Crasher", "", "node")
	if err != nil {
		t.Fatalf("CreateBeam: %v", err)
	}
	if err := w.o.SetSecret(ctx, w.build, w.bh.ID, beam.ID, "API_TOKEN", []byte("crash-secret-value")); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}

	// The workload dies right after start; its logs leak the secret and show
	// a read-only-rootfs write.
	code := 1
	w.drv.exitCode = &code
	w.drv.logContent = "boot with token crash-secret-value\nError: EROFS: read-only file system, open '/app/data.json'\n"

	_, err = w.o.DeployBeam(ctx, w.build, w.bh.ID, beam.ID,
		DeployRequest{ImageRef: "reg/beam:1", ImageDigest: "sha256:abc"})
	if err == nil {
		t.Fatal("crash-on-startup deploy reported success")
	}
	msg := err.Error()
	for _, want := range []string{"exited during startup with code 1", "/tmp", "EROFS", "***REDACTED***"} {
		if !strings.Contains(msg, want) {
			t.Errorf("diagnosis missing %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "crash-secret-value") {
		t.Fatal("diagnosis leaked a secret value")
	}

	got, err := w.st.GetBeam(ctx, beam.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != domain.StateFailed {
		t.Errorf("beam state = %s, want failed", got.State)
	}
}

func TestDeployFailsClosedWhenEgressSyncFails(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	synced := 0
	WithEgressSync(func(ctx context.Context) error {
		synced++
		if synced == 1 {
			return nil
		}
		return errors.New("iptables exploded")
	})(w.o)

	w.deployed(t, "ok-beam") // first sync succeeds

	beam, err := w.o.CreateBeam(ctx, w.build, w.bh.ID, "unprotected", "U", "", "node")
	if err != nil {
		t.Fatal(err)
	}
	_, err = w.o.DeployBeam(ctx, w.build, w.bh.ID, beam.ID,
		DeployRequest{ImageRef: "reg/x:1", ImageDigest: "sha256:x"})
	if err == nil || !strings.Contains(err.Error(), "egress policy could not be asserted") {
		t.Fatalf("deploy with failing egress sync = %v, want fail-closed", err)
	}
	got, _ := w.st.GetBeam(ctx, beam.ID)
	if got.State != domain.StateFailed {
		t.Fatalf("beam state = %s, want failed", got.State)
	}
	if len(w.drv.started) != 1 {
		t.Fatalf("workload started despite missing egress policy: %v", w.drv.started)
	}
}

func TestSetSecretRejectsPathShapedKey(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	beam, err := w.o.CreateBeam(ctx, w.build, w.bh.ID, "keycheck", "Keycheck", "", "node")
	if err != nil {
		t.Fatalf("CreateBeam: %v", err)
	}

	// The key becomes the container-side bind target /run/secrets/<key>
	// verbatim; a path-shaped key would relocate the read-only mount anywhere
	// in the workload rootfs, and keys that sanitize to the same staged file
	// would silently alias each other.
	for _, key := range []string{"../../app/server.js", "a/b", "a b", "", "x:y", string(make([]byte, 65))} {
		if err := w.o.SetSecret(ctx, w.build, w.bh.ID, beam.ID, key, []byte("v")); err == nil {
			t.Fatalf("key %q must be rejected", key)
		}
	}
	if err := w.o.SetSecret(ctx, w.build, w.bh.ID, beam.ID, "GOOD_KEY_9", []byte("v")); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
}

// progressLeakBuilder simulates pack echoing a hardcoded copy of a vaulted
// value into the build output and failing with it in the error tail.
type progressLeakBuilder struct{ leak string }

func (b *progressLeakBuilder) BuildFromDir(ctx context.Context, hallSlug, beamSlug, srcDir string) (build.Result, error) {
	if w := build.ProgressWriter(ctx); w != nil {
		fmt.Fprintf(w, "config dump: PASSWORD=%s\n", b.leak)
	}
	return build.Result{}, fmt.Errorf("build failed: connection to db with password %s refused", b.leak)
}

func (b *progressLeakBuilder) BuildFromCommit(ctx context.Context, hallSlug, beamSlug, sha string) (build.Result, error) {
	return b.BuildFromDir(ctx, hallSlug, beamSlug, "")
}

func TestBuildOutputAndErrorScrubbed(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()

	const leaked = "sup3r-secret-dsn-value"
	WithBuilder(&progressLeakBuilder{leak: leaked})(w.o)

	beam, err := w.o.CreateBeam(ctx, w.build, w.bh.ID, "leaky", "Leaky", "", "node")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.o.SetSecret(ctx, w.build, w.bh.ID, beam.ID, "DB_PASS", []byte(leaked)); err != nil {
		t.Fatal(err)
	}

	var progress bytes.Buffer
	bctx := build.WithProgress(ctx, &progress)
	_, err = w.o.DeployBeamFromSource(bctx, w.build, w.bh.ID, beam.ID, "/tmp/src")
	if err == nil {
		t.Fatal("build was rigged to fail")
	}
	if strings.Contains(err.Error(), leaked) {
		t.Fatalf("vaulted value leaked through the build error: %v", err)
	}
	if !strings.Contains(err.Error(), secret.Mask) {
		t.Fatalf("error should carry the redaction mask: %v", err)
	}
	if strings.Contains(progress.String(), leaked) {
		t.Fatalf("vaulted value leaked through the progress stream: %q", progress.String())
	}
	if !strings.Contains(progress.String(), secret.Mask) {
		t.Fatalf("progress should carry the redaction mask: %q", progress.String())
	}
}

func TestSetSecretRefusedOnArchivedBeam(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	beam, err := w.o.CreateBeam(ctx, w.build, w.bh.ID, "gone", "Gone", "", "node")
	if err != nil {
		t.Fatal(err)
	}
	it := Actor{ID: w.admin.ID, ITAdmin: true}
	if err := w.o.DestroyBeam(ctx, it, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("DestroyBeam: %v", err)
	}
	// An archived beam's scope must not accept new secrets — nothing can ever
	// inject or reclaim them again.
	if err := w.o.SetSecret(ctx, w.build, w.bh.ID, beam.ID, "LATE_KEY", []byte("v")); err == nil {
		t.Fatal("set_secret on an archived beam must be refused")
	}
	// Beamhall-wide secrets are unaffected by the beam check.
	if err := w.o.SetSecret(ctx, w.build, w.bh.ID, "", "HALL_KEY", []byte("v")); err != nil {
		t.Fatalf("hall-wide set_secret: %v", err)
	}
}

func TestBootFailsInterruptedBuilds(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	beam, err := w.o.CreateBeam(ctx, w.build, w.bh.ID, "stuck", "Stuck", "", "node")
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a daemon crash mid-build: the row persists in `building`, a
	// state with no legal deploy transition.
	beam.State = domain.StateBuilding
	if err := w.st.UpdateBeam(ctx, beam); err != nil {
		t.Fatal(err)
	}
	if err := w.o.Boot(ctx); err != nil {
		t.Fatalf("Boot: %v", err)
	}
	got, err := w.st.GetBeam(ctx, beam.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != domain.StateFailed {
		t.Fatalf("interrupted build should land in failed, got %s", got.State)
	}
	// The standard recovery path must work: redeploy from failed.
	if _, err := w.o.DeployBeam(ctx, w.build, w.bh.ID, beam.ID, DeployRequest{
		ImageRef: "reg/stuck:v1", ImageDigest: "sha256:aa"}); err != nil {
		t.Fatalf("redeploy after boot recovery: %v", err)
	}
}

func TestPauseTimerClearsOnPermanentRefusal(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	beam, err := w.o.CreateBeam(ctx, w.build, w.bh.ID, "wedged", "Wedged", "", "node")
	if err != nil {
		t.Fatal(err)
	}
	beam.State = domain.StateFailed
	if err := w.st.UpdateBeam(ctx, beam); err != nil {
		t.Fatal(err)
	}
	// The scheduler clears a timer whose PauseFunc returns nil; a permanent
	// FSM refusal must therefore surface as nil, not as a retryable error the
	// scheduler re-arms every cycle forever.
	if err := w.o.PauseFunc()(ctx, string(beam.ID)); err != nil {
		t.Fatalf("PauseFunc on an unpausable beam should clear the timer (nil), got: %v", err)
	}
}

func TestSetMembershipRoleUpdatesInPlace(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	it := Actor{ID: w.admin.ID, ITAdmin: true}
	if err := w.o.SetMembershipRole(ctx, it, w.build.ID, w.bh.ID, domain.RoleViewer); err != nil {
		t.Fatalf("SetMembershipRole: %v", err)
	}
	m, err := w.st.GetMembership(ctx, w.build.ID, w.bh.ID)
	if err != nil {
		t.Fatal(err)
	}
	if m.Role != domain.RoleViewer {
		t.Fatalf("role not updated: %s", m.Role)
	}
	// No membership → actionable error, not a silent create.
	ident := &domain.Identity{ExternalSubject: "stranger", IdPIssuer: "idp", Email: "s@x", Status: domain.IdentityActive}
	if err := w.st.CreateIdentity(ctx, ident); err != nil {
		t.Fatal(err)
	}
	if err := w.o.SetMembershipRole(ctx, it, ident.ID, w.bh.ID, domain.RoleBuilder); err == nil {
		t.Fatal("role change without a membership must be refused")
	}
}
