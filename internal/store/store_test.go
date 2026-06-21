package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/scheduler"
)

// pauseStore must satisfy the scheduler's seam.
var _ scheduler.Store = pauseStore{}

// testClock is a controllable clock with nanosecond-exact, UTC values so
// round-trip comparisons can use reflect.DeepEqual.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock() *testClock {
	return &testClock{t: time.Unix(1_700_000_000, 123456789).UTC()}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func openTestStore(t *testing.T) (*Store, *testClock) {
	t.Helper()
	clock := newTestClock()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "test.db"), WithNow(clock.Now))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s, clock
}

// newBeamhall returns a fully-populated Beamhall + SecurityContext pair so
// round-trip tests cover every column, including the JSON ones.
func newBeamhall(slug string) (*domain.Beamhall, *domain.SecurityContext) {
	w := &domain.Beamhall{
		Slug:        slug,
		DisplayName: "Finance Tools",
		Department:  "finance",
		Status:      domain.BeamhallActive,
		NetworkPolicy: domain.NetworkPolicy{
			EgressMode:      domain.EgressAllowSet,
			EgressAllowlist: []string{"api.internal:443", "10.1.2.0/24:5432"},
		},
		Quota: domain.ResourceQuota{
			MaxBeams:        10,
			MaxLiveSlots:    2,
			MaxDBCount:      5,
			MaxStorageBytes: 1 << 30,
			CPUCeiling:      400000,
			MemCeiling:      2 << 30,
		},
		LiveSlotLimit: 2,
		CreatedBy:     NewID(),
	}
	sc := &domain.SecurityContext{
		RuntimeClass:    domain.RuntimeRunsc,
		UsernsRemap:     true,
		CapDrop:         []string{"ALL"},
		CapAdd:          []string{"NET_BIND_SERVICE"},
		SeccompProfile:  "default",
		AppArmorProfile: "docker-default",
		NoNewPrivileges: true,
		ReadOnlyRootfs:  true,
		Tmpfs:           []string{"/tmp"},
		CgroupLimits:    domain.ResourceLimits{CPUQuota: 100000, MemBytes: 512 << 20, PidsMax: 256},
		Template:        domain.TemplateWebApp,
	}
	return w, sc
}

func mustCreateBeamhall(t *testing.T, s *Store, slug string) *domain.Beamhall {
	t.Helper()
	w, sc := newBeamhall(slug)
	if err := s.CreateBeamhall(context.Background(), w, sc); err != nil {
		t.Fatalf("CreateBeamhall(%s): %v", slug, err)
	}
	return w
}

func mustCreateBeam(t *testing.T, s *Store, beamhallID domain.ID, slug string) *domain.Beam {
	t.Helper()
	a := &domain.Beam{
		BeamhallID:        beamhallID,
		Slug:              slug,
		DisplayName:       slug,
		RuntimeHint:       "node",
		Mode:              domain.ModePreview,
		State:             domain.StateCreated,
		SecurityTemplate:  domain.TemplateWebApp,
		PreviewPauseAfter: 4 * time.Hour,
		CreatedBy:         NewID(),
	}
	if err := s.CreateBeam(context.Background(), a); err != nil {
		t.Fatalf("CreateBeam(%s): %v", slug, err)
	}
	return a
}

func TestMigrateFreshAndReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "reopen.db")

	s, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	w := mustCreateBeamhall(t, s, "alpha")
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopen: migrations must be skipped (idempotent) and data durable.
	s2, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer s2.Close()
	got, err := s2.GetBeamhall(ctx, w.ID)
	if err != nil {
		t.Fatalf("GetBeamhall after reopen: %v", err)
	}
	if got.Slug != "alpha" {
		t.Fatalf("got slug %q, want alpha", got.Slug)
	}
}

func TestBeamhallRoundTrip(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()

	w, sc := newBeamhall("finance")
	if err := s.CreateBeamhall(ctx, w, sc); err != nil {
		t.Fatalf("CreateBeamhall: %v", err)
	}
	if w.ID == "" || sc.ID == "" {
		t.Fatal("CreateBeamhall did not assign IDs")
	}
	if w.SecurityContextID != sc.ID || sc.BeamhallID != w.ID {
		t.Fatal("CreateBeamhall did not cross-link beamhall and security context")
	}

	got, err := s.GetBeamhall(ctx, w.ID)
	if err != nil {
		t.Fatalf("GetBeamhall: %v", err)
	}
	if !reflect.DeepEqual(got, *w) {
		t.Errorf("beamhall round-trip mismatch:\n got %+v\nwant %+v", got, *w)
	}

	bySlug, err := s.GetBeamhallBySlug(ctx, "finance")
	if err != nil {
		t.Fatalf("GetBeamhallBySlug: %v", err)
	}
	if bySlug.ID != w.ID {
		t.Errorf("GetBeamhallBySlug returned %s, want %s", bySlug.ID, w.ID)
	}

	gotSC, err := s.GetSecurityContext(ctx, w.ID)
	if err != nil {
		t.Fatalf("GetSecurityContext: %v", err)
	}
	if !reflect.DeepEqual(gotSC, *sc) {
		t.Errorf("security context round-trip mismatch:\n got %+v\nwant %+v", gotSC, *sc)
	}

	// Update mutable fields.
	w.Status = domain.BeamhallSuspended
	w.NetworkPolicy.EgressAllowlist = append(w.NetworkPolicy.EgressAllowlist, "mail.internal:587")
	if err := s.UpdateBeamhall(ctx, w); err != nil {
		t.Fatalf("UpdateBeamhall: %v", err)
	}
	got, err = s.GetBeamhall(ctx, w.ID)
	if err != nil {
		t.Fatalf("GetBeamhall after update: %v", err)
	}
	if !reflect.DeepEqual(got, *w) {
		t.Errorf("beamhall update mismatch:\n got %+v\nwant %+v", got, *w)
	}

	gotSC.RuntimeClass = domain.RuntimeRunc
	gotSC.ReadOnlyRootfs = false
	if err := s.UpdateSecurityContext(ctx, gotSC); err != nil {
		t.Fatalf("UpdateSecurityContext: %v", err)
	}
	scAfter, err := s.GetSecurityContext(ctx, w.ID)
	if err != nil {
		t.Fatalf("GetSecurityContext after update: %v", err)
	}
	if !reflect.DeepEqual(scAfter, gotSC) {
		t.Errorf("security context update mismatch:\n got %+v\nwant %+v", scAfter, gotSC)
	}

	// Listing.
	mustCreateBeamhall(t, s, "eng")
	all, err := s.ListBeamhalls(ctx)
	if err != nil {
		t.Fatalf("ListBeamhalls: %v", err)
	}
	if len(all) != 2 || all[0].Slug != "eng" || all[1].Slug != "finance" {
		t.Errorf("ListBeamhalls order/content wrong: %+v", all)
	}

	// Sentinels.
	if _, err := s.GetBeamhall(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetBeamhall(missing) = %v, want ErrNotFound", err)
	}
	dup, dupSC := newBeamhall("finance")
	if err := s.CreateBeamhall(ctx, dup, dupSC); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate slug = %v, want ErrConflict", err)
	}
}

func TestIdentityAndMembership(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	w := mustCreateBeamhall(t, s, "wc")

	ident := &domain.Identity{
		ExternalSubject: "sub-123",
		Email:           "dev@example.com",
		DisplayName:     "Dev",
		IdPIssuer:       "https://idp.example.com/realms/main",
		Status:          "active",
	}
	if err := s.CreateIdentity(ctx, ident); err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}

	got, err := s.GetIdentityByIssuerSubject(ctx, ident.IdPIssuer, "sub-123")
	if err != nil {
		t.Fatalf("GetIdentityByIssuerSubject: %v", err)
	}
	if !reflect.DeepEqual(got, *ident) {
		t.Errorf("identity round-trip mismatch:\n got %+v\nwant %+v", got, *ident)
	}

	// Same (issuer, sub) pair must conflict.
	dup := &domain.Identity{ExternalSubject: "sub-123", IdPIssuer: ident.IdPIssuer}
	if err := s.CreateIdentity(ctx, dup); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate identity = %v, want ErrConflict", err)
	}

	m := &domain.Membership{
		IdentityID: ident.ID,
		BeamhallID: w.ID,
		Role:       domain.RoleBuilder,
		GrantedBy:  NewID(),
	}
	if err := s.CreateMembership(ctx, m); err != nil {
		t.Fatalf("CreateMembership: %v", err)
	}
	gotM, err := s.GetMembership(ctx, ident.ID, w.ID)
	if err != nil {
		t.Fatalf("GetMembership: %v", err)
	}
	if !reflect.DeepEqual(gotM, *m) {
		t.Errorf("membership round-trip mismatch:\n got %+v\nwant %+v", gotM, *m)
	}

	dupM := &domain.Membership{IdentityID: ident.ID, BeamhallID: w.ID, Role: domain.RoleViewer}
	if err := s.CreateMembership(ctx, dupM); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate membership = %v, want ErrConflict", err)
	}

	if err := s.DeleteMembership(ctx, m.ID); err != nil {
		t.Fatalf("DeleteMembership: %v", err)
	}
	if _, err := s.GetMembership(ctx, ident.ID, w.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetMembership after delete = %v, want ErrNotFound", err)
	}
	// Revocation is idempotent.
	if err := s.DeleteMembership(ctx, m.ID); err != nil {
		t.Errorf("second DeleteMembership = %v, want nil", err)
	}
}

func TestBeamRoundTripAndCounts(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	w := mustCreateBeamhall(t, s, "wc")

	a := mustCreateBeam(t, s, w.ID, "tracker")
	got, err := s.GetBeam(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetBeam: %v", err)
	}
	if !reflect.DeepEqual(got, *a) {
		t.Errorf("beam round-trip mismatch:\n got %+v\nwant %+v", got, *a)
	}

	bySlug, err := s.GetBeamBySlug(ctx, w.ID, "tracker")
	if err != nil {
		t.Fatalf("GetBeamBySlug: %v", err)
	}
	if bySlug.ID != a.ID {
		t.Errorf("GetBeamBySlug returned %s, want %s", bySlug.ID, a.ID)
	}

	// FSM-shaped update: deploy → running → live.
	a.State = domain.StateRunning
	a.Mode = domain.ModeLive
	a.CurrentReleaseID = NewID()
	a.ResumedAt = time.Unix(1_700_001_000, 42).UTC()
	if err := s.UpdateBeam(ctx, a); err != nil {
		t.Fatalf("UpdateBeam: %v", err)
	}
	got, err = s.GetBeam(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetBeam after update: %v", err)
	}
	if !reflect.DeepEqual(got, *a) {
		t.Errorf("beam update mismatch:\n got %+v\nwant %+v", got, *a)
	}

	mustCreateBeam(t, s, w.ID, "wiki")
	if n, _ := s.CountBeamsByBeamhall(ctx, w.ID); n != 2 {
		t.Errorf("CountBeamsByBeamhall = %d, want 2", n)
	}
	if n, _ := s.CountLiveBeamsByBeamhall(ctx, w.ID); n != 1 {
		t.Errorf("CountLiveBeamsByBeamhall = %d, want 1", n)
	}

	dup := &domain.Beam{BeamhallID: w.ID, Slug: "tracker", State: domain.StateCreated, Mode: domain.ModePreview}
	if err := s.CreateBeam(ctx, dup); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate beam slug = %v, want ErrConflict", err)
	}
	// Same slug in another beamhall is fine.
	w2 := mustCreateBeamhall(t, s, "other")
	mustCreateBeam(t, s, w2.ID, "tracker")
}

func TestBuildReleaseFlow(t *testing.T) {
	s, clock := openTestStore(t)
	ctx := context.Background()
	w := mustCreateBeamhall(t, s, "wc")
	a := mustCreateBeam(t, s, w.ID, "beam")

	b := &domain.Build{
		BeamID:     a.ID,
		SourceRef:  "0123abc",
		SourceKind: domain.SourceManagedGit,
		Builder:    "paketobuildpacks/builder-jammy-base",
		Status:     domain.BuildQueued,
	}
	if err := s.CreateBuild(ctx, b); err != nil {
		t.Fatalf("CreateBuild: %v", err)
	}
	if b.StartedAt.IsZero() {
		t.Fatal("CreateBuild did not stamp StartedAt")
	}

	clock.Advance(2 * time.Minute)
	b.Status = domain.BuildSucceeded
	b.ImageRef = "registry.internal/wc/beam:1"
	b.ImageDigest = "sha256:deadbeef"
	b.SBOMRef = "sbom-1"
	b.CVEScanStatus = "pass"
	b.FinishedAt = clock.Now()
	if err := s.UpdateBuild(ctx, *b); err != nil {
		t.Fatalf("UpdateBuild: %v", err)
	}
	gotB, err := s.GetBuild(ctx, b.ID)
	if err != nil {
		t.Fatalf("GetBuild: %v", err)
	}
	if !reflect.DeepEqual(gotB, *b) {
		t.Errorf("build round-trip mismatch:\n got %+v\nwant %+v", gotB, *b)
	}

	// Releases get monotonic per-beam versions regardless of caller input.
	_, sc := newBeamhall("ignored")
	mkRelease := func() *domain.Release {
		return &domain.Release{
			BeamID:              a.ID,
			BuildID:             b.ID,
			Version:             999, // must be overwritten
			ConfigSnapshot:      map[string]string{"PORT": "8080"},
			SecretRefs:          []domain.SecretRef{{BeamhallID: w.ID, BeamID: a.ID, Key: "DATABASE_URL"}},
			SecurityProfileSnap: *sc,
			Status:              domain.ReleasePending,
		}
	}
	r1, r2 := mkRelease(), mkRelease()
	if err := s.CreateRelease(ctx, r1); err != nil {
		t.Fatalf("CreateRelease r1: %v", err)
	}
	if err := s.CreateRelease(ctx, r2); err != nil {
		t.Fatalf("CreateRelease r2: %v", err)
	}
	if r1.Version != 1 || r2.Version != 2 {
		t.Errorf("versions = %d,%d, want 1,2", r1.Version, r2.Version)
	}

	gotR, err := s.GetRelease(ctx, r1.ID)
	if err != nil {
		t.Fatalf("GetRelease: %v", err)
	}
	if !reflect.DeepEqual(gotR, *r1) {
		t.Errorf("release round-trip mismatch:\n got %+v\nwant %+v", gotR, *r1)
	}

	if err := s.ActivateRelease(ctx, r1.ID); err != nil {
		t.Fatalf("ActivateRelease: %v", err)
	}
	gotR, _ = s.GetRelease(ctx, r1.ID)
	if gotR.Status != domain.ReleaseActive || gotR.ActivatedAt.IsZero() {
		t.Errorf("after activate: status=%s activated_at=%v", gotR.Status, gotR.ActivatedAt)
	}

	if err := s.UpdateReleaseStatus(ctx, r1.ID, domain.ReleaseSuperseded); err != nil {
		t.Fatalf("UpdateReleaseStatus: %v", err)
	}
	routeID := NewID()
	if err := s.SetReleaseRoute(ctx, r2.ID, routeID); err != nil {
		t.Fatalf("SetReleaseRoute: %v", err)
	}
	gotR, _ = s.GetRelease(ctx, r2.ID)
	if gotR.RouteID != routeID {
		t.Errorf("RouteID = %s, want %s", gotR.RouteID, routeID)
	}

	list, err := s.ListReleasesByBeam(ctx, a.ID)
	if err != nil {
		t.Fatalf("ListReleasesByBeam: %v", err)
	}
	if len(list) != 2 || list[0].Version != 2 || list[1].Version != 1 {
		t.Errorf("ListReleasesByBeam order wrong: %+v", list)
	}
}

func TestRouteLifecycleAndRestore(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	w := mustCreateBeamhall(t, s, "wc")
	a := mustCreateBeam(t, s, w.ID, "beam")

	mkRoute := func(host string, kind domain.RouteKind) *domain.Route {
		r := &domain.Route{
			BeamID:      a.ID,
			Kind:        kind,
			Hostname:    host,
			RandomToken: "tok",
			BackendAddr: "172.18.0.2:8080",
			TLSCertRef:  "auto",
			Status:      domain.RouteActive,
		}
		if err := s.CreateRoute(ctx, r); err != nil {
			t.Fatalf("CreateRoute(%s): %v", host, err)
		}
		return r
	}
	preview := mkRoute("abc123.preview.beamhall.internal", domain.RoutePreview)
	live := mkRoute("beam.wc.beamhall.internal", domain.RouteLive)

	got, err := s.GetActiveRouteByHostname(ctx, preview.Hostname)
	if err != nil {
		t.Fatalf("GetActiveRouteByHostname: %v", err)
	}
	if !reflect.DeepEqual(got, *preview) {
		t.Errorf("route round-trip mismatch:\n got %+v\nwant %+v", got, *preview)
	}

	// A second ACTIVE route on the same hostname must conflict...
	clash := &domain.Route{BeamID: a.ID, Kind: domain.RoutePreview, Hostname: preview.Hostname, Status: domain.RouteActive}
	if err := s.CreateRoute(ctx, clash); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate active hostname = %v, want ErrConflict", err)
	}

	// ...but a retired hostname may be reused (live redeploys, resume cycles).
	if err := s.RetireRoute(ctx, preview.ID); err != nil {
		t.Fatalf("RetireRoute: %v", err)
	}
	if _, err := s.GetActiveRouteByHostname(ctx, preview.Hostname); !errors.Is(err, ErrNotFound) {
		t.Errorf("retired hostname still resolves: %v", err)
	}
	reuse := &domain.Route{BeamID: a.ID, Kind: domain.RoutePreview, Hostname: preview.Hostname, Status: domain.RouteActive}
	if err := s.CreateRoute(ctx, reuse); err != nil {
		t.Fatalf("CreateRoute(reused hostname): %v", err)
	}

	// ActiveRoutes is the gateway's boot restore source: active only, sorted.
	active, err := s.ActiveRoutes(ctx)
	if err != nil {
		t.Fatalf("ActiveRoutes: %v", err)
	}
	if len(active) != 2 {
		t.Fatalf("ActiveRoutes len = %d, want 2", len(active))
	}
	if active[0].Hostname != preview.Hostname || active[1].Hostname != live.Hostname {
		t.Errorf("ActiveRoutes order wrong: %s, %s", active[0].Hostname, active[1].Hostname)
	}

	all, err := s.ListRoutesByBeam(ctx, a.ID)
	if err != nil {
		t.Fatalf("ListRoutesByBeam: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("ListRoutesByBeam len = %d, want 3", len(all))
	}
}

func TestResourceRoundTrip(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	w := mustCreateBeamhall(t, s, "wc")
	a := mustCreateBeam(t, s, w.ID, "beam")

	r := &domain.Resource{
		BeamhallID:          w.ID,
		BeamID:              a.ID,
		Type:                domain.ResourceDatabase,
		Status:              domain.ResourceProvisioning,
		ConnectionSecretRef: domain.SecretRef{BeamhallID: w.ID, BeamID: a.ID, Key: "DATABASE_URL"},
		Spec:                map[string]string{"db_name": "beam", "version": "16"},
	}
	if err := s.CreateResource(ctx, r); err != nil {
		t.Fatalf("CreateResource: %v", err)
	}

	r.Status = domain.ResourceReady
	r.BackingHandle = "pg:database/beam"
	if err := s.UpdateResource(ctx, r); err != nil {
		t.Fatalf("UpdateResource: %v", err)
	}
	got, err := s.GetResource(ctx, r.ID)
	if err != nil {
		t.Fatalf("GetResource: %v", err)
	}
	if !reflect.DeepEqual(got, *r) {
		t.Errorf("resource round-trip mismatch:\n got %+v\nwant %+v", got, *r)
	}

	byWC, err := s.ListResourcesByBeamhall(ctx, w.ID)
	if err != nil || len(byWC) != 1 {
		t.Fatalf("ListResourcesByBeamhall: %v len=%d", err, len(byWC))
	}
	byBeam, err := s.ListResourcesByBeam(ctx, a.ID)
	if err != nil || len(byBeam) != 1 {
		t.Fatalf("ListResourcesByBeam: %v len=%d", err, len(byBeam))
	}
	if n, _ := s.CountResourcesByType(ctx, w.ID, domain.ResourceDatabase); n != 1 {
		t.Errorf("CountResourcesByType = %d, want 1", n)
	}
	if n, _ := s.CountResourcesByType(ctx, w.ID, domain.ResourceQueue); n != 0 {
		t.Errorf("CountResourcesByType(queue) = %d, want 0", n)
	}
}

func TestSecretUpsertVersioning(t *testing.T) {
	s, clock := openTestStore(t)
	ctx := context.Background()
	w := mustCreateBeamhall(t, s, "wc")
	a := mustCreateBeam(t, s, w.ID, "beam")

	sec := &domain.Secret{
		BeamhallID: w.ID,
		BeamID:     a.ID,
		Key:        "DATABASE_URL",
		ValueRef:   "age:v1",
		CreatedBy:  NewID(),
	}
	if err := s.PutSecret(ctx, sec); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}
	if sec.Version != 1 || sec.ID == "" {
		t.Fatalf("first put: version=%d id=%q, want version 1 and an id", sec.Version, sec.ID)
	}
	firstID := sec.ID

	clock.Advance(time.Hour)
	rewrite := &domain.Secret{
		BeamhallID: w.ID,
		BeamID:     a.ID,
		Key:        "DATABASE_URL",
		ValueRef:   "age:v2",
		CreatedBy:  NewID(),
	}
	if err := s.PutSecret(ctx, rewrite); err != nil {
		t.Fatalf("PutSecret rewrite: %v", err)
	}
	if rewrite.Version != 2 {
		t.Errorf("rewrite version = %d, want 2", rewrite.Version)
	}
	if rewrite.ID != firstID {
		t.Errorf("rewrite changed row identity: %s -> %s", firstID, rewrite.ID)
	}
	if rewrite.ValueRef != "age:v2" {
		t.Errorf("rewrite value_ref = %s, want age:v2", rewrite.ValueRef)
	}

	got, err := s.GetSecret(ctx, w.ID, a.ID, "DATABASE_URL", domain.ChannelShared)
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if !reflect.DeepEqual(got, *rewrite) {
		t.Errorf("secret round-trip mismatch:\n got %+v\nwant %+v", got, *rewrite)
	}

	// Beamhall-scoped secret (empty beam id) is a distinct key space.
	wcScoped := &domain.Secret{BeamhallID: w.ID, Key: "DATABASE_URL", ValueRef: "age:wc"}
	if err := s.PutSecret(ctx, wcScoped); err != nil {
		t.Fatalf("PutSecret beamhall-scoped: %v", err)
	}
	if wcScoped.Version != 1 {
		t.Errorf("beamhall-scoped version = %d, want 1 (separate row)", wcScoped.Version)
	}

	list, err := s.ListSecretsByBeamhall(ctx, w.ID)
	if err != nil || len(list) != 2 {
		t.Fatalf("ListSecretsByBeamhall: %v len=%d, want 2", err, len(list))
	}

	if err := s.DeleteSecret(ctx, w.ID, a.ID, "DATABASE_URL", domain.ChannelShared); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	if _, err := s.GetSecret(ctx, w.ID, a.ID, "DATABASE_URL", domain.ChannelShared); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetSecret after delete = %v, want ErrNotFound", err)
	}
	if err := s.DeleteSecret(ctx, w.ID, a.ID, "DATABASE_URL", domain.ChannelShared); err != nil {
		t.Errorf("second DeleteSecret = %v, want nil (idempotent)", err)
	}
}

func TestAuditAppendOnlyChainOrder(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()

	if _, ok, err := s.LastAuditEvent(ctx); err != nil || ok {
		t.Fatalf("LastAuditEvent(empty) = ok=%v err=%v, want ok=false err=nil", ok, err)
	}

	wcA, wcB := NewID(), NewID()
	var lastSeq int64
	for i := range 5 {
		wc := wcA
		if i%2 == 1 {
			wc = wcB
		}
		ev := &domain.AuditEvent{
			ActorID:    NewID(),
			BeamhallID: wc,
			Action:     fmt.Sprintf("op_%d", i),
			Decision:   domain.DecisionAllow,
			PrevHash:   fmt.Sprintf("h%d", i-1),
			Hash:       fmt.Sprintf("h%d", i),
		}
		seq, err := s.AppendAuditEvent(ctx, ev)
		if err != nil {
			t.Fatalf("AppendAuditEvent %d: %v", i, err)
		}
		if seq <= lastSeq {
			t.Fatalf("seq not increasing: %d after %d", seq, lastSeq)
		}
		lastSeq = seq
		if ev.ID == "" || ev.At.IsZero() {
			t.Fatal("AppendAuditEvent did not fill ID/At")
		}
	}

	last, ok, err := s.LastAuditEvent(ctx)
	if err != nil || !ok {
		t.Fatalf("LastAuditEvent: ok=%v err=%v", ok, err)
	}
	if last.Seq != lastSeq || last.Event.Hash != "h4" {
		t.Errorf("LastAuditEvent = seq %d hash %s, want %d h4", last.Seq, last.Event.Hash, lastSeq)
	}

	// Cursor walk, ascending.
	page1, err := s.ListAuditEvents(ctx, 0, 3)
	if err != nil || len(page1) != 3 {
		t.Fatalf("ListAuditEvents page1: %v len=%d", err, len(page1))
	}
	page2, err := s.ListAuditEvents(ctx, page1[2].Seq, 10)
	if err != nil || len(page2) != 2 {
		t.Fatalf("ListAuditEvents page2: %v len=%d", err, len(page2))
	}
	if page1[0].Event.Action != "op_0" || page2[1].Event.Action != "op_4" {
		t.Errorf("cursor walk order wrong: %s ... %s", page1[0].Event.Action, page2[1].Event.Action)
	}

	byWC, err := s.ListAuditEventsByBeamhall(ctx, wcB, 0, 10)
	if err != nil || len(byWC) != 2 {
		t.Fatalf("ListAuditEventsByBeamhall: %v len=%d, want 2", err, len(byWC))
	}
}

func TestPauseStoreContract(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	ps := s.PauseStore()

	if got, err := ps.Load(ctx); err != nil || len(got) != 0 {
		t.Fatalf("Load(empty) = %v, %v", got, err)
	}

	d1 := time.Unix(1_700_100_000, 555).UTC()
	if err := ps.Save(ctx, scheduler.ArmedPause{BeamID: "beam-1", Deadline: d1}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// Re-arm (resume) overwrites — Save is an upsert.
	d2 := d1.Add(4 * time.Hour)
	if err := ps.Save(ctx, scheduler.ArmedPause{BeamID: "beam-1", Deadline: d2}); err != nil {
		t.Fatalf("Save (re-arm): %v", err)
	}
	if err := ps.Save(ctx, scheduler.ArmedPause{BeamID: "beam-2", Deadline: d1}); err != nil {
		t.Fatalf("Save beam-2: %v", err)
	}

	got, err := ps.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	byID := map[string]time.Time{}
	for _, p := range got {
		byID[p.BeamID] = p.Deadline
	}
	if len(byID) != 2 || !byID["beam-1"].Equal(d2) || !byID["beam-2"].Equal(d1) {
		t.Errorf("Load = %+v, want beam-1 @ %v, beam-2 @ %v", byID, d2, d1)
	}

	if err := ps.Delete(ctx, "beam-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := ps.Delete(ctx, "beam-1"); err != nil {
		t.Errorf("second Delete = %v, want nil (idempotent)", err)
	}
	got, _ = ps.Load(ctx)
	if len(got) != 1 || got[0].BeamID != "beam-2" {
		t.Errorf("after delete Load = %+v, want only beam-2", got)
	}
}

// TestSchedulerOnRealStore proves the seam end-to-end: a deadline persisted
// through the SQLite store fires after a simulated restart (boot catch-up).
func TestSchedulerOnRealStore(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()

	deadline := time.Now().Add(-time.Minute) // already due: must fire on boot
	if err := s.PauseStore().Save(ctx, scheduler.ArmedPause{BeamID: "beam-1", Deadline: deadline}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	paused := make(chan string, 1)
	sched := scheduler.New(s.PauseStore(), func(ctx context.Context, beamID string) error {
		paused <- beamID
		return nil
	})
	if err := sched.Start(ctx); err != nil {
		t.Fatalf("scheduler.Start: %v", err)
	}
	defer sched.Stop()

	select {
	case id := <-paused:
		if id != "beam-1" {
			t.Fatalf("paused %q, want beam-1", id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("boot catch-up pause never fired")
	}

	// The fired deadline must be cleared from the store (poll briefly: the
	// scheduler deletes it just after invoking PauseFunc).
	wait := time.Now().Add(5 * time.Second)
	for {
		got, err := s.PauseStore().Load(ctx)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if len(got) == 0 {
			break
		}
		if time.Now().After(wait) {
			t.Fatalf("armed pause not cleared after fire: %+v", got)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestConcurrentAccess exercises the single-connection setup under -race:
// concurrent writers and readers across tables must serialize, not error.
func TestConcurrentAccess(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	w := mustCreateBeamhall(t, s, "wc")

	var wg sync.WaitGroup
	errCh := make(chan error, 64)
	for i := range 8 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a := &domain.Beam{
				BeamhallID: w.ID,
				Slug:       fmt.Sprintf("beam-%d", i),
				Mode:       domain.ModePreview,
				State:      domain.StateCreated,
			}
			if err := s.CreateBeam(ctx, a); err != nil {
				errCh <- fmt.Errorf("CreateBeam %d: %w", i, err)
				return
			}
			if _, err := s.AppendAuditEvent(ctx, &domain.AuditEvent{
				BeamhallID: w.ID, Action: "create_beam", Decision: domain.DecisionAllow,
			}); err != nil {
				errCh <- fmt.Errorf("AppendAuditEvent %d: %w", i, err)
				return
			}
			if err := s.PauseStore().Save(ctx, scheduler.ArmedPause{
				BeamID: string(a.ID), Deadline: time.Now().Add(time.Hour),
			}); err != nil {
				errCh <- fmt.Errorf("Save pause %d: %w", i, err)
				return
			}
			if _, err := s.ListBeamsByBeamhall(ctx, w.ID); err != nil {
				errCh <- fmt.Errorf("ListBeams %d: %w", i, err)
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}

	if n, _ := s.CountBeamsByBeamhall(ctx, w.ID); n != 8 {
		t.Errorf("CountBeamsByBeamhall = %d, want 8", n)
	}
	pauses, _ := s.PauseStore().Load(ctx)
	if len(pauses) != 8 {
		t.Errorf("armed pauses = %d, want 8", len(pauses))
	}
}

// TestZeroTimeRoundTrip pins the 0 <-> time.Time{} convention: a zero time
// must come back exactly zero (IsZero), not 1970-01-01.
func TestZeroTimeRoundTrip(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	w := mustCreateBeamhall(t, s, "wc")
	a := mustCreateBeam(t, s, w.ID, "beam") // ResumedAt left zero

	got, err := s.GetBeam(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetBeam: %v", err)
	}
	if !got.ResumedAt.IsZero() {
		t.Errorf("zero ResumedAt came back as %v", got.ResumedAt)
	}
	b := &domain.Build{BeamID: a.ID, Status: domain.BuildQueued}
	if err := s.CreateBuild(ctx, b); err != nil {
		t.Fatalf("CreateBuild: %v", err)
	}
	gotB, _ := s.GetBuild(ctx, b.ID)
	if !gotB.FinishedAt.IsZero() {
		t.Errorf("zero FinishedAt came back as %v", gotB.FinishedAt)
	}
}
