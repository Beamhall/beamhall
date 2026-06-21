package policy

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Beamhall/beamhall/internal/audit"
	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/store"
)

type fixture struct {
	pep *PEP
	st  *store.Store
	log *audit.Logger
	bh  *domain.Beamhall
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "policy.db"))
	if err != nil {
		t.Fatalf("Open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	bh := &domain.Beamhall{
		Slug: "ops", DisplayName: "Ops", Status: domain.BeamhallActive,
		Quota:         domain.ResourceQuota{MaxBeams: 2, MaxLiveSlots: 1, MaxDBCount: 1},
		LiveSlotLimit: 1,
	}
	sc := &domain.SecurityContext{RuntimeClass: domain.RuntimeRunsc, Template: domain.TemplateWebApp}
	if err := st.CreateBeamhall(ctx, bh, sc); err != nil {
		t.Fatalf("CreateBeamhall: %v", err)
	}

	log := audit.New(st)
	return &fixture{pep: New(st, log), st: st, log: log, bh: bh}
}

func (f *fixture) identity(t *testing.T, role domain.MembershipRole) domain.ID {
	t.Helper()
	ctx := context.Background()
	ident := &domain.Identity{
		ExternalSubject: string(store.NewID()), Email: "u@x", DisplayName: "u",
		IdPIssuer: "https://idp", Status: domain.IdentityActive,
	}
	if err := f.st.CreateIdentity(ctx, ident); err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	if role != "" {
		m := &domain.Membership{IdentityID: ident.ID, BeamhallID: f.bh.ID, Role: role, GrantedBy: ident.ID}
		if err := f.st.CreateMembership(ctx, m); err != nil {
			t.Fatalf("CreateMembership: %v", err)
		}
	}
	return ident.ID
}

func (f *fixture) authorize(actor domain.ID, action Action) error {
	return f.pep.Authorize(context.Background(), Request{
		Actor: actor, BeamhallID: f.bh.ID, Action: action,
	})
}

func wantDenied(t *testing.T, err error, reasonPart string) {
	t.Helper()
	var d *Denial
	if !errors.As(err, &d) {
		t.Fatalf("got %v, want *Denial", err)
	}
	if !strings.Contains(d.Reason, reasonPart) {
		t.Fatalf("denial reason %q does not contain %q", d.Reason, reasonPart)
	}
}

func TestRoleMatrix(t *testing.T) {
	f := newFixture(t)
	viewer := f.identity(t, domain.RoleViewer)
	builder := f.identity(t, domain.RoleBuilder)
	admin := f.identity(t, domain.RoleBeamhallAdmin)

	if err := f.authorize(viewer, ActionShowLogs); err != nil {
		t.Fatalf("viewer show_logs: %v", err)
	}
	wantDenied(t, f.authorize(viewer, ActionDeployBeam), `does not grant`)

	if err := f.authorize(builder, ActionDeployBeam); err != nil {
		t.Fatalf("builder deploy_beam: %v", err)
	}
	// The demo's 403 moment: builders never promote.
	wantDenied(t, f.authorize(builder, ActionPromoteToLive), `role "builder" does not grant`)

	// Builders may archive (shelve) their own previews, but never destroy (the
	// IT-gated live teardown) and viewers may not archive at all.
	if err := f.authorize(builder, ActionArchiveBeam); err != nil {
		t.Fatalf("builder archive_beam: %v", err)
	}
	wantDenied(t, f.authorize(builder, ActionDestroyBeam), `role "builder" does not grant`)
	wantDenied(t, f.authorize(viewer, ActionArchiveBeam), `does not grant`)

	if err := f.authorize(admin, ActionPromoteToLive); err != nil {
		t.Fatalf("beamhall_admin promote_to_live: %v", err)
	}
	if err := f.authorize(admin, ActionDestroyBeam); err != nil {
		t.Fatalf("beamhall_admin destroy_beam: %v", err)
	}
	if err := f.authorize(admin, ActionArchiveBeam); err != nil {
		t.Fatalf("beamhall_admin archive_beam: %v", err)
	}
}

func TestForbiddenActionsDeniedForEveryone(t *testing.T) {
	f := newFixture(t)
	admin := f.identity(t, domain.RoleBeamhallAdmin)

	for _, a := range []Action{ActionGetSecret, ActionMutateSecurityContext,
		ActionMutateQuota, ActionMutateEgress, ActionRawRuntimeAccess, ActionSupplyDockerfile} {
		wantDenied(t, f.authorize(admin, a), "forbidden for every role")
		// Even an it_admin token cannot reach a forbidden action.
		err := f.pep.Authorize(context.Background(), Request{
			Actor: admin, BeamhallID: f.bh.ID, Action: a, ITAdmin: true,
		})
		wantDenied(t, err, "forbidden for every role")
	}
}

func TestNoMembershipNoAccess(t *testing.T) {
	f := newFixture(t)
	outsider := f.identity(t, "") // exists, active, but no membership here
	wantDenied(t, f.authorize(outsider, ActionShowLogs), "no membership")

	// Membership in another Beamhall does not help (the cross-Beamhall
	// isolation invariant).
	other := &domain.Beamhall{Slug: "other", DisplayName: "Other", Status: domain.BeamhallActive}
	osc := &domain.SecurityContext{RuntimeClass: domain.RuntimeRunc, Template: domain.TemplateWebApp}
	if err := f.st.CreateBeamhall(context.Background(), other, osc); err != nil {
		t.Fatal(err)
	}
	m := &domain.Membership{IdentityID: outsider, BeamhallID: other.ID, Role: domain.RoleBeamhallAdmin, GrantedBy: outsider}
	if err := f.st.CreateMembership(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	wantDenied(t, f.authorize(outsider, ActionShowLogs), "no membership")
}

func TestInactiveIdentityAndBeamhall(t *testing.T) {
	f := newFixture(t)

	ident := &domain.Identity{ExternalSubject: "s", Email: "e@x", DisplayName: "d",
		IdPIssuer: "i", Status: domain.IdentityDisabled}
	if err := f.st.CreateIdentity(context.Background(), ident); err != nil {
		t.Fatal(err)
	}
	wantDenied(t, f.authorize(ident.ID, ActionShowLogs), "identity is disabled")

	wantDenied(t, f.authorize("ghost-id", ActionShowLogs), "unknown identity")

	builder := f.identity(t, domain.RoleBuilder)
	f.bh.Status = domain.BeamhallSuspended
	if err := f.st.UpdateBeamhall(context.Background(), f.bh); err != nil {
		t.Fatal(err)
	}
	wantDenied(t, f.authorize(builder, ActionDeployBeam), "beamhall is suspended")
}

func TestITAdminBypassesMembershipOnly(t *testing.T) {
	f := newFixture(t)
	it := f.identity(t, "") // no membership anywhere
	err := f.pep.Authorize(context.Background(), Request{
		Actor: it, BeamhallID: f.bh.ID, Action: ActionPromoteToLive, ITAdmin: true,
	})
	if err != nil {
		t.Fatalf("it_admin promote without membership: %v", err)
	}
}

func TestEveryDecisionIsAudited(t *testing.T) {
	f := newFixture(t)
	builder := f.identity(t, domain.RoleBuilder)

	if err := f.authorize(builder, ActionDeployBeam); err != nil { // allow
		t.Fatal(err)
	}
	_ = f.authorize(builder, ActionPromoteToLive) // deny
	_ = f.authorize(builder, ActionGetSecret)     // forbidden deny

	recs, err := f.st.ListAuditEvents(context.Background(), 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 {
		t.Fatalf("got %d audit events, want 3 (every decision recorded)", len(recs))
	}
	wantDecisions := []domain.AuditDecision{domain.DecisionAllow, domain.DecisionDeny, domain.DecisionDeny}
	wantActions := []Action{ActionDeployBeam, ActionPromoteToLive, ActionGetSecret}
	for i, rec := range recs {
		if rec.Event.Decision != wantDecisions[i] || rec.Event.Action != string(wantActions[i]) {
			t.Fatalf("event %d = (%s, %s), want (%s, %s)",
				i, rec.Event.Action, rec.Event.Decision, wantActions[i], wantDecisions[i])
		}
		if rec.Event.ActorID != builder || rec.Event.BeamhallID != f.bh.ID {
			t.Fatalf("event %d actor/beamhall not recorded: %+v", i, rec.Event)
		}
	}
	if issues, err := f.log.Verify(context.Background()); err != nil || len(issues) > 0 {
		t.Fatalf("audit chain after decisions: issues=%v err=%v", issues, err)
	}
}

func TestQuotaGates(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	// Under limit (MaxBeams 2): ok. At limit: QuotaError.
	if err := f.pep.CheckBeamQuota(ctx, *f.bh); err != nil {
		t.Fatalf("CheckBeamQuota empty: %v", err)
	}
	for _, slug := range []string{"a", "b"} {
		beam := &domain.Beam{BeamhallID: f.bh.ID, Slug: slug, Mode: domain.ModePreview, State: domain.StateCreated}
		if err := f.st.CreateBeam(ctx, beam); err != nil {
			t.Fatal(err)
		}
	}
	var qe *QuotaError
	if err := f.pep.CheckBeamQuota(ctx, *f.bh); !errors.As(err, &qe) || qe.Used != 2 || qe.Max != 2 {
		t.Fatalf("CheckBeamQuota at limit: %v", err)
	}

	// Unset quota fails closed.
	unset := *f.bh
	unset.Quota.MaxBeams = 0
	if err := f.pep.CheckBeamQuota(ctx, unset); !errors.As(err, &qe) {
		t.Fatalf("CheckBeamQuota unset limit should fail closed: %v", err)
	}

	if err := f.pep.CheckDatabaseQuota(ctx, *f.bh); err != nil {
		t.Fatalf("CheckDatabaseQuota empty: %v", err)
	}
}

func TestEffectiveLiveSlotLimit(t *testing.T) {
	bh := domain.Beamhall{LiveSlotLimit: 3, Quota: domain.ResourceQuota{MaxLiveSlots: 2}}
	if got := EffectiveLiveSlotLimit(bh); got != 2 {
		t.Fatalf("min(3,2) = %d, want 2", got)
	}
	bh.Quota.MaxLiveSlots = 5
	if got := EffectiveLiveSlotLimit(bh); got != 3 {
		t.Fatalf("min(3,5) = %d, want 3", got)
	}
	bh.LiveSlotLimit = 0 // unset fails closed
	if got := EffectiveLiveSlotLimit(bh); got != 0 {
		t.Fatalf("unset limit = %d, want 0", got)
	}
}

func TestPromoteBeamTransactionalSlot(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	mkRunning := func(slug string) *domain.Beam {
		b := &domain.Beam{BeamhallID: f.bh.ID, Slug: slug, Mode: domain.ModePreview, State: domain.StateRunning}
		if err := f.st.CreateBeam(ctx, b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	b1, b2 := mkRunning("one"), mkRunning("two")

	// Missing beam: ErrNotFound, slot untouched.
	if err := f.st.PromoteBeam(ctx, f.bh.ID, "ghost", 1); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("promote missing beam: %v", err)
	}

	// First promote takes the only slot.
	if err := f.st.PromoteBeam(ctx, f.bh.ID, b1.ID, 1); err != nil {
		t.Fatalf("first promote: %v", err)
	}
	// PromoteBeam reserves the live slot by flipping mode only; the preview
	// channel's state is left as-is (the orchestrator sets live_state after the
	// live workload is healthy).
	got, err := f.st.GetBeam(ctx, b1.ID)
	if err != nil || got.Mode != domain.ModeLive || got.State != domain.StateRunning {
		t.Fatalf("promoted beam = mode %s state %s err %v", got.Mode, got.State, err)
	}

	// Second promote hits the slot wall.
	if err := f.st.PromoteBeam(ctx, f.bh.ID, b2.ID, 1); !errors.Is(err, store.ErrQuota) {
		t.Fatalf("second promote: %v, want ErrQuota", err)
	}
}

func TestPromoteBeamConcurrentRace(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	const n = 8
	beams := make([]*domain.Beam, n)
	for i := range beams {
		b := &domain.Beam{BeamhallID: f.bh.ID, Slug: string(rune('a' + i)), Mode: domain.ModePreview, State: domain.StateRunning}
		if err := f.st.CreateBeam(ctx, b); err != nil {
			t.Fatal(err)
		}
		beams[i] = b
	}

	var wg sync.WaitGroup
	results := make(chan error, n)
	for _, b := range beams {
		wg.Add(1)
		go func(id domain.ID) {
			defer wg.Done()
			results <- f.st.PromoteBeam(ctx, f.bh.ID, id, 1)
		}(b.ID)
	}
	wg.Wait()
	close(results)

	var wins, quotaDenies int
	for err := range results {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, store.ErrQuota):
			quotaDenies++
		default:
			t.Fatalf("unexpected promote error: %v", err)
		}
	}
	if wins != 1 || quotaDenies != n-1 {
		t.Fatalf("wins=%d quotaDenies=%d, want exactly 1 winner with limit 1", wins, quotaDenies)
	}
	live, err := f.st.CountLiveBeamsByBeamhall(ctx, f.bh.ID)
	if err != nil || live != 1 {
		t.Fatalf("live count = %d (err %v), want 1", live, err)
	}
}
