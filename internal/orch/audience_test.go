package orch

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/store"
)

// userActor registers an identity with NO membership anywhere — the using
// tier's defining shape.
func userActor(t *testing.T, w *world, groups ...string) Actor {
	t.Helper()
	ident := &domain.Identity{ExternalSubject: string(store.NewID()), Email: "u@x",
		DisplayName: "u", IdPIssuer: "idp", Status: domain.IdentityActive}
	if err := w.st.CreateIdentity(context.Background(), ident); err != nil {
		t.Fatal(err)
	}
	return Actor{ID: ident.ID, Groups: groups}
}

func TestSetAppAudienceRequiresITAndAudits(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	beam := w.deployed(t, "tracker")

	spec := AudienceSpec{Audience: domain.Audience{Everyone: true}}
	if err := w.o.SetAppAudience(ctx, w.build, w.bh.ID, beam.ID, spec); err == nil {
		t.Fatal("builder should not be able to publish an app")
	}
	recs, _ := w.st.ListAuditEvents(ctx, 0, 50)
	var denied bool
	for _, rec := range recs {
		if rec.Event.Action == "admin_set_app_audience" && rec.Event.Decision == domain.DecisionDeny {
			denied = true
			if rec.Event.BeamID != beam.ID {
				t.Errorf("deny event missing beam id: %+v", rec.Event)
			}
		}
	}
	if !denied {
		t.Fatal("denied admin_set_app_audience not on the audit chain")
	}

	it := Actor{ITAdmin: true}
	if err := w.o.SetAppAudience(ctx, it, w.bh.ID, beam.ID, spec); err != nil {
		t.Fatalf("SetAppAudience (IT): %v", err)
	}
	if _, err := w.st.GetBeamAudience(ctx, beam.ID); err != nil {
		t.Fatalf("publication not persisted: %v", err)
	}
}

func TestSetAppAudienceRejectsEmptyAudience(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	beam := w.deployed(t, "tracker")
	err := w.o.SetAppAudience(ctx, Actor{ITAdmin: true}, w.bh.ID, beam.ID, AudienceSpec{})
	if err == nil {
		t.Fatal("an audience of nobody was accepted")
	}
	if _, gerr := w.st.GetBeamAudience(ctx, beam.ID); !errors.Is(gerr, store.ErrNotFound) {
		t.Fatalf("empty audience was persisted: %v", gerr)
	}
}

func TestListAppsAudienceMatrix(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	it := Actor{ITAdmin: true}
	beam := w.deployed(t, "tracker")

	erin := userActor(t, w)
	frank := userActor(t, w)

	// Unpublished: nobody sees it.
	for _, a := range []Actor{erin, frank} {
		if views, _ := w.o.ListApps(ctx, a); len(views) != 0 {
			t.Fatalf("unpublished app listed: %+v", views)
		}
	}

	// Identity audience: erin in, frank out.
	if err := w.o.SetAppAudience(ctx, it, w.bh.ID, beam.ID, AudienceSpec{
		Audience: domain.Audience{Identities: []domain.ID{erin.ID}},
	}); err != nil {
		t.Fatal(err)
	}
	views, err := w.o.ListApps(ctx, erin)
	if err != nil || len(views) != 1 {
		t.Fatalf("erin: %v %+v", err, views)
	}
	if views[0].App != "tracker" || views[0].Workspace != "ops" {
		t.Errorf("view = %+v", views[0])
	}
	if views[0].Live || views[0].URL != "" {
		t.Errorf("unpromoted app must have no URL and Live=false: %+v", views[0])
	}
	if views, _ := w.o.ListApps(ctx, frank); len(views) != 0 {
		t.Fatalf("frank is outside the audience but sees: %+v", views)
	}

	// Group audience (union with the identity list).
	if err := w.o.SetAppAudience(ctx, it, w.bh.ID, beam.ID, AudienceSpec{
		Audience: domain.Audience{Groups: []string{"finance"}},
	}); err != nil {
		t.Fatal(err)
	}
	fin := userActor(t, w, "finance")
	if views, _ := w.o.ListApps(ctx, fin); len(views) != 1 {
		t.Fatal("finance-group member should see the app")
	}
	if views, _ := w.o.ListApps(ctx, erin); len(views) != 0 {
		t.Fatal("re-publish replaced the audience; erin should be out now")
	}

	// Promote: the live URL appears with no re-publish.
	if _, err := w.o.PromoteToLive(ctx, w.admin, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("promote: %v", err)
	}
	views, _ = w.o.ListApps(ctx, fin)
	if len(views) != 1 || !views[0].Live || views[0].URL != "https://tracker.ops.bh.example" {
		t.Fatalf("promoted view = %+v", views)
	}

	// IT gets no bypass: an IT actor outside the audience sees nothing.
	itUser := userActor(t, w)
	itUser.ITAdmin = true
	if views, _ := w.o.ListApps(ctx, itUser); len(views) != 0 {
		t.Fatalf("ITAdmin bypassed the audience check: %+v", views)
	}
}

// A stale publication row must not resurrect an archived app (or an archived
// workspace's apps) in anyone's list.
func TestListAppsSkipsArchived(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	it := Actor{ITAdmin: true}
	erin := userActor(t, w)

	beam := w.deployed(t, "tracker")
	if err := w.o.SetAppAudience(ctx, it, w.bh.ID, beam.ID, AudienceSpec{
		Audience: domain.Audience{Everyone: true},
	}); err != nil {
		t.Fatal(err)
	}
	if views, _ := w.o.ListApps(ctx, erin); len(views) != 1 {
		t.Fatal("published app should be listed")
	}

	got, _ := w.st.GetBeam(ctx, beam.ID)
	got.Status = domain.BeamArchived
	if err := w.st.UpdateBeam(ctx, &got); err != nil {
		t.Fatal(err)
	}
	if views, _ := w.o.ListApps(ctx, erin); len(views) != 0 {
		t.Fatalf("archived app still listed: %+v", views)
	}
}

func TestDescribeAppUniformNotFound(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	erin := userActor(t, w)

	// "tracker" exists but is unpublished; "ghost" does not exist at all. The
	// two answers must be indistinguishable or describe_app becomes an
	// enumeration oracle over every hall on the appliance.
	w.deployed(t, "tracker")
	_, errUnpublished := w.o.DescribeApp(ctx, erin, "tracker", "")
	_, errMissing := w.o.DescribeApp(ctx, erin, "ghost", "")
	if !errors.Is(errUnpublished, ErrAppNotPublished) || !errors.Is(errMissing, ErrAppNotPublished) {
		t.Fatalf("want ErrAppNotPublished for both: %v / %v", errUnpublished, errMissing)
	}
	if errUnpublished.Error() != errMissing.Error() {
		t.Fatalf("answers differ: %q vs %q", errUnpublished, errMissing)
	}
}

func TestDescribeAppAndDescriptionUpdate(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	it := Actor{ITAdmin: true}
	erin := userActor(t, w)
	beam := w.deployed(t, "tracker")

	if err := w.o.SetAppAudience(ctx, it, w.bh.ID, beam.ID, AudienceSpec{
		Audience:       domain.Audience{Identities: []domain.ID{erin.ID}},
		Description:    "Track the things",
		SetDescription: true,
	}); err != nil {
		t.Fatal(err)
	}
	view, err := w.o.DescribeApp(ctx, erin, "tracker", "")
	if err != nil {
		t.Fatalf("DescribeApp: %v", err)
	}
	if view.Description != "Track the things" || view.SignIn != "app_managed" {
		t.Errorf("view = %+v", view)
	}
	// Unpublish: gone, but the description stays on the beam.
	if err := w.o.SetAppAudience(ctx, it, w.bh.ID, beam.ID, AudienceSpec{Clear: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.o.DescribeApp(ctx, erin, "tracker", ""); !errors.Is(err, ErrAppNotPublished) {
		t.Fatalf("unpublished app still resolves: %v", err)
	}
	got, _ := w.st.GetBeam(ctx, beam.ID)
	if got.Description != "Track the things" {
		t.Errorf("description lost on unpublish: %q", got.Description)
	}
}

// Discovery reads must leave no trace on the audit chain: they are the
// highest-frequency call of the tier and the chain evidences mutations.
func TestListAppsIsUnaudited(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	it := Actor{ITAdmin: true}
	erin := userActor(t, w)
	beam := w.deployed(t, "tracker")
	if err := w.o.SetAppAudience(ctx, it, w.bh.ID, beam.ID, AudienceSpec{
		Audience: domain.Audience{Everyone: true},
	}); err != nil {
		t.Fatal(err)
	}

	before, err := w.st.MaxAuditSeq(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.o.ListApps(ctx, erin); err != nil {
		t.Fatal(err)
	}
	if _, err := w.o.DescribeApp(ctx, erin, "tracker", ""); err != nil {
		t.Fatal(err)
	}
	after, err := w.st.MaxAuditSeq(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("discovery reads appended %d audit event(s)", after-before)
	}
}

func TestRegisterUserIdentityGetOrCreate(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()

	first, err := w.o.RegisterUserIdentity(ctx, "idp", "erin", "erin@x")
	if err != nil {
		t.Fatalf("RegisterUserIdentity: %v", err)
	}
	again, err := w.o.RegisterUserIdentity(ctx, "idp", "erin", "erin@x")
	if err != nil || again.ID != first.ID {
		t.Fatalf("not idempotent: %v (%s vs %s)", err, again.ID, first.ID)
	}

	// The create path (and only the create path) lands on the audit chain.
	recs, _ := w.st.ListAuditEvents(ctx, 0, 100)
	var n int
	for _, rec := range recs {
		if rec.Event.Action == "user_auto_register" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("user_auto_register events = %d, want 1", n)
	}

	// Two concurrent first calls must converge on one row.
	var wg sync.WaitGroup
	ids := make([]domain.ID, 2)
	errs := make([]error, 2)
	for i := range ids {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ident, err := w.o.RegisterUserIdentity(ctx, "idp", "frank", "frank@x")
			ids[i], errs[i] = ident.ID, err
		}(i)
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil || ids[0] != ids[1] || ids[0] == "" {
		t.Fatalf("concurrent registration diverged: %v %v %s %s", errs[0], errs[1], ids[0], ids[1])
	}
}

func TestRegisterUserIdentityRespectsOffSwitch(t *testing.T) {
	w := newWorld(t)
	w.o.userTier = UserTierConfig{} // BEAMHALL_USER_AUTO_REGISTER=off
	if _, err := w.o.RegisterUserIdentity(context.Background(), "idp", "erin", "erin@x"); err == nil {
		t.Fatal("auto-registration ran while disabled")
	}
}
