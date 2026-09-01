package orch

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/driver"
	"github.com/Beamhall/beamhall/internal/store"
)

// releasesOf returns a beam's releases newest-first by version.
func releasesOf(t *testing.T, w *world, beamID domain.ID) []domain.Release {
	t.Helper()
	rels, err := w.st.ListReleasesByBeam(context.Background(), beamID)
	if err != nil {
		t.Fatal(err)
	}
	return rels
}

func TestRollbackReactivatesPriorRelease(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()

	// Rollback re-pins the LIVE channel: promote to create a live release,
	// ship a second build, then roll production back to the first.
	beam := w.deployed(t, "tracker")
	if _, err := w.o.PromoteToLive(ctx, w.admin, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("promote v1: %v", err)
	}
	got, _ := w.st.GetBeam(ctx, beam.ID)
	liveRel1 := got.LiveReleaseID
	if liveRel1 == "" {
		t.Fatal("no live release after promote")
	}

	// New preview build, then promote again — production rolls forward to v2.
	if _, err := w.o.DeployBeam(ctx, w.build, w.bh.ID, beam.ID,
		DeployRequest{ImageRef: "reg/beam:2", ImageDigest: "sha256:def"}); err != nil {
		t.Fatalf("redeploy preview: %v", err)
	}
	if _, err := w.o.PromoteToLive(ctx, w.admin, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("promote v2: %v", err)
	}
	got, _ = w.st.GetBeam(ctx, beam.ID)
	liveRel2 := got.LiveReleaseID
	if liveRel2 == liveRel1 {
		t.Fatal("re-promote did not mint a new live release")
	}

	// Roll production back to v1.
	host, err := w.o.RollbackBeam(ctx, w.admin, w.bh.ID, beam.ID, liveRel1)
	if err != nil {
		t.Fatalf("RollbackBeam: %v", err)
	}
	if !strings.Contains(host, "tracker.ops.") {
		t.Errorf("rollback host = %q, want the stable live host", host)
	}
	got, _ = w.st.GetBeam(ctx, beam.ID)
	if got.LiveReleaseID != liveRel1 {
		t.Fatalf("live release = %s, want the rolled-back-to %s", got.LiveReleaseID, liveRel1)
	}
	// The preview channel is untouched by a production rollback.
	if got.State != domain.StateRunning {
		t.Errorf("preview state = %s, want running", got.State)
	}
	for _, r := range releasesOf(t, w, beam.ID) {
		switch r.ID {
		case liveRel1:
			if r.Status != domain.ReleaseActive {
				t.Errorf("target live release status = %s, want active", r.Status)
			}
		case liveRel2:
			if r.Status != domain.ReleaseSuperseded {
				t.Errorf("departed live release status = %s, want superseded", r.Status)
			}
		}
	}
}

func TestRollbackRejectsForeignOrCurrentRelease(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	beam := w.deployed(t, "tracker")
	if _, err := w.o.PromoteToLive(ctx, w.admin, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("promote: %v", err)
	}
	got, _ := w.st.GetBeam(ctx, beam.ID)
	other := w.deployed(t, "other")

	// Rolling back without a live channel is refused (preview-only beam).
	if _, err := w.o.RollbackBeam(ctx, w.admin, w.bh.ID, other.ID, other.CurrentReleaseID); err == nil {
		t.Fatal("rollback on a beam with no live channel should fail")
	}
	// The current live release cannot be a rollback target.
	if _, err := w.o.RollbackBeam(ctx, w.admin, w.bh.ID, beam.ID, got.LiveReleaseID); err == nil {
		t.Fatal("rollback to the active live release should fail")
	}
	// A different beam's release is rejected.
	if _, err := w.o.RollbackBeam(ctx, w.admin, w.bh.ID, beam.ID, other.CurrentReleaseID); err == nil {
		t.Fatal("rollback to another beam's release should fail")
	}
}

// TestRollbackRejectsPreviewChannelRelease is a regression test:
// an older,
// superseded PREVIEW release must not be a valid rollback target — only the
// two checks for "is it the current live release" and "is it the current
// preview release" existed before, and both pass for a superseded preview
// release, which would then get pinned to production carrying its preview
// secret scope (the preview DB DSN under the app's shared key).
func TestRollbackRejectsPreviewChannelRelease(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	beam := w.deployed(t, "tracker")
	previewV1 := beam.CurrentReleaseID // about to be superseded, never a live release

	if _, err := w.o.PromoteToLive(ctx, w.admin, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("promote: %v", err)
	}
	// A second preview deploy supersedes v1 — it is now neither the current
	// live release nor the current preview release, just an old preview build.
	if _, err := w.o.DeployBeam(ctx, w.build, w.bh.ID, beam.ID,
		DeployRequest{ImageRef: "reg/beam:2", ImageDigest: "sha256:def"}); err != nil {
		t.Fatalf("redeploy preview: %v", err)
	}
	for _, r := range releasesOf(t, w, beam.ID) {
		if r.ID == previewV1 && r.Status != domain.ReleaseSuperseded {
			t.Fatalf("setup: v1 release status = %s, want superseded", r.Status)
		}
	}

	if _, err := w.o.RollbackBeam(ctx, w.admin, w.bh.ID, beam.ID, previewV1); err == nil {
		t.Fatal("rollback to a superseded PREVIEW release should be rejected")
	} else if !strings.Contains(err.Error(), "preview build") {
		t.Fatalf("rollback error = %q, want it to name the release as a preview build", err.Error())
	}
	// Production must be untouched: still on the release PromoteToLive minted.
	got, _ := w.st.GetBeam(ctx, beam.ID)
	if got.LiveReleaseID == previewV1 {
		t.Fatal("production was pinned to a preview-channel release")
	}
}

// TestDestroySweepsOrphanedReleaseWorkloads is a further regression test:
// destroy must tear down EVERY release's workload, not just the two pointers
// (CurrentReleaseID/LiveReleaseID) — a release left over from a partial
// finalize failure or any other path that references a running
// container without ever becoming the beam's pointer would otherwise survive
// the beam's own destruction, permanently orphaned.
func TestDestroySweepsOrphanedReleaseWorkloads(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	beam := w.deployed(t, "tracker")

	// An orphaned release: a real workload handle, but never pointed to by
	// the beam's CurrentReleaseID or LiveReleaseID.
	build := &domain.Build{BeamID: beam.ID, SourceKind: domain.SourceImageRef, Status: domain.BuildSucceeded}
	if err := w.st.CreateBuild(ctx, build); err != nil {
		t.Fatalf("create build for orphan release: %v", err)
	}
	orphan := &domain.Release{
		BeamID: beam.ID, BuildID: build.ID, Version: 2, Channel: domain.ChannelPreview, Status: domain.ReleasePending,
	}
	if err := w.st.CreateRelease(ctx, orphan); err != nil {
		t.Fatalf("create orphan release: %v", err)
	}
	// CreateRelease doesn't persist the workload handle — it's set separately
	// once a container exists (SetReleaseWorkload), matching the real flow.
	if err := w.st.SetReleaseWorkload(ctx, orphan.ID, domain.WorkloadHandle{Driver: "fake", Ref: "ctr-orphan"}); err != nil {
		t.Fatalf("set orphan workload: %v", err)
	}

	if err := w.o.DestroyBeam(ctx, w.admin, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("DestroyBeam: %v", err)
	}

	foundOrphan := false
	for _, ref := range w.drv.destroyed {
		if ref == "ctr-orphan" {
			foundOrphan = true
		}
	}
	if !foundOrphan {
		t.Fatalf("destroyed = %v, want the orphaned release's workload (ctr-orphan) cleaned up", w.drv.destroyed)
	}
	got, err := w.st.GetRelease(ctx, orphan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != domain.ReleaseSuperseded {
		t.Fatalf("orphan release status = %s, want superseded", got.Status)
	}
}

// TestConcurrentDeployAndDestroyNeverResurrects is a regression test:
// a deploy and a
// destroy racing on the SAME beam must not interleave their read-modify-write
// on the Beam row. Before the per-beam lock, a deploy that read the beam
// before a concurrent destroy archived it could finish later and blindly
// persist beam.Status="active" over top of "archived" — resurrecting a
// beam whose managed resources (db, route, quota slot) were already reclaimed.
// Run with -race; the fake driver/gateway are themselves mutex-guarded so any
// data race reported is in the orchestrator, not the test doubles.
func TestConcurrentDeployAndDestroyNeverResurrects(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	beam := w.deployed(t, "tracker")

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = w.o.DeployBeam(ctx, w.build, w.bh.ID, beam.ID,
			DeployRequest{ImageRef: "reg/beam:2", ImageDigest: "sha256:def"})
	}()
	go func() {
		defer wg.Done()
		_ = w.o.DestroyBeam(ctx, w.admin, w.bh.ID, beam.ID)
	}()
	wg.Wait()

	// Whichever operation the lock let run second must have seen the first
	// one's committed result, not raced past it — so exactly one terminal
	// state is possible: destroyed. A resurrection would show up as "active".
	got, err := w.st.GetBeam(ctx, beam.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != domain.BeamArchived {
		t.Fatalf("beam status = %s, want archived (a non-archived result means destroy was resurrected by a racing deploy)", got.Status)
	}
}

func TestDestroyArchivesAndFreesQuotaAndSlug(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	beam := w.deployed(t, "tracker")

	if err := w.o.DestroyBeam(ctx, w.admin, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("DestroyBeam: %v", err)
	}
	// Workload torn down, route retired.
	if len(w.drv.destroyed) == 0 {
		t.Error("workload not destroyed")
	}
	if len(w.gw.routes) != 0 {
		t.Errorf("route not retired: %v", w.gw.routes)
	}
	// Archived beams refuse further operations (destroy is terminal; the FSM
	// still reads "running", so the guard is on Status).
	if _, err := w.o.RollbackBeam(ctx, w.build, w.bh.ID, beam.ID, beam.CurrentReleaseID); err == nil {
		t.Error("rollback on a destroyed beam should fail")
	}
	got, _ := w.st.GetBeam(ctx, beam.ID)
	if got.Status != domain.BeamArchived {
		t.Fatalf("status = %s, want archived", got.Status)
	}
	if _, err := w.st.GetBeamBySlug(ctx, w.bh.ID, "tracker"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("destroyed slug still resolves: %v", err)
	}
	if pauses := w.armedPauses(t); len(pauses) != 0 {
		t.Error("destroyed beam still has an armed pause")
	}

	// The slug is reusable and quota is freed: re-create "tracker".
	if _, err := w.o.CreateBeam(ctx, w.build, w.bh.ID, "tracker", "Tracker 2", "", "node"); err != nil {
		t.Fatalf("recreate destroyed slug: %v", err)
	}
}

func TestDestroyIsIdempotentlyTerminal(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	beam := w.deployed(t, "tracker")
	if err := w.o.DestroyBeam(ctx, w.admin, w.bh.ID, beam.ID); err != nil {
		t.Fatal(err)
	}
	if err := w.o.DestroyBeam(ctx, w.admin, w.bh.ID, beam.ID); err == nil {
		t.Fatal("second destroy should fail (already archived)")
	}
}

func TestShowMetrics(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.drv.stats = driver.Stats{CPUPct: 12.5, MemBytes: 64 << 20}
	beam := w.deployed(t, "tracker")

	stats, err := w.o.ShowMetrics(ctx, w.build, w.bh.ID, beam.ID)
	if err != nil {
		t.Fatalf("ShowMetrics: %v", err)
	}
	if stats.CPUPct != 12.5 || stats.MemBytes != 64<<20 {
		t.Fatalf("stats = %+v", stats)
	}
}

// TestCrossHallBeamAccessRefused is a regression test:
// pause, resume,
// show_logs, show_metrics, show_email, and show_object_store must all refuse
// a beamID that belongs to a DIFFERENT beamhall than the one the caller is
// authorized (a member) in — not just trust that every caller happens to
// resolve beams by slug-within-hall first.
func TestCrossHallBeamAccessRefused(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()

	// A second beamhall, with its own beam, that w.build has no membership in.
	otherHall := &domain.Beamhall{
		Slug: "other", DisplayName: "Other", Status: domain.BeamhallActive,
		NetworkPolicy: domain.NetworkPolicy{EgressMode: domain.EgressDenyAll},
		Quota:         domain.ResourceQuota{MaxBeams: 5, MaxLiveSlots: 1, MaxDBCount: 1},
		LiveSlotLimit: 1,
	}
	otherSC := &domain.SecurityContext{
		RuntimeClass: domain.RuntimeRunsc, CapDrop: []string{"ALL"}, NoNewPrivileges: true,
		ReadOnlyRootfs: true, Tmpfs: []string{"/tmp"}, Template: domain.TemplateWebApp,
		CgroupLimits: domain.ResourceLimits{CPUQuota: 100000, MemBytes: 256 << 20, PidsMax: 128},
	}
	if err := w.st.CreateBeamhall(ctx, otherHall, otherSC); err != nil {
		t.Fatalf("create other beamhall: %v", err)
	}
	otherBeam := &domain.Beam{
		BeamhallID: otherHall.ID, Slug: "victim", Mode: domain.ModePreview,
		State: domain.StateRunning, SecurityTemplate: domain.TemplateWebApp,
	}
	if err := w.st.CreateBeam(ctx, otherBeam); err != nil {
		t.Fatalf("create beam in other hall: %v", err)
	}

	// w.build is a member of w.bh ("ops"), NOT otherHall — the PEP passes
	// membership for w.bh.ID, but the supplied beam actually lives in
	// otherHall. Every call below must be refused BY THE CONTAINMENT CHECK
	// specifically (asserted on the error text, not just "some error") — a
	// beam missing a release/route/workload would already error out for an
	// unrelated reason first, which would let this test pass without actually
	// exercising the fix.
	const wantErr = "is not in beamhall"
	check := func(name string, err error) {
		t.Helper()
		if err == nil {
			t.Errorf("%s reached a beam in a different beamhall (no error)", name)
		} else if !strings.Contains(err.Error(), wantErr) {
			t.Errorf("%s error = %q, want it to name the cross-beamhall refusal (%q)", name, err.Error(), wantErr)
		}
	}
	check("PausePreview", w.o.PausePreview(ctx, w.build, w.bh.ID, otherBeam.ID))
	_, err := w.o.ResumePreview(ctx, w.build, w.bh.ID, otherBeam.ID)
	check("ResumePreview", err)
	_, err = w.o.ShowLogs(ctx, w.build, w.bh.ID, otherBeam.ID, driver.LogOptions{})
	check("ShowLogs", err)
	_, err = w.o.ShowMetrics(ctx, w.build, w.bh.ID, otherBeam.ID)
	check("ShowMetrics", err)
	_, err = w.o.ShowEmail(ctx, w.build, w.bh.ID, otherBeam.ID)
	check("ShowEmail", err)
	_, err = w.o.ShowObjectStore(ctx, w.build, w.bh.ID, otherBeam.ID)
	check("ShowObjectStore", err)
}

func TestBuildSlotCapRefusesOverflow(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	WithMaxConcurrentBuilds(1)(w.o)

	// Occupy the only slot, then a second acquire must be refused.
	release, err := w.o.acquireBuildSlot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.o.acquireBuildSlot(); err == nil {
		t.Fatal("second build slot granted past the cap")
	}
	release()
	if _, err := w.o.acquireBuildSlot(); err != nil {
		t.Fatalf("slot not released: %v", err)
	}
	_ = ctx
}
