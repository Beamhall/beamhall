package orch

import (
	"context"
	"errors"
	"strings"
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
	if _, err := w.o.CreateBeam(ctx, w.build, w.bh.ID, "tracker", "Tracker 2", "node"); err != nil {
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
