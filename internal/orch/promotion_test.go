package orch

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/store"
)

// TestPromoteApprovalGate exercises the request → approve flow, the four-eyes
// rule, the reject path, and the one-pending-per-beam guard.
func TestPromoteApprovalGate(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	beam := w.deployed(t, "tracker")

	it := Actor{ID: store.NewID(), ITAdmin: true} // a distinct IT operator

	// Builder requests promotion.
	req, err := w.o.RequestPromotion(ctx, w.build, w.bh.ID, beam.ID)
	if err != nil {
		t.Fatalf("RequestPromotion: %v", err)
	}
	if req.Status != domain.PromotionPending {
		t.Fatalf("request status = %s, want pending", req.Status)
	}

	// One pending per beam: a second request is refused.
	if _, err := w.o.RequestPromotion(ctx, w.build, w.bh.ID, beam.ID); err == nil {
		t.Fatal("second RequestPromotion should fail (one pending per beam)")
	}

	// IT sees it pending.
	pending, err := w.o.ListPendingPromotions(ctx, it, w.bh.ID)
	if err != nil || len(pending) != 1 {
		t.Fatalf("ListPendingPromotions: n=%d err=%v", len(pending), err)
	}

	// Four-eyes: the requester cannot approve their own request, even as IT.
	selfIT := Actor{ID: w.build.ID, ITAdmin: true}
	if _, err := w.o.ApprovePromotion(ctx, selfIT, req.ID); err == nil || !strings.Contains(err.Error(), "four-eyes") {
		t.Fatalf("self-approval should be refused (four-eyes), got %v", err)
	}

	// A different IT operator approves → the beam goes live.
	host, err := w.o.ApprovePromotion(ctx, it, req.ID)
	if err != nil {
		t.Fatalf("ApprovePromotion: %v", err)
	}
	if host == "" {
		t.Fatal("approve returned no live hostname")
	}
	got, _ := w.st.GetBeam(ctx, beam.ID)
	if got.Mode != domain.ModeLive {
		t.Fatalf("beam mode = %s, want live", got.Mode)
	}
	decided, _ := w.st.GetPromotionRequest(ctx, req.ID)
	if decided.Status != domain.PromotionApproved || decided.DecidedBy != it.ID {
		t.Fatalf("request not recorded approved by IT: %+v", decided)
	}

	// Approving an already-decided request fails.
	if _, err := w.o.ApprovePromotion(ctx, it, req.ID); err == nil {
		t.Fatal("re-approving a decided request should fail")
	}
}

func TestPromoteApprovalReject(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	beam := w.deployed(t, "tracker")
	it := Actor{ID: store.NewID(), ITAdmin: true}

	req, err := w.o.RequestPromotion(ctx, w.build, w.bh.ID, beam.ID)
	if err != nil {
		t.Fatalf("RequestPromotion: %v", err)
	}
	if err := w.o.RejectPromotion(ctx, it, req.ID, "not ready"); err != nil {
		t.Fatalf("RejectPromotion: %v", err)
	}
	decided, _ := w.st.GetPromotionRequest(ctx, req.ID)
	if decided.Status != domain.PromotionRejected || decided.Reason != "not ready" {
		t.Fatalf("request not rejected: %+v", decided)
	}
	// Beam stays in preview; a fresh request is allowed after a rejection.
	if got, _ := w.st.GetBeam(ctx, beam.ID); got.Mode == domain.ModeLive {
		t.Fatal("rejected request must not have promoted the beam")
	}
	if _, err := w.o.RequestPromotion(ctx, w.build, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("a new request after rejection should be allowed: %v", err)
	}
}

// TestApprovePromotionRefusesStaleRelease is a regression test:
// if the preview build
// moves on while a promotion request is pending, approving that request must
// NOT silently ship the new build under the guise of an approval for the old
// one — the approver is signing off on the exact release named in the
// request, not "whatever preview happens to be running when they click
// approve".
func TestApprovePromotionRefusesStaleRelease(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	beam := w.deployed(t, "tracker")
	previewV1 := beam.CurrentReleaseID
	it := Actor{ID: store.NewID(), ITAdmin: true}

	req, err := w.o.RequestPromotion(ctx, w.build, w.bh.ID, beam.ID)
	if err != nil {
		t.Fatalf("RequestPromotion: %v", err)
	}
	if req.ReleaseID != previewV1 {
		t.Fatalf("request pinned release = %s, want %s", req.ReleaseID, previewV1)
	}

	// The preview moves on WHILE the request is pending — the FSM doesn't
	// block a redeploy just because a promotion request is outstanding.
	if _, err := w.o.DeployBeam(ctx, w.build, w.bh.ID, beam.ID,
		DeployRequest{ImageRef: "reg/beam:2", ImageDigest: "sha256:def"}); err != nil {
		t.Fatalf("redeploy preview while promotion pending: %v", err)
	}
	got, _ := w.st.GetBeam(ctx, beam.ID)
	if got.CurrentReleaseID == previewV1 {
		t.Fatal("setup: redeploy did not advance the preview release")
	}

	// A different IT operator approves the now-stale request.
	if _, err := w.o.ApprovePromotion(ctx, it, req.ID); err == nil {
		t.Fatal("approving a request whose release is no longer current should be refused")
	} else if !strings.Contains(err.Error(), "changed since this promotion was requested") {
		t.Fatalf("approve error = %q, want it to name the stale-release mismatch", err.Error())
	}
	// Nothing shipped: the beam never went live.
	got, _ = w.st.GetBeam(ctx, beam.ID)
	if got.Mode == domain.ModeLive {
		t.Fatal("a refused approval must not have promoted the beam")
	}
	// The request itself is left pending (not silently decided), so IT can
	// reject it and the requester can re-request against the current build.
	decided, _ := w.st.GetPromotionRequest(ctx, req.ID)
	if decided.Status != domain.PromotionPending {
		t.Fatalf("request status = %s, want still pending", decided.Status)
	}
}

// TestConcurrentApproveRejectNeverDisagreesWithReality is a further
// regression test:
// racing an ApprovePromotion against a RejectPromotion for the SAME request
// must not let the beam go live via the approve's o.promote() call while the
// reject wins the request-decision race — leaving a live beam whose audit
// record says "rejected". Exactly one consistent outcome must hold: approved
// (Mode==live) or rejected (Mode!=live) — never both/neither. Run with -race.
func TestConcurrentApproveRejectNeverDisagreesWithReality(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	beam := w.deployed(t, "tracker")
	itApprove := Actor{ID: store.NewID(), ITAdmin: true}
	itReject := Actor{ID: store.NewID(), ITAdmin: true}

	req, err := w.o.RequestPromotion(ctx, w.build, w.bh.ID, beam.ID)
	if err != nil {
		t.Fatalf("RequestPromotion: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = w.o.ApprovePromotion(ctx, itApprove, req.ID)
	}()
	go func() {
		defer wg.Done()
		_ = w.o.RejectPromotion(ctx, itReject, req.ID, "racing reject")
	}()
	wg.Wait()

	got, err := w.st.GetBeam(ctx, beam.ID)
	if err != nil {
		t.Fatal(err)
	}
	decided, err := w.st.GetPromotionRequest(ctx, req.ID)
	if err != nil {
		t.Fatal(err)
	}
	live := got.Mode == domain.ModeLive
	switch decided.Status {
	case domain.PromotionApproved:
		if !live {
			t.Fatal("request decided approved but the beam never went live")
		}
	case domain.PromotionRejected:
		if live {
			t.Fatal("request decided rejected but the beam went live anyway (H7 regression)")
		}
	default:
		t.Fatalf("request left in status %s, want approved or rejected", decided.Status)
	}
}

// TestRequestPromotionNeedsMembership: a non-member cannot request.
func TestRequestPromotionDeniedWithoutRole(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	beam := w.deployed(t, "tracker")
	stranger := Actor{ID: store.NewID()} // no membership
	if _, err := w.o.RequestPromotion(ctx, stranger, w.bh.ID, beam.ID); err == nil {
		t.Fatal("a non-member must not be able to request promotion")
	}
}
