package orch

import (
	"context"
	"strings"
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
