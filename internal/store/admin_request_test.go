package store

import (
	"context"
	"errors"
	"testing"

	"github.com/Beamhall/beamhall/internal/domain"
)

func TestAdminActionRequestRoundTripAndDecideOnce(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()

	req := &domain.AdminActionRequest{
		ActionType:    domain.AdminActionFederateDirectory,
		Summary:       "federate corp-ad → ldaps://dc1:636",
		PayloadCipher: []byte{0x01, 0x02, 0x03}, // opaque sealed bytes
		RequestedBy:   "ident-requester",
		Status:        domain.AdminActionPending,
	}
	if err := s.CreateAdminActionRequest(ctx, req); err != nil {
		t.Fatalf("CreateAdminActionRequest: %v", err)
	}
	if req.ID == "" {
		t.Fatal("id not assigned")
	}

	got, err := s.GetAdminActionRequest(ctx, req.ID)
	if err != nil {
		t.Fatalf("GetAdminActionRequest: %v", err)
	}
	if got.Summary != req.Summary || string(got.PayloadCipher) != string(req.PayloadCipher) || got.Status != domain.AdminActionPending {
		t.Fatalf("round-trip mismatch: %+v", got)
	}

	pending, err := s.ListPendingAdminActionRequests(ctx)
	if err != nil || len(pending) != 1 {
		t.Fatalf("ListPending: n=%d err=%v", len(pending), err)
	}

	// Approve: marks decided, records result, leaves no pending.
	if err := s.DecideAdminActionRequest(ctx, req.ID, domain.AdminActionApproved, "ident-approver", "", "directory federated"); err != nil {
		t.Fatalf("DecideAdminActionRequest: %v", err)
	}
	pending, _ = s.ListPendingAdminActionRequests(ctx)
	if len(pending) != 0 {
		t.Fatalf("approved request still pending (%d)", len(pending))
	}

	// Deciding again is a no-op guarded by ErrNotFound (can't double-decide).
	err = s.DecideAdminActionRequest(ctx, req.ID, domain.AdminActionRejected, "ident-approver", "x", "")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("second decide: want ErrNotFound, got %v", err)
	}
	final, _ := s.GetAdminActionRequest(ctx, req.ID)
	if final.Status != domain.AdminActionApproved || final.Result != "directory federated" || final.DecidedBy != "ident-approver" {
		t.Fatalf("decision not recorded: %+v", final)
	}
}
