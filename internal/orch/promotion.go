package orch

import (
	"context"
	"errors"
	"fmt"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/policy"
	"github.com/Beamhall/beamhall/internal/store"
)

// RequestPromotion records a pending promotion request when the IT-approval
// gate is on. The PEP gates who may request (builder+); a different IT operator
// approves it via ApprovePromotion (four-eyes). Returns the created request.
func (o *Orchestrator) RequestPromotion(ctx context.Context, actor Actor, beamhallID, beamID domain.ID) (domain.PromotionRequest, error) {
	if err := o.authorize(ctx, actor, policy.ActionRequestPromote, beamhallID, beamID); err != nil {
		return domain.PromotionRequest{}, err
	}
	req, err := o.requestPromotion(ctx, actor, beamhallID, beamID)
	return req, o.outcome(ctx, actor, policy.ActionRequestPromote, beamhallID, beamID, err)
}

func (o *Orchestrator) requestPromotion(ctx context.Context, actor Actor, beamhallID, beamID domain.ID) (domain.PromotionRequest, error) {
	beam, err := o.operableBeam(ctx, beamhallID, beamID)
	if err != nil {
		return domain.PromotionRequest{}, err
	}
	// Must be promotable now (same FSM guard the direct promote applies), so a
	// request can't be queued for a beam that could never go live.
	if _, ok, reason := beam.Can(domain.EvPromote); !ok {
		return domain.PromotionRequest{}, &domain.TransitionError{From: beam.State, Mode: beam.Mode, Event: domain.EvPromote, Reason: reason}
	}
	if existing, err := o.st.GetPendingPromotionByBeam(ctx, beamID); err == nil {
		return domain.PromotionRequest{}, fmt.Errorf("a promotion request (%s) is already pending for this beam", existing.ID)
	} else if !errors.Is(err, store.ErrNotFound) {
		return domain.PromotionRequest{}, err
	}
	req := &domain.PromotionRequest{
		BeamhallID: beamhallID, BeamID: beamID, ReleaseID: beam.CurrentReleaseID,
		RequestedBy: actor.ID, Status: domain.PromotionPending,
	}
	if err := o.st.CreatePromotionRequest(ctx, req); err != nil {
		return domain.PromotionRequest{}, err
	}
	o.log.Info("promotion requested", "beam", beamID, "by", actor.ID, "request", req.ID)
	return *req, nil
}

// ListPendingPromotions returns a beamhall's pending requests. IT only.
func (o *Orchestrator) ListPendingPromotions(ctx context.Context, actor Actor, beamhallID domain.ID) ([]domain.PromotionRequest, error) {
	if err := o.requireIT(actor); err != nil {
		return nil, err
	}
	return o.st.ListPendingPromotionRequests(ctx, beamhallID)
}

// ApprovePromotion approves a pending request and promotes the beam to live. IT
// only, and the approver MUST differ from the requester (four-eyes). Returns the
// live hostname.
func (o *Orchestrator) ApprovePromotion(ctx context.Context, actor Actor, requestID domain.ID) (string, error) {
	if err := o.requireIT(actor); err != nil {
		return "", o.itAudit(ctx, actor, "approve_promotion", "", err)
	}
	hostname, req, err := o.approvePromotion(ctx, actor, requestID)
	bhID := req.BeamhallID
	return hostname, o.itAudit(ctx, actor, "approve_promotion", bhID, err)
}

func (o *Orchestrator) approvePromotion(ctx context.Context, actor Actor, requestID domain.ID) (string, domain.PromotionRequest, error) {
	req, err := o.st.GetPromotionRequest(ctx, requestID)
	if err != nil {
		return "", req, err
	}
	if req.Status != domain.PromotionPending {
		return "", req, fmt.Errorf("request %s is already %s", requestID, req.Status)
	}
	// Four-eyes: the approver cannot be the requester.
	if req.RequestedBy == actor.ID {
		return "", req, fmt.Errorf("the requester cannot approve their own promotion (four-eyes)")
	}
	hostname, err := o.promote(ctx, actor, req.BeamhallID, req.BeamID)
	if err != nil {
		return "", req, err
	}
	if err := o.st.DecidePromotionRequest(ctx, req.ID, domain.PromotionApproved, actor.ID, ""); err != nil {
		return hostname, req, err
	}
	o.log.Info("promotion approved", "request", req.ID, "by", actor.ID, "beam", req.BeamID)
	return hostname, req, nil
}

// RejectPromotion rejects a pending request without promoting. IT only.
func (o *Orchestrator) RejectPromotion(ctx context.Context, actor Actor, requestID domain.ID, reason string) error {
	if err := o.requireIT(actor); err != nil {
		return o.itAudit(ctx, actor, "reject_promotion", "", err)
	}
	req, err := o.st.GetPromotionRequest(ctx, requestID)
	if err != nil {
		return o.itAudit(ctx, actor, "reject_promotion", "", err)
	}
	op := o.st.DecidePromotionRequest(ctx, requestID, domain.PromotionRejected, actor.ID, reason)
	return o.itAudit(ctx, actor, "reject_promotion", req.BeamhallID, op)
}
