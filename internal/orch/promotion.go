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
	// Serialize against any other deploy/promote/rollback/destroy on this
	// beam, and against a concurrent RejectPromotion for the SAME request:
	// without this, an approve and a reject can interleave so the beam
	// goes live via this call's o.promote() while a concurrent reject wins
	// the DecidePromotionRequest race below — the request record ends up
	// "rejected" even though production already shipped. Held for this
	// call's entire read-decide-persist sequence, not just around o.promote,
	// which is why the lock lives here rather than inside o.promote itself.
	unlock := o.beamLocks.lock(req.BeamID)
	defer unlock()
	// Re-read: another decision may have landed while we waited for the lock.
	req, err = o.st.GetPromotionRequest(ctx, requestID)
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
	// The approver is signing off on the EXACT release named in the request
	// (req.ReleaseID, pinned at request time). promote() always pins to
	// whatever the preview channel is running NOW — if a deploy landed while
	// this request was pending, approving it would ship a build the approver
	// never reviewed, under the guise of an approval for the old one.
	beam, err := o.st.GetBeam(ctx, req.BeamID)
	if err != nil {
		return "", req, err
	}
	if beam.CurrentReleaseID != req.ReleaseID {
		return "", req, fmt.Errorf("the preview build has changed since this promotion was requested (requested %s, preview is now on %s) — reject this request and have it re-requested against the current build",
			req.ReleaseID, beam.CurrentReleaseID)
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
	// Same per-beam serialization as approvePromotion, so an approve
	// racing this reject can't land the beam live while the request record
	// ends up "rejected".
	unlock := o.beamLocks.lock(req.BeamID)
	defer unlock()
	op := o.st.DecidePromotionRequest(ctx, requestID, domain.PromotionRejected, actor.ID, reason)
	return o.itAudit(ctx, actor, "reject_promotion", req.BeamhallID, op)
}
