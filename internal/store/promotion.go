package store

import (
	"context"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/store/db"
)

// CreatePromotionRequest records a pending promotion request (the IT-approval
// gate). The partial unique index enforces at most one pending request per beam.
func (s *Store) CreatePromotionRequest(ctx context.Context, r *domain.PromotionRequest) error {
	if r.ID == "" {
		r.ID = NewID()
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = s.now()
	}
	return mapErr(s.q.InsertPromotionRequest(ctx, db.InsertPromotionRequestParams{
		ID:          string(r.ID),
		BeamhallID:  string(r.BeamhallID),
		BeamID:      string(r.BeamID),
		ReleaseID:   string(r.ReleaseID),
		RequestedBy: string(r.RequestedBy),
		CreatedAt:   ns(r.CreatedAt),
	}))
}

// GetPromotionRequest returns a request by id.
func (s *Store) GetPromotionRequest(ctx context.Context, id domain.ID) (domain.PromotionRequest, error) {
	row, err := s.q.GetPromotionRequest(ctx, string(id))
	if err != nil {
		return domain.PromotionRequest{}, mapErr(err)
	}
	return promotionFromRow(row), nil
}

// GetPendingPromotionByBeam returns the beam's pending request (ErrNotFound if none).
func (s *Store) GetPendingPromotionByBeam(ctx context.Context, beamID domain.ID) (domain.PromotionRequest, error) {
	row, err := s.q.GetPendingPromotionByBeam(ctx, string(beamID))
	if err != nil {
		return domain.PromotionRequest{}, mapErr(err)
	}
	return promotionFromRow(row), nil
}

// ListPendingPromotionRequests returns a beamhall's pending requests, oldest first.
func (s *Store) ListPendingPromotionRequests(ctx context.Context, beamhallID domain.ID) ([]domain.PromotionRequest, error) {
	rows, err := s.q.ListPendingPromotionRequests(ctx, string(beamhallID))
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]domain.PromotionRequest, 0, len(rows))
	for _, r := range rows {
		out = append(out, promotionFromRow(r))
	}
	return out, nil
}

// DecidePromotionRequest marks a pending request approved or rejected. It is a
// no-op (returns ErrNotFound) if the request is not pending — the guard against
// deciding the same request twice.
func (s *Store) DecidePromotionRequest(ctx context.Context, id domain.ID, status domain.PromotionStatus, decidedBy domain.ID, reason string) error {
	n, err := s.q.DecidePromotionRequest(ctx, db.DecidePromotionRequestParams{
		Status:    string(status),
		Reason:    reason,
		DecidedBy: string(decidedBy),
		DecidedAt: ns(s.now()),
		ID:        string(id),
	})
	if err != nil {
		return mapErr(err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func promotionFromRow(r db.PromotionRequest) domain.PromotionRequest {
	return domain.PromotionRequest{
		ID:          domain.ID(r.ID),
		BeamhallID:  domain.ID(r.BeamhallID),
		BeamID:      domain.ID(r.BeamID),
		ReleaseID:   domain.ID(r.ReleaseID),
		RequestedBy: domain.ID(r.RequestedBy),
		Status:      domain.PromotionStatus(r.Status),
		Reason:      r.Reason,
		CreatedAt:   fromNS(r.CreatedAt),
		DecidedBy:   domain.ID(r.DecidedBy),
		DecidedAt:   fromNS(r.DecidedAt),
	}
}
