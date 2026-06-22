package store

import (
	"context"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/store/db"
)

// CreateAdminActionRequest records a pending sensitive admin action awaiting
// four-eyes approval (PLAN §5.9). The payload is already vault-sealed by the
// caller.
func (s *Store) CreateAdminActionRequest(ctx context.Context, r *domain.AdminActionRequest) error {
	if r.ID == "" {
		r.ID = NewID()
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = s.now()
	}
	return mapErr(s.q.InsertAdminActionRequest(ctx, db.InsertAdminActionRequestParams{
		ID:            string(r.ID),
		ActionType:    string(r.ActionType),
		Summary:       r.Summary,
		PayloadCipher: r.PayloadCipher,
		RequestedBy:   string(r.RequestedBy),
		CreatedAt:     ns(r.CreatedAt),
	}))
}

// GetAdminActionRequest returns a request by id.
func (s *Store) GetAdminActionRequest(ctx context.Context, id domain.ID) (domain.AdminActionRequest, error) {
	row, err := s.q.GetAdminActionRequest(ctx, string(id))
	if err != nil {
		return domain.AdminActionRequest{}, mapErr(err)
	}
	return adminActionFromRow(row), nil
}

// ListPendingAdminActionRequests returns all pending requests, oldest first.
func (s *Store) ListPendingAdminActionRequests(ctx context.Context) ([]domain.AdminActionRequest, error) {
	rows, err := s.q.ListPendingAdminActionRequests(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]domain.AdminActionRequest, 0, len(rows))
	for _, r := range rows {
		out = append(out, adminActionFromRow(r))
	}
	return out, nil
}

// DecideAdminActionRequest marks a pending request approved or rejected and
// records its execution result. It is a no-op (ErrNotFound) if the request is
// not pending — the guard against deciding the same request twice.
func (s *Store) DecideAdminActionRequest(ctx context.Context, id domain.ID, status domain.AdminActionStatus, decidedBy domain.ID, reason, result string) error {
	n, err := s.q.DecideAdminActionRequest(ctx, db.DecideAdminActionRequestParams{
		Status:    string(status),
		Reason:    reason,
		Result:    result,
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

func adminActionFromRow(r db.AdminActionRequest) domain.AdminActionRequest {
	return domain.AdminActionRequest{
		ID:            domain.ID(r.ID),
		ActionType:    domain.AdminActionType(r.ActionType),
		Summary:       r.Summary,
		PayloadCipher: r.PayloadCipher,
		RequestedBy:   domain.ID(r.RequestedBy),
		Status:        domain.AdminActionStatus(r.Status),
		Reason:        r.Reason,
		Result:        r.Result,
		CreatedAt:     fromNS(r.CreatedAt),
		DecidedBy:     domain.ID(r.DecidedBy),
		DecidedAt:     fromNS(r.DecidedAt),
	}
}
