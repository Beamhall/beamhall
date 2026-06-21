package store

import (
	"context"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/store/db"
)

// CreateRoute persists a Route, filling ID and CreatedAt if unset. A second
// active route for the same hostname returns ErrConflict (partial unique
// index); retired hostnames may recur.
func (s *Store) CreateRoute(ctx context.Context, r *domain.Route) error {
	if r.ID == "" {
		r.ID = NewID()
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = s.now()
	}
	return mapErr(s.q.InsertRoute(ctx, db.InsertRouteParams{
		ID:          string(r.ID),
		BeamID:      string(r.BeamID),
		ReleaseID:   string(r.ReleaseID),
		Kind:        string(r.Kind),
		Hostname:    r.Hostname,
		RandomToken: r.RandomToken,
		BackendAddr: r.BackendAddr,
		TlsCertRef:  r.TLSCertRef,
		Status:      string(r.Status),
		CreatedAt:   ns(r.CreatedAt),
		RetiredAt:   ns(r.RetiredAt),
	}))
}

// GetRoute returns the Route with the given id.
func (s *Store) GetRoute(ctx context.Context, id domain.ID) (domain.Route, error) {
	row, err := s.q.GetRoute(ctx, string(id))
	if err != nil {
		return domain.Route{}, mapErr(err)
	}
	return routeFromRow(row), nil
}

// GetActiveRouteByHostname returns the active Route serving a hostname (the
// on-demand-TLS ask lookup, once routes are persisted).
func (s *Store) GetActiveRouteByHostname(ctx context.Context, hostname string) (domain.Route, error) {
	row, err := s.q.GetActiveRouteByHostname(ctx, hostname)
	if err != nil {
		return domain.Route{}, mapErr(err)
	}
	return routeFromRow(row), nil
}

// ActiveRoutes returns all active Routes ordered by hostname. This is the
// gateway's restore source on boot: map each to gateway.Route and seed
// gateway.Restore, then Apply (see internal/gateway).
func (s *Store) ActiveRoutes(ctx context.Context) ([]domain.Route, error) {
	rows, err := s.q.ListActiveRoutes(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]domain.Route, 0, len(rows))
	for _, r := range rows {
		out = append(out, routeFromRow(r))
	}
	return out, nil
}

// ListRoutesByBeam returns a Beam's Routes, newest first.
func (s *Store) ListRoutesByBeam(ctx context.Context, beamID domain.ID) ([]domain.Route, error) {
	rows, err := s.q.ListRoutesByBeam(ctx, string(beamID))
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]domain.Route, 0, len(rows))
	for _, r := range rows {
		out = append(out, routeFromRow(r))
	}
	return out, nil
}

// RetireRoute marks a Route retired and stamps RetiredAt. Idempotent: retiring
// a retired route refreshes the timestamp only.
func (s *Store) RetireRoute(ctx context.Context, id domain.ID) error {
	return affected(s.q.RetireRoute(ctx, db.RetireRouteParams{
		RetiredAt: ns(s.now()),
		ID:        string(id),
	}))
}

func routeFromRow(r db.Route) domain.Route {
	return domain.Route{
		ID:          domain.ID(r.ID),
		BeamID:      domain.ID(r.BeamID),
		ReleaseID:   domain.ID(r.ReleaseID),
		Kind:        domain.RouteKind(r.Kind),
		Hostname:    r.Hostname,
		RandomToken: r.RandomToken,
		BackendAddr: r.BackendAddr,
		TLSCertRef:  r.TlsCertRef,
		Status:      domain.RouteStatus(r.Status),
		CreatedAt:   fromNS(r.CreatedAt),
		RetiredAt:   fromNS(r.RetiredAt),
	}
}
