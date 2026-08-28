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

// SwapActiveRoute atomically retires oldRouteID (when non-empty) and inserts
// newRoute as the new active route, in one transaction. Both share newRoute's
// hostname's unique-active-hostname slot (routes_active_hostname allows only
// one active row per hostname), so a caller that retired the old row and
// created the new one as two separate calls has a real window in between with
// zero active routes for that hostname — and if the create then fails, the
// route table is stuck in that zero-route state. Call this only after the
// gateway has already accepted the new backend (gw.Upsert): a failure here
// (e.g. oldRouteID was already retired by a concurrent caller) then never
// leaves the gateway and the store disagreeing about which backend serves the
// hostname, and the caller keeps the old route intact to retry against.
func (s *Store) SwapActiveRoute(ctx context.Context, oldRouteID domain.ID, newRoute *domain.Route) error {
	if newRoute.ID == "" {
		newRoute.ID = NewID()
	}
	if newRoute.CreatedAt.IsZero() {
		newRoute.CreatedAt = s.now()
	}
	return s.withTx(ctx, func(q *db.Queries) error {
		if oldRouteID != "" {
			if err := affected(q.RetireRoute(ctx, db.RetireRouteParams{
				RetiredAt: ns(s.now()),
				ID:        string(oldRouteID),
			})); err != nil {
				return err
			}
		}
		return mapErr(q.InsertRoute(ctx, db.InsertRouteParams{
			ID:          string(newRoute.ID),
			BeamID:      string(newRoute.BeamID),
			ReleaseID:   string(newRoute.ReleaseID),
			Kind:        string(newRoute.Kind),
			Hostname:    newRoute.Hostname,
			RandomToken: newRoute.RandomToken,
			BackendAddr: newRoute.BackendAddr,
			TlsCertRef:  newRoute.TLSCertRef,
			Status:      string(newRoute.Status),
			CreatedAt:   ns(newRoute.CreatedAt),
			RetiredAt:   ns(newRoute.RetiredAt),
		}))
	})
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
