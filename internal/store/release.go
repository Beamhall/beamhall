package store

import (
	"context"
	"fmt"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/store/db"
)

// CreateRelease persists a Release, filling ID and CreatedAt if unset and
// always assigning the next monotonic per-beam version (any caller-set Version
// is overwritten) — version assignment and insert happen in one transaction.
func (s *Store) CreateRelease(ctx context.Context, r *domain.Release) error {
	if r.ID == "" {
		r.ID = NewID()
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = s.now()
	}
	cfg, err := encJSON(r.ConfigSnapshot)
	if err != nil {
		return fmt.Errorf("encode config snapshot: %w", err)
	}
	refs, err := encJSON(r.SecretRefs)
	if err != nil {
		return fmt.Errorf("encode secret refs: %w", err)
	}
	prof, err := encJSON(r.SecurityProfileSnap)
	if err != nil {
		return fmt.Errorf("encode security profile: %w", err)
	}
	return mapErr(s.withTx(ctx, func(q *db.Queries) error {
		v, err := q.NextReleaseVersion(ctx, string(r.BeamID))
		if err != nil {
			return err
		}
		r.Version = int(v)
		return q.InsertRelease(ctx, db.InsertReleaseParams{
			ID:                  string(r.ID),
			BeamID:              string(r.BeamID),
			BuildID:             string(r.BuildID),
			Version:             v,
			Channel:             string(r.Channel),
			ConfigSnapshotJson:  cfg,
			SecretRefsJson:      refs,
			SecurityProfileJson: prof,
			RouteID:             string(r.RouteID),
			Status:              string(r.Status),
			CreatedAt:           ns(r.CreatedAt),
			ActivatedAt:         ns(r.ActivatedAt),
		})
	}))
}

// GetRelease returns the Release with the given id.
func (s *Store) GetRelease(ctx context.Context, id domain.ID) (domain.Release, error) {
	row, err := s.q.GetRelease(ctx, string(id))
	if err != nil {
		return domain.Release{}, mapErr(err)
	}
	return releaseFromRow(row)
}

// ListReleasesByBeam returns a Beam's Releases, newest version first.
func (s *Store) ListReleasesByBeam(ctx context.Context, beamID domain.ID) ([]domain.Release, error) {
	rows, err := s.q.ListReleasesByBeam(ctx, string(beamID))
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]domain.Release, 0, len(rows))
	for _, r := range rows {
		rel, err := releaseFromRow(r)
		if err != nil {
			return nil, err
		}
		out = append(out, rel)
	}
	return out, nil
}

// ActivateRelease marks a Release active and stamps ActivatedAt. Superseding
// the previously active Release is the orchestrator's job.
func (s *Store) ActivateRelease(ctx context.Context, id domain.ID) error {
	return affected(s.q.ActivateRelease(ctx, db.ActivateReleaseParams{
		ActivatedAt: ns(s.now()),
		ID:          string(id),
	}))
}

// UpdateReleaseStatus sets a Release's status (superseded, rolled_back, ...).
func (s *Store) UpdateReleaseStatus(ctx context.Context, id domain.ID, status domain.ReleaseStatus) error {
	return affected(s.q.UpdateReleaseStatus(ctx, db.UpdateReleaseStatusParams{
		Status: string(status),
		ID:     string(id),
	}))
}

// SetReleaseRoute points a Release at its Route (set after the route is
// created; the pair is cross-referencing).
func (s *Store) SetReleaseRoute(ctx context.Context, releaseID, routeID domain.ID) error {
	return affected(s.q.SetReleaseRoute(ctx, db.SetReleaseRouteParams{
		RouteID: string(routeID),
		ID:      string(releaseID),
	}))
}

// SetReleaseWorkload records the runtime handle of the workload deployed for
// a Release, so the orchestrator can pause/stop/destroy it after a restart.
func (s *Store) SetReleaseWorkload(ctx context.Context, releaseID domain.ID, h domain.WorkloadHandle) error {
	return affected(s.q.SetReleaseWorkload(ctx, db.SetReleaseWorkloadParams{
		HandleDriver: h.Driver,
		HandleRef:    h.Ref,
		ID:           string(releaseID),
	}))
}

func releaseFromRow(r db.Release) (domain.Release, error) {
	var cfg map[string]string
	if err := decJSON(r.ConfigSnapshotJson, &cfg); err != nil {
		return domain.Release{}, fmt.Errorf("release %s: decode config snapshot: %w", r.ID, err)
	}
	var refs []domain.SecretRef
	if err := decJSON(r.SecretRefsJson, &refs); err != nil {
		return domain.Release{}, fmt.Errorf("release %s: decode secret refs: %w", r.ID, err)
	}
	var prof domain.SecurityContext
	if err := decJSON(r.SecurityProfileJson, &prof); err != nil {
		return domain.Release{}, fmt.Errorf("release %s: decode security profile: %w", r.ID, err)
	}
	return domain.Release{
		ID:                  domain.ID(r.ID),
		BeamID:              domain.ID(r.BeamID),
		BuildID:             domain.ID(r.BuildID),
		Version:             int(r.Version),
		Channel:             domain.Channel(r.Channel),
		ConfigSnapshot:      cfg,
		SecretRefs:          refs,
		SecurityProfileSnap: prof,
		RouteID:             domain.ID(r.RouteID),
		Workload:            domain.WorkloadHandle{Driver: r.HandleDriver, Ref: r.HandleRef},
		Status:              domain.ReleaseStatus(r.Status),
		CreatedAt:           fromNS(r.CreatedAt),
		ActivatedAt:         fromNS(r.ActivatedAt),
	}, nil
}
