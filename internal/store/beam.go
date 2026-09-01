package store

import (
	"context"
	"fmt"
	"time"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/store/db"
)

// CreateBeam persists a Beam, filling ID and timestamps if unset. A duplicate
// (beamhall, slug) returns ErrConflict.
func (s *Store) CreateBeam(ctx context.Context, a *domain.Beam) error {
	s.fillBeam(a)
	return mapErr(s.q.InsertBeam(ctx, beamInsertParams(a)))
}

// CreateBeamWithQuota atomically counts the beamhall's active beams and
// inserts the new one inside one transaction — a plain count-then-insert (as
// two separate calls) leaves a window where two concurrent create_beam calls
// can each pass their own count check and together exceed maxBeams.
// Returns ErrQuota, not the insert,
// when the beamhall is already at (or maxBeams is unset/non-positive).
func (s *Store) CreateBeamWithQuota(ctx context.Context, a *domain.Beam, maxBeams int) error {
	s.fillBeam(a)
	return mapErr(s.withTx(ctx, func(q *db.Queries) error {
		n, err := q.CountBeamsByBeamhall(ctx, string(a.BeamhallID))
		if err != nil {
			return err
		}
		if maxBeams <= 0 || int(n) >= maxBeams {
			return fmt.Errorf("%w: %d of %d beams in use", ErrQuota, n, maxBeams)
		}
		return q.InsertBeam(ctx, beamInsertParams(a))
	}))
}

func (s *Store) fillBeam(a *domain.Beam) {
	if a.ID == "" {
		a.ID = NewID()
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = s.now()
	}
	if a.Status == "" {
		a.Status = domain.BeamActive
	}
	a.UpdatedAt = a.CreatedAt
}

func beamInsertParams(a *domain.Beam) db.InsertBeamParams {
	return db.InsertBeamParams{
		ID:                string(a.ID),
		BeamhallID:        string(a.BeamhallID),
		Slug:              a.Slug,
		DisplayName:       a.DisplayName,
		Description:       a.Description,
		RuntimeHint:       a.RuntimeHint,
		Mode:              string(a.Mode),
		State:             string(a.State),
		CurrentReleaseID:  string(a.CurrentReleaseID),
		DesiredReleaseID:  string(a.DesiredReleaseID),
		LiveReleaseID:     string(a.LiveReleaseID),
		LiveState:         string(a.LiveState),
		SecurityTemplate:  string(a.SecurityTemplate),
		PreviewPauseAfter: int64(a.PreviewPauseAfter),
		ResumedAt:         ns(a.ResumedAt),
		PreviewHost:       a.PreviewHost,
		GitRemoteUrl:      a.GitRemoteURL,
		RepoID:            string(a.RepoID),
		CreatedBy:         string(a.CreatedBy),
		CreatedAt:         ns(a.CreatedAt),
		UpdatedAt:         ns(a.UpdatedAt),
		Status:            string(a.Status),
	}
}

// GetBeam returns the Beam with the given id.
func (s *Store) GetBeam(ctx context.Context, id domain.ID) (domain.Beam, error) {
	row, err := s.q.GetBeam(ctx, string(id))
	if err != nil {
		return domain.Beam{}, mapErr(err)
	}
	return beamFromRow(row), nil
}

// GetBeamBySlug returns the Beam with the given slug inside a Beamhall.
func (s *Store) GetBeamBySlug(ctx context.Context, beamhallID domain.ID, slug string) (domain.Beam, error) {
	row, err := s.q.GetBeamBySlug(ctx, db.GetBeamBySlugParams{
		BeamhallID: string(beamhallID),
		Slug:       slug,
	})
	if err != nil {
		return domain.Beam{}, mapErr(err)
	}
	return beamFromRow(row), nil
}

// ListBeamsByBeamhall returns a Beamhall's Beams ordered by slug.
func (s *Store) ListBeamsByBeamhall(ctx context.Context, beamhallID domain.ID) ([]domain.Beam, error) {
	rows, err := s.q.ListBeamsByBeamhall(ctx, string(beamhallID))
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]domain.Beam, 0, len(rows))
	for _, r := range rows {
		out = append(out, beamFromRow(r))
	}
	return out, nil
}

// ListBeamsByState returns every beam (any beamhall, any status) whose FSM
// state matches — the boot-reconcile source for beams a daemon crash left
// mid-transition.
func (s *Store) ListBeamsByState(ctx context.Context, state domain.BeamState) ([]domain.Beam, error) {
	rows, err := s.q.ListBeamsByState(ctx, string(state))
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]domain.Beam, 0, len(rows))
	for _, r := range rows {
		out = append(out, beamFromRow(r))
	}
	return out, nil
}

// CountBeamsByBeamhall counts a Beamhall's Beams (for ResourceQuota.MaxBeams).
func (s *Store) CountBeamsByBeamhall(ctx context.Context, beamhallID domain.ID) (int, error) {
	n, err := s.q.CountBeamsByBeamhall(ctx, string(beamhallID))
	return int(n), mapErr(err)
}

// CountLiveBeamsByBeamhall counts a Beamhall's live-mode Beams (live slots).
func (s *Store) CountLiveBeamsByBeamhall(ctx context.Context, beamhallID domain.ID) (int, error) {
	n, err := s.q.CountLiveBeamsByBeamhall(ctx, string(beamhallID))
	return int(n), mapErr(err)
}

// PromoteBeam flips a Beam to live mode/state if and only if the Beamhall has
// a free live slot, counting and updating inside one write transaction so two
// concurrent promotes cannot both squeeze into the last slot. liveSlotLimit is
// the effective limit (the policy layer computes it, e.g. min(LiveSlotLimit,
// Quota.MaxLiveSlots)); at or over it, ErrQuota is returned and nothing
// changes. A missing beam returns ErrNotFound. FSM legality (running preview
// only) is checked by the orchestrator before calling.
func (s *Store) PromoteBeam(ctx context.Context, beamhallID, beamID domain.ID, liveSlotLimit int) error {
	err := s.withTx(ctx, func(q *db.Queries) error {
		n, err := q.CountLiveBeamsByBeamhall(ctx, string(beamhallID))
		if err != nil {
			return err
		}
		if int(n) >= liveSlotLimit {
			return fmt.Errorf("%w: %d of %d live slots in use", ErrQuota, n, liveSlotLimit)
		}
		rows, err := q.PromoteBeam(ctx, db.PromoteBeamParams{
			UpdatedAt: ns(s.now()),
			ID:        string(beamID),
		})
		if err != nil {
			return err
		}
		if rows == 0 {
			return ErrNotFound
		}
		return nil
	})
	return mapErr(err)
}

// UpdateBeam updates a Beam's mutable fields (everything except identity,
// beamhall, slug, and creation metadata) and bumps UpdatedAt. The FSM legality
// of a state change is the orchestrator's job (domain.Beam FSM); the store
// persists what it is given.
func (s *Store) UpdateBeam(ctx context.Context, a *domain.Beam) error {
	a.UpdatedAt = s.now()
	if a.Status == "" {
		a.Status = domain.BeamActive
	}
	return affected(s.q.UpdateBeam(ctx, db.UpdateBeamParams{
		DisplayName:       a.DisplayName,
		Description:       a.Description,
		RuntimeHint:       a.RuntimeHint,
		Mode:              string(a.Mode),
		State:             string(a.State),
		CurrentReleaseID:  string(a.CurrentReleaseID),
		DesiredReleaseID:  string(a.DesiredReleaseID),
		LiveReleaseID:     string(a.LiveReleaseID),
		LiveState:         string(a.LiveState),
		SecurityTemplate:  string(a.SecurityTemplate),
		PreviewPauseAfter: int64(a.PreviewPauseAfter),
		ResumedAt:         ns(a.ResumedAt),
		PreviewHost:       a.PreviewHost,
		GitRemoteUrl:      a.GitRemoteURL,
		RepoID:            string(a.RepoID),
		Status:            string(a.Status),
		UpdatedAt:         ns(a.UpdatedAt),
		ID:                string(a.ID),
	}))
}

func beamFromRow(r db.Beam) domain.Beam {
	return domain.Beam{
		ID:                domain.ID(r.ID),
		BeamhallID:        domain.ID(r.BeamhallID),
		Slug:              r.Slug,
		DisplayName:       r.DisplayName,
		Description:       r.Description,
		RuntimeHint:       r.RuntimeHint,
		Mode:              domain.BeamMode(r.Mode),
		State:             domain.BeamState(r.State),
		CurrentReleaseID:  domain.ID(r.CurrentReleaseID),
		DesiredReleaseID:  domain.ID(r.DesiredReleaseID),
		LiveReleaseID:     domain.ID(r.LiveReleaseID),
		LiveState:         domain.BeamState(r.LiveState),
		SecurityTemplate:  domain.SecurityTemplate(r.SecurityTemplate),
		PreviewPauseAfter: time.Duration(r.PreviewPauseAfter),
		ResumedAt:         fromNS(r.ResumedAt),
		PreviewHost:       r.PreviewHost,
		GitRemoteURL:      r.GitRemoteUrl,
		RepoID:            domain.ID(r.RepoID),
		Status:            domain.BeamStatus(r.Status),
		CreatedBy:         domain.ID(r.CreatedBy),
		CreatedAt:         fromNS(r.CreatedAt),
		UpdatedAt:         fromNS(r.UpdatedAt),
	}
}
