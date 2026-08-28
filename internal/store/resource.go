package store

import (
	"context"
	"fmt"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/store/db"
)

// CreateResource persists a Resource, filling ID and timestamps if unset.
func (s *Store) CreateResource(ctx context.Context, r *domain.Resource) error {
	params, err := resourceInsertParams(s, r)
	if err != nil {
		return err
	}
	return mapErr(s.q.InsertResource(ctx, params))
}

// CreateResourceWithQuota atomically counts the beamhall's resources of r's
// own type and inserts r inside one transaction — a plain count-then-insert
// (as two separate calls) leaves a window where two concurrent
// create_database calls can each pass their own count check and together
// exceed maxCount. Returns
// ErrQuota, not the insert, when the beamhall is already at (or maxCount is
// unset/non-positive).
func (s *Store) CreateResourceWithQuota(ctx context.Context, r *domain.Resource, maxCount int) error {
	params, err := resourceInsertParams(s, r)
	if err != nil {
		return err
	}
	return mapErr(s.withTx(ctx, func(q *db.Queries) error {
		n, err := q.CountResourcesByBeamhallAndType(ctx, db.CountResourcesByBeamhallAndTypeParams{
			BeamhallID: string(r.BeamhallID),
			Type:       string(r.Type),
		})
		if err != nil {
			return err
		}
		if maxCount <= 0 || int(n) >= maxCount {
			return fmt.Errorf("%w: %d of %d %s resources in use", ErrQuota, n, maxCount, r.Type)
		}
		return q.InsertResource(ctx, params)
	}))
}

func resourceInsertParams(s *Store, r *domain.Resource) (db.InsertResourceParams, error) {
	if r.ID == "" {
		r.ID = NewID()
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = s.now()
	}
	r.UpdatedAt = r.CreatedAt
	connRef, err := encJSON(r.ConnectionSecretRef)
	if err != nil {
		return db.InsertResourceParams{}, fmt.Errorf("encode connection secret ref: %w", err)
	}
	spec, err := encJSON(r.Spec)
	if err != nil {
		return db.InsertResourceParams{}, fmt.Errorf("encode spec: %w", err)
	}
	return db.InsertResourceParams{
		ID:                   string(r.ID),
		BeamhallID:           string(r.BeamhallID),
		BeamID:               string(r.BeamID),
		Channel:              string(r.Channel),
		Type:                 string(r.Type),
		Status:               string(r.Status),
		ConnectionSecretJson: connRef,
		SpecJson:             spec,
		BackingHandle:        r.BackingHandle,
		CreatedAt:            ns(r.CreatedAt),
		UpdatedAt:            ns(r.UpdatedAt),
	}, nil
}

// GetResource returns the Resource with the given id.
func (s *Store) GetResource(ctx context.Context, id domain.ID) (domain.Resource, error) {
	row, err := s.q.GetResource(ctx, string(id))
	if err != nil {
		return domain.Resource{}, mapErr(err)
	}
	return resourceFromRow(row)
}

// ListResourcesByBeamhall returns a Beamhall's Resources, oldest first.
func (s *Store) ListResourcesByBeamhall(ctx context.Context, beamhallID domain.ID) ([]domain.Resource, error) {
	rows, err := s.q.ListResourcesByBeamhall(ctx, string(beamhallID))
	if err != nil {
		return nil, mapErr(err)
	}
	return resourcesFromRows(rows)
}

// ListResourcesByBeam returns a Beam's Resources, oldest first.
func (s *Store) ListResourcesByBeam(ctx context.Context, beamID domain.ID) ([]domain.Resource, error) {
	rows, err := s.q.ListResourcesByBeam(ctx, string(beamID))
	if err != nil {
		return nil, mapErr(err)
	}
	return resourcesFromRows(rows)
}

// ListResourcesByBeamAndChannel returns a Beam's Resources bound to one channel
// (preview | live), oldest first.
func (s *Store) ListResourcesByBeamAndChannel(ctx context.Context, beamID domain.ID, ch domain.Channel) ([]domain.Resource, error) {
	rows, err := s.q.ListResourcesByBeamAndChannel(ctx, db.ListResourcesByBeamAndChannelParams{
		BeamID:  string(beamID),
		Channel: string(ch),
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return resourcesFromRows(rows)
}

// CountResourcesByType counts a Beamhall's Resources of one type (for
// ResourceQuota.MaxDBCount and friends).
func (s *Store) CountResourcesByType(ctx context.Context, beamhallID domain.ID, typ domain.ResourceType) (int, error) {
	n, err := s.q.CountResourcesByBeamhallAndType(ctx, db.CountResourcesByBeamhallAndTypeParams{
		BeamhallID: string(beamhallID),
		Type:       string(typ),
	})
	return int(n), mapErr(err)
}

// UpdateResource updates a Resource's mutable fields (status, connection
// secret ref, spec, backing handle) and bumps UpdatedAt.
func (s *Store) UpdateResource(ctx context.Context, r *domain.Resource) error {
	connRef, err := encJSON(r.ConnectionSecretRef)
	if err != nil {
		return fmt.Errorf("encode connection secret ref: %w", err)
	}
	spec, err := encJSON(r.Spec)
	if err != nil {
		return fmt.Errorf("encode spec: %w", err)
	}
	r.UpdatedAt = s.now()
	return affected(s.q.UpdateResource(ctx, db.UpdateResourceParams{
		Status:               string(r.Status),
		ConnectionSecretJson: connRef,
		SpecJson:             spec,
		BackingHandle:        r.BackingHandle,
		UpdatedAt:            ns(r.UpdatedAt),
		ID:                   string(r.ID),
	}))
}

// DeleteResource removes a resource row (called on beam teardown so the
// reclaimed database stops counting against the beamhall's quota).
func (s *Store) DeleteResource(ctx context.Context, id domain.ID) error {
	return s.q.DeleteResource(ctx, string(id))
}

func resourcesFromRows(rows []db.Resource) ([]domain.Resource, error) {
	out := make([]domain.Resource, 0, len(rows))
	for _, r := range rows {
		res, err := resourceFromRow(r)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func resourceFromRow(r db.Resource) (domain.Resource, error) {
	var connRef domain.SecretRef
	if err := decJSON(r.ConnectionSecretJson, &connRef); err != nil {
		return domain.Resource{}, fmt.Errorf("resource %s: decode connection secret ref: %w", r.ID, err)
	}
	var spec map[string]string
	if err := decJSON(r.SpecJson, &spec); err != nil {
		return domain.Resource{}, fmt.Errorf("resource %s: decode spec: %w", r.ID, err)
	}
	return domain.Resource{
		ID:                  domain.ID(r.ID),
		BeamhallID:          domain.ID(r.BeamhallID),
		BeamID:              domain.ID(r.BeamID),
		Channel:             domain.Channel(r.Channel),
		Type:                domain.ResourceType(r.Type),
		Status:              domain.ResourceStatus(r.Status),
		ConnectionSecretRef: connRef,
		Spec:                spec,
		BackingHandle:       r.BackingHandle,
		CreatedAt:           fromNS(r.CreatedAt),
		UpdatedAt:           fromNS(r.UpdatedAt),
	}, nil
}
