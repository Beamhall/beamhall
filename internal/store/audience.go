package store

import (
	"context"
	"fmt"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/store/db"
)

// GetBeamAudience returns one beam's publication record. ErrNotFound when the
// beam is unpublished (no row).
func (s *Store) GetBeamAudience(ctx context.Context, beamID domain.ID) (domain.BeamAudience, error) {
	row, err := s.q.GetBeamAudience(ctx, string(beamID))
	if err != nil {
		return domain.BeamAudience{}, mapErr(err)
	}
	return beamAudienceFromRow(row)
}

// PutBeamAudience publishes (or re-publishes) a beam. On re-publish only the
// audience changes; the original publisher/time stand.
func (s *Store) PutBeamAudience(ctx context.Context, ba domain.BeamAudience) error {
	enc, err := encJSON(ba.Audience)
	if err != nil {
		return fmt.Errorf("encode audience: %w", err)
	}
	now := ns(s.now())
	return mapErr(s.q.UpsertBeamAudience(ctx, db.UpsertBeamAudienceParams{
		BeamID:       string(ba.BeamID),
		BeamhallID:   string(ba.BeamhallID),
		AudienceJson: enc,
		PublishedBy:  string(ba.PublishedBy),
		PublishedAt:  now,
		UpdatedAt:    now,
	}))
}

// ListBeamAudiences returns every publication record, oldest first.
func (s *Store) ListBeamAudiences(ctx context.Context) ([]domain.BeamAudience, error) {
	rows, err := s.q.ListBeamAudiences(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]domain.BeamAudience, 0, len(rows))
	for _, r := range rows {
		ba, err := beamAudienceFromRow(r)
		if err != nil {
			return nil, err
		}
		out = append(out, ba)
	}
	return out, nil
}

// ListBeamAudiencesByBeamhall returns a beamhall's publication records.
func (s *Store) ListBeamAudiencesByBeamhall(ctx context.Context, beamhallID domain.ID) ([]domain.BeamAudience, error) {
	rows, err := s.q.ListBeamAudiencesByBeamhall(ctx, string(beamhallID))
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]domain.BeamAudience, 0, len(rows))
	for _, r := range rows {
		ba, err := beamAudienceFromRow(r)
		if err != nil {
			return nil, err
		}
		out = append(out, ba)
	}
	return out, nil
}

// DeleteBeamAudience unpublishes a beam. Idempotent: unpublishing an
// unpublished beam succeeds.
func (s *Store) DeleteBeamAudience(ctx context.Context, beamID domain.ID) error {
	return mapErr(s.q.DeleteBeamAudience(ctx, string(beamID)))
}

func beamAudienceFromRow(r db.BeamAudience) (domain.BeamAudience, error) {
	var a domain.Audience
	if err := decJSON(r.AudienceJson, &a); err != nil {
		return domain.BeamAudience{}, fmt.Errorf("audience %q: decode: %w", r.BeamID, err)
	}
	return domain.BeamAudience{
		BeamID:      domain.ID(r.BeamID),
		BeamhallID:  domain.ID(r.BeamhallID),
		Audience:    a,
		PublishedBy: domain.ID(r.PublishedBy),
		PublishedAt: fromNS(r.PublishedAt),
		UpdatedAt:   fromNS(r.UpdatedAt),
	}, nil
}
