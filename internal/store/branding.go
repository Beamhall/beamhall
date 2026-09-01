package store

import (
	"context"
	"fmt"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/store/db"
)

// GetBranding returns one scope's branding (domain.FacilityScope for the
// facility-wide default). ErrNotFound when the scope has none.
func (s *Store) GetBranding(ctx context.Context, beamhallID domain.ID) (domain.Branding, error) {
	row, err := s.q.GetBranding(ctx, string(beamhallID))
	if err != nil {
		return domain.Branding{}, mapErr(err)
	}
	var b domain.Branding
	if err := decJSON(row.BrandingJson, &b); err != nil {
		return domain.Branding{}, fmt.Errorf("branding %q: decode: %w", row.BeamhallID, err)
	}
	return b, nil
}

// PutBranding replaces one scope's branding.
func (s *Store) PutBranding(ctx context.Context, beamhallID domain.ID, b domain.Branding) error {
	enc, err := encJSON(b)
	if err != nil {
		return fmt.Errorf("encode branding: %w", err)
	}
	return mapErr(s.q.UpsertBranding(ctx, db.UpsertBrandingParams{
		BeamhallID:   string(beamhallID),
		BrandingJson: enc,
		UpdatedAt:    ns(s.now()),
	}))
}

// DeleteBranding removes one scope's branding row. Idempotent: clearing an
// unset scope succeeds.
func (s *Store) DeleteBranding(ctx context.Context, beamhallID domain.ID) error {
	return mapErr(s.q.DeleteBranding(ctx, string(beamhallID)))
}

// GetBrandingLogo returns one scope's logo. ErrNotFound when the scope has none.
func (s *Store) GetBrandingLogo(ctx context.Context, beamhallID domain.ID) (domain.BrandingLogo, error) {
	row, err := s.q.GetBrandingLogo(ctx, string(beamhallID))
	if err != nil {
		return domain.BrandingLogo{}, mapErr(err)
	}
	return domain.BrandingLogo{
		Bytes:     row.Logo,
		MIME:      row.LogoMime,
		ETag:      row.LogoEtag,
		UpdatedAt: fromNS(row.UpdatedAt),
	}, nil
}

// GetBrandingLogoMeta returns one scope's logo metadata without loading the
// image bytes — the read resolution and spawn paths use on every deploy.
func (s *Store) GetBrandingLogoMeta(ctx context.Context, beamhallID domain.ID) (domain.BrandingLogo, error) {
	row, err := s.q.GetBrandingLogoMeta(ctx, string(beamhallID))
	if err != nil {
		return domain.BrandingLogo{}, mapErr(err)
	}
	return domain.BrandingLogo{
		MIME:      row.LogoMime,
		ETag:      row.LogoEtag,
		UpdatedAt: fromNS(row.UpdatedAt),
	}, nil
}

// PutBrandingLogo replaces one scope's logo.
func (s *Store) PutBrandingLogo(ctx context.Context, beamhallID domain.ID, l domain.BrandingLogo) error {
	return mapErr(s.q.UpsertBrandingLogo(ctx, db.UpsertBrandingLogoParams{
		BeamhallID: string(beamhallID),
		Logo:       l.Bytes,
		LogoMime:   l.MIME,
		LogoEtag:   l.ETag,
		UpdatedAt:  ns(s.now()),
	}))
}

// DeleteBrandingLogo removes one scope's logo. Idempotent.
func (s *Store) DeleteBrandingLogo(ctx context.Context, beamhallID domain.ID) error {
	return mapErr(s.q.DeleteBrandingLogo(ctx, string(beamhallID)))
}

// ClearBrandingScope removes a scope's branding and logo together.
func (s *Store) ClearBrandingScope(ctx context.Context, beamhallID domain.ID) error {
	return mapErr(s.withTx(ctx, func(q *db.Queries) error {
		if err := q.DeleteBranding(ctx, string(beamhallID)); err != nil {
			return err
		}
		return q.DeleteBrandingLogo(ctx, string(beamhallID))
	}))
}
