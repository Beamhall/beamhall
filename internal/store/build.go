package store

import (
	"context"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/store/db"
)

// CreateBuild persists a Build, filling ID and StartedAt if unset.
func (s *Store) CreateBuild(ctx context.Context, b *domain.Build) error {
	if b.ID == "" {
		b.ID = NewID()
	}
	if b.StartedAt.IsZero() {
		b.StartedAt = s.now()
	}
	return mapErr(s.q.InsertBuild(ctx, db.InsertBuildParams{
		ID:            string(b.ID),
		BeamID:        string(b.BeamID),
		SourceRef:     b.SourceRef,
		SourceKind:    string(b.SourceKind),
		Builder:       b.Builder,
		Status:        string(b.Status),
		ImageRef:      b.ImageRef,
		ImageDigest:   b.ImageDigest,
		SbomRef:       b.SBOMRef,
		CveScanStatus: b.CVEScanStatus,
		LogStreamID:   string(b.LogStreamID),
		TriggeredBy:   string(b.TriggeredBy),
		StartedAt:     ns(b.StartedAt),
		FinishedAt:    ns(b.FinishedAt),
	}))
}

// GetBuild returns the Build with the given id.
func (s *Store) GetBuild(ctx context.Context, id domain.ID) (domain.Build, error) {
	row, err := s.q.GetBuild(ctx, string(id))
	if err != nil {
		return domain.Build{}, mapErr(err)
	}
	return buildFromRow(row), nil
}

// ListBuildsByBeam returns a Beam's Builds, newest first.
func (s *Store) ListBuildsByBeam(ctx context.Context, beamID domain.ID) ([]domain.Build, error) {
	rows, err := s.q.ListBuildsByBeam(ctx, string(beamID))
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]domain.Build, 0, len(rows))
	for _, r := range rows {
		out = append(out, buildFromRow(r))
	}
	return out, nil
}

// UpdateBuild updates a Build's outcome fields (status, image pin, SBOM, CVE
// scan, log stream, finish time). Source and trigger metadata are immutable.
func (s *Store) UpdateBuild(ctx context.Context, b domain.Build) error {
	return affected(s.q.UpdateBuild(ctx, db.UpdateBuildParams{
		Status:        string(b.Status),
		ImageRef:      b.ImageRef,
		ImageDigest:   b.ImageDigest,
		SbomRef:       b.SBOMRef,
		CveScanStatus: b.CVEScanStatus,
		LogStreamID:   string(b.LogStreamID),
		FinishedAt:    ns(b.FinishedAt),
		ID:            string(b.ID),
	}))
}

func buildFromRow(r db.Build) domain.Build {
	return domain.Build{
		ID:            domain.ID(r.ID),
		BeamID:        domain.ID(r.BeamID),
		SourceRef:     r.SourceRef,
		SourceKind:    domain.SourceKind(r.SourceKind),
		Builder:       r.Builder,
		Status:        domain.BuildStatus(r.Status),
		ImageRef:      r.ImageRef,
		ImageDigest:   r.ImageDigest,
		SBOMRef:       r.SbomRef,
		CVEScanStatus: r.CveScanStatus,
		LogStreamID:   domain.ID(r.LogStreamID),
		TriggeredBy:   domain.ID(r.TriggeredBy),
		StartedAt:     fromNS(r.StartedAt),
		FinishedAt:    fromNS(r.FinishedAt),
	}
}
