package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/store/db"
)

// GetBeamPeers returns one source beam's grant record. ErrNotFound when the
// beam has no grants (no row).
func (s *Store) GetBeamPeers(ctx context.Context, sourceBeamID domain.ID) (domain.BeamPeers, error) {
	row, err := s.q.GetBeamPeers(ctx, string(sourceBeamID))
	if err != nil {
		return domain.BeamPeers{}, mapErr(err)
	}
	return beamPeersFromRow(row)
}

// PutBeamPeers replaces a source beam's grant set (set-replace upsert).
func (s *Store) PutBeamPeers(ctx context.Context, bp domain.BeamPeers) error {
	enc, err := encJSON(bp.Peers)
	if err != nil {
		return fmt.Errorf("encode peer set: %w", err)
	}
	return mapErr(s.q.UpsertBeamPeers(ctx, db.UpsertBeamPeersParams{
		SourceBeamID: string(bp.SourceBeamID),
		BeamhallID:   string(bp.BeamhallID),
		PeersJson:    enc,
		UpdatedBy:    string(bp.UpdatedBy),
		UpdatedAt:    ns(s.now()),
	}))
}

// ListBeamPeers returns every grant record.
func (s *Store) ListBeamPeers(ctx context.Context) ([]domain.BeamPeers, error) {
	rows, err := s.q.ListBeamPeers(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]domain.BeamPeers, 0, len(rows))
	for _, r := range rows {
		bp, err := beamPeersFromRow(r)
		if err != nil {
			return nil, err
		}
		out = append(out, bp)
	}
	return out, nil
}

// DeleteBeamPeers removes a source beam's grants. Idempotent.
func (s *Store) DeleteBeamPeers(ctx context.Context, sourceBeamID domain.ID) error {
	return mapErr(s.q.DeleteBeamPeers(ctx, string(sourceBeamID)))
}

func beamPeersFromRow(r db.BeamPeer) (domain.BeamPeers, error) {
	var p domain.PeerSet
	if err := decJSON(r.PeersJson, &p); err != nil {
		return domain.BeamPeers{}, fmt.Errorf("peers %q: decode: %w", r.SourceBeamID, err)
	}
	return domain.BeamPeers{
		SourceBeamID: domain.ID(r.SourceBeamID),
		BeamhallID:   domain.ID(r.BeamhallID),
		Peers:        p,
		UpdatedBy:    domain.ID(r.UpdatedBy),
		UpdatedAt:    fromNS(r.UpdatedAt),
	}, nil
}

// InsertC2CKey records a beam's relay-key hash. Returns created=false when the
// beam already has one — the ON CONFLICT DO NOTHING insert is the mint mutex:
// exactly one of two racing mints wins and proceeds to seal key material.
func (s *Store) InsertC2CKey(ctx context.Context, beamID domain.ID, keyHash string) (created bool, err error) {
	n, err := s.q.InsertC2CKey(ctx, db.InsertC2CKeyParams{
		BeamID:    string(beamID),
		KeyHash:   keyHash,
		CreatedAt: ns(s.now()),
	})
	if err != nil {
		return false, mapErr(err)
	}
	return n > 0, nil
}

// GetC2CKeyBeam resolves a relay-key hash to its beam. ErrNotFound for an
// unknown hash.
func (s *Store) GetC2CKeyBeam(ctx context.Context, keyHash string) (domain.ID, error) {
	row, err := s.q.GetC2CKeyByHash(ctx, keyHash)
	if err != nil {
		return "", mapErr(err)
	}
	return domain.ID(row.BeamID), nil
}

// HasC2CKey reports whether a beam holds a relay key.
func (s *Store) HasC2CKey(ctx context.Context, beamID domain.ID) (bool, error) {
	_, err := s.q.GetC2CKeyByBeam(ctx, string(beamID))
	if err != nil {
		if errors.Is(mapErr(err), ErrNotFound) {
			return false, nil
		}
		return false, mapErr(err)
	}
	return true, nil
}

// DeleteC2CKey removes a beam's relay-key hash. Idempotent.
func (s *Store) DeleteC2CKey(ctx context.Context, beamID domain.ID) error {
	return mapErr(s.q.DeleteC2CKey(ctx, string(beamID)))
}
