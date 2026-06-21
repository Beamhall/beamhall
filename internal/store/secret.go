package store

import (
	"context"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/store/db"
)

// PutSecret upserts a Secret's metadata by (beamhall, beam, key): a first write
// inserts version 1; a rewrite keeps the row's identity, points value_ref at
// the new ciphertext, and bumps version. sec is updated in place with the
// stored row (final ID, version, timestamps). Values never pass through here —
// only the value_ref pointer into the encrypted store (internal/secret owns
// encryption; there is no get-value API anywhere, per the write-only design).
func (s *Store) PutSecret(ctx context.Context, sec *domain.Secret) error {
	id := sec.ID
	if id == "" {
		id = NewID()
	}
	if sec.CreatedAt.IsZero() {
		sec.CreatedAt = s.now()
	}
	row, err := s.q.UpsertSecret(ctx, db.UpsertSecretParams{
		ID:         string(id),
		BeamhallID: string(sec.BeamhallID),
		BeamID:     string(sec.BeamID),
		Key:        sec.Key,
		Channel:    string(sec.Channel),
		ValueRef:   sec.ValueRef,
		CreatedBy:  string(sec.CreatedBy),
		CreatedAt:  ns(sec.CreatedAt),
	})
	if err != nil {
		return mapErr(err)
	}
	*sec = secretFromRow(row)
	return nil
}

// GetSecret returns a Secret's metadata (never a value) by scope, key, and
// channel.
func (s *Store) GetSecret(ctx context.Context, beamhallID, beamID domain.ID, key string, ch domain.Channel) (domain.Secret, error) {
	row, err := s.q.GetSecret(ctx, db.GetSecretParams{
		BeamhallID: string(beamhallID),
		BeamID:     string(beamID),
		Key:        key,
		Channel:    string(ch),
	})
	if err != nil {
		return domain.Secret{}, mapErr(err)
	}
	return secretFromRow(row), nil
}

// ListSecretsByBeamhall returns a Beamhall's Secret metadata (keys and refs,
// never values), ordered by beam then key.
func (s *Store) ListSecretsByBeamhall(ctx context.Context, beamhallID domain.ID) ([]domain.Secret, error) {
	rows, err := s.q.ListSecretsByBeamhall(ctx, string(beamhallID))
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]domain.Secret, 0, len(rows))
	for _, r := range rows {
		out = append(out, secretFromRow(r))
	}
	return out, nil
}

// DeleteSecret removes a Secret's metadata row. Idempotent. Erasing the
// ciphertext behind value_ref is internal/secret's job.
func (s *Store) DeleteSecret(ctx context.Context, beamhallID, beamID domain.ID, key string, ch domain.Channel) error {
	return mapErr(s.q.DeleteSecret(ctx, db.DeleteSecretParams{
		BeamhallID: string(beamhallID),
		BeamID:     string(beamID),
		Key:        key,
		Channel:    string(ch),
	}))
}

// PutSecretValue stores an age-encrypted secret value under an opaque ref
// (secrets.value_ref points at it). The store never inspects or decrypts the
// blob — internal/secret owns the envelope.
func (s *Store) PutSecretValue(ctx context.Context, ref string, ciphertext []byte) error {
	return mapErr(s.q.PutSecretValue(ctx, db.PutSecretValueParams{
		Ref:        ref,
		Ciphertext: ciphertext,
		CreatedAt:  ns(s.now()),
	}))
}

// GetSecretValue returns the ciphertext blob for a ref, or ErrNotFound.
func (s *Store) GetSecretValue(ctx context.Context, ref string) ([]byte, error) {
	b, err := s.q.GetSecretValue(ctx, ref)
	if err != nil {
		return nil, mapErr(err)
	}
	return b, nil
}

// DeleteSecretValue removes a ciphertext blob. Idempotent — used to GC the
// ciphertext of a superseded version after a rewrite.
func (s *Store) DeleteSecretValue(ctx context.Context, ref string) error {
	return mapErr(s.q.DeleteSecretValue(ctx, ref))
}

func secretFromRow(r db.Secret) domain.Secret {
	return domain.Secret{
		ID:         domain.ID(r.ID),
		BeamhallID: domain.ID(r.BeamhallID),
		BeamID:     domain.ID(r.BeamID),
		Channel:    domain.Channel(r.Channel),
		Key:        r.Key,
		ValueRef:   r.ValueRef,
		Version:    int(r.Version),
		CreatedBy:  domain.ID(r.CreatedBy),
		CreatedAt:  fromNS(r.CreatedAt),
	}
}
