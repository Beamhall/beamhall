package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/Beamhall/beamhall/internal/store/db"
)

// GetControlKey returns the sealed control-plane key material stored under
// kind, with ok=false when none exists.
func (s *Store) GetControlKey(ctx context.Context, kind string) ([]byte, bool, error) {
	row, err := s.q.GetControlKey(ctx, kind)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	sealed, err := base64.StdEncoding.DecodeString(row.Sealed)
	if err != nil {
		return nil, false, fmt.Errorf("control key %s: decode: %w", kind, err)
	}
	return sealed, true, nil
}

// PutControlKey stores sealed key material under kind. kind is unique — a
// second write conflicts rather than silently replacing a key workloads may
// already verify against.
func (s *Store) PutControlKey(ctx context.Context, kind string, sealed []byte) error {
	return mapErr(s.q.InsertControlKey(ctx, db.InsertControlKeyParams{
		Kind:      kind,
		Sealed:    base64.StdEncoding.EncodeToString(sealed),
		CreatedAt: ns(s.now()),
	}))
}
