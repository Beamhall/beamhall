package store

import (
	"context"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/store/db"
)

// CreateIdentity persists an Identity, filling ID and CreatedAt if unset.
func (s *Store) CreateIdentity(ctx context.Context, ident *domain.Identity) error {
	if ident.ID == "" {
		ident.ID = NewID()
	}
	if ident.CreatedAt.IsZero() {
		ident.CreatedAt = s.now()
	}
	return mapErr(s.q.InsertIdentity(ctx, db.InsertIdentityParams{
		ID:              string(ident.ID),
		ExternalSubject: ident.ExternalSubject,
		Email:           ident.Email,
		DisplayName:     ident.DisplayName,
		IdpIssuer:       ident.IdPIssuer,
		Status:          ident.Status,
		CreatedAt:       ns(ident.CreatedAt),
	}))
}

// GetIdentity returns the Identity with the given id.
func (s *Store) GetIdentity(ctx context.Context, id domain.ID) (domain.Identity, error) {
	row, err := s.q.GetIdentity(ctx, string(id))
	if err != nil {
		return domain.Identity{}, mapErr(err)
	}
	return identityFromRow(row), nil
}

// GetIdentityByIssuerSubject looks an Identity up by its IdP (issuer, sub)
// pair — the lookup the OAuth resource-server middleware performs per request.
func (s *Store) GetIdentityByIssuerSubject(ctx context.Context, issuer, subject string) (domain.Identity, error) {
	row, err := s.q.GetIdentityByIssuerSubject(ctx, db.GetIdentityByIssuerSubjectParams{
		IdpIssuer:       issuer,
		ExternalSubject: subject,
	})
	if err != nil {
		return domain.Identity{}, mapErr(err)
	}
	return identityFromRow(row), nil
}

// ListIdentities returns all Identities ordered by email.
func (s *Store) ListIdentities(ctx context.Context) ([]domain.Identity, error) {
	rows, err := s.q.ListIdentities(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]domain.Identity, 0, len(rows))
	for _, r := range rows {
		out = append(out, identityFromRow(r))
	}
	return out, nil
}

// UpdateIdentity updates an Identity's mutable fields (email, display name,
// status).
func (s *Store) UpdateIdentity(ctx context.Context, ident domain.Identity) error {
	return affected(s.q.UpdateIdentity(ctx, db.UpdateIdentityParams{
		Email:       ident.Email,
		DisplayName: ident.DisplayName,
		Status:      ident.Status,
		ID:          string(ident.ID),
	}))
}

// CreateMembership grants an Identity a role in a Beamhall, filling ID and
// GrantedAt if unset. A second membership for the same (identity, beamhall)
// pair returns ErrConflict.
func (s *Store) CreateMembership(ctx context.Context, m *domain.Membership) error {
	if m.ID == "" {
		m.ID = NewID()
	}
	if m.GrantedAt.IsZero() {
		m.GrantedAt = s.now()
	}
	return mapErr(s.q.InsertMembership(ctx, db.InsertMembershipParams{
		ID:         string(m.ID),
		IdentityID: string(m.IdentityID),
		BeamhallID: string(m.BeamhallID),
		Role:       string(m.Role),
		GrantedBy:  string(m.GrantedBy),
		GrantedAt:  ns(m.GrantedAt),
	}))
}

// GetMembership returns the Membership for an (identity, beamhall) pair —
// the per-request authorization lookup.
func (s *Store) GetMembership(ctx context.Context, identityID, beamhallID domain.ID) (domain.Membership, error) {
	row, err := s.q.GetMembership(ctx, db.GetMembershipParams{
		IdentityID: string(identityID),
		BeamhallID: string(beamhallID),
	})
	if err != nil {
		return domain.Membership{}, mapErr(err)
	}
	return membershipFromRow(row), nil
}

// ListMembershipsByBeamhall returns a Beamhall's memberships, oldest first.
func (s *Store) ListMembershipsByBeamhall(ctx context.Context, beamhallID domain.ID) ([]domain.Membership, error) {
	rows, err := s.q.ListMembershipsByBeamhall(ctx, string(beamhallID))
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]domain.Membership, 0, len(rows))
	for _, r := range rows {
		out = append(out, membershipFromRow(r))
	}
	return out, nil
}

// ListMembershipsByIdentity returns an Identity's memberships, oldest first.
func (s *Store) ListMembershipsByIdentity(ctx context.Context, identityID domain.ID) ([]domain.Membership, error) {
	rows, err := s.q.ListMembershipsByIdentity(ctx, string(identityID))
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]domain.Membership, 0, len(rows))
	for _, r := range rows {
		out = append(out, membershipFromRow(r))
	}
	return out, nil
}

// DeleteMembership revokes a membership. Deleting an absent membership is a
// no-op (revocation is idempotent).
func (s *Store) DeleteMembership(ctx context.Context, id domain.ID) error {
	return mapErr(s.q.DeleteMembership(ctx, string(id)))
}

// DeleteIdentity removes a registered identity row. The caller must ensure no
// memberships reference it (the orchestrator refuses otherwise); audit rows
// reference the id as an opaque string and are unaffected.
func (s *Store) DeleteIdentity(ctx context.Context, id domain.ID) error {
	return mapErr(s.q.DeleteIdentity(ctx, string(id)))
}

func identityFromRow(r db.Identity) domain.Identity {
	return domain.Identity{
		ID:              domain.ID(r.ID),
		ExternalSubject: r.ExternalSubject,
		Email:           r.Email,
		DisplayName:     r.DisplayName,
		IdPIssuer:       r.IdpIssuer,
		Status:          r.Status,
		CreatedAt:       fromNS(r.CreatedAt),
	}
}

func membershipFromRow(r db.Membership) domain.Membership {
	return domain.Membership{
		ID:         domain.ID(r.ID),
		IdentityID: domain.ID(r.IdentityID),
		BeamhallID: domain.ID(r.BeamhallID),
		Role:       domain.MembershipRole(r.Role),
		GrantedBy:  domain.ID(r.GrantedBy),
		GrantedAt:  fromNS(r.GrantedAt),
	}
}
