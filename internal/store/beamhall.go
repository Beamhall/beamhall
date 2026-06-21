package store

import (
	"context"
	"fmt"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/store/db"
)

// CreateBeamhall persists a Beamhall together with its immutable
// SecurityContext in one transaction (the pair is 1:1 and cross-referencing).
// It fills the IDs, the cross-links, and the timestamps on both structs.
func (s *Store) CreateBeamhall(ctx context.Context, w *domain.Beamhall, sc *domain.SecurityContext) error {
	if w.ID == "" {
		w.ID = NewID()
	}
	if sc.ID == "" {
		sc.ID = NewID()
	}
	sc.BeamhallID = w.ID
	w.SecurityContextID = sc.ID
	if w.CreatedAt.IsZero() {
		w.CreatedAt = s.now()
	}
	w.UpdatedAt = w.CreatedAt

	np, err := encJSON(w.NetworkPolicy)
	if err != nil {
		return fmt.Errorf("encode network policy: %w", err)
	}
	quota, err := encJSON(w.Quota)
	if err != nil {
		return fmt.Errorf("encode quota: %w", err)
	}
	scParams, err := securityContextInsertParams(*sc)
	if err != nil {
		return err
	}

	return mapErr(s.withTx(ctx, func(q *db.Queries) error {
		if err := q.InsertBeamhall(ctx, db.InsertBeamhallParams{
			ID:                string(w.ID),
			Slug:              w.Slug,
			DisplayName:       w.DisplayName,
			Department:        w.Department,
			Status:            string(w.Status),
			SecurityContextID: string(w.SecurityContextID),
			NetworkPolicyJson: np,
			QuotaJson:         quota,
			LiveSlotLimit:     int64(w.LiveSlotLimit),
			CreatedBy:         string(w.CreatedBy),
			CreatedAt:         ns(w.CreatedAt),
			UpdatedAt:         ns(w.UpdatedAt),
		}); err != nil {
			return err
		}
		return q.InsertSecurityContext(ctx, scParams)
	}))
}

// GetBeamhall returns the Beamhall with the given id.
func (s *Store) GetBeamhall(ctx context.Context, id domain.ID) (domain.Beamhall, error) {
	row, err := s.q.GetBeamhall(ctx, string(id))
	if err != nil {
		return domain.Beamhall{}, mapErr(err)
	}
	return beamhallFromRow(row)
}

// GetBeamhallBySlug returns the Beamhall with the given slug.
func (s *Store) GetBeamhallBySlug(ctx context.Context, slug string) (domain.Beamhall, error) {
	row, err := s.q.GetBeamhallBySlug(ctx, slug)
	if err != nil {
		return domain.Beamhall{}, mapErr(err)
	}
	return beamhallFromRow(row)
}

// ListBeamhalls returns all Beamhalls ordered by slug.
func (s *Store) ListBeamhalls(ctx context.Context) ([]domain.Beamhall, error) {
	rows, err := s.q.ListBeamhalls(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]domain.Beamhall, 0, len(rows))
	for _, r := range rows {
		w, err := beamhallFromRow(r)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, nil
}

// UpdateBeamhall updates the mutable Beamhall fields (display name,
// department, status, network policy, quota, live slot limit) and bumps
// UpdatedAt. Slug, security context link, and creation metadata are immutable.
func (s *Store) UpdateBeamhall(ctx context.Context, w *domain.Beamhall) error {
	np, err := encJSON(w.NetworkPolicy)
	if err != nil {
		return fmt.Errorf("encode network policy: %w", err)
	}
	quota, err := encJSON(w.Quota)
	if err != nil {
		return fmt.Errorf("encode quota: %w", err)
	}
	w.UpdatedAt = s.now()
	return affected(s.q.UpdateBeamhall(ctx, db.UpdateBeamhallParams{
		DisplayName:       w.DisplayName,
		Department:        w.Department,
		Status:            string(w.Status),
		NetworkPolicyJson: np,
		QuotaJson:         quota,
		LiveSlotLimit:     int64(w.LiveSlotLimit),
		UpdatedAt:         ns(w.UpdatedAt),
		ID:                string(w.ID),
	}))
}

// GetSecurityContext returns the SecurityContext owned by a Beamhall.
func (s *Store) GetSecurityContext(ctx context.Context, beamhallID domain.ID) (domain.SecurityContext, error) {
	row, err := s.q.GetSecurityContextByBeamhall(ctx, string(beamhallID))
	if err != nil {
		return domain.SecurityContext{}, mapErr(err)
	}
	return securityContextFromRow(row)
}

// UpdateSecurityContext replaces a SecurityContext's hardening fields. The
// caller (policy layer) is responsible for restricting this to it_admin and
// auditing it — the domain invariant is that agents can never reach this.
func (s *Store) UpdateSecurityContext(ctx context.Context, sc domain.SecurityContext) error {
	capDrop, err := encJSON(sc.CapDrop)
	if err != nil {
		return fmt.Errorf("encode cap_drop: %w", err)
	}
	capAdd, err := encJSON(sc.CapAdd)
	if err != nil {
		return fmt.Errorf("encode cap_add: %w", err)
	}
	tmpfs, err := encJSON(sc.Tmpfs)
	if err != nil {
		return fmt.Errorf("encode tmpfs: %w", err)
	}
	limits, err := encJSON(sc.CgroupLimits)
	if err != nil {
		return fmt.Errorf("encode cgroup limits: %w", err)
	}
	return affected(s.q.UpdateSecurityContext(ctx, db.UpdateSecurityContextParams{
		RuntimeClass:     string(sc.RuntimeClass),
		UsernsRemap:      sc.UsernsRemap,
		CapDropJson:      capDrop,
		CapAddJson:       capAdd,
		SeccompProfile:   sc.SeccompProfile,
		ApparmorProfile:  sc.AppArmorProfile,
		NoNewPrivileges:  sc.NoNewPrivileges,
		ReadOnlyRootfs:   sc.ReadOnlyRootfs,
		TmpfsJson:        tmpfs,
		CgroupLimitsJson: limits,
		Template:         string(sc.Template),
		ID:               string(sc.ID),
	}))
}

func securityContextInsertParams(sc domain.SecurityContext) (db.InsertSecurityContextParams, error) {
	capDrop, err := encJSON(sc.CapDrop)
	if err != nil {
		return db.InsertSecurityContextParams{}, fmt.Errorf("encode cap_drop: %w", err)
	}
	capAdd, err := encJSON(sc.CapAdd)
	if err != nil {
		return db.InsertSecurityContextParams{}, fmt.Errorf("encode cap_add: %w", err)
	}
	tmpfs, err := encJSON(sc.Tmpfs)
	if err != nil {
		return db.InsertSecurityContextParams{}, fmt.Errorf("encode tmpfs: %w", err)
	}
	limits, err := encJSON(sc.CgroupLimits)
	if err != nil {
		return db.InsertSecurityContextParams{}, fmt.Errorf("encode cgroup limits: %w", err)
	}
	return db.InsertSecurityContextParams{
		ID:               string(sc.ID),
		BeamhallID:       string(sc.BeamhallID),
		RuntimeClass:     string(sc.RuntimeClass),
		UsernsRemap:      sc.UsernsRemap,
		CapDropJson:      capDrop,
		CapAddJson:       capAdd,
		SeccompProfile:   sc.SeccompProfile,
		ApparmorProfile:  sc.AppArmorProfile,
		NoNewPrivileges:  sc.NoNewPrivileges,
		ReadOnlyRootfs:   sc.ReadOnlyRootfs,
		TmpfsJson:        tmpfs,
		CgroupLimitsJson: limits,
		Template:         string(sc.Template),
	}, nil
}

func beamhallFromRow(r db.Beamhall) (domain.Beamhall, error) {
	var np domain.NetworkPolicy
	if err := decJSON(r.NetworkPolicyJson, &np); err != nil {
		return domain.Beamhall{}, fmt.Errorf("beamhall %s: decode network policy: %w", r.ID, err)
	}
	var quota domain.ResourceQuota
	if err := decJSON(r.QuotaJson, &quota); err != nil {
		return domain.Beamhall{}, fmt.Errorf("beamhall %s: decode quota: %w", r.ID, err)
	}
	return domain.Beamhall{
		ID:                domain.ID(r.ID),
		Slug:              r.Slug,
		DisplayName:       r.DisplayName,
		Department:        r.Department,
		Status:            domain.BeamhallStatus(r.Status),
		SecurityContextID: domain.ID(r.SecurityContextID),
		NetworkPolicy:     np,
		Quota:             quota,
		LiveSlotLimit:     int(r.LiveSlotLimit),
		CreatedBy:         domain.ID(r.CreatedBy),
		CreatedAt:         fromNS(r.CreatedAt),
		UpdatedAt:         fromNS(r.UpdatedAt),
	}, nil
}

func securityContextFromRow(r db.SecurityContext) (domain.SecurityContext, error) {
	var capDrop, capAdd, tmpfs []string
	if err := decJSON(r.CapDropJson, &capDrop); err != nil {
		return domain.SecurityContext{}, fmt.Errorf("security context %s: decode cap_drop: %w", r.ID, err)
	}
	if err := decJSON(r.CapAddJson, &capAdd); err != nil {
		return domain.SecurityContext{}, fmt.Errorf("security context %s: decode cap_add: %w", r.ID, err)
	}
	if err := decJSON(r.TmpfsJson, &tmpfs); err != nil {
		return domain.SecurityContext{}, fmt.Errorf("security context %s: decode tmpfs: %w", r.ID, err)
	}
	var limits domain.ResourceLimits
	if err := decJSON(r.CgroupLimitsJson, &limits); err != nil {
		return domain.SecurityContext{}, fmt.Errorf("security context %s: decode cgroup limits: %w", r.ID, err)
	}
	return domain.SecurityContext{
		ID:              domain.ID(r.ID),
		BeamhallID:      domain.ID(r.BeamhallID),
		RuntimeClass:    domain.RuntimeClass(r.RuntimeClass),
		UsernsRemap:     r.UsernsRemap,
		CapDrop:         capDrop,
		CapAdd:          capAdd,
		SeccompProfile:  r.SeccompProfile,
		AppArmorProfile: r.ApparmorProfile,
		NoNewPrivileges: r.NoNewPrivileges,
		ReadOnlyRootfs:  r.ReadOnlyRootfs,
		Tmpfs:           tmpfs,
		CgroupLimits:    limits,
		Template:        domain.SecurityTemplate(r.Template),
	}, nil
}
