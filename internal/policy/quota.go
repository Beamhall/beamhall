package policy

import (
	"context"
	"fmt"

	"github.com/Beamhall/beamhall/internal/domain"
)

// QuotaError is the typed quota failure; the MCP layer maps it to an
// actionable "limit reached" response rather than a 403.
type QuotaError struct {
	Limit  string // which limit, e.g. "max_beams"
	Used   int
	Max    int
	Reason string
}

func (q *QuotaError) Error() string {
	return fmt.Sprintf("quota %s exhausted (%d of %d): %s", q.Limit, q.Used, q.Max, q.Reason)
}

// CheckBeamQuota gates create_beam on ResourceQuota.MaxBeams. A zero or
// negative MaxBeams means the quota was never set and denies creation — IT
// sets quotas explicitly; an unset limit must fail closed, not open.
func (p *PEP) CheckBeamQuota(ctx context.Context, bh domain.Beamhall) error {
	n, err := p.st.CountBeamsByBeamhall(ctx, bh.ID)
	if err != nil {
		return err
	}
	if bh.Quota.MaxBeams <= 0 || n >= bh.Quota.MaxBeams {
		return &QuotaError{Limit: "max_beams", Used: n, Max: bh.Quota.MaxBeams,
			Reason: "destroy an unused beam or ask IT to raise the quota"}
	}
	return nil
}

// CheckDatabaseQuota gates create_database on ResourceQuota.MaxDBCount, with
// the same fail-closed semantics for an unset limit.
func (p *PEP) CheckDatabaseQuota(ctx context.Context, bh domain.Beamhall) error {
	n, err := p.st.CountResourcesByType(ctx, bh.ID, domain.ResourceDatabase)
	if err != nil {
		return err
	}
	if bh.Quota.MaxDBCount <= 0 || n >= bh.Quota.MaxDBCount {
		return &QuotaError{Limit: "max_db_count", Used: n, Max: bh.Quota.MaxDBCount,
			Reason: "drop an unused database or ask IT to raise the quota"}
	}
	return nil
}

// EffectiveLiveSlotLimit is the promote_to_live gate: the stricter of the
// commercial LiveSlotLimit and the quota's MaxLiveSlots (either unset value
// fails closed via 0). The transactional count-and-flip against this limit is
// store.PromoteBeam — pass the result there.
func EffectiveLiveSlotLimit(bh domain.Beamhall) int {
	l, q := bh.LiveSlotLimit, bh.Quota.MaxLiveSlots
	if l <= 0 || q <= 0 {
		return 0
	}
	if q < l {
		return q
	}
	return l
}
