package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/Beamhall/beamhall/internal/domain"
)

// RetentionPolicy bounds the live audit log so it does not grow forever. An
// event is KEPT if it is among the KeepLast newest OR younger than MaxAge;
// everything else is pruned. A zero field is ignored; a zero policy prunes
// nothing. Pruned events are removed for good (no SIEM export in this build), so
// pick a window the compliance story can stand behind.
type RetentionPolicy struct {
	MaxAge   time.Duration // remove events older than this (0 = ignore)
	KeepLast int64         // keep at most this many newest events (0 = ignore)
}

func (p RetentionPolicy) Describe() string {
	switch {
	case p.MaxAge > 0 && p.KeepLast > 0:
		return fmt.Sprintf("older than %s and beyond the last %d", p.MaxAge, p.KeepLast)
	case p.MaxAge > 0:
		return fmt.Sprintf("older than %s", p.MaxAge)
	case p.KeepLast > 0:
		return fmt.Sprintf("beyond the last %d", p.KeepLast)
	default:
		return "none"
	}
}

// Prune trims the audit log per policy and records an integrity checkpoint
// anchoring the survivors, so Verify keeps passing and any deletion NOT recorded
// by a checkpoint is still caught (seq gap / prev_hash break). The checkpoint row
// is itself the audit record of the prune (when, who, how many) — deliberately
// NOT a chain event, so it does not count toward KeepLast and re-pruning is
// idempotent. `by` labels the operator/system that triggered it. Returns the
// number of events removed (0 if the policy matched nothing new). Pass the wall
// clock as `now` (the package never reads it itself).
//
// Integrity note: the deletion and chain continuity are tamper-evident; the
// checkpoint's metadata fields (count/by/at) are not hash-sealed, so treat them
// as informational, not forensic.
func (l *Logger) Prune(ctx context.Context, policy RetentionPolicy, by domain.ID, now time.Time) (int64, error) {
	cut, floor, err := l.resolveCut(ctx, policy, now)
	if err != nil || cut <= floor {
		return 0, err
	}
	return l.st.PruneAuditThrough(ctx, cut, by)
}

// WouldPrune reports how many events Prune would remove under policy, without
// deleting anything (for a CLI dry-run / size preview).
func (l *Logger) WouldPrune(ctx context.Context, policy RetentionPolicy, now time.Time) (int64, error) {
	cut, floor, err := l.resolveCut(ctx, policy, now)
	if err != nil || cut <= floor {
		return 0, err
	}
	return cut - floor, nil
}

// resolveCut computes the highest seq that may be pruned under policy (cut) and
// the last already-pruned seq (floor). Each active constraint can only lower the
// cut — an event is KEPT if ANY constraint says keep — so it starts at maxSeq and
// takes the minimum across active constraints. cut <= floor means nothing to do.
func (l *Logger) resolveCut(ctx context.Context, policy RetentionPolicy, now time.Time) (cut, floor int64, err error) {
	if policy.MaxAge <= 0 && policy.KeepLast <= 0 {
		return 0, 0, nil
	}
	maxSeq, err := l.st.MaxAuditSeq(ctx)
	if err != nil {
		return 0, 0, err
	}
	if cp, ok, err := l.st.LatestAuditCheckpoint(ctx); err != nil {
		return 0, 0, err
	} else if ok {
		floor = cp.ThroughSeq
	}
	cut = maxSeq
	if policy.KeepLast > 0 && maxSeq-policy.KeepLast < cut {
		cut = maxSeq - policy.KeepLast
	}
	if policy.MaxAge > 0 {
		byAge, err := l.st.AuditCutSeqByAge(ctx, now.Add(-policy.MaxAge))
		if err != nil {
			return 0, 0, err
		}
		if byAge < cut {
			cut = byAge
		}
	}
	return cut, floor, nil
}
