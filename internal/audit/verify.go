package audit

import (
	"context"
	"fmt"
)

// verifyBatch is how many records Verify and Export pull per cursor step.
const verifyBatch = 512

// Issue is one chain-integrity violation found by Verify.
type Issue struct {
	Seq    int64
	Reason string
}

func (i Issue) String() string { return fmt.Sprintf("seq %d: %s", i.Seq, i.Reason) }

// Verify walks the whole log in seq order and checks, for every record, that
// (a) its seq is exactly the previous seq + 1 starting at 1 (AUTOINCREMENT
// with no deletes is contiguous; a gap means rows were removed), (b) its
// PrevHash equals the previous record's Hash ("" for the genesis event), and
// (c) its Hash recomputes from the canonical encoding. It returns every
// violation rather than stopping at the first, so one report shows the full
// extent of the damage. A nil slice means the chain is intact.
//
// Note the documented blind spot: a truncated tail (newest rows deleted, no
// later append) passes — the remaining prefix is a valid chain. Anchor the
// tail externally via Export.
func (l *Logger) Verify(ctx context.Context) ([]Issue, error) {
	var issues []Issue
	prevSeq := int64(0)
	prevHash := ""
	// If the log has been pruned, resume from the latest checkpoint's anchor
	// instead of genesis: the surviving chain must continue from there, and an
	// un-checkpointed deletion still shows as a seq gap or prev_hash break.
	if cp, ok, err := l.st.LatestAuditCheckpoint(ctx); err != nil {
		return nil, err
	} else if ok {
		prevSeq = cp.ThroughSeq
		prevHash = cp.AnchorHash
	}
	for {
		recs, err := l.st.ListAuditEvents(ctx, prevSeq, verifyBatch)
		if err != nil {
			return nil, err
		}
		if len(recs) == 0 {
			return issues, nil
		}
		for _, rec := range recs {
			if rec.Seq != prevSeq+1 {
				issues = append(issues, Issue{Seq: rec.Seq, Reason: fmt.Sprintf(
					"seq gap: expected %d (rows deleted?)", prevSeq+1)})
			}
			if rec.Event.PrevHash != prevHash {
				issues = append(issues, Issue{Seq: rec.Seq, Reason: fmt.Sprintf(
					"chain break: prev_hash %.12q does not match previous hash %.12q",
					rec.Event.PrevHash, prevHash)})
			}
			if got := eventHash(&rec.Event); got != rec.Event.Hash {
				issues = append(issues, Issue{Seq: rec.Seq, Reason: "hash mismatch: event content was altered"})
			}
			prevSeq = rec.Seq
			prevHash = rec.Event.Hash
		}
	}
}
