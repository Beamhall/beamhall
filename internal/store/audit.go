package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/store/db"
)

// AuditRecord pairs an AuditEvent with its chain sequence number. seq is
// storage-assigned (AUTOINCREMENT, so never reused even after deletes — there
// is deliberately no delete query) and is the cursor for SIEM export.
type AuditRecord struct {
	Seq   int64
	Event domain.AuditEvent
}

// AppendAuditEvent appends ev to the audit log and returns its sequence
// number, filling ID and At if unset. The store persists the hash fields as
// given; computing the chain (and serializing appends so prev_hash is correct)
// is internal/audit's job — use its writer rather than calling this directly.
func (s *Store) AppendAuditEvent(ctx context.Context, ev *domain.AuditEvent) (int64, error) {
	s.fillAuditEvent(ev)
	seq, err := s.q.AppendAuditEvent(ctx, appendAuditEventParams(ev))
	return seq, mapErr(err)
}

// AuditChainAppend appends ev as the new chain head: inside a single write
// transaction it reads the current head's hash ("" on an empty log), calls
// seal so the caller can set ev.PrevHash and ev.Hash, then inserts. The
// transaction (BEGIN IMMEDIATE, single connection) makes read→seal→insert
// atomic against every other writer, so the chain cannot fork or skip even
// under concurrent appends. ID and At are filled before seal runs, so the
// hash can cover their final values.
func (s *Store) AuditChainAppend(ctx context.Context, ev *domain.AuditEvent, seal func(prevHash string)) (int64, error) {
	s.fillAuditEvent(ev)
	var seq int64
	err := s.withTx(ctx, func(q *db.Queries) error {
		var prev string
		switch row, err := q.LastAuditEvent(ctx); {
		case err == nil:
			prev = row.Hash
		case errors.Is(err, sql.ErrNoRows):
			prev = "" // chain genesis
		default:
			return err
		}
		seal(prev)
		var err error
		seq, err = q.AppendAuditEvent(ctx, appendAuditEventParams(ev))
		return err
	})
	return seq, mapErr(err)
}

func (s *Store) fillAuditEvent(ev *domain.AuditEvent) {
	if ev.ID == "" {
		ev.ID = NewID()
	}
	if ev.At.IsZero() {
		ev.At = s.now()
	}
}

func appendAuditEventParams(ev *domain.AuditEvent) db.AppendAuditEventParams {
	return db.AppendAuditEventParams{
		ID:            string(ev.ID),
		At:            ns(ev.At),
		ActorID:       string(ev.ActorID),
		ActorTokenJti: ev.ActorTokenJTI,
		BeamhallID:    string(ev.BeamhallID),
		BeamID:        string(ev.BeamID),
		Action:        ev.Action,
		Decision:      string(ev.Decision),
		Reason:        ev.Reason,
		RequestDigest: ev.RequestDigest,
		ResultStatus:  ev.ResultStatus,
		SourceIp:      ev.SourceIP,
		PrevHash:      ev.PrevHash,
		Hash:          ev.Hash,
	}
}

// LastAuditEvent returns the newest audit record, or ok=false on an empty log
// (the chain seed case).
func (s *Store) LastAuditEvent(ctx context.Context) (rec AuditRecord, ok bool, err error) {
	row, err := s.q.LastAuditEvent(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return AuditRecord{}, false, nil
	}
	if err != nil {
		return AuditRecord{}, false, mapErr(err)
	}
	return auditRecordFromRow(row), true, nil
}

// ListAuditEvents returns up to limit records with seq > afterSeq, ascending —
// the SIEM-export / chain-verification cursor walk.
func (s *Store) ListAuditEvents(ctx context.Context, afterSeq int64, limit int) ([]AuditRecord, error) {
	rows, err := s.q.ListAuditEvents(ctx, db.ListAuditEventsParams{
		Seq:   afterSeq,
		Limit: int64(limit),
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return auditRecordsFromRows(rows), nil
}

// ListAuditEventsByBeamhall is ListAuditEvents filtered to one Beamhall.
func (s *Store) ListAuditEventsByBeamhall(ctx context.Context, beamhallID domain.ID, afterSeq int64, limit int) ([]AuditRecord, error) {
	rows, err := s.q.ListAuditEventsByBeamhall(ctx, db.ListAuditEventsByBeamhallParams{
		BeamhallID: string(beamhallID),
		Seq:        afterSeq,
		Limit:      int64(limit),
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return auditRecordsFromRows(rows), nil
}

func auditRecordsFromRows(rows []db.AuditEvent) []AuditRecord {
	out := make([]AuditRecord, 0, len(rows))
	for _, r := range rows {
		out = append(out, auditRecordFromRow(r))
	}
	return out
}

func auditRecordFromRow(r db.AuditEvent) AuditRecord {
	return AuditRecord{
		Seq: r.Seq,
		Event: domain.AuditEvent{
			ID:            domain.ID(r.ID),
			At:            fromNS(r.At),
			ActorID:       domain.ID(r.ActorID),
			ActorTokenJTI: r.ActorTokenJti,
			BeamhallID:    domain.ID(r.BeamhallID),
			BeamID:        domain.ID(r.BeamID),
			Action:        r.Action,
			Decision:      domain.AuditDecision(r.Decision),
			Reason:        r.Reason,
			RequestDigest: r.RequestDigest,
			ResultStatus:  r.ResultStatus,
			SourceIP:      r.SourceIp,
			PrevHash:      r.PrevHash,
			Hash:          r.Hash,
		},
	}
}

// AuditCheckpoint records a prune of the audit chain: every event with seq <=
// ThroughSeq was removed, and AnchorHash is the chain hash that was at
// ThroughSeq — the point Verify resumes from.
type AuditCheckpoint struct {
	ThroughSeq  int64
	AnchorHash  string
	PrunedCount int64
	At          time.Time
	PrunedBy    domain.ID
}

// LatestAuditCheckpoint returns the most recent prune checkpoint; ok=false when
// the chain has never been pruned (Verify then starts from genesis).
func (s *Store) LatestAuditCheckpoint(ctx context.Context) (AuditCheckpoint, bool, error) {
	row, err := s.q.LatestAuditCheckpoint(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return AuditCheckpoint{}, false, nil
	}
	if err != nil {
		return AuditCheckpoint{}, false, mapErr(err)
	}
	return AuditCheckpoint{
		ThroughSeq: row.ThroughSeq, AnchorHash: row.AnchorHash, PrunedCount: row.PrunedCount,
		At: fromNS(row.At), PrunedBy: domain.ID(row.PrunedBy),
	}, true, nil
}

// MaxAuditSeq returns the highest assigned audit seq (0 on an empty log).
func (s *Store) MaxAuditSeq(ctx context.Context) (int64, error) {
	v, err := s.q.MaxAuditSeq(ctx)
	return asInt64(v), mapErr(err)
}

// AuditCutSeqByAge returns the newest seq strictly older than cutoff (0 if none)
// — the prune-through point for an age-based retention policy.
func (s *Store) AuditCutSeqByAge(ctx context.Context, cutoff time.Time) (int64, error) {
	v, err := s.q.AuditCutSeqByAge(ctx, ns(cutoff))
	return asInt64(v), mapErr(err)
}

// PruneAuditThrough deletes every audit event with seq <= throughSeq and records
// a checkpoint anchoring the surviving chain (so Verify resumes correctly and an
// un-checkpointed deletion is still detected as a seq gap / chain break).
// throughSeq must name a currently-present event. Returns the number removed.
// Read-anchor, delete, and checkpoint-insert run in one transaction.
func (s *Store) PruneAuditThrough(ctx context.Context, throughSeq int64, by domain.ID) (int64, error) {
	var pruned int64
	err := s.withTx(ctx, func(q *db.Queries) error {
		anchor, err := q.AuditHashBySeq(ctx, throughSeq) // read the anchor BEFORE deleting it
		if err != nil {
			return err
		}
		n, err := q.DeleteAuditEventsThrough(ctx, throughSeq)
		if err != nil {
			return err
		}
		pruned = n
		return q.InsertAuditCheckpoint(ctx, db.InsertAuditCheckpointParams{
			ThroughSeq: throughSeq, AnchorHash: anchor, PrunedCount: n,
			At: ns(s.now()), PrunedBy: string(by),
		})
	})
	return pruned, mapErr(err)
}

// asInt64 normalizes a COALESCE(MAX(...),0) scalar (sqlc types it as interface{}).
func asInt64(v interface{}) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	default:
		return 0
	}
}
