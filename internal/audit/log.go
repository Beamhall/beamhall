// Package audit is the hash-chained, append-only audit log (PLAN §6, §11.2).
// Every backplane action lands here as a domain.AuditEvent whose Hash covers
// the event's content and the previous event's Hash, forming a chain anchored
// at the genesis event (PrevHash ""). The storage total order is the
// audit_events.seq AUTOINCREMENT (never reused; the store has no delete
// query), so any in-place edit, deletion, or reordering breaks either a hash,
// the PrevHash linkage, or seq contiguity — all reported by Verify.
//
// Tamper-evidence scope: the chain detects db-level edits by anything short
// of an attacker who can rewrite the whole chain consistently (full write
// access to the file). Truncating the tail of the log is detectable only
// after the next append (sqlite_sequence keeps the high-water mark, so the
// gap shows) or against a copy exported earlier — which is why Export exists:
// ship the log to an external SIEM and the tail is anchored off-box.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"time"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/store"
)

// Store is the persistence the log needs. *store.Store satisfies it.
// AuditChainAppend must run read-head → seal → insert atomically with respect
// to all other writers (the store does this in one BEGIN IMMEDIATE
// transaction).
type Store interface {
	AuditChainAppend(ctx context.Context, ev *domain.AuditEvent, seal func(prevHash string)) (int64, error)
	ListAuditEvents(ctx context.Context, afterSeq int64, limit int) ([]store.AuditRecord, error)

	// Retention: prune old events while keeping the surviving chain verifiable.
	MaxAuditSeq(ctx context.Context) (int64, error)
	AuditCutSeqByAge(ctx context.Context, cutoff time.Time) (int64, error)
	LatestAuditCheckpoint(ctx context.Context) (store.AuditCheckpoint, bool, error)
	PruneAuditThrough(ctx context.Context, throughSeq int64, by domain.ID) (int64, error)
}

// Logger appends hash-chained audit events. It is safe for concurrent use:
// chain consistency comes from the store's transactional append, not from
// in-process state (the Logger holds none, so it is also restart-safe by
// construction).
type Logger struct {
	st Store
}

// New returns a Logger over st.
func New(st Store) *Logger { return &Logger{st: st} }

// Append seals ev onto the chain and returns its sequence number. The store
// fills ID and At if unset before the hash is computed; PrevHash and Hash are
// always overwritten here — callers never supply them.
func (l *Logger) Append(ctx context.Context, ev *domain.AuditEvent) (int64, error) {
	return l.st.AuditChainAppend(ctx, ev, func(prevHash string) {
		ev.PrevHash = prevHash
		ev.Hash = eventHash(ev)
	})
}

// encodingVersion is the domain separator and version tag of the canonical
// encoding. Bump it (and branch in eventHash) if the hashed field set ever
// changes; old events keep verifying under the version recorded in their
// chain position.
const encodingVersion = "beamhall-audit-v1"

// eventHash returns hex(SHA-256) over the canonical encoding of ev: every
// field except Hash itself and the storage seq, including PrevHash (the chain
// link). seq stays outside the hash because it is assigned by the database on
// insert; ordering integrity comes from PrevHash linkage plus Verify's seq
// contiguity check. Each field is length-prefixed (uvarint) so field
// boundaries are unambiguous regardless of content.
func eventHash(ev *domain.AuditEvent) string {
	h := sha256.New()
	var lenBuf [binary.MaxVarintLen64]byte
	put := func(field string) {
		n := binary.PutUvarint(lenBuf[:], uint64(len(field)))
		h.Write(lenBuf[:n])
		h.Write([]byte(field))
	}
	put(encodingVersion)
	put(string(ev.ID))
	put(strconv.FormatInt(ev.At.UnixNano(), 10))
	put(string(ev.ActorID))
	put(ev.ActorTokenJTI)
	put(string(ev.BeamhallID))
	put(string(ev.BeamID))
	put(ev.Action)
	put(string(ev.Decision))
	put(ev.Reason)
	put(ev.RequestDigest)
	put(ev.ResultStatus)
	put(ev.SourceIP)
	put(ev.PrevHash)
	return hex.EncodeToString(h.Sum(nil))
}
