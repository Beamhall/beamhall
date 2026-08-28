package orch

import (
	"sync"

	"github.com/Beamhall/beamhall/internal/domain"
)

// beamLocks serializes lifecycle-mutating operations per beam ID: deploy,
// promote/approve/reject-promotion, rollback, and destroy/archive all read a
// Beam (and, for promotions, a PromotionRequest) and later blindly persist
// their own copy of it. Two such operations racing on the SAME beam can
// otherwise interleave a read-modify-write — e.g. a slow deploy's in-flight
// beam.Status="active" overwriting a concurrent destroy's beam.Status=
// "archived" (resurrecting a torn-down beam whose managed resources are
// already gone), or an approve interleaving with a reject so the beam goes
// live while the request record says rejected.
//
// Entries are created lazily and never removed: bounded by the number of
// distinct beam IDs ever touched, which is fine for an appliance's lifetime
// (a beam row is never deleted from the store, only archived).
//
// This blocks the calling goroutine on a plain sync.Mutex — it does not
// respect ctx cancellation while waiting for the lock. That's an accepted
// simplification: the wait is bounded by another operation on the SAME beam
// completing, not by an external dependency, and every caller here already
// holds the lock only for the duration of a single lifecycle operation.
type beamLocks struct {
	mu    sync.Mutex
	locks map[domain.ID]*sync.Mutex
}

func newBeamLocks() *beamLocks {
	return &beamLocks{locks: make(map[domain.ID]*sync.Mutex)}
}

// lock blocks until beamID's lock is held and returns the function that
// releases it. Callers must defer the returned function.
func (b *beamLocks) lock(beamID domain.ID) func() {
	b.mu.Lock()
	l, ok := b.locks[beamID]
	if !ok {
		l = &sync.Mutex{}
		b.locks[beamID] = l
	}
	b.mu.Unlock()
	l.Lock()
	return l.Unlock
}
