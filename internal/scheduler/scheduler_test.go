package scheduler

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

func quiet() Option {
	return WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// --- test doubles -----------------------------------------------------------

type memStore struct {
	mu sync.Mutex
	m  map[string]time.Time
}

func newMemStore() *memStore { return &memStore{m: map[string]time.Time{}} }

func (s *memStore) Load(context.Context) ([]ArmedPause, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ArmedPause, 0, len(s.m))
	for id, dl := range s.m {
		out = append(out, ArmedPause{BeamID: id, Deadline: dl})
	}
	return out, nil
}

func (s *memStore) Save(_ context.Context, p ArmedPause) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[p.BeamID] = p.Deadline
	return nil
}

func (s *memStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
	return nil
}

func (s *memStore) has(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.m[id]
	return ok
}

type pauser struct {
	mu    sync.Mutex
	calls map[string]int
	fail  map[string]int // remaining forced failures per beam
}

func newPauser() *pauser { return &pauser{calls: map[string]int{}, fail: map[string]int{}} }

func (p *pauser) fn(_ context.Context, beamID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls[beamID]++
	if p.fail[beamID] > 0 {
		p.fail[beamID]--
		return errors.New("transient pause failure")
	}
	return nil
}

func (p *pauser) count(id string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls[id]
}

func waitFor(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

// --- tests ------------------------------------------------------------------

func TestDue(t *testing.T) {
	now := time.Unix(1000, 0)
	armed := map[string]time.Time{
		"a": now.Add(-time.Second), // overdue
		"c": now,                   // exactly now -> due (deadline <= now)
		"b": now.Add(time.Second),  // earliest future
		"d": now.Add(2 * time.Second),
	}
	fire, next, has := due(armed, now)
	if len(fire) != 2 || fire[0] != "a" || fire[1] != "c" {
		t.Fatalf("fire=%v want [a c] (sorted)", fire)
	}
	if !has || !next.Equal(now.Add(time.Second)) {
		t.Fatalf("next=%v has=%v want now+1s", next, has)
	}

	if f, _, h := due(map[string]time.Time{}, now); len(f) != 0 || h {
		t.Fatalf("empty: fire=%v has=%v", f, h)
	}
}

// Crash-correct boot reconciliation: a deadline that passed during downtime
// pauses immediately on Start; the persisted entry is then cleared.
func TestBootReconcilePausesOverdue(t *testing.T) {
	st := newMemStore()
	st.m["overdue"] = time.Now().Add(-time.Hour)
	st.m["future"] = time.Now().Add(time.Hour)
	p := newPauser()
	s := New(st, p.fn, quiet())
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.Stop()

	if !waitFor(time.Second, func() bool { return p.count("overdue") >= 1 }) {
		t.Fatal("overdue preview was not paused on boot")
	}
	if !waitFor(time.Second, func() bool { return !st.has("overdue") }) {
		t.Fatal("paused deadline not cleared from store")
	}
	if p.count("future") != 0 {
		t.Fatalf("future preview paused on boot (count=%d) — must not pause everything", p.count("future"))
	}
}

func TestArmFiresAtDeadlineAndClears(t *testing.T) {
	st := newMemStore()
	p := newPauser()
	s := New(st, p.fn, quiet())
	_ = s.Start(context.Background())
	defer s.Stop()

	if err := s.ArmAfter(context.Background(), "x", 60*time.Millisecond); err != nil {
		t.Fatalf("arm: %v", err)
	}
	if p.count("x") != 0 {
		t.Fatal("fired immediately; should wait for the deadline")
	}
	if !waitFor(time.Second, func() bool { return p.count("x") >= 1 && !st.has("x") }) {
		t.Fatalf("x not paused+cleared (count=%d, inStore=%v)", p.count("x"), st.has("x"))
	}
}

func TestDisarmPreventsFire(t *testing.T) {
	st := newMemStore()
	p := newPauser()
	s := New(st, p.fn, quiet())
	_ = s.Start(context.Background())
	defer s.Stop()

	_ = s.ArmAfter(context.Background(), "y", 100*time.Millisecond)
	_ = s.Disarm(context.Background(), "y")
	time.Sleep(250 * time.Millisecond)
	if p.count("y") != 0 {
		t.Fatalf("disarmed beam still paused (count=%d)", p.count("y"))
	}
	if st.has("y") {
		t.Fatal("disarmed beam still in store")
	}
}

// resume_preview re-arms a fresh, later deadline; the earlier one must not fire.
func TestResumeReArmsExtendsDeadline(t *testing.T) {
	st := newMemStore()
	p := newPauser()
	s := New(st, p.fn, quiet())
	_ = s.Start(context.Background())
	defer s.Stop()

	_ = s.ArmAfter(context.Background(), "z", 60*time.Millisecond)
	_ = s.ArmAfter(context.Background(), "z", time.Second) // resume, before the first fires
	time.Sleep(250 * time.Millisecond)
	if p.count("z") != 0 {
		t.Fatalf("z paused at the old (shorter) deadline despite re-arm (count=%d)", p.count("z"))
	}
}

func TestPauseRetriesOnError(t *testing.T) {
	st := newMemStore()
	p := newPauser()
	p.fail["r"] = 1 // first pause attempt fails, then succeeds
	s := New(st, p.fn, quiet(), WithRetry(40*time.Millisecond))
	_ = s.Start(context.Background())
	defer s.Stop()

	_ = s.ArmAfter(context.Background(), "r", 30*time.Millisecond)
	if !waitFor(2*time.Second, func() bool { return p.count("r") >= 2 && !st.has("r") }) {
		t.Fatalf("expected retry then success+clear (count=%d, inStore=%v)", p.count("r"), st.has("r"))
	}
}
