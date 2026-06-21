// Package scheduler implements Beamhall's durable preview auto-pause: a preview
// beam pauses after Y hours of CONTINUOUS runtime (wall-clock since its last
// resume, not idle time). Deadlines are absolute and persisted, so they survive
// a backplane restart: on boot the scheduler pauses whatever should have paused
// during downtime (deadline already passed) and re-schedules the rest — without
// pausing everything and without running previews forever. See docs/PLAN.md §5.6
// and hardest-problem #3.
//
// The scheduler is generic over absolute deadlines; the orchestrator computes
// deadline = resumed_at + preview_pause_after and wires PauseFunc to
// driver.Pause + route retire + state/audit. resume re-Arms (new deadline + new
// URL is the orchestrator's job); promote_to_live / pause / destroy Disarm. Live
// beams are never Armed.
package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"
)

// maxSleep bounds how long the loop sleeps without re-evaluating, as a defensive
// backstop against a missed wake or wall-clock adjustment.
const maxSleep = time.Hour

// ArmedPause is a persisted preview auto-pause deadline.
type ArmedPause struct {
	BeamID   string
	Deadline time.Time
}

// Store persists armed pause deadlines so they survive a backplane restart.
// Implementations must be safe for concurrent use.
type Store interface {
	Load(ctx context.Context) ([]ArmedPause, error)
	Save(ctx context.Context, p ArmedPause) error
	Delete(ctx context.Context, beamID string) error
}

// PauseFunc is invoked when a preview's continuous-runtime deadline fires. The
// orchestrator wires it to driver.Pause + gateway route retire + beam-state/audit.
// It must be idempotent (pausing an already-paused/promoted beam is a no-op):
// boot reconciliation is at-least-once. Returning an error triggers a bounded
// retry; returning nil disarms the timer.
type PauseFunc func(ctx context.Context, beamID string) error

// Scheduler drives durable preview auto-pause.
type Scheduler struct {
	store        Store
	pause        PauseFunc
	now          func() time.Time
	retry        time.Duration
	pauseTimeout time.Duration
	log          *slog.Logger

	mu    sync.Mutex
	armed map[string]time.Time // beamID -> absolute deadline (in-memory mirror of Store)

	wake   chan struct{}
	cancel context.CancelFunc
	done   chan struct{}
}

// Option configures a Scheduler.
type Option func(*Scheduler)

// WithNow overrides the clock (for tests).
func WithNow(now func() time.Time) Option { return func(s *Scheduler) { s.now = now } }

// WithRetry sets the re-arm delay used when PauseFunc fails.
func WithRetry(d time.Duration) Option { return func(s *Scheduler) { s.retry = d } }

// WithPauseTimeout bounds a single PauseFunc call.
func WithPauseTimeout(d time.Duration) Option { return func(s *Scheduler) { s.pauseTimeout = d } }

// WithLogger sets the logger.
func WithLogger(l *slog.Logger) Option { return func(s *Scheduler) { s.log = l } }

// New builds a Scheduler. Call Start to load persisted deadlines and run.
func New(store Store, pause PauseFunc, opts ...Option) *Scheduler {
	s := &Scheduler{
		store:        store,
		pause:        pause,
		now:          time.Now,
		retry:        30 * time.Second,
		pauseTimeout: 30 * time.Second,
		log:          slog.Default(),
		armed:        make(map[string]time.Time),
		wake:         make(chan struct{}, 1),
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Start loads persisted deadlines and launches the loop. The provided context
// is the base for every PauseFunc call; cancel it (or call Stop) to shut down.
func (s *Scheduler) Start(ctx context.Context) error {
	loaded, err := s.store.Load(ctx)
	if err != nil {
		return fmt.Errorf("load armed pauses: %w", err)
	}
	s.mu.Lock()
	for _, p := range loaded {
		s.armed[p.BeamID] = p.Deadline
	}
	n := len(s.armed)
	s.mu.Unlock()

	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.done = make(chan struct{})
	go s.loop(runCtx)
	s.log.Info("preview-pause scheduler started", "armed", n)
	return nil
}

// Stop shuts the loop down and waits for it to exit.
func (s *Scheduler) Stop() {
	if s.cancel != nil {
		s.cancel()
		<-s.done
	}
}

// Arm schedules (or reschedules) beam's preview to pause at deadline. Used on
// start/resume of a preview. Persisted before it takes effect so a crash after
// Arm still honors the deadline.
func (s *Scheduler) Arm(ctx context.Context, beamID string, deadline time.Time) error {
	if err := s.store.Save(ctx, ArmedPause{BeamID: beamID, Deadline: deadline}); err != nil {
		return fmt.Errorf("persist armed pause: %w", err)
	}
	s.mu.Lock()
	s.armed[beamID] = deadline
	s.mu.Unlock()
	s.signal()
	return nil
}

// ArmAfter is Arm with a deadline of now + d.
func (s *Scheduler) ArmAfter(ctx context.Context, beamID string, d time.Duration) error {
	return s.Arm(ctx, beamID, s.now().Add(d))
}

// Disarm cancels beam's pending pause (promote_to_live / manual pause / destroy).
func (s *Scheduler) Disarm(ctx context.Context, beamID string) error {
	if err := s.store.Delete(ctx, beamID); err != nil {
		return fmt.Errorf("delete armed pause: %w", err)
	}
	s.mu.Lock()
	delete(s.armed, beamID)
	s.mu.Unlock()
	s.signal()
	return nil
}

// loop fires due pauses and sleeps until the next deadline (or a wake/stop).
func (s *Scheduler) loop(ctx context.Context) {
	defer close(s.done)
	for {
		s.mu.Lock()
		fire, next, hasNext := due(s.armed, s.now())
		for _, id := range fire {
			delete(s.armed, id) // claim it; re-armed on retry by fire()
		}
		s.mu.Unlock()

		for _, id := range fire {
			s.fire(ctx, id)
		}

		d := maxSleep
		if hasNext {
			if rem := next.Sub(s.now()); rem < d {
				d = rem
			}
			if d < 0 {
				d = 0
			}
		}
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-s.wake:
			t.Stop()
		case <-t.C:
		}
	}
}

// fire runs PauseFunc for a due beam. On success it deletes the persisted entry;
// on failure it re-Arms a bounded retry so the deadline is never silently lost.
func (s *Scheduler) fire(ctx context.Context, beamID string) {
	pctx, cancel := context.WithTimeout(ctx, s.pauseTimeout)
	err := s.pause(pctx, beamID)
	cancel()
	if err != nil {
		s.log.Warn("preview pause failed; retrying", "beam", beamID, "retry_in", s.retry, "err", err)
		if aerr := s.Arm(ctx, beamID, s.now().Add(s.retry)); aerr != nil {
			s.log.Error("failed to re-arm pause retry", "beam", beamID, "err", aerr)
		}
		return
	}
	if derr := s.store.Delete(ctx, beamID); derr != nil {
		s.log.Warn("paused but failed to clear persisted deadline", "beam", beamID, "err", derr)
	}
}

// signal nudges the loop to re-evaluate without blocking the caller.
func (s *Scheduler) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// due returns the beams whose deadline has passed (deadline <= now) and the
// earliest still-future deadline. Pure and deterministic (fire is sorted).
func due(armed map[string]time.Time, now time.Time) (fire []string, next time.Time, hasNext bool) {
	for id, dl := range armed {
		if !dl.After(now) {
			fire = append(fire, id)
			continue
		}
		if !hasNext || dl.Before(next) {
			next, hasNext = dl, true
		}
	}
	sort.Strings(fire)
	return fire, next, hasNext
}
