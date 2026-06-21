package domain

import "fmt"

// BeamState is the lifecycle state of a Beam. Mode (preview|live) is orthogonal
// and gates which transitions are legal. See docs/PLAN.md §5.4.
type BeamState string

const (
	StateCreated  BeamState = "created"
	StateBuilding BeamState = "building"
	StateDeployed BeamState = "deployed"
	StateRunning  BeamState = "running"
	StatePaused   BeamState = "paused"
	StateLive     BeamState = "live"
	StateFailed   BeamState = "failed"
)

// Event drives a lifecycle transition. Most map directly to an MCP tool.
type Event string

const (
	EvDeploy        Event = "deploy_beam"
	EvBuildOK       Event = "build_ok"
	EvBuildFail     Event = "build_fail"
	EvStartOK       Event = "start_ok"
	EvStartFail     Event = "start_fail"
	EvPauseTimer    Event = "pause_timer"     // continuous-runtime deadline fired (preview only)
	EvPausePreview  Event = "pause_preview"   // manual (preview only)
	EvResumePreview Event = "resume_preview"  // mints a new random route + re-arms timer
	EvPromote       Event = "promote_to_live" // consumes a live slot; stable route
	EvRollback      Event = "rollback"        // activate a prior Release, no rebuild
	EvDestroy       Event = "destroy"         // terminal: caller archives the Beam
)

// Can reports whether ev is legal from the Beam's current State and what the
// resulting state would be. It is pure and never mutates the Beam. The returned
// reason is non-empty only when ok is false, and is suitable for an audit record
// and an actionable MCP error.
//
// State tracks the PREVIEW channel: a beam always runs a preview deployment that
// the builder iterates on, and it never leaves preview. promote_to_live adds a
// separate, pinned LIVE channel (its own release/workload/route, tracked by
// LiveReleaseID + LiveState) and flips Mode to ModeLive — but the preview
// channel keeps running, so pause/resume/promote remain legal afterwards.
//
// rolled_back is modeled as a Release status, not a Beam state: rollback
// re-activates a prior live Release and the live channel returns to serving.
// destroy is allowed from any state and signals archival (the Beam's Status, not
// a BeamState, becomes archived).
func (a *Beam) Can(ev Event) (next BeamState, ok bool, reason string) {
	s := a.State
	switch ev {
	case EvDeploy:
		// Initial deploy from created, or redeploy from any settled state. Deploy
		// always targets the preview channel; promote pins the result to live.
		switch s {
		case StateCreated, StateDeployed, StateRunning, StatePaused, StateFailed:
			return StateBuilding, true, ""
		default:
			return s, false, fmt.Sprintf("cannot deploy while in state %q", s)
		}

	case EvBuildOK:
		if s == StateBuilding {
			return StateDeployed, true, ""
		}
		return s, false, fmt.Sprintf("build_ok is only valid while building, not %q", s)

	case EvBuildFail:
		if s == StateBuilding {
			return StateFailed, true, ""
		}
		return s, false, fmt.Sprintf("build_fail is only valid while building, not %q", s)

	case EvStartOK:
		// The preview workload is healthy; the orchestrator arms its pause timer.
		if s == StateDeployed {
			return StateRunning, true, ""
		}
		return s, false, fmt.Sprintf("start_ok is only valid from deployed, not %q", s)

	case EvStartFail:
		switch s {
		case StateDeployed, StateRunning:
			return StateFailed, true, ""
		default:
			return s, false, fmt.Sprintf("start_fail is not valid from %q", s)
		}

	case EvPauseTimer, EvPausePreview:
		// The preview channel auto-pauses on idle and can be paused manually,
		// independently of whether a live channel exists.
		if s == StateRunning {
			return StatePaused, true, ""
		}
		return s, false, fmt.Sprintf("can only pause a running preview, not %q", s)

	case EvResumePreview:
		if s == StatePaused {
			return StateRunning, true, ""
		}
		return s, false, fmt.Sprintf("can only resume a paused preview, not %q", s)

	case EvPromote:
		// Pin the live channel to the build the preview is currently running.
		// Repeatable: re-promoting an already-live beam rolls production forward
		// to a newer preview build. The preview state is unchanged.
		if s == StateRunning {
			return s, true, ""
		}
		return s, false, fmt.Sprintf("can only promote a running preview, not %q", s)

	case EvRollback:
		// Rollback re-pins the live channel to a prior release; it requires an
		// existing live channel and leaves the preview state untouched.
		if a.Mode != ModeLive {
			return s, false, "nothing to roll back: this beam has no live channel (promote one first)"
		}
		return s, true, ""

	case EvDestroy:
		// Terminal from any state; the caller archives the Beam.
		return s, true, ""

	default:
		return s, false, fmt.Sprintf("unknown event %q", ev)
	}
}

// Apply transitions the Beam in place if ev is legal, returning an error
// otherwise. promote_to_live flips Mode to live (adding the live channel)
// without changing the preview State. Side effects that are not pure domain
// concerns (arming the pause timer, minting routes, consuming a live slot,
// bringing up the live workload) are the orchestrator's responsibility.
func (a *Beam) Apply(ev Event) error {
	next, ok, reason := a.Can(ev)
	if !ok {
		return &TransitionError{From: a.State, Mode: a.Mode, Event: ev, Reason: reason}
	}
	if ev == EvPromote {
		a.Mode = ModeLive
	}
	a.State = next
	return nil
}

// TransitionError describes an illegal lifecycle transition.
type TransitionError struct {
	From   BeamState
	Mode   BeamMode
	Event  Event
	Reason string
}

func (e *TransitionError) Error() string {
	return fmt.Sprintf("illegal transition %q on %s beam in state %q: %s", e.Event, e.Mode, e.From, e.Reason)
}
