package domain

import "testing"

func TestBeamCan(t *testing.T) {
	cases := []struct {
		name     string
		state    BeamState
		mode     BeamMode
		event    Event
		wantNext BeamState
		wantOK   bool
	}{
		// Happy path: create -> build -> deploy -> run (preview). State always
		// tracks the preview channel; promote adds a live channel without
		// changing the preview State.
		{"deploy from created", StateCreated, ModePreview, EvDeploy, StateBuilding, true},
		{"build ok", StateBuilding, ModePreview, EvBuildOK, StateDeployed, true},
		{"build fail", StateBuilding, ModePreview, EvBuildFail, StateFailed, true},
		{"start ok preview", StateDeployed, ModePreview, EvStartOK, StateRunning, true},
		{"start ok preview while live exists", StateDeployed, ModeLive, EvStartOK, StateRunning, true},
		{"promote running preview", StateRunning, ModePreview, EvPromote, StateRunning, true},
		{"re-promote already-live (roll forward)", StateRunning, ModeLive, EvPromote, StateRunning, true},

		// Preview pause/resume — independent of whether a live channel exists
		{"pause timer running preview", StateRunning, ModePreview, EvPauseTimer, StatePaused, true},
		{"manual pause running preview", StateRunning, ModePreview, EvPausePreview, StatePaused, true},
		{"resume paused preview", StatePaused, ModePreview, EvResumePreview, StateRunning, true},
		{"pause preview even when live", StateRunning, ModeLive, EvPausePreview, StatePaused, true},
		{"resume preview even when live", StatePaused, ModeLive, EvResumePreview, StateRunning, true},

		// Promote only from a running preview
		{"promote denied from deployed", StateDeployed, ModePreview, EvPromote, StateDeployed, false},
		{"promote denied from paused", StatePaused, ModePreview, EvPromote, StatePaused, false},

		// Redeploy from settled states (always targets the preview channel)
		{"redeploy from running", StateRunning, ModePreview, EvDeploy, StateBuilding, true},
		{"redeploy from running while live", StateRunning, ModeLive, EvDeploy, StateBuilding, true},
		{"redeploy from paused", StatePaused, ModePreview, EvDeploy, StateBuilding, true},
		{"redeploy from failed", StateFailed, ModePreview, EvDeploy, StateBuilding, true},

		// Rollback re-pins the live channel; it needs one and leaves State as-is
		{"rollback denied without live channel", StateRunning, ModePreview, EvRollback, StateRunning, false},
		{"rollback live keeps preview state", StateRunning, ModeLive, EvRollback, StateRunning, true},
		{"rollback live from paused preview", StatePaused, ModeLive, EvRollback, StatePaused, true},

		// Illegal: build_ok only from building
		{"build ok from running invalid", StateRunning, ModePreview, EvBuildOK, StateRunning, false},
		{"start ok from created invalid", StateCreated, ModePreview, EvStartOK, StateCreated, false},

		// Destroy is terminal from any state
		{"destroy from running", StateRunning, ModePreview, EvDestroy, StateRunning, true},
		{"destroy from created", StateCreated, ModePreview, EvDestroy, StateCreated, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := &Beam{State: tc.state, Mode: tc.mode}
			next, ok, reason := a.Can(tc.event)
			if ok != tc.wantOK {
				t.Fatalf("ok=%v want %v (reason=%q)", ok, tc.wantOK, reason)
			}
			if next != tc.wantNext {
				t.Fatalf("next=%q want %q", next, tc.wantNext)
			}
			if !ok && reason == "" {
				t.Fatalf("expected a non-empty reason for a denied transition")
			}
		})
	}
}

func TestBeamApplyPromoteFlipsMode(t *testing.T) {
	a := &Beam{State: StateRunning, Mode: ModePreview}
	if err := a.Apply(EvPromote); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if a.State != StateRunning { // preview channel keeps running
		t.Fatalf("state=%q want running (preview is untouched by promote)", a.State)
	}
	if a.Mode != ModeLive {
		t.Fatalf("mode=%q want live", a.Mode)
	}
}

func TestBeamApplyRejectsIllegal(t *testing.T) {
	a := &Beam{State: StateDeployed, Mode: ModePreview}
	err := a.Apply(EvPausePreview)
	if err == nil {
		t.Fatal("expected an error pausing a beam that is not running")
	}
	if _, ok := err.(*TransitionError); !ok {
		t.Fatalf("want *TransitionError, got %T", err)
	}
	if a.State != StateDeployed { // unchanged on failure
		t.Fatalf("state mutated to %q on a rejected transition", a.State)
	}
}
