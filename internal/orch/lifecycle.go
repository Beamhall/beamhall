package orch

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/driver"
	"github.com/Beamhall/beamhall/internal/gateway"
	"github.com/Beamhall/beamhall/internal/policy"
	"github.com/Beamhall/beamhall/internal/scheduler"
)

// PauseFunc is what the durable scheduler fires when a preview's
// continuous-runtime window expires. It is the same path as a manual pause
// but attributed to the system actor and the pause_timer event. The
// scheduler only knows a beam ID (no caller-supplied beamhall claim to
// validate against), so it looks the beam's own hall up first and passes
// that through as ground truth — pause() still runs its containment check
// uniformly for both callers.
func (o *Orchestrator) PauseFunc() scheduler.PauseFunc {
	return func(ctx context.Context, beamID string) error {
		beam, err := o.st.GetBeam(ctx, domain.ID(beamID))
		if err != nil {
			return err
		}
		err = o.pause(ctx, beam.BeamhallID, domain.ID(beamID), domain.EvPauseTimer)
		// An FSM refusal is permanent for THIS timer (the beam is failed,
		// already paused, or mid-transition — any state change that makes it
		// pausable again re-arms a fresh deadline). Returning the error would
		// make the scheduler retry the same refusal every cycle forever;
		// returning nil lets it clear the stale timer.
		var te *domain.TransitionError
		if errors.As(err, &te) {
			o.log.Info("auto-pause timer cleared on FSM refusal", "beam", beamID, "reason", te.Reason)
			return nil
		}
		return err
	}
}

// PausePreview is the operator/agent-requested pause (pause_preview tool).
func (o *Orchestrator) PausePreview(ctx context.Context, actor Actor, beamhallID, beamID domain.ID) error {
	if err := o.authorize(ctx, actor, policy.ActionPausePreview, beamhallID, beamID); err != nil {
		return err
	}
	err := o.pause(ctx, beamhallID, beamID, domain.EvPausePreview)
	if err == nil {
		err = o.sched.Disarm(ctx, string(beamID))
	}
	return o.outcome(ctx, actor, policy.ActionPausePreview, beamhallID, beamID, err)
}

// pause freezes the workload and retires the preview route — a paused
// preview's URL is gone; resume mints a fresh one (PLAN §5.6). Routed through
// operableBeam (not a bare GetBeam) so a beamID belonging to a different
// beamhall than the PEP authorized against is refused here too, not just by
// callers that happen to resolve beams by slug-within-hall.
func (o *Orchestrator) pause(ctx context.Context, beamhallID, beamID domain.ID, ev domain.Event) error {
	// Serialize against deploy/promote/rollback/destroy on this beam: pause
	// ends in a full-row UpdateBeam, so a pause racing e.g. a promote would
	// persist a pre-promote snapshot (erasing the live channel), and one racing
	// a destroy would resurrect the archived row.
	unlock := o.beamLocks.lock(beamID)
	defer unlock()

	beam, err := o.operableBeam(ctx, beamhallID, beamID)
	if err != nil {
		return err
	}
	if err := beam.Apply(ev); err != nil {
		return err
	}
	rel, err := o.st.GetRelease(ctx, beam.CurrentReleaseID)
	if err != nil {
		return fmt.Errorf("paused beam has no usable release: %w", err)
	}
	if err := o.drv.Pause(ctx, handleOf(rel)); err != nil {
		return err
	}
	if rel.RouteID != "" {
		if rt, rerr := o.st.GetRoute(ctx, rel.RouteID); rerr == nil && rt.Status == domain.RouteActive {
			if err := o.gw.Retire(ctx, rt.Hostname); err != nil {
				return err
			}
			if err := o.st.RetireRoute(ctx, rt.ID); err != nil {
				return err
			}
		}
	}
	// The preview URL dies on pause; resume mints a fresh one (the rotation
	// that makes a leaked/idle preview link stop working).
	beam.PreviewHost = ""
	// Empty the preview OIDC client's redirect allowlist while idle (no valid
	// callback until resume re-syncs) — PLAN §5.10.
	o.syncAuthRedirects(ctx, beamID, domain.ChannelPreview, "")
	return o.st.UpdateBeam(ctx, &beam)
}

// ResumePreview thaws a paused preview, mints a NEW random URL, and re-arms
// the auto-pause window from now.
func (o *Orchestrator) ResumePreview(ctx context.Context, actor Actor, beamhallID, beamID domain.ID) (hostname string, err error) {
	if err := o.authorize(ctx, actor, policy.ActionResumePreview, beamhallID, beamID); err != nil {
		return "", err
	}
	hostname, err = o.resume(ctx, beamhallID, beamID)
	return hostname, o.outcome(ctx, actor, policy.ActionResumePreview, beamhallID, beamID, err)
}

func (o *Orchestrator) resume(ctx context.Context, beamhallID, beamID domain.ID) (string, error) {
	// Same serialization as pause: resume's stale full-row UpdateBeam must not
	// interleave with another lifecycle op's read-modify-write on this beam.
	unlock := o.beamLocks.lock(beamID)
	defer unlock()

	beam, err := o.operableBeam(ctx, beamhallID, beamID)
	if err != nil {
		return "", err
	}
	if err := beam.Apply(domain.EvResumePreview); err != nil {
		return "", err
	}
	rel, err := o.st.GetRelease(ctx, beam.CurrentReleaseID)
	if err != nil {
		return "", err
	}
	h := handleOf(rel)
	if err := o.drv.Resume(ctx, h); err != nil {
		return "", err
	}
	status, err := o.drv.Status(ctx, h)
	if err != nil {
		return "", err
	}
	hostname := o.previewHost() // rotate: resume always gets a fresh URL
	beam.PreviewHost = hostname // redeploys after resume reuse this one
	if _, err := o.mintRoute(ctx, &beam, rel.ID, hostname, gateway.Preview, status.BackendAddr); err != nil {
		return "", err
	}
	beam.ResumedAt = o.now()
	if err := o.sched.Arm(ctx, string(beam.ID), beam.ResumedAt.Add(o.pauseAfter(beam))); err != nil {
		return "", err
	}
	// Resume rotated the preview URL — re-point the OIDC client's redirect
	// allowlist to the new host so sign-in keeps working (no redeploy) — PLAN §5.10.
	o.syncAuthRedirects(ctx, beam.ID, domain.ChannelPreview, hostname)
	return hostname, o.st.UpdateBeam(ctx, &beam)
}

// PromoteToLive consumes a live slot (transactionally — no concurrent-promote
// race) and swaps the random preview URL for the stable live hostname. The
// PEP gates who may call this; builders get the demo's 403.
func (o *Orchestrator) PromoteToLive(ctx context.Context, actor Actor, beamhallID, beamID domain.ID) (hostname string, err error) {
	if err := o.authorize(ctx, actor, policy.ActionPromoteToLive, beamhallID, beamID); err != nil {
		return "", err
	}
	// Serialize against any other deploy/promote/rollback/destroy on this beam,
	// and against a concurrent ApprovePromotion/RejectPromotion for the same
	// beam — locked here, at the caller, rather than inside o.promote
	// itself, because approvePromotion must hold the SAME lock across its own
	// read-decide-DecidePromotionRequest sequence (not just the o.promote
	// call), and o.promote has no way to know it's already covered.
	unlock := o.beamLocks.lock(beamID)
	defer unlock()
	hostname, err = o.promote(ctx, actor, beamhallID, beamID)
	return hostname, o.outcome(ctx, actor, policy.ActionPromoteToLive, beamhallID, beamID, err)
}

// ShowLogs returns the beam's recent log bytes with every in-scope secret
// value redacted backplane-side before anything leaves the process (PLAN §6).
// The scrubber is built per call and dropped — plaintext never lingers.
func (o *Orchestrator) ShowLogs(ctx context.Context, actor Actor, beamhallID, beamID domain.ID,
	opts driver.LogOptions) ([]byte, error) {
	if err := o.authorize(ctx, actor, policy.ActionShowLogs, beamhallID, beamID); err != nil {
		return nil, err
	}
	out, err := o.showLogs(ctx, beamhallID, beamID, opts)
	return out, o.outcome(ctx, actor, policy.ActionShowLogs, beamhallID, beamID, err)
}

func (o *Orchestrator) showLogs(ctx context.Context, beamhallID, beamID domain.ID, opts driver.LogOptions) ([]byte, error) {
	beam, err := o.operableBeam(ctx, beamhallID, beamID)
	if err != nil {
		return nil, err
	}
	if beam.CurrentReleaseID == "" {
		return nil, fmt.Errorf("beam %s has never been deployed", beamID)
	}
	rel, err := o.st.GetRelease(ctx, beam.CurrentReleaseID)
	if err != nil {
		return nil, err
	}
	rc, err := o.drv.Logs(ctx, handleOf(rel), opts)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	raw, err := io.ReadAll(rc)
	if err != nil {
		return nil, err
	}
	scrub, err := o.vault.ScrubberFor(ctx, beamhallID, beamID)
	if err != nil {
		return nil, err
	}
	return scrub.Scrub(raw), nil
}

// Boot restores runtime state after a restart: active routes back into the
// gateway (Restore + Apply happen on the concrete gateway in cmd wiring; here
// we re-Upsert through the interface so fakes observe it too). The pause
// scheduler reloads its own armed deadlines from the store on Start.
func (o *Orchestrator) Boot(ctx context.Context) error {
	// A daemon crash mid-build leaves the beam in `building` — a state with no
	// legal deploy transition, so without this it is wedged until destroyed.
	// Boot runs before any request is served, so every `building` beam here is
	// an interrupted build, never an in-flight one: land it in failed with an
	// actionable reason (the standard redeploy path recovers from failed).
	if stuck, err := o.st.ListBeamsByState(ctx, domain.StateBuilding); err != nil {
		o.log.Error("boot: listing interrupted builds", "err", err)
	} else {
		for _, beam := range stuck {
			if beam.Status == domain.BeamArchived {
				continue
			}
			if err := beam.Apply(domain.EvBuildFail); err != nil {
				o.log.Error("boot: failing interrupted build", "beam", beam.ID, "err", err)
				continue
			}
			if err := o.st.UpdateBeam(ctx, &beam); err != nil {
				o.log.Error("boot: persisting interrupted build failure", "beam", beam.ID, "err", err)
				continue
			}
			o.log.Warn("boot: build was interrupted by the restart; beam moved to failed — redeploy it", "beam", beam.ID, "slug", beam.Slug)
		}
	}
	routes, err := o.st.ActiveRoutes(ctx)
	if err != nil {
		return err
	}
	for _, rt := range routes {
		kind := gateway.Preview
		if rt.Kind == domain.RouteLive {
			kind = gateway.Live
		}
		if err := o.gw.Upsert(ctx, gateway.Route{Hostname: rt.Hostname, BackendAddr: rt.BackendAddr, Kind: kind}); err != nil {
			return fmt.Errorf("restore route %s: %w", rt.Hostname, err)
		}
	}
	// Push the rendered config even when there are zero beam routes, so static
	// routes (the bundled IdP) and the listeners are materialized at boot —
	// otherwise the IdP and Admin console stay unreachable until the first deploy.
	if err := o.gw.Apply(ctx); err != nil {
		return fmt.Errorf("apply gateway config at boot: %w", err)
	}
	o.log.Info("boot: routes restored", "count", len(routes))
	return nil
}
