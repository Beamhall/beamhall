package orch

import (
	"context"
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
// but attributed to the system actor and the pause_timer event.
func (o *Orchestrator) PauseFunc() scheduler.PauseFunc {
	return func(ctx context.Context, beamID string) error {
		return o.pause(ctx, domain.ID(beamID), domain.EvPauseTimer)
	}
}

// PausePreview is the operator/agent-requested pause (pause_preview tool).
func (o *Orchestrator) PausePreview(ctx context.Context, actor Actor, beamhallID, beamID domain.ID) error {
	if err := o.authorize(ctx, actor, policy.ActionPausePreview, beamhallID, beamID); err != nil {
		return err
	}
	err := o.pause(ctx, beamID, domain.EvPausePreview)
	if err == nil {
		err = o.sched.Disarm(ctx, string(beamID))
	}
	return o.outcome(ctx, actor, policy.ActionPausePreview, beamhallID, beamID, err)
}

// pause freezes the workload and retires the preview route — a paused
// preview's URL is gone; resume mints a fresh one (PLAN §5.6).
func (o *Orchestrator) pause(ctx context.Context, beamID domain.ID, ev domain.Event) error {
	beam, err := o.st.GetBeam(ctx, beamID)
	if err != nil {
		return err
	}
	if beam.Status == domain.BeamArchived {
		return fmt.Errorf("beam %s has been destroyed", beamID)
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
	return o.st.UpdateBeam(ctx, &beam)
}

// ResumePreview thaws a paused preview, mints a NEW random URL, and re-arms
// the auto-pause window from now.
func (o *Orchestrator) ResumePreview(ctx context.Context, actor Actor, beamhallID, beamID domain.ID) (hostname string, err error) {
	if err := o.authorize(ctx, actor, policy.ActionResumePreview, beamhallID, beamID); err != nil {
		return "", err
	}
	hostname, err = o.resume(ctx, beamID)
	return hostname, o.outcome(ctx, actor, policy.ActionResumePreview, beamhallID, beamID, err)
}

func (o *Orchestrator) resume(ctx context.Context, beamID domain.ID) (string, error) {
	beam, err := o.st.GetBeam(ctx, beamID)
	if err != nil {
		return "", err
	}
	if beam.Status == domain.BeamArchived {
		return "", fmt.Errorf("beam %s has been destroyed", beamID)
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
	return hostname, o.st.UpdateBeam(ctx, &beam)
}

// PromoteToLive consumes a live slot (transactionally — no concurrent-promote
// race) and swaps the random preview URL for the stable live hostname. The
// PEP gates who may call this; builders get the demo's 403.
func (o *Orchestrator) PromoteToLive(ctx context.Context, actor Actor, beamhallID, beamID domain.ID) (hostname string, err error) {
	if err := o.authorize(ctx, actor, policy.ActionPromoteToLive, beamhallID, beamID); err != nil {
		return "", err
	}
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
	beam, err := o.st.GetBeam(ctx, beamID)
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
