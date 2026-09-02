// Agent-facing app tools (PLAN §5.15, stage 2): a beam may expose its own
// tools by serving the apptools contract on its origin; the backplane brokers
// every call and delivers the caller's identity as a short-lived signed
// assertion — the user's IdP token is never forwarded, and the agent never
// reaches the beam directly. The user path (UseApp) is audience-driven like
// discovery; the builder path (TryBeamTool) is membership-driven through the
// PEP and targets the preview channel, so tools are testable before IT
// promotes and publishes.
package orch

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"golang.org/x/time/rate"

	"github.com/Beamhall/beamhall/internal/apptools"
	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/driver"
	"github.com/Beamhall/beamhall/internal/policy"
)

// ErrAppNotLive reports a published app whose live channel does not exist yet
// — users can only reach production.
var ErrAppNotLive = errors.New("the app is not live yet")

// ErrAppNoTools re-exports the contract sentinel for callers of UseApp.
var ErrAppNoTools = apptools.ErrNoAgentTools

// AppToolError is a non-2xx answer from the app's own tool handler, with the
// app-authored body already scrubbed and bounded.
type AppToolError struct {
	Status int
	Body   string
}

func (e *AppToolError) Error() string {
	return fmt.Sprintf("the app answered HTTP %d", e.Status)
}

// AppToolsConfig bounds the user-tier invocation rate per identity.
// RatePerMinute <= 0 disables the limiter.
type AppToolsConfig struct {
	RatePerMinute int
	Burst         int
}

// WithAppTools wires the assertion signer and the broker HTTP client. Without
// this option the binding, the probe, and both invocation paths are inert —
// unit-test worlds construct the orchestrator bare and must not dial anything.
func WithAppTools(signer *apptools.Signer, client *apptools.Client, cfg AppToolsConfig) Option {
	return func(o *Orchestrator) {
		o.appSigner = signer
		o.appClient = client
		o.appToolsCfg = cfg
	}
}

// UseAppRequest is the user-tier invocation: empty Tool means "show me the
// app's tool menu".
type UseAppRequest struct {
	App       string
	Workspace string
	Tool      string
	Arguments []byte
}

// UseAppResult carries either the menu (menu fetch) or the app's scrubbed
// response (invocation).
type UseAppResult struct {
	View   AppView
	Menu   *apptools.Manifest
	Result []byte
}

// UseApp brokers one user-tier call into a published, live app. Access is
// pure audience (no membership, no IT bypass); refusals for apps outside the
// caller's published set are the uniform ErrAppNotPublished. Unlike the
// discovery reads, every resolved call is audited — this is a write-shaped
// action performed on the user's behalf.
func (o *Orchestrator) UseApp(ctx context.Context, actor Actor, req UseAppRequest) (UseAppResult, error) {
	if o.appSigner == nil || o.appClient == nil {
		return UseAppResult{}, errors.New("app tools are not enabled on this appliance")
	}
	// The limiter runs before anything else and its refusals are deliberately
	// NOT audited: it exists to bound per-call audit growth, and an event per
	// rejected attempt would hand a flood exactly that growth.
	if !o.useAppAllow(actor.ID) {
		return UseAppResult{}, fmt.Errorf("you are calling apps faster than this appliance allows (max %d calls per minute) — retry in a moment", o.appToolsCfg.RatePerMinute)
	}
	res, hallID, beamID, opErr := o.useApp(ctx, actor, req)

	ev := domain.AuditEvent{
		ActorID:       actor.ID,
		ActorTokenJTI: actor.TokenJTI,
		BeamhallID:    hallID,
		BeamID:        beamID,
		Action:        "use_app",
		Decision:      domain.DecisionAllow,
		RequestDigest: useAppDigest(req),
		ResultStatus:  "ok",
		SourceIP:      actor.SourceIP,
	}
	if opErr != nil {
		ev.Reason = opErr.Error()
		var amb *AmbiguousAppError
		var ate *AppToolError
		switch {
		case errors.Is(opErr, ErrAppNotPublished), errors.Is(opErr, ErrAppNotLive),
			errors.Is(opErr, ErrAppNoTools), errors.As(opErr, &amb):
			ev.Decision = domain.DecisionDeny
			ev.ResultStatus = "denied"
		case errors.As(opErr, &ate):
			// The app itself refused or failed — the brokered call happened.
			ev.ResultStatus = "failed"
		default:
			ev.ResultStatus = "failed"
		}
	}
	if _, err := o.alog.Append(ctx, &ev); err != nil {
		o.log.Error("audit use_app append failed", "beam", beamID, "err", err)
		if opErr == nil {
			return res, fmt.Errorf("the call succeeded but could NOT be recorded on the audit chain: %w — investigate the audit store before continuing", err)
		}
	}
	return res, opErr
}

func useAppDigest(req UseAppRequest) string {
	if req.Tool == "" {
		return "menu"
	}
	return fmt.Sprintf("tool=%s args_sha256=%x", req.Tool, sha256.Sum256(req.Arguments))
}

func (o *Orchestrator) useApp(ctx context.Context, actor Actor, req UseAppRequest) (UseAppResult, domain.ID, domain.ID, error) {
	pub, view, err := o.resolvePublishedApp(ctx, actor, req.App, req.Workspace)
	if err != nil {
		return UseAppResult{}, "", "", err
	}
	hallID, beamID := pub.BeamhallID, pub.BeamID
	if !view.Live {
		return UseAppResult{}, hallID, beamID, ErrAppNotLive
	}
	beam, err := o.st.GetBeam(ctx, beamID)
	if err != nil {
		return UseAppResult{}, hallID, beamID, err
	}
	addr, err := o.resolveLiveBackend(ctx, beam, view.Workspace)
	if err != nil {
		return UseAppResult{}, hallID, beamID, err
	}
	res, err := o.callAppTool(ctx, actor, apptools.CallerUser, hallID, beamID, addr, "live", req.Tool, req.Arguments)
	res.View = view
	return res, hallID, beamID, err
}

// TryBeamTool is the builder-side twin of UseApp: exercise a beam's tool
// surface on the PREVIEW channel before IT promotes and publishes it.
func (o *Orchestrator) TryBeamTool(ctx context.Context, actor Actor, beamhallID, beamID domain.ID, tool string, args []byte) (UseAppResult, error) {
	if err := o.authorize(ctx, actor, policy.ActionUseBeamTools, beamhallID, beamID); err != nil {
		return UseAppResult{}, err
	}
	res, opErr := o.tryBeamTool(ctx, actor, beamhallID, beamID, tool, args)
	return res, o.outcome(ctx, actor, policy.ActionUseBeamTools, beamhallID, beamID, opErr)
}

func (o *Orchestrator) tryBeamTool(ctx context.Context, actor Actor, beamhallID, beamID domain.ID, tool string, args []byte) (UseAppResult, error) {
	if o.appSigner == nil || o.appClient == nil {
		return UseAppResult{}, errors.New("app tools are not enabled on this appliance")
	}
	beam, err := o.operableBeam(ctx, beamhallID, beamID)
	if err != nil {
		return UseAppResult{}, err
	}
	if beam.CurrentReleaseID == "" {
		return UseAppResult{}, fmt.Errorf("no preview is running — deploy_beam first, then retry")
	}
	rel, err := o.st.GetRelease(ctx, beam.CurrentReleaseID)
	if err != nil {
		return UseAppResult{}, err
	}
	st, err := o.drv.Status(ctx, handleOf(rel))
	if err != nil {
		return UseAppResult{}, fmt.Errorf("the preview workload is not reachable: %w", err)
	}
	switch {
	case st.State == driver.WorkloadPaused:
		return UseAppResult{}, fmt.Errorf("the preview is paused — resume_preview first, then retry")
	case st.State != driver.WorkloadRunning || st.BackendAddr == "":
		return UseAppResult{}, fmt.Errorf("the preview is not running (state %s) — deploy_beam to bring it up", st.State)
	}
	return o.callAppTool(ctx, actor, apptools.CallerUser, beamhallID, beamID, st.BackendAddr, "preview", tool, args)
}

// callAppTool mints the assertion, performs the brokered request, and scrubs
// everything app-authored before it leaves the process.
func (o *Orchestrator) callAppTool(ctx context.Context, actor Actor, callerType string, beamhallID, beamID domain.ID,
	addr, channel, tool string, args []byte) (UseAppResult, error) {
	assertion, err := o.appSigner.Mint(apptools.Assertion{
		Subject:    string(actor.ID),
		CallerType: callerType,
		Email:      actor.Email,
		Groups:     actor.Groups,
		Audience:   string(beamID),
		Channel:    channel,
		Tool:       tool,
	})
	if err != nil {
		return UseAppResult{}, fmt.Errorf("mint assertion: %w", err)
	}
	scrub, err := o.vault.ScrubberFor(ctx, beamhallID, beamID)
	if err != nil {
		return UseAppResult{}, err
	}
	if tool == "" {
		m, err := o.appClient.FetchManifest(ctx, addr, assertion)
		if err != nil {
			return UseAppResult{}, err
		}
		for i := range m.Tools {
			m.Tools[i].Description = string(scrub.Scrub([]byte(m.Tools[i].Description)))
		}
		return UseAppResult{Menu: &m}, nil
	}
	out, err := o.appClient.Invoke(ctx, addr, tool, assertion, args)
	if err != nil {
		var ie *apptools.InvokeError
		if errors.As(err, &ie) {
			return UseAppResult{}, &AppToolError{Status: ie.Status, Body: string(scrub.Scrub(ie.Body))}
		}
		return UseAppResult{}, err
	}
	return UseAppResult{Result: scrub.Scrub(out)}, nil
}

// resolveLiveBackend finds the live workload's bridge address. The active
// live route row is the primary source: during a promote the route already
// points at the new workload while beam.LiveReleaseID still names the retired
// one. The driver is the fallback (it survives lost route rows and reports
// actual run state). Never takes the beam lock — it spans entire builds, and
// a user relay must not queue behind one; the brief swap window is covered by
// one bounded retry.
func (o *Orchestrator) resolveLiveBackend(ctx context.Context, beam domain.Beam, hallSlug string) (string, error) {
	host := o.liveHost(beam.Slug, hallSlug)
	for attempt := 0; ; attempt++ {
		route, err := o.st.GetActiveRouteByHostname(ctx, host)
		if err == nil && route.BackendAddr != "" {
			return route.BackendAddr, nil
		}
		if beam.CurrentReleaseID != "" || beam.LiveReleaseID != "" {
			if rel, rerr := o.st.GetRelease(ctx, beam.LiveReleaseID); rerr == nil && rel.Workload.Ref != "" {
				if st, serr := o.drv.Status(ctx, handleOf(rel)); serr == nil &&
					st.State == driver.WorkloadRunning && st.BackendAddr != "" {
					return st.BackendAddr, nil
				}
			}
		}
		if attempt >= 1 {
			return "", fmt.Errorf("the app is not reachable right now — retry in a moment")
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (o *Orchestrator) useAppAllow(id domain.ID) bool {
	if o.appToolsCfg.RatePerMinute <= 0 {
		return true
	}
	o.useLimMu.Lock()
	defer o.useLimMu.Unlock()
	if o.useLimiters == nil {
		o.useLimiters = make(map[domain.ID]*rate.Limiter)
	}
	lim, ok := o.useLimiters[id]
	if !ok {
		burst := o.appToolsCfg.Burst
		if burst <= 0 {
			burst = 1
		}
		lim = rate.NewLimiter(rate.Limit(float64(o.appToolsCfg.RatePerMinute)/60.0), burst)
		o.useLimiters[id] = lim
	}
	return lim.Allow()
}

// assertionBinding mounts the per-beam verification material every workload
// gets — issuer, expected audience, and the public JWKS. Public data on the
// brandingBinding contract: never fails a deploy.
func (o *Orchestrator) assertionBinding(beamID domain.ID) []driver.ResourceBinding {
	if o.appSigner == nil {
		return nil
	}
	return []driver.ResourceBinding{{
		Alias:     "assertion.json",
		MountPath: apptools.MountPath,
		Value:     o.appSigner.BindingJSON(string(beamID)),
	}}
}

// probeAgentTools asks a just-started workload whether it serves the app-tools
// contract and records the answer on its release, where describe_app reads it.
// Advisory: a miss only costs the capability flag — use_app fetches the menu
// live — so failures never block a bring-up.
func (o *Orchestrator) probeAgentTools(ctx context.Context, beamID, releaseID domain.ID, backendAddr string) {
	if o.appSigner == nil || o.appClient == nil || backendAddr == "" {
		return
	}
	rel, err := o.st.GetRelease(ctx, releaseID)
	if err != nil {
		return
	}
	channel := string(rel.Channel)
	if channel == "" {
		channel = string(domain.ChannelPreview)
	}
	assertion, err := o.appSigner.Mint(apptools.Assertion{
		Subject:    apptools.ProbeSubject,
		CallerType: apptools.CallerProbe,
		Audience:   string(beamID),
		Channel:    channel,
	})
	if err != nil {
		return
	}
	if _, err := o.appClient.FetchManifest(ctx, backendAddr, assertion); err != nil {
		if !errors.Is(err, apptools.ErrNoAgentTools) {
			o.log.Debug("agent-tools probe inconclusive", "beam", beamID, "err", err)
		}
		return
	}
	if err := o.st.SetReleaseAgentTools(ctx, releaseID, true); err != nil {
		o.log.Warn("agent-tools flag not persisted", "release", releaseID, "err", err)
	}
}

// BeamUpdate is the builder-side catalog edit: nil fields stay unchanged.
type BeamUpdate struct {
	Description *string
	DisplayName *string
}

// UpdateBeam changes a beam's catalog copy (description, display name) after
// creation — the builder-side counterpart of the description IT may set when
// publishing.
func (o *Orchestrator) UpdateBeam(ctx context.Context, actor Actor, beamhallID, beamID domain.ID, upd BeamUpdate) (*domain.Beam, error) {
	if err := o.authorize(ctx, actor, policy.ActionUpdateBeam, beamhallID, beamID); err != nil {
		return nil, err
	}
	beam, opErr := o.updateBeam(ctx, beamhallID, beamID, upd)
	return beam, o.outcome(ctx, actor, policy.ActionUpdateBeam, beamhallID, beamID, opErr)
}

func (o *Orchestrator) updateBeam(ctx context.Context, beamhallID, beamID domain.ID, upd BeamUpdate) (*domain.Beam, error) {
	beam, err := o.operableBeam(ctx, beamhallID, beamID)
	if err != nil {
		return nil, err
	}
	if upd.Description == nil && upd.DisplayName == nil {
		return nil, fmt.Errorf("nothing to change — pass description and/or display_name")
	}
	if upd.Description != nil {
		beam.Description = *upd.Description
	}
	if upd.DisplayName != nil {
		if *upd.DisplayName == "" {
			return nil, fmt.Errorf("display_name cannot be empty (omit it to keep the current one)")
		}
		beam.DisplayName = *upd.DisplayName
	}
	if err := o.st.UpdateBeam(ctx, &beam); err != nil {
		return nil, err
	}
	return &beam, nil
}
