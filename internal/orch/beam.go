package orch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/Beamhall/beamhall/internal/build"
	"github.com/Beamhall/beamhall/internal/diagnose"
	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/driver"
	"github.com/Beamhall/beamhall/internal/gateway"
	"github.com/Beamhall/beamhall/internal/policy"
	"github.com/Beamhall/beamhall/internal/store"
)

// CreateBeam registers a new Beam in a Beamhall (no workload yet). The slug
// must be DNS-safe — it becomes the live subdomain.
func (o *Orchestrator) CreateBeam(ctx context.Context, actor Actor, beamhallID domain.ID,
	slug, displayName, description, runtimeHint string) (*domain.Beam, error) {
	if err := o.authorize(ctx, actor, policy.ActionCreateBeam, beamhallID, ""); err != nil {
		return nil, err
	}
	op := func() (*domain.Beam, error) {
		if !slugRe.MatchString(slug) {
			return nil, fmt.Errorf("invalid slug %q: lowercase letters, digits, and inner hyphens only (max 32)", slug)
		}
		bh, err := o.st.GetBeamhall(ctx, beamhallID)
		if err != nil {
			return nil, err
		}
		if err := o.pep.CheckBeamQuota(ctx, bh); err != nil {
			return nil, err
		}
		beam := &domain.Beam{
			BeamhallID:        beamhallID,
			Slug:              slug,
			DisplayName:       displayName,
			Description:       description,
			RuntimeHint:       runtimeHint,
			Mode:              domain.ModePreview,
			State:             domain.StateCreated,
			SecurityTemplate:  domain.TemplateWebApp,
			PreviewPauseAfter: o.defaultPauseAfter,
			CreatedBy:         actor.ID,
		}
		// Atomic count+insert (not a separate CheckBeamQuota-then-CreateBeam):
		// two concurrent create_beam calls could otherwise each pass the
		// pre-check above and together exceed max_beams.
		if err := o.st.CreateBeamWithQuota(ctx, beam, bh.Quota.MaxBeams); err != nil {
			if errors.Is(err, store.ErrQuota) {
				// The pre-check above passed but a concurrent create_beam won
				// the race — surface the same friendly QuotaError shape it
				// would have produced had it run after the race instead of
				// before.
				if qerr := o.pep.CheckBeamQuota(ctx, bh); qerr != nil {
					return nil, qerr
				}
			}
			return nil, err
		}
		return beam, nil
	}
	beam, err := op()
	var beamID domain.ID
	if beam != nil {
		beamID = beam.ID
	}
	return beam, o.outcome(ctx, actor, policy.ActionCreateBeam, beamhallID, beamID, err)
}

// SetSecret writes a secret value through the vault (write-only; PLAN §6).
// The audit trail records the key, never the value.
func (o *Orchestrator) SetSecret(ctx context.Context, actor Actor, beamhallID, beamID domain.ID,
	key string, value []byte) error {
	if err := o.authorize(ctx, actor, policy.ActionSetSecret, beamhallID, beamID); err != nil {
		return err
	}
	err := validateSecretKey(key)
	// A beam-scoped secret must target a live beam in the authorized hall —
	// without this, a raw-ID caller could hang secrets on a foreign or
	// archived beam's scope. Beamhall-wide secrets (no beam) skip it.
	if err == nil && beamID != "" {
		_, err = o.operableBeam(ctx, beamhallID, beamID)
	}
	if err == nil {
		_, err = o.vault.Set(ctx, domain.SecretRef{BeamhallID: beamhallID, BeamID: beamID, Key: key}, value, actor.ID)
	}
	return o.outcome(ctx, actor, policy.ActionSetSecret, beamhallID, beamID, err)
}

// secretKeyRe bounds caller-supplied secret keys. The key becomes both a host
// staging filename and, unsanitized, the container-side bind target
// /run/secrets/<key> — path separators or dot-segments in it would relocate a
// read-only mount anywhere in the workload rootfs, and two keys that sanitize
// to the same staged filename would silently serve one secret under the
// other's name. A conservative charset closes both.
var secretKeyRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

func validateSecretKey(key string) error {
	if !secretKeyRe.MatchString(key) {
		return fmt.Errorf("invalid secret key %q: use 1-64 letters, digits, or underscores (the key becomes the file name /run/secrets/<key>)", key)
	}
	return nil
}

// DeployRequest is a stage-2 deploy input: a pinned, pre-built image. The
// managed-git + pack build pipeline replaces this with source-driven builds
// without changing the lifecycle.
type DeployRequest struct {
	ImageRef    string // human ref, e.g. registry/beam:tag
	ImageDigest string // immutable pin, sha256:...
}

// buildStep produces the Build row and the image reference the runtime
// daemon deploys. It runs after the Beam enters building; an error lands the
// Beam in failed via EvBuildFail.
type buildStep func(ctx context.Context, beam *domain.Beam, bh domain.Beamhall) (*domain.Build, string, error)

// DeployBeam runs the deploy lifecycle from a pre-built pinned image:
// building → deployed → running, with a fresh Release, vault-injected
// secrets, a gateway route, and (for previews) the armed auto-pause timer. On
// failure the Beam lands in failed with the reason in the audit outcome.
func (o *Orchestrator) DeployBeam(ctx context.Context, actor Actor, beamhallID, beamID domain.ID,
	req DeployRequest) (*domain.Beam, error) {
	if err := o.authorize(ctx, actor, policy.ActionDeployBeam, beamhallID, beamID); err != nil {
		return nil, err
	}
	beam, err := o.deploy(ctx, beamhallID, beamID, func(ctx context.Context, beam *domain.Beam, bh domain.Beamhall) (*domain.Build, string, error) {
		if req.ImageDigest == "" {
			return nil, "", fmt.Errorf("deploy needs a pinned image digest or a source build (DeployBeamFromSource)")
		}
		return &domain.Build{
			BeamID:      beam.ID,
			SourceKind:  domain.SourceImageRef,
			Status:      domain.BuildSucceeded,
			ImageRef:    req.ImageRef,
			ImageDigest: req.ImageDigest,
			TriggeredBy: actor.ID,
		}, req.ImageDigest, nil
	})
	return beam, o.outcome(ctx, actor, policy.ActionDeployBeam, beamhallID, beamID, err)
}

// DeployBeamFromSource converges srcDir into the beam's managed repo, builds
// it via the configured build pipeline (pack in the separate build context →
// internal registry), and deploys the pinned result. This is the path the
// git-push post-receive hook and the MCP source_tarball fallback both call
// once their transports land (item 5).
func (o *Orchestrator) DeployBeamFromSource(ctx context.Context, actor Actor, beamhallID, beamID domain.ID,
	srcDir string) (*domain.Beam, error) {
	if err := o.authorize(ctx, actor, policy.ActionDeployBeam, beamhallID, beamID); err != nil {
		return nil, err
	}
	beam, err := o.deploy(ctx, beamhallID, beamID, func(ctx context.Context, beam *domain.Beam, bh domain.Beamhall) (*domain.Build, string, error) {
		if o.builder == nil {
			return nil, "", fmt.Errorf("no build pipeline configured on this backplane")
		}
		release, err := o.acquireBuildSlot()
		if err != nil {
			return nil, "", err
		}
		defer release()
		res, err := o.scrubbedBuild(ctx, beamhallID, beamID, func(ctx context.Context) (build.Result, error) {
			return o.builder.BuildFromDir(ctx, bh.Slug, beam.Slug, srcDir)
		})
		if err != nil {
			return nil, "", err
		}
		return &domain.Build{
			BeamID:      beam.ID,
			SourceRef:   res.SourceSHA,
			SourceKind:  domain.SourceManagedGit,
			Builder:     res.Builder,
			Status:      domain.BuildSucceeded,
			ImageRef:    res.ImageRef,
			ImageDigest: res.ImageDigest,
			TriggeredBy: actor.ID,
		}, res.PullRef, nil
	})
	return beam, o.outcome(ctx, actor, policy.ActionDeployBeam, beamhallID, beamID, err)
}

// DeployBeamFromGit deploys a commit the agent pushed to the beam's managed
// repo (the git smart-HTTP transport, PLAN §5.5). The commit is already in
// the repo; this builds and deploys it. Same PEP action and lifecycle as the
// tarball path — only the source ingress differs.
func (o *Orchestrator) DeployBeamFromGit(ctx context.Context, actor Actor, beamhallID, beamID domain.ID,
	sha string) (*domain.Beam, error) {
	if err := o.authorize(ctx, actor, policy.ActionDeployBeam, beamhallID, beamID); err != nil {
		return nil, err
	}
	beam, err := o.deploy(ctx, beamhallID, beamID, func(ctx context.Context, beam *domain.Beam, bh domain.Beamhall) (*domain.Build, string, error) {
		if o.builder == nil {
			return nil, "", fmt.Errorf("no build pipeline configured on this backplane")
		}
		release, err := o.acquireBuildSlot()
		if err != nil {
			return nil, "", err
		}
		defer release()
		res, err := o.scrubbedBuild(ctx, beamhallID, beamID, func(ctx context.Context) (build.Result, error) {
			return o.builder.BuildFromCommit(ctx, bh.Slug, beam.Slug, sha)
		})
		if err != nil {
			return nil, "", err
		}
		return &domain.Build{
			BeamID:      beam.ID,
			SourceRef:   res.SourceSHA,
			SourceKind:  domain.SourceManagedGit,
			Builder:     res.Builder,
			Status:      domain.BuildSucceeded,
			ImageRef:    res.ImageRef,
			ImageDigest: res.ImageDigest,
			TriggeredBy: actor.ID,
		}, res.PullRef, nil
	})
	return beam, o.outcome(ctx, actor, policy.ActionDeployBeam, beamhallID, beamID, err)
}

// scrubbedBuild runs a source build with the beam's secret scrubber over both
// the live progress stream (MCP notifications, the git push sideband) and the
// returned error (whose diagnosis tail also lands in the audit outcome
// Reason): pack echoes the app's own files and config, so a value the builder
// both vaulted and hardcoded must not transit any of those unredacted. Same
// fail-closed posture as crash-log tails: no scrubber, no build output.
func (o *Orchestrator) scrubbedBuild(ctx context.Context, beamhallID, beamID domain.ID,
	run func(ctx context.Context) (build.Result, error)) (build.Result, error) {
	scrub, err := o.vault.ScrubberFor(ctx, beamhallID, beamID)
	if err != nil {
		return build.Result{}, fmt.Errorf("build refused: cannot construct the log scrubber: %w", err)
	}
	if w := build.ProgressWriter(ctx); w != nil {
		sw := scrub.Writer(w)
		defer sw.Flush()
		ctx = build.WithProgress(ctx, sw)
	}
	res, err := run(ctx)
	if err != nil {
		return res, errors.New(scrub.ScrubString(err.Error()))
	}
	return res, nil
}

func (o *Orchestrator) deploy(ctx context.Context, beamhallID, beamID domain.ID, step buildStep) (*domain.Beam, error) {
	// Serialize against any other deploy/promote/rollback/destroy on this beam:
	// without this, a concurrent destroy can archive the beam and reclaim
	// its resources while a slow build is still in flight, and the deploy's
	// stale in-memory copy then overwrites Status back to "active" on finalize.
	unlock := o.beamLocks.lock(beamID)
	defer unlock()

	beam, err := o.operableBeam(ctx, beamhallID, beamID)
	if err != nil {
		return nil, err
	}
	bh, err := o.st.GetBeamhall(ctx, beamhallID)
	if err != nil {
		return nil, err
	}
	sc, err := o.st.GetSecurityContext(ctx, beamhallID)
	if err != nil {
		return nil, err
	}

	prevRelease := beam.CurrentReleaseID

	// created/running/... → building.
	if err := beam.Apply(domain.EvDeploy); err != nil {
		return nil, err
	}
	if err := o.st.UpdateBeam(ctx, &beam); err != nil {
		return nil, err
	}

	// Produce the image: either the caller's pinned digest or a real pipeline
	// build (snapshot → pack → registry). pullRef is what the runtime daemon
	// deploys — for pipeline builds, registry/<repo>@sha256:... .
	build, pullRef, err := step(ctx, &beam, bh)
	if err != nil {
		return nil, o.failBeam(ctx, &beam, domain.EvBuildFail, err)
	}
	if err := o.st.CreateBuild(ctx, build); err != nil {
		return nil, o.failBeam(ctx, &beam, domain.EvBuildFail, err)
	}

	// Snapshot the preview channel's secret scope (beam's own + beamhall-wide
	// keys) into the Release, then mint it. Deploy always targets preview;
	// promote pins the result to the live channel.
	refs, err := o.secretRefs(ctx, beamhallID, beam.ID, domain.ChannelPreview)
	if err != nil {
		return nil, o.failBeam(ctx, &beam, domain.EvBuildFail, err)
	}
	rel := &domain.Release{
		BeamID:              beam.ID,
		BuildID:             build.ID,
		Channel:             domain.ChannelPreview,
		ConfigSnapshot:      map[string]string{"port": fmt.Sprint(o.beamPort), "pull_ref": pullRef},
		SecretRefs:          refs,
		SecurityProfileSnap: sc,
		Status:              domain.ReleasePending,
	}
	if err := o.st.CreateRelease(ctx, rel); err != nil {
		return nil, o.failBeam(ctx, &beam, domain.EvBuildFail, err)
	}
	if err := beam.Apply(domain.EvBuildOK); err != nil {
		return nil, err
	}
	beam.DesiredReleaseID = rel.ID
	if err := o.st.UpdateBeam(ctx, &beam); err != nil {
		return nil, err
	}

	// Decrypt secrets backplane-side and bring the workload up under the
	// Beamhall's profile.
	status, err := o.spawnWorkload(ctx, beamhallID, beam.ID, rel.ID, bh, sc, refs, pullRef)
	if err != nil {
		return nil, o.failBeam(ctx, &beam, domain.EvStartFail, err)
	}

	// Running: activate the release, retire the predecessor, route, arm.
	if err := beam.Apply(domain.EvStartOK); err != nil {
		return nil, err
	}
	if err := o.st.ActivateRelease(ctx, rel.ID); err != nil {
		return nil, err
	}
	// Point the beam at the new release BEFORE retiring the predecessor, and
	// persist it immediately: if anything after this fails (route mint,
	// pause-arm, or another store write inside finalizeActiveRelease), the
	// beam still correctly points at the running, active release rather than
	// a now-destroyed one.
	// finalizeActiveRelease sets the same field again (harmless) alongside
	// PreviewHost/DesiredReleaseID/ResumedAt once those are known.
	beam.CurrentReleaseID = rel.ID
	if err := o.st.UpdateBeam(ctx, &beam); err != nil {
		return nil, err
	}
	if prevRelease != "" {
		if err := o.retireRelease(ctx, prevRelease, domain.ReleaseSuperseded); err != nil {
			o.log.Warn("retiring previous release failed", "release", prevRelease, "err", err)
		}
	}

	hostname, err := o.finalizeActiveRelease(ctx, &beam, bh, rel.ID, status.BackendAddr)
	if err != nil {
		return nil, err
	}
	o.log.Info("beam deployed", "beam", beam.ID, "release", rel.ID, "route", hostname)
	return &beam, nil
}

// spawnWorkload runs the security-critical bring-up shared by deploy and
// rollback: inject secrets, create the container under the Beamhall's
// hardening profile, assert egress (fail-closed: no policy, no beam), persist
// the workload handle, start, and confirm the workload survives startup. The
// caller owns FSM state, the route, and the pause timer.
func (o *Orchestrator) spawnWorkload(ctx context.Context, beamhallID, beamID, releaseID domain.ID,
	bh domain.Beamhall, sc domain.SecurityContext, refs []domain.SecretRef, pullRef string) (driver.Status, error) {
	mounts, err := o.vault.Inject(ctx, refs)
	if err != nil {
		return driver.Status{}, err
	}
	h, err := o.drv.Deploy(ctx, driver.DeploySpec{
		BeamID:      string(beamID),
		BeamhallID:  string(beamhallID),
		ImageDigest: pullRef,
		Network: driver.NetworkPolicy{
			BeamhallNetwork: networkName(beamhallID),
			EgressDenyAll:   bh.NetworkPolicy.EgressMode == domain.EgressDenyAll,
			EgressAllowlist: bh.NetworkPolicy.EgressAllowlist,
		},
		Security:  profileOf(sc),
		Resources: limitsOf(sc),
		Secrets:   mounts,
		Bindings:  o.brandingBinding(ctx, bh),
		Port:      o.beamPort,
	})
	if err != nil {
		return driver.Status{}, err
	}
	// From here on a container exists, with its secrets already staged — any
	// early return below must tear it down, or a failed bring-up (egress
	// assert, store write, start failure, crash-on-boot, or the caller's own
	// ctx being cancelled mid-poll in awaitStartup) leaks it and its staged
	// secret files with nothing left referencing them to ever clean up.
	// Uses a fresh background context with its own timeout: the triggering
	// ctx may itself be the thing that got cancelled.
	needsCleanup := true
	defer func() {
		if !needsCleanup {
			return
		}
		cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := o.drv.Stop(cctx, h, 0); err != nil {
			o.log.Warn("cleanup: stop workload after failed bring-up", "ref", h.Ref, "err", err)
		}
		if err := o.drv.Destroy(cctx, h); err != nil {
			o.log.Warn("cleanup: destroy workload after failed bring-up", "ref", h.Ref, "err", err)
		}
	}()
	// The per-Beamhall bridge now exists — assert its egress policy BEFORE
	// the workload starts (fail-closed).
	if o.egressSync != nil {
		if err := o.egressSync(ctx); err != nil {
			return driver.Status{}, fmt.Errorf("egress policy could not be asserted for this beamhall's network: %w", err)
		}
	}
	if err := o.st.SetReleaseWorkload(ctx, releaseID, domain.WorkloadHandle{Driver: h.DriverName, Ref: h.Ref}); err != nil {
		return driver.Status{}, err
	}
	if err := o.drv.Start(ctx, h); err != nil {
		return driver.Status{}, err
	}
	status, err := o.awaitStartup(ctx, beamhallID, beamID, h)
	if err != nil {
		return driver.Status{}, err
	}
	needsCleanup = false
	return status, nil
}

// finalizeActiveRelease mints the preview channel's route, points the Beam at
// the new active preview release, and arms the auto-pause timer. Deploy targets
// the preview channel exclusively; the live channel is brought up by promote
// (see livechannel.go). Reuse the beam's stable preview host across redeploys (a
// developer iterating keeps the same URL); mint a fresh one only on the first
// deploy or after a pause cleared it. Rotation on pause->resume lives in
// resume(), not here.
func (o *Orchestrator) finalizeActiveRelease(ctx context.Context, beam *domain.Beam, bh domain.Beamhall,
	relID domain.ID, backendAddr string) (hostname string, err error) {
	hostname = beam.PreviewHost
	if hostname == "" {
		hostname = o.previewHost()
		beam.PreviewHost = hostname
	}
	if _, err := o.mintRoute(ctx, beam, relID, hostname, gateway.Preview, backendAddr); err != nil {
		return "", err
	}
	beam.CurrentReleaseID = relID
	beam.DesiredReleaseID = ""
	beam.ResumedAt = o.now()
	if err := o.sched.Arm(ctx, string(beam.ID), beam.ResumedAt.Add(o.pauseAfter(*beam))); err != nil {
		return "", err
	}
	if err := o.st.UpdateBeam(ctx, beam); err != nil {
		return "", err
	}
	// Keep the preview OIDC client's redirect allowlist current with this host
	// (no-op unless the beam has provisioned auth) — PLAN §5.10.
	o.syncAuthRedirects(ctx, beam.ID, domain.ChannelPreview, hostname)
	return hostname, nil
}

// awaitStartup verifies the workload survives its first moments instead of
// reporting success on a container that dies one second later (a dead preview
// URL with no explanation is exactly the failure mode PLAN §8 Phase 3 calls
// out). If the workload exits inside the grace window, the returned error
// carries the exit code, a scrubbed log tail, and the diagnose catalog's best
// hint — everything the agent needs to self-correct.
func (o *Orchestrator) awaitStartup(ctx context.Context, beamhallID, beamID domain.ID, h driver.Handle) (driver.Status, error) {
	deadline := time.Now().Add(o.startupGrace)
	for {
		status, err := o.drv.Status(ctx, h)
		if err != nil {
			return driver.Status{}, err
		}
		if status.State == driver.WorkloadExited {
			return driver.Status{}, errors.New(diagnose.StartFailure(status.ExitCode, o.crashLogs(ctx, beamhallID, beamID, h)))
		}
		if time.Now().After(deadline) {
			if status.State == driver.WorkloadRunning {
				return status, nil
			}
			return driver.Status{}, fmt.Errorf("workload did not reach running within the startup grace (state %q)", status.State)
		}
		select {
		case <-ctx.Done():
			return driver.Status{}, ctx.Err()
		case <-time.After(o.startupGrace / startupPolls):
		}
	}
}

// crashLogs fetches and scrubs the dead workload's last lines for the failure
// message; best-effort — diagnosis must never mask the original failure.
func (o *Orchestrator) crashLogs(ctx context.Context, beamhallID, beamID domain.ID, h driver.Handle) string {
	rc, err := o.drv.Logs(ctx, h, driver.LogOptions{TailN: 30})
	if err != nil {
		return ""
	}
	defer rc.Close()
	raw, err := io.ReadAll(io.LimitReader(rc, 16<<10))
	if err != nil || len(raw) == 0 {
		return ""
	}
	scrub, err := o.vault.ScrubberFor(ctx, beamhallID, beamID)
	if err != nil {
		return "" // no scrubber, no logs — fail closed
	}
	return string(scrub.Scrub(raw))
}

// failBeam transitions to failed (when legal), persists, and returns cause.
func (o *Orchestrator) failBeam(ctx context.Context, beam *domain.Beam, ev domain.Event, cause error) error {
	if err := beam.Apply(ev); err == nil {
		if uerr := o.st.UpdateBeam(ctx, beam); uerr != nil {
			o.log.Error("persisting failed state", "beam", beam.ID, "err", uerr)
		}
	}
	return cause
}

// retireRelease supersedes a release and tears down its workload and route.
func (o *Orchestrator) retireRelease(ctx context.Context, relID domain.ID, status domain.ReleaseStatus) error {
	rel, err := o.st.GetRelease(ctx, relID)
	if err != nil {
		return err
	}
	if err := o.st.UpdateReleaseStatus(ctx, relID, status); err != nil {
		return err
	}
	if rel.RouteID != "" {
		if rt, err := o.st.GetRoute(ctx, rel.RouteID); err == nil && rt.Status == domain.RouteActive {
			if err := o.gw.Retire(ctx, rt.Hostname); err != nil {
				return err
			}
			if err := o.st.RetireRoute(ctx, rt.ID); err != nil {
				return err
			}
		}
	}
	if rel.Workload.Ref != "" {
		h := handleOf(rel)
		if err := o.drv.Stop(ctx, h, 10*time.Second); err != nil {
			o.log.Warn("stopping superseded workload", "release", relID, "err", err)
		}
		if err := o.drv.Destroy(ctx, h); err != nil {
			return err
		}
	}
	return nil
}

// mintRoute creates and programs a route, cross-linking release ↔ route.
func (o *Orchestrator) mintRoute(ctx context.Context, beam *domain.Beam, relID domain.ID,
	hostname string, kind gateway.RouteKind, backendAddr string) (domain.ID, error) {
	rt := &domain.Route{
		BeamID:      beam.ID,
		ReleaseID:   relID,
		Kind:        domain.RouteKind(kind),
		Hostname:    hostname,
		BackendAddr: backendAddr,
		Status:      domain.RouteActive,
	}
	if err := o.st.CreateRoute(ctx, rt); err != nil {
		return "", err
	}
	if err := o.gw.Upsert(ctx, gateway.Route{Hostname: hostname, BackendAddr: backendAddr, Kind: kind}); err != nil {
		return "", err
	}
	if err := o.st.SetReleaseRoute(ctx, relID, rt.ID); err != nil {
		return "", err
	}
	return rt.ID, nil
}

// secretRefs lists the keys in scope for one channel of a beam: its own plus
// beamhall-wide. ChannelShared secrets (user- and beamhall-set) inject into both
// channels; channel-specific secrets (database DSNs) inject only into their own
// channel, so the same app key (e.g. MAIN_URL) resolves to that channel's DSN.
// Deduped by Key: every ref mounts to /run/secrets/<key> regardless of
// channel, so a shared and a channel-specific secret sharing a key would
// otherwise produce two mounts at the identical target path — Docker rejects
// that as a duplicate mount, failing every subsequent deploy with no
// delete_secret tool to recover. The
// channel-specific one wins.
func (o *Orchestrator) secretRefs(ctx context.Context, beamhallID, beamID domain.ID, ch domain.Channel) ([]domain.SecretRef, error) {
	metas, err := o.st.ListSecretsByBeamhall(ctx, beamhallID)
	if err != nil {
		return nil, err
	}
	refs := make([]domain.SecretRef, 0, len(metas))
	idxByKey := make(map[string]int, len(metas))
	for _, m := range metas {
		if m.BeamID != "" && m.BeamID != beamID {
			continue
		}
		if m.Channel != domain.ChannelShared && m.Channel != ch {
			continue
		}
		ref := domain.SecretRef{BeamhallID: m.BeamhallID, BeamID: m.BeamID, Key: m.Key, Channel: m.Channel}
		if i, ok := idxByKey[m.Key]; ok {
			if refs[i].Channel == domain.ChannelShared && ref.Channel != domain.ChannelShared {
				refs[i] = ref
			}
			continue
		}
		idxByKey[m.Key] = len(refs)
		refs = append(refs, ref)
	}
	return refs, nil
}

func (o *Orchestrator) pauseAfter(beam domain.Beam) time.Duration {
	if beam.PreviewPauseAfter > 0 {
		return beam.PreviewPauseAfter
	}
	return o.defaultPauseAfter
}

func (o *Orchestrator) now() time.Time { return time.Now().UTC() }
