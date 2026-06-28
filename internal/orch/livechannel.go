package orch

import (
	"context"
	"fmt"
	"time"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/gateway"
	"github.com/Beamhall/beamhall/internal/policy"
	"github.com/Beamhall/beamhall/internal/resource"
)

// promote pins the beam's LIVE channel to the build its PREVIEW channel is
// running right now, bringing up a separate live workload behind the stable live
// host. The preview channel is left untouched — it keeps running, iterating, and
// auto-pausing — so a builder can keep shipping new previews after going to
// production. Promote is repeatable: re-promoting an already-live beam rolls
// production forward to a newer preview build with zero downtime (the previous
// live workload serves until the new one is healthy). A failed promote never
// drops production.
//
// The live channel gets its own data: reconcileLiveResources provisions a fresh
// database per preview database, sealed under the same app key for the live
// channel, so production never reads or writes the builder's preview data.
func (o *Orchestrator) promote(ctx context.Context, actor Actor, beamhallID, beamID domain.ID) (string, error) {
	beam, err := o.operableBeam(ctx, beamhallID, beamID)
	if err != nil {
		return "", err
	}
	bh, err := o.st.GetBeamhall(ctx, beamhallID)
	if err != nil {
		return "", err
	}
	if _, ok, reason := beam.Can(domain.EvPromote); !ok {
		return "", &domain.TransitionError{From: beam.State, Mode: beam.Mode, Event: domain.EvPromote, Reason: reason}
	}

	// The build to pin: whatever the preview channel is running right now.
	previewRel, err := o.st.GetRelease(ctx, beam.CurrentReleaseID)
	if err != nil {
		return "", fmt.Errorf("promote needs a running preview release: %w", err)
	}
	pullRef := previewRel.ConfigSnapshot["pull_ref"]
	if pullRef == "" {
		return "", fmt.Errorf("preview release %s has no stored image reference; redeploy the preview first", previewRel.ID)
	}

	// First promote reserves a live slot (count-and-flip mode in one tx);
	// re-promote already holds the slot and just rolls the build forward.
	firstPromote := beam.Mode != domain.ModeLive
	if firstPromote {
		if err := o.st.PromoteBeam(ctx, beamhallID, beamID, policy.EffectiveLiveSlotLimit(bh)); err != nil {
			return "", err
		}
		beam.Mode = domain.ModeLive
	}

	if err := o.reconcileLiveResources(ctx, actor, bh, beam.Slug, beamID); err != nil {
		if firstPromote {
			o.releaseSlot(ctx, &beam)
		}
		return "", err
	}

	// Pin a new live release to the preview's build, but scope it to the live
	// channel's own secrets (its DB DSNs + shared user/beamhall secrets).
	liveRefs, err := o.secretRefs(ctx, beamhallID, beamID, domain.ChannelLive)
	if err != nil {
		if firstPromote {
			o.releaseSlot(ctx, &beam)
		}
		return "", err
	}
	rel := &domain.Release{
		BeamID:              beamID,
		BuildID:             previewRel.BuildID,
		Channel:             domain.ChannelLive,
		ConfigSnapshot:      map[string]string{"port": fmt.Sprint(o.beamPort), "pull_ref": pullRef},
		SecretRefs:          liveRefs,
		SecurityProfileSnap: previewRel.SecurityProfileSnap,
		Status:              domain.ReleasePending,
	}
	if err := o.st.CreateRelease(ctx, rel); err != nil {
		if firstPromote {
			o.releaseSlot(ctx, &beam)
		}
		return "", err
	}

	// Bring the live workload up. The previous live release (re-promote) keeps
	// serving until the new one is healthy — promote never drops production.
	status, err := o.spawnWorkload(ctx, beamhallID, beamID, rel.ID, bh, rel.SecurityProfileSnap, liveRefs, pullRef)
	if err != nil {
		_ = o.st.UpdateReleaseStatus(ctx, rel.ID, domain.ReleaseSuperseded)
		if firstPromote {
			o.releaseSlot(ctx, &beam)
			return "", fmt.Errorf("promote failed bringing up the live workload: %w", err)
		}
		return "", fmt.Errorf("promote failed bringing up the new live workload (current production left running): %w", err)
	}

	hostname, err := o.finalizeLiveRelease(ctx, &beam, bh, rel.ID, status.BackendAddr)
	if err != nil {
		return "", err
	}
	o.log.Info("beam promoted", "beam", beamID, "live_release", rel.ID, "route", hostname, "first_promote", firstPromote)
	return hostname, nil
}

// finalizeLiveRelease points the stable live host at the new live workload and
// retires the superseded one. The hostname is reused across re-promotes, so the
// gateway Upsert atomically repoints it to the new backend and production never
// loses its route. The preview channel and its pointers are not touched.
func (o *Orchestrator) finalizeLiveRelease(ctx context.Context, beam *domain.Beam, bh domain.Beamhall,
	relID domain.ID, backendAddr string) (string, error) {
	hostname := o.liveHost(beam.Slug, bh.Slug)
	prevLive := beam.LiveReleaseID

	// Free the stable hostname's active-route row before minting the new one
	// (the unique active-hostname index allows only one). We deliberately do NOT
	// gw.Retire(hostname) — mintRoute's Upsert below repoints the same hostname
	// to the new backend in one step, so there is no production gap.
	if prevLive != "" {
		if prevRel, err := o.st.GetRelease(ctx, prevLive); err == nil && prevRel.RouteID != "" {
			if rt, err := o.st.GetRoute(ctx, prevRel.RouteID); err == nil && rt.Status == domain.RouteActive {
				if err := o.st.RetireRoute(ctx, rt.ID); err != nil {
					return "", err
				}
			}
		}
	}
	if _, err := o.mintRoute(ctx, beam, relID, hostname, gateway.Live, backendAddr); err != nil {
		return "", err
	}
	if err := o.st.ActivateRelease(ctx, relID); err != nil {
		return "", err
	}

	// Now that traffic flows to the new live workload, tear the old one down.
	// Its route row is already retired (the hostname was reused), so only stop +
	// destroy the container and mark the release superseded.
	if prevLive != "" && prevLive != relID {
		if err := o.retireLiveWorkload(ctx, prevLive); err != nil {
			o.log.Warn("retiring superseded live workload", "release", prevLive, "err", err)
		}
	}

	beam.LiveReleaseID = relID
	beam.LiveState = domain.StateLive
	// Re-assert the live OIDC client's redirect to the stable production host
	// (idempotent across re-promote and rollback) — PLAN §5.10.
	o.syncAuthRedirects(ctx, beam.ID, domain.ChannelLive, hostname)
	return hostname, o.st.UpdateBeam(ctx, beam)
}

// retireLiveWorkload stops and destroys a superseded live release's workload and
// marks the release superseded. Unlike retireRelease it does not touch the route
// (the live hostname is reused by the successor and repointed via Upsert).
func (o *Orchestrator) retireLiveWorkload(ctx context.Context, relID domain.ID) error {
	rel, err := o.st.GetRelease(ctx, relID)
	if err != nil {
		return err
	}
	if err := o.st.UpdateReleaseStatus(ctx, relID, domain.ReleaseSuperseded); err != nil {
		return err
	}
	if rel.Workload.Ref != "" {
		h := handleOf(rel)
		if err := o.drv.Stop(ctx, h, 10*time.Second); err != nil {
			o.log.Warn("stopping superseded live workload", "release", relID, "err", err)
		}
		if err := o.drv.Destroy(ctx, h); err != nil {
			return err
		}
	}
	return nil
}

// releaseSlot reverts a first-promote's reserved live slot (mode back to
// preview) after a later step fails, so a failed promote does not strand a slot.
func (o *Orchestrator) releaseSlot(ctx context.Context, beam *domain.Beam) {
	beam.Mode = domain.ModePreview
	beam.LiveState = ""
	if err := o.st.UpdateBeam(ctx, beam); err != nil {
		o.log.Warn("releasing reserved live slot after failed promote", "beam", beam.ID, "err", err)
	}
}

// reconcileLiveResources gives the live channel its own database for every
// preview database the beam has, sealed under the same app key (e.g. MAIN_URL)
// but scoped to the live channel — so the same image, deployed live, connects to
// production data, never the builder's preview data. Idempotent: a live database
// that already exists for a name is left as-is (re-promote reuses it, preserving
// production data across version bumps).
func (o *Orchestrator) reconcileLiveResources(ctx context.Context, actor Actor, bh domain.Beamhall,
	beamSlug string, beamID domain.ID) error {
	// Mirror the preview OIDC client to a distinct live client (own secret, own
	// aud, stable live redirect) on first promote — PLAN §5.10. Independent of the
	// database provisioner, so it runs even on a backplane without one.
	if err := o.mirrorLiveAuthClient(ctx, actor, bh, beamSlug, beamID); err != nil {
		return err
	}
	// Mirror the preview object store to a distinct live bucket (own credentials,
	// own data) on first promote — PLAN §5.13, so production never reads or writes
	// the builder's preview objects. Independent of the database provisioner.
	if err := o.reconcileLiveObjectStore(ctx, actor, bh, beamID); err != nil {
		return err
	}
	if o.dbProv == nil {
		return nil
	}
	previewRes, err := o.st.ListResourcesByBeamAndChannel(ctx, beamID, domain.ChannelPreview)
	if err != nil {
		return err
	}
	liveRes, err := o.st.ListResourcesByBeamAndChannel(ctx, beamID, domain.ChannelLive)
	if err != nil {
		return err
	}
	have := make(map[string]bool, len(liveRes))
	for _, r := range liveRes {
		if r.Type == domain.ResourceDatabase {
			have[r.Spec["name"]] = true
		}
	}
	for _, pr := range previewRes {
		if pr.Type != domain.ResourceDatabase || have[pr.Spec["name"]] {
			continue
		}
		name := pr.Spec["name"]
		// No quota check here: the live mirror is the production counterpart of a
		// preview database that already passed the quota gate (MaxDBCount caps
		// logical databases, not their per-channel mirrors).
		provisioned, err := o.dbProv.Provision(ctx, resource.Request{
			BeamhallSlug: bh.Slug,
			BeamSlug:     beamSlug + "-live", // distinct backing database from the preview channel's
			Name:         name,
			Network:      networkName(bh.ID),
		})
		if err != nil {
			return fmt.Errorf("provision live database %q: %w", name, err)
		}
		ref := domain.SecretRef{BeamhallID: bh.ID, BeamID: beamID, Key: dbSecretKey(name), Channel: domain.ChannelLive}
		if _, err := o.vault.Set(ctx, ref, []byte(provisioned.DSN), actor.ID); err != nil {
			if derr := o.dbProv.Drop(ctx, provisioned); derr != nil {
				o.log.Error("rollback of provisioned live database failed", "db", provisioned.Database, "err", derr)
			}
			return fmt.Errorf("seal live connection secret: %w", err)
		}
		res := &domain.Resource{
			BeamhallID:          bh.ID,
			BeamID:              beamID,
			Channel:             domain.ChannelLive,
			Type:                domain.ResourceDatabase,
			Status:              domain.ResourceReady,
			ConnectionSecretRef: ref,
			Spec:                map[string]string{"name": name, "database": provisioned.Database, "role": provisioned.Role},
			BackingHandle:       provisioned.Database,
		}
		if err := o.st.CreateResource(ctx, res); err != nil {
			return err
		}
		o.log.Info("live database provisioned", "beam", beamID, "database", provisioned.Database, "name", name)
	}
	return nil
}
