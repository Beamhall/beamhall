package orch

import (
	"context"
	"fmt"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/driver"
	"github.com/Beamhall/beamhall/internal/policy"
	"github.com/Beamhall/beamhall/internal/resource"
)

// RollbackBeam re-pins the LIVE channel to a prior live Release without
// rebuilding (PLAN §5.7): it brings up a fresh production workload from that
// release's pinned image, hardening snapshot, and live secret scope, then
// retires the one it rolled back from. The new workload comes up healthy BEFORE
// the current production workload is touched, so a failed rollback leaves
// production exactly as it was. The preview channel is unaffected (to undo a
// preview change, just push again).
func (o *Orchestrator) RollbackBeam(ctx context.Context, actor Actor, beamhallID, beamID, targetReleaseID domain.ID) (hostname string, err error) {
	if err := o.authorize(ctx, actor, policy.ActionRollback, beamhallID, beamID); err != nil {
		return "", err
	}
	hostname, err = o.rollback(ctx, beamhallID, beamID, targetReleaseID)
	return hostname, o.outcome(ctx, actor, policy.ActionRollback, beamhallID, beamID, err)
}

func (o *Orchestrator) rollback(ctx context.Context, beamhallID, beamID, targetReleaseID domain.ID) (string, error) {
	beam, err := o.operableBeam(ctx, beamhallID, beamID)
	if err != nil {
		return "", err
	}
	bh, err := o.st.GetBeamhall(ctx, beamhallID)
	if err != nil {
		return "", err
	}
	if _, ok, reason := beam.Can(domain.EvRollback); !ok {
		return "", &domain.TransitionError{From: beam.State, Mode: beam.Mode, Event: domain.EvRollback, Reason: reason}
	}
	target, err := o.st.GetRelease(ctx, targetReleaseID)
	if err != nil {
		return "", err
	}
	if target.BeamID != beamID {
		return "", fmt.Errorf("release %s does not belong to beam %s", targetReleaseID, beamID)
	}
	if targetReleaseID == beam.LiveReleaseID {
		return "", fmt.Errorf("release %s is already serving production", targetReleaseID)
	}
	if targetReleaseID == beam.CurrentReleaseID {
		return "", fmt.Errorf("release %s is the preview build, not a prior production release; to roll production back, target a prior live release", targetReleaseID)
	}
	pullRef := target.ConfigSnapshot["pull_ref"]
	if pullRef == "" {
		return "", fmt.Errorf("release %s has no stored image reference (it predates rollback support); redeploy instead", targetReleaseID)
	}

	// Bring the target's production workload up first; only once it is healthy
	// does finalizeLiveRelease repoint the live host and tear down the workload
	// we rolled back from. The target keeps its own snapshotted security profile
	// and live secret scope — a rollback reproduces the prior production deploy
	// exactly, against the live database.
	status, err := o.spawnWorkload(ctx, beamhallID, beamID, target.ID, bh, target.SecurityProfileSnap, target.SecretRefs, pullRef)
	if err != nil {
		return "", fmt.Errorf("rollback bring-up failed (current production left running): %w", err)
	}
	if err := beam.Apply(domain.EvRollback); err != nil {
		return "", err
	}
	hostname, err := o.finalizeLiveRelease(ctx, &beam, bh, target.ID, status.BackendAddr)
	if err != nil {
		return "", err
	}
	o.log.Info("live channel rolled back", "beam", beamID, "release", target.ID, "route", hostname)
	return hostname, nil
}

// DestroyBeam tears a Beam down and archives it (terminal; PLAN §5.7). The
// active workload and route are removed, the pause timer disarmed, and the
// Beam marked archived — freeing its quota slot and releasing its slug for
// reuse. Releases and builds stay for the audit trail.
func (o *Orchestrator) DestroyBeam(ctx context.Context, actor Actor, beamhallID, beamID domain.ID) error {
	if err := o.authorize(ctx, actor, policy.ActionDestroyBeam, beamhallID, beamID); err != nil {
		return err
	}
	err := o.destroy(ctx, beamhallID, beamID)
	return o.outcome(ctx, actor, policy.ActionDestroyBeam, beamhallID, beamID, err)
}

// ArchiveBeam shelves a PREVIEW beam (e.g. an idea the team rejected): the same
// terminal archival as DestroyBeam — workload + URL retired, quota slot and slug
// freed, source repo + audit retained — but builder-accessible and preview-only.
// Archiving a LIVE beam stays IT-gated via DestroyBeam (production teardown).
func (o *Orchestrator) ArchiveBeam(ctx context.Context, actor Actor, beamhallID, beamID domain.ID) error {
	if err := o.authorize(ctx, actor, policy.ActionArchiveBeam, beamhallID, beamID); err != nil {
		return err
	}
	err := o.archivePreview(ctx, beamhallID, beamID)
	return o.outcome(ctx, actor, policy.ActionArchiveBeam, beamhallID, beamID, err)
}

func (o *Orchestrator) archivePreview(ctx context.Context, beamhallID, beamID domain.ID) error {
	beam, err := o.st.GetBeam(ctx, beamID)
	if err != nil {
		return err
	}
	if beam.BeamhallID != beamhallID {
		return fmt.Errorf("beam %s is not in beamhall %s", beamID, beamhallID)
	}
	if beam.Mode == domain.ModeLive {
		return fmt.Errorf("beam %q is live; archiving a live beam is IT-gated — ask IT to destroy_beam it", beam.Slug)
	}
	return o.destroy(ctx, beamhallID, beamID)
}

func (o *Orchestrator) destroy(ctx context.Context, beamhallID, beamID domain.ID) error {
	beam, err := o.st.GetBeam(ctx, beamID)
	if err != nil {
		return err
	}
	if beam.BeamhallID != beamhallID {
		return fmt.Errorf("beam %s is not in beamhall %s", beamID, beamhallID)
	}
	if beam.Status == domain.BeamArchived {
		return fmt.Errorf("beam %s is already destroyed", beamID)
	}
	if _, ok, reason := beam.Can(domain.EvDestroy); !ok {
		return &domain.TransitionError{From: beam.State, Mode: beam.Mode, Event: domain.EvDestroy, Reason: reason}
	}

	// Tear down both channels' workloads + routes, if any.
	if beam.CurrentReleaseID != "" {
		if err := o.retireRelease(ctx, beam.CurrentReleaseID, domain.ReleaseSuperseded); err != nil {
			o.log.Warn("retiring preview release on destroy", "release", beam.CurrentReleaseID, "err", err)
		}
	}
	if beam.LiveReleaseID != "" && beam.LiveReleaseID != beam.CurrentReleaseID {
		if err := o.retireRelease(ctx, beam.LiveReleaseID, domain.ReleaseSuperseded); err != nil {
			o.log.Warn("retiring live release on destroy", "release", beam.LiveReleaseID, "err", err)
		}
	}
	if err := o.sched.Disarm(ctx, string(beamID)); err != nil {
		o.log.Warn("disarming pause timer on destroy", "beam", beamID, "err", err)
	}

	// Reclaim the beam's managed resources (databases): drop the backing
	// Postgres db/role and remove the resource row, so an archived beam stops
	// counting against the beamhall's quota. Without this, repeated
	// archive/redeploy cycles silently exhaust max_db_count (lab finding).
	o.reclaimResources(ctx, beamID)

	// Retire the managed git repo aside so a reused slug starts fresh (a stale
	// inherited history otherwise forces divergent-push reconciliation; lab
	// finding). The source is preserved under the retired name, not deleted.
	if o.repoRetire != nil {
		if bh, err := o.st.GetBeamhall(ctx, beamhallID); err == nil {
			if err := o.repoRetire(bh.Slug, beam.Slug, string(beamID)); err != nil {
				o.log.Warn("retiring repo on destroy", "beam", beamID, "err", err)
			}
		}
	}

	if err := beam.Apply(domain.EvDestroy); err != nil {
		return err
	}
	beam.Status = domain.BeamArchived
	beam.CurrentReleaseID = ""
	beam.DesiredReleaseID = ""
	beam.LiveReleaseID = ""
	beam.LiveState = ""
	if err := o.st.UpdateBeam(ctx, &beam); err != nil {
		return err
	}
	o.log.Info("beam destroyed", "beam", beamID, "slug", beam.Slug)
	return nil
}

// reclaimResources drops the beam's managed databases and removes their
// resource rows. Best-effort: a drop failure is logged, not fatal — the beam is
// being torn down regardless, and a leaked backing db is recoverable by IT.
func (o *Orchestrator) reclaimResources(ctx context.Context, beamID domain.ID) {
	resources, err := o.st.ListResourcesByBeam(ctx, beamID)
	if err != nil {
		o.log.Warn("listing resources on destroy", "beam", beamID, "err", err)
		return
	}
	for _, r := range resources {
		if r.Type == domain.ResourceDatabase && o.dbProv != nil {
			if err := o.dbProv.Drop(ctx, resource.Provisioned{
				Database: r.Spec["database"], Role: r.Spec["role"],
			}); err != nil {
				o.log.Warn("dropping database on destroy", "beam", beamID, "database", r.Spec["database"], "err", err)
			}
		}
		if r.Type == domain.ResourceAuthClient {
			// Delete the beam's OIDC client + its sealed secrets — no orphans (PLAN §5.10).
			o.reclaimAuthClient(ctx, r)
		}
		if r.Type == domain.ResourceEmail {
			// Deregister at the bh-mail broker + delete sealed SMTP secrets (PLAN §5.12).
			o.reclaimEmail(ctx, r)
		}
		if err := o.st.DeleteResource(ctx, r.ID); err != nil {
			o.log.Warn("deleting resource row on destroy", "beam", beamID, "resource", r.ID, "err", err)
		}
	}
}

// ShowMetrics returns a point-in-time resource sample for a beam's running
// workload. Metrics carry no secret material, so no scrubbing is needed.
func (o *Orchestrator) ShowMetrics(ctx context.Context, actor Actor, beamhallID, beamID domain.ID) (driver.Stats, error) {
	if err := o.authorize(ctx, actor, policy.ActionShowMetrics, beamhallID, beamID); err != nil {
		return driver.Stats{}, err
	}
	stats, err := o.showMetrics(ctx, beamID)
	return stats, o.outcome(ctx, actor, policy.ActionShowMetrics, beamhallID, beamID, err)
}

func (o *Orchestrator) showMetrics(ctx context.Context, beamID domain.ID) (driver.Stats, error) {
	beam, err := o.st.GetBeam(ctx, beamID)
	if err != nil {
		return driver.Stats{}, err
	}
	if beam.CurrentReleaseID == "" {
		return driver.Stats{}, fmt.Errorf("beam %s has no running workload", beamID)
	}
	rel, err := o.st.GetRelease(ctx, beam.CurrentReleaseID)
	if err != nil {
		return driver.Stats{}, err
	}
	return o.drv.Stats(ctx, handleOf(rel))
}
