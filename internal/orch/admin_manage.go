package orch

import (
	"context"
	"fmt"
	"time"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/store"
)

// IT management operations that complete the admin lifecycle over MCP (the
// UPDATE/DELETE half the create-only surface was missing): audit reads, the
// per-principal and per-workspace kill switches, post-create workspace edits,
// and release history. Like the rest of the admin family these are it_admin
// only and route through the orchestrator so the PEP/audit invariant holds.
// Reads (audit query/verify, release list) follow the existing convention of
// not appending an audit row per call (mirrors AdminListBeamhalls); mutations
// are recorded on the chain via itAudit.

// --- Audit read surface ------------------------------------------------------

// AuditEntry is the it_admin read model for one row of the hash-chained audit
// log. It flattens store.AuditRecord into a stable shape so the Backplane seam
// never leaks store types.
type AuditEntry struct {
	Seq          int64
	At           time.Time
	Action       string
	Decision     string
	Actor        string
	Beamhall     string
	Beam         string
	Reason       string
	ResultStatus string
	SourceIP     string
}

// AuditChainStatus reports the tamper-evidence check over the whole retained log.
type AuditChainStatus struct {
	Intact     bool
	Issues     []string // one human-readable line per violation; empty when intact
	Checkpoint *AuditCheckpoint
}

// AuditCheckpoint is the prune anchor: rows through ThroughSeq were retained
// off-box and removed, so Verify resumes from here (nil when nothing pruned).
type AuditCheckpoint struct {
	ThroughSeq  int64
	PrunedCount int64
	At          time.Time
}

const (
	auditQueryDefaultLimit = 100
	auditQueryMaxLimit     = 1000
)

// AdminQueryAudit returns audit-log entries, appliance-wide or scoped to one
// beamhall by slug. afterSeq paginates (0 = from the oldest retained row);
// limit caps the page (default 100, max 1000). it_admin only; a read.
func (o *Orchestrator) AdminQueryAudit(ctx context.Context, actor Actor, beamhallSlug string, afterSeq int64, limit int) ([]AuditEntry, error) {
	if err := o.requireIT(actor); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = auditQueryDefaultLimit
	}
	if limit > auditQueryMaxLimit {
		limit = auditQueryMaxLimit
	}
	var (
		recs []store.AuditRecord
		err  error
	)
	if beamhallSlug == "" {
		recs, err = o.st.ListAuditEvents(ctx, afterSeq, limit)
	} else {
		bh, gerr := o.st.GetBeamhallBySlug(ctx, beamhallSlug)
		if gerr != nil {
			return nil, fmt.Errorf("no beamhall named %q", beamhallSlug)
		}
		recs, err = o.st.ListAuditEventsByBeamhall(ctx, bh.ID, afterSeq, limit)
	}
	if err != nil {
		return nil, err
	}
	out := make([]AuditEntry, 0, len(recs))
	for _, r := range recs {
		out = append(out, AuditEntry{
			Seq: r.Seq, At: r.Event.At, Action: r.Event.Action,
			Decision: string(r.Event.Decision), Actor: string(r.Event.ActorID),
			Beamhall: string(r.Event.BeamhallID), Beam: string(r.Event.BeamID),
			Reason: r.Event.Reason, ResultStatus: r.Event.ResultStatus, SourceIP: r.Event.SourceIP,
		})
	}
	return out, nil
}

// AdminVerifyAuditChain runs the hash-chain integrity check over the retained
// audit log and reports every violation found, plus the prune checkpoint.
// it_admin only; a read.
func (o *Orchestrator) AdminVerifyAuditChain(ctx context.Context, actor Actor) (AuditChainStatus, error) {
	if err := o.requireIT(actor); err != nil {
		return AuditChainStatus{}, err
	}
	issues, err := o.alog.Verify(ctx)
	if err != nil {
		return AuditChainStatus{}, err
	}
	st := AuditChainStatus{Intact: len(issues) == 0}
	for _, is := range issues {
		st.Issues = append(st.Issues, is.String())
	}
	if cp, ok, cerr := o.st.LatestAuditCheckpoint(ctx); cerr != nil {
		return AuditChainStatus{}, cerr
	} else if ok {
		st.Checkpoint = &AuditCheckpoint{ThroughSeq: cp.ThroughSeq, PrunedCount: cp.PrunedCount, At: cp.At}
	}
	return st, nil
}

// --- Membership / identity lifecycle ----------------------------------------

// RevokeMembership removes an identity's access to a beamhall (offboarding).
// A missing membership is reported as an error so the operator knows nothing
// changed. it_admin only.
func (o *Orchestrator) RevokeMembership(ctx context.Context, actor Actor, identityID, beamhallID domain.ID) error {
	if err := o.requireIT(actor); err != nil {
		return o.itAudit(ctx, actor, "admin_revoke_membership", beamhallID, err)
	}
	op := func() error {
		m, err := o.st.GetMembership(ctx, identityID, beamhallID)
		if err != nil {
			return fmt.Errorf("that identity has no membership in this beamhall")
		}
		return o.st.DeleteMembership(ctx, m.ID)
	}
	return o.itAudit(ctx, actor, "admin_revoke_membership", beamhallID, op())
}

// SetMembershipRole changes an identity's role within a beamhall in place
// (e.g. promote a viewer to builder). The store has no role-update query, so
// this revokes the old membership and grants the new role; a no-op when the
// role already matches. it_admin only.
func (o *Orchestrator) SetMembershipRole(ctx context.Context, actor Actor, identityID, beamhallID domain.ID, role domain.MembershipRole) error {
	if err := o.requireIT(actor); err != nil {
		return o.itAudit(ctx, actor, "admin_set_membership_role", beamhallID, err)
	}
	op := func() error {
		m, err := o.st.GetMembership(ctx, identityID, beamhallID)
		if err != nil {
			return fmt.Errorf("that identity has no membership in this beamhall — grant one first")
		}
		if m.Role == role {
			return nil
		}
		if err := o.st.DeleteMembership(ctx, m.ID); err != nil {
			return err
		}
		return o.st.CreateMembership(ctx, &domain.Membership{
			IdentityID: identityID, BeamhallID: beamhallID, Role: role, GrantedBy: actor.ID,
		})
	}
	return o.itAudit(ctx, actor, "admin_set_membership_role", beamhallID, op())
}

// SetIdentityStatus flips a registered identity active<->disabled. A disabled
// identity keeps its row but fails every authorization at the PEP — the
// per-principal kill switch for a departed or compromised user. it_admin only.
func (o *Orchestrator) SetIdentityStatus(ctx context.Context, actor Actor, identityID domain.ID, status string) error {
	if err := o.requireIT(actor); err != nil {
		return o.itAudit(ctx, actor, "admin_set_identity_status", "", err)
	}
	op := func() error {
		switch status {
		case domain.IdentityActive, domain.IdentityDisabled:
		default:
			return fmt.Errorf("status must be %q or %q, got %q", domain.IdentityActive, domain.IdentityDisabled, status)
		}
		ident, err := o.st.GetIdentity(ctx, identityID)
		if err != nil {
			return fmt.Errorf("identity %q: %w", identityID, err)
		}
		ident.Status = status
		return o.st.UpdateIdentity(ctx, ident)
	}
	return o.itAudit(ctx, actor, "admin_set_identity_status", "", op())
}

// DeregisterIdentity removes a registered identity entirely (cleanup of an
// offboarded principal — the RegisterIdentity inverse). It refuses while the
// identity still has any workspace membership, so access is always revoked
// before the record is dropped. Audit rows reference the id as an opaque string
// and are preserved. it_admin only.
func (o *Orchestrator) DeregisterIdentity(ctx context.Context, actor Actor, identityID domain.ID) error {
	if err := o.requireIT(actor); err != nil {
		return o.itAudit(ctx, actor, "admin_deregister_identity", "", err)
	}
	op := func() error {
		if _, err := o.st.GetIdentity(ctx, identityID); err != nil {
			return fmt.Errorf("identity %q is not registered", identityID)
		}
		mships, err := o.st.ListMembershipsByIdentity(ctx, identityID)
		if err != nil {
			return err
		}
		if len(mships) > 0 {
			return fmt.Errorf("identity still has %d workspace membership(s) — revoke them first (admin_revoke_membership)", len(mships))
		}
		return o.st.DeleteIdentity(ctx, identityID)
	}
	return o.itAudit(ctx, actor, "admin_deregister_identity", "", op())
}

// --- Workspace lifecycle (post-create edits) --------------------------------

// BeamhallUpdate carries the optional changes to an existing workspace; a nil
// field is left unchanged. Quota, live-slot limit, status, and metadata are all
// IT-owned and immutable to builders by design — this is the it_admin path to
// adjust them after creation.
type BeamhallUpdate struct {
	MaxBeams     *int
	MaxLiveSlots *int
	MaxDatabases *int
	Status       *domain.BeamhallStatus
	DisplayName  *string
	Department   *string
}

// AdminUpdateBeamhall mutates an existing workspace's quota, live-slot limit,
// status (active|suspended|archived), or metadata, returning the updated
// record. Suspending/archiving is a real control: the PEP denies every action
// in a non-active beamhall. it_admin only.
func (o *Orchestrator) AdminUpdateBeamhall(ctx context.Context, actor Actor, slug string, upd BeamhallUpdate) (*domain.Beamhall, error) {
	if err := o.requireIT(actor); err != nil {
		return nil, o.itAudit(ctx, actor, "admin_update_beamhall", "", err)
	}
	var (
		updated *domain.Beamhall
		bhID    domain.ID
	)
	op := func() error {
		bh, err := o.st.GetBeamhallBySlug(ctx, slug)
		if err != nil {
			return fmt.Errorf("no beamhall named %q", slug)
		}
		bhID = bh.ID
		if upd.MaxBeams != nil {
			if *upd.MaxBeams < 0 {
				return fmt.Errorf("max_beams cannot be negative")
			}
			bh.Quota.MaxBeams = *upd.MaxBeams
		}
		if upd.MaxDatabases != nil {
			if *upd.MaxDatabases < 0 {
				return fmt.Errorf("max_databases cannot be negative")
			}
			bh.Quota.MaxDBCount = *upd.MaxDatabases
		}
		if upd.MaxLiveSlots != nil {
			if *upd.MaxLiveSlots < 0 {
				return fmt.Errorf("max_live_slots cannot be negative")
			}
			bh.Quota.MaxLiveSlots = *upd.MaxLiveSlots
			bh.LiveSlotLimit = *upd.MaxLiveSlots
		}
		if upd.Status != nil {
			switch *upd.Status {
			case domain.BeamhallActive, domain.BeamhallSuspended, domain.BeamhallArchived:
				bh.Status = *upd.Status
			default:
				return fmt.Errorf("status must be active, suspended or archived, got %q", *upd.Status)
			}
		}
		if upd.DisplayName != nil {
			bh.DisplayName = *upd.DisplayName
		}
		if upd.Department != nil {
			bh.Department = *upd.Department
		}
		if err := o.st.UpdateBeamhall(ctx, &bh); err != nil {
			return err
		}
		updated = &bh
		return nil
	}
	if err := op(); err != nil {
		return nil, o.itAudit(ctx, actor, "admin_update_beamhall", bhID, err)
	}
	return updated, o.itAudit(ctx, actor, "admin_update_beamhall", bhID, nil)
}

// --- Release history ---------------------------------------------------------

// ReleaseEntry is one production (live-channel) release in a beam's history,
// renumbered to a clean v1,v2,… production sequence (independent of the raw
// global release counter) so rollback has a discoverable target.
type ReleaseEntry struct {
	Label     string // v1, v2, … (production sequence)
	ReleaseID string
	Version   int  // raw global release version (the rollback to_version)
	Current   bool // currently serving production
	CreatedAt time.Time
}

// AdminListReleases lists a beam's production (live) release history, newest
// first, renumbered v1,v2,… (mirrors the Admin console's liveHistory). it_admin
// only; a read.
func (o *Orchestrator) AdminListReleases(ctx context.Context, actor Actor, beamID domain.ID) ([]ReleaseEntry, error) {
	if err := o.requireIT(actor); err != nil {
		return nil, err
	}
	beam, err := o.st.GetBeam(ctx, beamID)
	if err != nil {
		return nil, err
	}
	rels, err := o.st.ListReleasesByBeam(ctx, beamID)
	if err != nil {
		return nil, err
	}
	// ListReleasesByBeam is newest-first; walk oldest-first to number v1,v2,…
	var out []ReleaseEntry
	n := 0
	for i := len(rels) - 1; i >= 0; i-- {
		r := rels[i]
		if r.Channel != domain.ChannelLive {
			continue
		}
		n++
		out = append(out, ReleaseEntry{
			Label: fmt.Sprintf("v%d", n), ReleaseID: string(r.ID), Version: r.Version,
			Current: r.ID == beam.LiveReleaseID, CreatedAt: r.CreatedAt,
		})
	}
	// Present newest-first.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// channelURLs returns a beam's active preview and live route URLs ("" for a
// channel with no active route). Mirrors the MCP layer's helper so the admin
// read model can include channel URLs without the MCP layer re-querying routes.
func (o *Orchestrator) channelURLs(ctx context.Context, beamID domain.ID) (preview, live string) {
	routes, err := o.st.ListRoutesByBeam(ctx, beamID)
	if err != nil {
		return "", ""
	}
	for _, rt := range routes {
		if rt.Status != domain.RouteActive {
			continue
		}
		if rt.Kind == domain.RouteLive {
			live = "https://" + rt.Hostname
		} else {
			preview = "https://" + rt.Hostname
		}
	}
	return preview, live
}
