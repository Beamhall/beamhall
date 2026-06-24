// Package policy is the backplane's single policy enforcement point (PLAN §6):
// every MCP tool call and backplane operation passes Authorize before any
// effect. Authorization is data-driven — membership role per Beamhall, never
// token-encoded — and a hard deny list forbids the agent-unreachable actions
// (read secrets, weaken security, raw runtime access) for every role,
// including IT. Each authorization decision is appended to the hash-chained
// audit log; for allowed calls the orchestrator appends a second event with
// the operation's outcome.
package policy

import (
	"context"
	"errors"
	"fmt"

	"github.com/Beamhall/beamhall/internal/audit"
	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/store"
)

// Action names a policy-relevant operation. The MCP-facing ones match the
// tool names in PLAN §5.7; the forbidden ones exist so that an attempt lands
// in the audit log under a precise name.
type Action string

const (
	ActionReadBeamhall   Action = "read_beamhall"
	ActionShowLogs       Action = "show_logs"
	ActionShowMetrics    Action = "show_metrics"
	ActionCreateBeam     Action = "create_beam"
	ActionDeployBeam     Action = "deploy_beam"
	ActionCreateDatabase Action = "create_database"
	ActionSetSecret      Action = "set_secret"
	ActionPausePreview   Action = "pause_preview"
	ActionResumePreview  Action = "resume_preview"
	ActionRollback       Action = "rollback"
	ActionPromoteToLive  Action = "promote_to_live"
	ActionRequestPromote Action = "request_promotion"
	ActionArchiveBeam    Action = "archive_beam"
	ActionDestroyBeam    Action = "destroy_beam"
	// Provisioned auth (PLAN §5.10): a per-beam managed primitive, like a database.
	// provision_auth is a builder write; show_auth is a read. The IT-curated group
	// allowlist (admin_set_auth_groups) is an admin:it action via requireIT/itAudit,
	// not a role-matrix entry.
	ActionProvisionAuth Action = "provision_auth"
	ActionShowAuth      Action = "show_auth"
)

// Forbidden actions: hard-denied for every role, including it_admin, on the
// agent-facing path (PLAN §6 deny list). Security context, quota, and egress
// changes happen through the IT Admin UI surface, never through here.
const (
	ActionGetSecret             Action = "get_secret"
	ActionMutateSecurityContext Action = "mutate_security_context"
	ActionMutateQuota           Action = "mutate_quota"
	ActionMutateEgress          Action = "mutate_egress"
	ActionRawRuntimeAccess      Action = "raw_runtime_access"
	ActionSupplyDockerfile      Action = "supply_dockerfile"
)

var forbidden = map[Action]bool{
	ActionGetSecret:             true,
	ActionMutateSecurityContext: true,
	ActionMutateQuota:           true,
	ActionMutateEgress:          true,
	ActionRawRuntimeAccess:      true,
	ActionSupplyDockerfile:      true,
}

// matrix maps each membership role to the actions it grants. Roles are
// strictly additive: viewer ⊂ builder ⊂ beamhall_admin. The deliberate gap is
// promote_to_live and destroy_beam for builders — governance stays with the
// Beamhall admin (or IT), which is the demo's 403 moment (PLAN §7).
var matrix = map[domain.MembershipRole]map[Action]bool{
	domain.RoleViewer: {
		ActionReadBeamhall: true,
		ActionShowLogs:     true,
		ActionShowMetrics:  true,
		ActionShowAuth:     true,
	},
	domain.RoleBuilder: {
		ActionReadBeamhall:   true,
		ActionShowLogs:       true,
		ActionShowMetrics:    true,
		ActionCreateBeam:     true,
		ActionDeployBeam:     true,
		ActionCreateDatabase: true,
		ActionSetSecret:      true,
		ActionPausePreview:   true,
		ActionResumePreview:  true,
		ActionRollback:       true,
		// A builder may archive their own *preview* beam (rejected idea →
		// shelve it); the orchestrator enforces preview-only. Archiving a LIVE
		// beam stays IT-gated via destroy_beam (production teardown).
		ActionArchiveBeam: true,
		// May *request* promotion (the IT-approval gate); the actual promote
		// stays IT/admin-gated and a different operator must approve.
		ActionRequestPromote: true,
		// May give their beam company sign-in (provision_auth) and inspect it.
		ActionProvisionAuth: true,
		ActionShowAuth:      true,
	},
	domain.RoleBeamhallAdmin: {
		ActionReadBeamhall:   true,
		ActionShowLogs:       true,
		ActionShowMetrics:    true,
		ActionCreateBeam:     true,
		ActionDeployBeam:     true,
		ActionCreateDatabase: true,
		ActionSetSecret:      true,
		ActionPausePreview:   true,
		ActionResumePreview:  true,
		ActionRollback:       true,
		ActionArchiveBeam:    true,
		ActionPromoteToLive:  true,
		ActionRequestPromote: true,
		ActionDestroyBeam:    true,
		ActionProvisionAuth:  true,
		ActionShowAuth:       true,
	},
}

// Store is the persistence the PEP reads. *store.Store satisfies it.
type Store interface {
	GetIdentity(ctx context.Context, id domain.ID) (domain.Identity, error)
	GetBeamhall(ctx context.Context, id domain.ID) (domain.Beamhall, error)
	GetMembership(ctx context.Context, identityID, beamhallID domain.ID) (domain.Membership, error)
	CountBeamsByBeamhall(ctx context.Context, beamhallID domain.ID) (int, error)
	CountResourcesByType(ctx context.Context, beamhallID domain.ID, typ domain.ResourceType) (int, error)
}

// Request is one authorization question: may Actor perform Action in
// Beamhall? The token-derived fields (JTI, global role, source IP, request
// digest) flow into the audit record.
type Request struct {
	Actor         domain.ID
	ActorTokenJTI string
	// ITAdmin is set by the auth layer when the actor's token carries the
	// admin:it scope; it bypasses membership but never the forbidden list.
	ITAdmin       bool
	BeamhallID    domain.ID
	BeamID        domain.ID
	Action        Action
	SourceIP      string
	RequestDigest string
}

// Denial is the typed authorization failure; the MCP layer maps it to 403
// with Reason as the actionable message.
type Denial struct {
	Action Action
	Reason string
}

func (d *Denial) Error() string {
	return fmt.Sprintf("denied %q: %s", d.Action, d.Reason)
}

// PEP decides and audits. Construct once with New and share.
type PEP struct {
	st  Store
	log *audit.Logger
}

// New returns a PEP over st that records every decision on log.
func New(st Store, log *audit.Logger) *PEP {
	return &PEP{st: st, log: log}
}

// Authorize decides req and appends the decision to the audit log (allow and
// deny alike — every attempt is on the record). It returns nil when allowed
// and a *Denial otherwise. Order matters: the forbidden list is checked first
// so that even a would-be-valid admin attempt at a forbidden action is denied
// and recorded as such.
func (p *PEP) Authorize(ctx context.Context, req Request) error {
	decide := func(allow bool, reason string) error {
		decision := domain.DecisionDeny
		if allow {
			decision = domain.DecisionAllow
		}
		ev := domain.AuditEvent{
			ActorID:       req.Actor,
			ActorTokenJTI: req.ActorTokenJTI,
			BeamhallID:    req.BeamhallID,
			BeamID:        req.BeamID,
			Action:        string(req.Action),
			Decision:      decision,
			Reason:        reason,
			RequestDigest: req.RequestDigest,
			SourceIP:      req.SourceIP,
		}
		if _, err := p.log.Append(ctx, &ev); err != nil {
			// An unauditable decision is a denied decision: the log is the
			// product's evidence and must never silently miss an action.
			return &Denial{Action: req.Action, Reason: "audit log unavailable: " + err.Error()}
		}
		if !allow {
			return &Denial{Action: req.Action, Reason: reason}
		}
		return nil
	}

	if forbidden[req.Action] {
		return decide(false, "forbidden for every role: the backplane has no such capability on the agent path")
	}

	ident, err := p.st.GetIdentity(ctx, req.Actor)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return decide(false, "unknown identity")
	case err != nil:
		return decide(false, "identity lookup failed: "+err.Error())
	}
	if ident.Status != domain.IdentityActive {
		return decide(false, fmt.Sprintf("identity is %s", ident.Status))
	}

	bh, err := p.st.GetBeamhall(ctx, req.BeamhallID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return decide(false, "unknown beamhall")
	case err != nil:
		return decide(false, "beamhall lookup failed: "+err.Error())
	}
	if bh.Status != domain.BeamhallActive {
		return decide(false, fmt.Sprintf("beamhall is %s", bh.Status))
	}

	if req.ITAdmin {
		return decide(true, "it_admin")
	}

	m, err := p.st.GetMembership(ctx, req.Actor, req.BeamhallID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// The cannot-touch-another-Beamhall invariant: no membership, no
		// access, regardless of what other Beamhalls the actor belongs to.
		return decide(false, "no membership in this beamhall")
	case err != nil:
		return decide(false, "membership lookup failed: "+err.Error())
	}

	if !matrix[m.Role][req.Action] {
		return decide(false, fmt.Sprintf("role %q does not grant %q", m.Role, req.Action))
	}
	return decide(true, string(m.Role))
}
