package orch

import (
	"context"
	"fmt"

	"github.com/Beamhall/beamhall/internal/domain"
)

// IT-structural operations for the Admin console (PLAN §8). These set up the
// control plane — create beamhalls, register identities, grant memberships,
// set egress — and are reserved for it_admin (the auth layer sets
// actor.ITAdmin from the admin:it scope). They are not in the agent PEP
// matrix (agents can never reach them), but every one is recorded on the
// audit chain so IT actions are as accountable as agent actions.

// itAudit appends an allow/deny outcome for an IT structural action.
func (o *Orchestrator) itAudit(ctx context.Context, actor Actor, action string, beamhallID domain.ID, opErr error) error {
	status, reason := "ok", ""
	decision := domain.DecisionAllow
	if !actor.ITAdmin {
		decision, status, reason = domain.DecisionDeny, "denied", "requires it_admin"
	} else if opErr != nil {
		status, reason = "failed", opErr.Error()
	}
	ev := domain.AuditEvent{
		ActorID: actor.ID, ActorTokenJTI: actor.TokenJTI, BeamhallID: beamhallID,
		Action: action, Decision: decision, Reason: reason, ResultStatus: status,
		SourceIP: actor.SourceIP,
	}
	if _, err := o.alog.Append(ctx, &ev); err != nil {
		o.log.Error("audit IT action failed", "action", action, "err", err)
	}
	return opErr
}

func (o *Orchestrator) requireIT(actor Actor) error {
	if !actor.ITAdmin {
		return fmt.Errorf("operation requires it_admin")
	}
	return nil
}

// NewBeamhallSpec is the IT input for creating a beamhall.
type NewBeamhallSpec struct {
	Slug         string
	DisplayName  string
	Department   string
	RuntimeClass domain.RuntimeClass // runc | runsc
	Template     domain.SecurityTemplate
	Quota        domain.ResourceQuota
	LiveSlots    int
	EgressMode   domain.EgressMode
	Allowlist    []string
}

// CreateBeamhall provisions a new beamhall with an immutable SecurityContext
// derived from the chosen hardening template (PLAN §3). it_admin only.
func (o *Orchestrator) CreateBeamhall(ctx context.Context, actor Actor, spec NewBeamhallSpec) (*domain.Beamhall, error) {
	if err := o.requireIT(actor); err != nil {
		return nil, o.itAudit(ctx, actor, "admin_create_beamhall", "", err)
	}
	bh, err := o.createBeamhall(ctx, spec)
	var id domain.ID
	if bh != nil {
		id = bh.ID
	}
	return bh, o.itAudit(ctx, actor, "admin_create_beamhall", id, err)
}

func (o *Orchestrator) createBeamhall(ctx context.Context, spec NewBeamhallSpec) (*domain.Beamhall, error) {
	if !slugRe.MatchString(spec.Slug) {
		return nil, fmt.Errorf("invalid slug %q: lowercase letters, digits, inner hyphens (max 32)", spec.Slug)
	}
	mode := spec.EgressMode
	if mode == "" {
		mode = domain.EgressDenyAll
	}
	tmpl := spec.Template
	if tmpl == "" {
		tmpl = domain.TemplateWebApp
	}
	rc := spec.RuntimeClass
	if rc == "" {
		rc = domain.RuntimeRunc
	}
	bh := &domain.Beamhall{
		Slug: spec.Slug, DisplayName: spec.DisplayName, Department: spec.Department,
		Status:        domain.BeamhallActive,
		NetworkPolicy: domain.NetworkPolicy{EgressMode: mode, EgressAllowlist: spec.Allowlist},
		Quota:         spec.Quota,
		LiveSlotLimit: spec.LiveSlots,
	}
	sc := securityContextFor(tmpl, rc, spec.Quota)
	if err := o.st.CreateBeamhall(ctx, bh, sc); err != nil {
		return nil, err
	}
	o.log.Info("beamhall created", "slug", bh.Slug, "template", tmpl, "runtime_class", rc)
	return bh, nil
}

// securityContextFor builds the immutable hardening profile for a template.
// Every template drops all capabilities, forbids new privileges, and runs a
// read-only rootfs with a writable /tmp; templates differ only in the narrow
// capabilities a workload class genuinely needs.
func securityContextFor(tmpl domain.SecurityTemplate, rc domain.RuntimeClass, q domain.ResourceQuota) *domain.SecurityContext {
	capAdd := []string{"NET_BIND_SERVICE"}
	switch tmpl {
	case domain.TemplateDataProcessor:
		capAdd = append(capAdd, "CHOWN")
	case domain.TemplateDatabaseInit:
		capAdd = append(capAdd, "DAC_OVERRIDE")
	}
	limits := domain.ResourceLimits{CPUQuota: q.CPUCeiling, MemBytes: q.MemCeiling, PidsMax: 256}
	if limits.MemBytes == 0 {
		limits.MemBytes = 512 << 20
	}
	if limits.CPUQuota == 0 {
		limits.CPUQuota = 100000
	}
	return &domain.SecurityContext{
		RuntimeClass: rc, UsernsRemap: true, CapDrop: []string{"ALL"}, CapAdd: capAdd,
		SeccompProfile: "default", NoNewPrivileges: true, ReadOnlyRootfs: true,
		Tmpfs: []string{"/tmp"}, CgroupLimits: limits, Template: tmpl,
	}
}

// RegisterIdentity records an external identity (IdP issuer + subject) so it
// can be granted memberships. it_admin only.
func (o *Orchestrator) RegisterIdentity(ctx context.Context, actor Actor, issuer, subject, email, displayName string) (*domain.Identity, error) {
	if err := o.requireIT(actor); err != nil {
		return nil, o.itAudit(ctx, actor, "admin_register_identity", "", err)
	}
	op := func() (*domain.Identity, error) {
		if issuer == "" || subject == "" {
			return nil, fmt.Errorf("issuer and subject are required")
		}
		if existing, err := o.st.GetIdentityByIssuerSubject(ctx, issuer, subject); err == nil {
			return &existing, nil // idempotent
		}
		ident := &domain.Identity{ExternalSubject: subject, IdPIssuer: issuer,
			Email: email, DisplayName: displayName, Status: domain.IdentityActive}
		if err := o.st.CreateIdentity(ctx, ident); err != nil {
			return nil, err
		}
		return ident, nil
	}
	ident, err := op()
	return ident, o.itAudit(ctx, actor, "admin_register_identity", "", err)
}

// GrantMembership gives an identity a role in a beamhall. it_admin only.
func (o *Orchestrator) GrantMembership(ctx context.Context, actor Actor, identityID, beamhallID domain.ID, role domain.MembershipRole) error {
	if err := o.requireIT(actor); err != nil {
		return o.itAudit(ctx, actor, "admin_grant_membership", beamhallID, err)
	}
	op := func() error {
		if _, err := o.st.GetIdentity(ctx, identityID); err != nil {
			return fmt.Errorf("identity: %w", err)
		}
		if _, err := o.st.GetBeamhall(ctx, beamhallID); err != nil {
			return fmt.Errorf("beamhall: %w", err)
		}
		m := &domain.Membership{IdentityID: identityID, BeamhallID: beamhallID,
			Role: role, GrantedBy: actor.ID}
		return o.st.CreateMembership(ctx, m)
	}
	return o.itAudit(ctx, actor, "admin_grant_membership", beamhallID, op())
}

// SetEgress replaces a beamhall's egress posture (mode + allowlist). The
// orchestrator re-asserts iptables on the next deploy; an immediate
// re-assertion happens here if an egress sync hook is configured. it_admin
// only.
func (o *Orchestrator) SetEgress(ctx context.Context, actor Actor, beamhallID domain.ID, mode domain.EgressMode, allowlist []string) error {
	if err := o.requireIT(actor); err != nil {
		return o.itAudit(ctx, actor, "admin_set_egress", beamhallID, err)
	}
	op := func() error {
		bh, err := o.st.GetBeamhall(ctx, beamhallID)
		if err != nil {
			return err
		}
		bh.NetworkPolicy.EgressMode = mode
		bh.NetworkPolicy.EgressAllowlist = allowlist
		if err := o.st.UpdateBeamhall(ctx, &bh); err != nil {
			return err
		}
		if o.egressSync != nil {
			return o.egressSync(ctx)
		}
		return nil
	}
	return o.itAudit(ctx, actor, "admin_set_egress", beamhallID, op())
}

// EnsureOperator resolves the logged-in operator to an Identity, creating one
// on first login (the Admin console's bootstrap: the first IT person the IdP
// grants admin:it becomes a registered identity). Not audited per call — it
// runs on every authenticated request.
func (o *Orchestrator) EnsureOperator(ctx context.Context, issuer, subject, email string) (domain.ID, error) {
	if existing, err := o.st.GetIdentityByIssuerSubject(ctx, issuer, subject); err == nil {
		return existing.ID, nil
	}
	ident := &domain.Identity{ExternalSubject: subject, IdPIssuer: issuer,
		Email: email, DisplayName: email, Status: domain.IdentityActive}
	if err := o.st.CreateIdentity(ctx, ident); err != nil {
		return "", err
	}
	return ident.ID, nil
}
