package orch

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/identityadmin"
)

// Owned-IdP administration (PLAN §5.9). These drive the IdP Beamhall provisions
// (the bundled Keycloak) through the identityadmin seam, so an operator manages
// users/groups/federation over the same MCP channel as everything else — never
// with the IdP admin credential in the agent's hands (Beamhall holds it).
//
// Tiering (the guardrail decision): routine onboarding ops (create user, set a
// temporary password, create/join groups) run autonomously and are audited;
// directory federation is a SENSITIVE auth-config change (it changes who can
// sign in to the whole appliance) and fails closed unless the operator has
// explicitly enabled the sensitive tier (the human-in-the-loop opt-in). The
// full four-eyes pending-approval flow for the sensitive tier mirrors the
// promotion approval path (PLAN §10) and is the documented next step.

// AdminCreateUser provisions a local account in the owned IdP. it_admin only.
func (o *Orchestrator) AdminCreateUser(ctx context.Context, actor Actor, u identityadmin.NewUser) (identityadmin.User, error) {
	if err := o.requireIT(actor); err != nil {
		return identityadmin.User{}, o.itAudit(ctx, actor, "admin_create_user", "", err)
	}
	user, err := o.idp.CreateUser(ctx, u)
	return user, o.itAudit(ctx, actor, "admin_create_user", "", err)
}

// AdminListUsers lists accounts in the owned IdP. it_admin only; not audited
// per call (a read, like ListPendingPromotions).
func (o *Orchestrator) AdminListUsers(ctx context.Context, actor Actor, query string, max int) ([]identityadmin.User, error) {
	if err := o.requireIT(actor); err != nil {
		return nil, err
	}
	return o.idp.ListUsers(ctx, query, max)
}

// AdminSetUserPassword sets a one-time password the user must change at next
// login (the onboarding hand-off). it_admin only.
func (o *Orchestrator) AdminSetUserPassword(ctx context.Context, actor Actor, userID, password string) error {
	if err := o.requireIT(actor); err != nil {
		return o.itAudit(ctx, actor, "admin_set_user_password", "", err)
	}
	return o.itAudit(ctx, actor, "admin_set_user_password", "", o.idp.SetTemporaryPassword(ctx, userID, password))
}

// AdminCreateGroup creates an IdP group. it_admin only.
func (o *Orchestrator) AdminCreateGroup(ctx context.Context, actor Actor, name string) (identityadmin.Group, error) {
	if err := o.requireIT(actor); err != nil {
		return identityadmin.Group{}, o.itAudit(ctx, actor, "admin_create_group", "", err)
	}
	g, err := o.idp.CreateGroup(ctx, name)
	return g, o.itAudit(ctx, actor, "admin_create_group", "", err)
}

// AdminListGroups lists IdP groups. it_admin only; not audited per call.
func (o *Orchestrator) AdminListGroups(ctx context.Context, actor Actor) ([]identityadmin.Group, error) {
	if err := o.requireIT(actor); err != nil {
		return nil, err
	}
	return o.idp.ListGroups(ctx)
}

// AdminAddUserToGroup adds an IdP user to an IdP group. it_admin only.
func (o *Orchestrator) AdminAddUserToGroup(ctx context.Context, actor Actor, userID, groupID string) error {
	if err := o.requireIT(actor); err != nil {
		return o.itAudit(ctx, actor, "admin_add_user_to_group", "", err)
	}
	return o.itAudit(ctx, actor, "admin_add_user_to_group", "", o.idp.AddUserToGroup(ctx, userID, groupID))
}

// --- SENSITIVE tier: four-eyes approval (PLAN §5.9) ---------------------------
//
// A sensitive admin action (today: directory federation; later: restore/upgrade)
// is never executed by the requesting operator. It records a pending request
// that a DIFFERENT IT operator must approve (separation of duties); the backplane
// executes the stored intent only on approval. The payload may carry secrets (an
// LDAP bind credential) and is vault-sealed at rest — only a non-secret summary
// is shown in listings. The master switch `idpSensitive`
// (BEAMHALL_IDP_SENSITIVE_ADMIN) governs whether sensitive actions can be
// requested at all; with it off they fail closed.

// RequestFederateDirectory files a pending request to federate an LDAP/AD
// directory onto the owned IdP. it_admin only; requires the sensitive tier to be
// enabled and an owned IdP to administer. A second IT operator approves it via
// ApproveAdminAction, at which point the federation executes.
func (o *Orchestrator) RequestFederateDirectory(ctx context.Context, actor Actor, d identityadmin.DirectoryFederation) (domain.AdminActionRequest, error) {
	if err := o.requireIT(actor); err != nil {
		return domain.AdminActionRequest{}, o.itAudit(ctx, actor, "admin_request_federate_directory", "", err)
	}
	if !o.idpSensitive {
		err := fmt.Errorf("the sensitive admin tier is disabled on this appliance; set BEAMHALL_IDP_SENSITIVE_ADMIN=on to permit sensitive actions (they still require a second IT operator's approval)")
		return domain.AdminActionRequest{}, o.itAudit(ctx, actor, "admin_request_federate_directory", "", err)
	}
	if !o.idp.Enabled() {
		err := fmt.Errorf("%w", identityadmin.ErrNotEnabled)
		return domain.AdminActionRequest{}, o.itAudit(ctx, actor, "admin_request_federate_directory", "", err)
	}
	summary := fmt.Sprintf("federate directory %q (%s) → %s users_dn=%s", d.Name, vendorLabel(d.Vendor), d.ConnectionURL, d.UsersDN)
	req, err := o.requestSensitive(ctx, actor, domain.AdminActionFederateDirectory, summary, d)
	return req, o.itAudit(ctx, actor, "admin_request_federate_directory", "", err)
}

// requestSensitive seals an action's payload and records the pending request.
func (o *Orchestrator) requestSensitive(ctx context.Context, actor Actor, typ domain.AdminActionType, summary string, payload any) (domain.AdminActionRequest, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return domain.AdminActionRequest{}, err
	}
	sealed, err := o.vault.Seal(raw)
	if err != nil {
		return domain.AdminActionRequest{}, fmt.Errorf("seal sensitive payload: %w", err)
	}
	req := &domain.AdminActionRequest{
		ActionType: typ, Summary: summary, PayloadCipher: sealed,
		RequestedBy: actor.ID, Status: domain.AdminActionPending,
	}
	if err := o.st.CreateAdminActionRequest(ctx, req); err != nil {
		return domain.AdminActionRequest{}, err
	}
	o.log.Info("sensitive admin action requested", "type", typ, "request", req.ID, "by", actor.ID)
	return *req, nil
}

// ListPendingAdminActions returns the sensitive admin actions awaiting approval.
// it_admin only; not audited per call (a read).
func (o *Orchestrator) ListPendingAdminActions(ctx context.Context, actor Actor) ([]domain.AdminActionRequest, error) {
	if err := o.requireIT(actor); err != nil {
		return nil, err
	}
	return o.st.ListPendingAdminActionRequests(ctx)
}

// ApproveAdminAction approves a pending sensitive action and executes it. it_admin
// only, and the approver MUST differ from the requester (four-eyes). On execution
// failure the request stays pending (it can be retried); only a successful
// execution marks it approved.
func (o *Orchestrator) ApproveAdminAction(ctx context.Context, actor Actor, id domain.ID) (domain.AdminActionRequest, error) {
	if err := o.requireIT(actor); err != nil {
		return domain.AdminActionRequest{}, o.itAudit(ctx, actor, "admin_approve_action", "", err)
	}
	req, result, err := o.approveAdminAction(ctx, actor, id)
	action := "admin_approve_action"
	if req.ActionType != "" {
		action = "admin_approve_" + string(req.ActionType)
	}
	if err := o.itAudit(ctx, actor, action, "", err); err != nil {
		return domain.AdminActionRequest{}, err
	}
	req.Result = result
	return req, nil
}

func (o *Orchestrator) approveAdminAction(ctx context.Context, actor Actor, id domain.ID) (domain.AdminActionRequest, string, error) {
	req, err := o.st.GetAdminActionRequest(ctx, id)
	if err != nil {
		return domain.AdminActionRequest{}, "", err
	}
	if req.Status != domain.AdminActionPending {
		return req, "", fmt.Errorf("request %s is already %s", id, req.Status)
	}
	// Four-eyes: the approver cannot be the requester.
	if req.RequestedBy == actor.ID {
		return req, "", fmt.Errorf("the requester cannot approve their own sensitive action (four-eyes); a different IT operator must approve")
	}
	plain, err := o.vault.Open(req.PayloadCipher)
	if err != nil {
		return req, "", fmt.Errorf("open sealed payload: %w", err)
	}
	result, err := o.executeAdminAction(ctx, req.ActionType, plain)
	if err != nil {
		// Leave the request pending so it can be retried after the cause is fixed.
		return req, "", err
	}
	if err := o.st.DecideAdminActionRequest(ctx, id, domain.AdminActionApproved, actor.ID, "", result); err != nil {
		return req, result, err
	}
	o.log.Info("sensitive admin action approved + executed", "type", req.ActionType, "request", id, "by", actor.ID)
	req.Status = domain.AdminActionApproved
	req.DecidedBy = actor.ID
	return req, result, nil
}

// RejectAdminAction rejects a pending sensitive action without executing it.
// it_admin only.
func (o *Orchestrator) RejectAdminAction(ctx context.Context, actor Actor, id domain.ID, reason string) error {
	if err := o.requireIT(actor); err != nil {
		return o.itAudit(ctx, actor, "admin_reject_action", "", err)
	}
	op := func() error {
		req, err := o.st.GetAdminActionRequest(ctx, id)
		if err != nil {
			return err
		}
		if req.Status != domain.AdminActionPending {
			return fmt.Errorf("request %s is already %s", id, req.Status)
		}
		return o.st.DecideAdminActionRequest(ctx, id, domain.AdminActionRejected, actor.ID, reason, "")
	}
	return o.itAudit(ctx, actor, "admin_reject_action", "", op())
}

// executeAdminAction dispatches a sensitive action by type. New sensitive
// actions add a case here (and an AdminActionType constant).
func (o *Orchestrator) executeAdminAction(ctx context.Context, typ domain.AdminActionType, payload []byte) (string, error) {
	switch typ {
	case domain.AdminActionFederateDirectory:
		var d identityadmin.DirectoryFederation
		if err := json.Unmarshal(payload, &d); err != nil {
			return "", fmt.Errorf("decode federation payload: %w", err)
		}
		if err := o.idp.FederateDirectory(ctx, d); err != nil {
			return "", err
		}
		return fmt.Sprintf("directory %q federated; its users can now authenticate", d.Name), nil
	default:
		return "", fmt.Errorf("unknown sensitive admin action %q", typ)
	}
}

func vendorLabel(v string) string {
	if v == "ad" {
		return "Active Directory"
	}
	return "LDAP"
}

// AdminListIdentities lists the identities registered on this appliance (the
// Beamhall-side identity store, distinct from the IdP's user store). it_admin
// only; not audited per call.
func (o *Orchestrator) AdminListIdentities(ctx context.Context, actor Actor) ([]domain.Identity, error) {
	if err := o.requireIT(actor); err != nil {
		return nil, err
	}
	return o.st.ListIdentities(ctx)
}
