package orch

import (
	"context"
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

// AdminFederateDirectory configures an LDAP/AD user-federation source on the
// owned IdP — the SENSITIVE tier. it_admin only, AND the sensitive tier must be
// enabled; otherwise it fails closed (the denied attempt is audited).
func (o *Orchestrator) AdminFederateDirectory(ctx context.Context, actor Actor, d identityadmin.DirectoryFederation) error {
	if err := o.requireIT(actor); err != nil {
		return o.itAudit(ctx, actor, "admin_federate_directory", "", err)
	}
	if !o.idpSensitive {
		err := fmt.Errorf("directory federation is a sensitive auth-config change that requires IT confirmation; " +
			"it is not enabled on this appliance (set the sensitive-admin opt-in, or perform it in the Admin console)")
		return o.itAudit(ctx, actor, "admin_federate_directory", "", err)
	}
	return o.itAudit(ctx, actor, "admin_federate_directory", "", o.idp.FederateDirectory(ctx, d))
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
