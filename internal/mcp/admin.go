package mcp

import (
	"context"
	"fmt"
	"strings"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Beamhall/beamhall/internal/auth"
	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/identityadmin"
	"github.com/Beamhall/beamhall/internal/orch"
)

// The admin_* tool family (PLAN §5.9): IT lifecycle over MCP, so an operator
// runs onboarding and IdP administration through the same channel as the rest
// of Beamhall instead of a separate web console. Every tool requires the
// admin:it scope (resolveActor enforces it before the call) and routes through
// the orchestrator, which is the single PEP and audit writer — the MCP layer
// stays a thin translation surface. admin:it is deliberately kept off the
// agent-facing scope advertisement (auth.AllScopes); it is granted out-of-band
// to IT operators, so a normal builder token can never reach these tools.
//
// Risk tiering (the guardrail decision): routine onboarding ops run
// autonomously and are audited; the SENSITIVE auth-config op
// (admin_federate_directory) fails closed unless the operator has enabled the
// sensitive tier — the human-in-the-loop opt-in.

type registerIdentityArgs struct {
	Issuer      string `json:"issuer" jsonschema:"the IdP issuer (iss) the identity authenticates against, e.g. https://idp.acme.internal/realms/beamhall"`
	Subject     string `json:"subject" jsonschema:"the stable IdP subject (sub) of the identity"`
	Email       string `json:"email,omitempty" jsonschema:"contact email"`
	DisplayName string `json:"display_name,omitempty" jsonschema:"human-readable name"`
}

type grantMembershipArgs struct {
	Beamhall   string `json:"beamhall" jsonschema:"slug of the beamhall (workspace) to grant access to"`
	Role       string `json:"role" jsonschema:"membership role: builder | beamhall_admin | viewer"`
	IdentityID string `json:"identity_id,omitempty" jsonschema:"the identity id from admin_register_identity (preferred). If omitted, give issuer+subject"`
	Issuer     string `json:"issuer,omitempty" jsonschema:"identity issuer (alternative to identity_id; the identity must already be registered)"`
	Subject    string `json:"subject,omitempty" jsonschema:"identity subject (alternative to identity_id)"`
}

type createBeamhallArgs struct {
	Slug         string `json:"slug" jsonschema:"DNS-safe workspace name: lowercase letters digits and inner hyphens"`
	DisplayName  string `json:"display_name,omitempty" jsonschema:"human-readable workspace name"`
	Department   string `json:"department,omitempty" jsonschema:"owning department/team"`
	RuntimeClass string `json:"runtime_class,omitempty" jsonschema:"isolation tier: runc (default) | runsc (gVisor, regulated)"`
}

type createUserArgs struct {
	Username  string `json:"username" jsonschema:"login username for the new account in the bundled IdP"`
	Email     string `json:"email,omitempty" jsonschema:"user email"`
	FirstName string `json:"first_name,omitempty" jsonschema:"given name"`
	LastName  string `json:"last_name,omitempty" jsonschema:"family name"`
}

type listUsersArgs struct {
	Query string `json:"query,omitempty" jsonschema:"free-text search over username/email/name; omit to list the first page"`
	Max   int    `json:"max,omitempty" jsonschema:"max results (default 100)"`
}

type setUserPasswordArgs struct {
	UserID   string `json:"user_id" jsonschema:"the IdP user id from admin_create_user / admin_list_users"`
	Password string `json:"password" jsonschema:"a temporary password; the user must change it at next login"`
}

type createGroupArgs struct {
	Name string `json:"name" jsonschema:"group name in the bundled IdP"`
}

type addUserToGroupArgs struct {
	UserID  string `json:"user_id" jsonschema:"the IdP user id"`
	GroupID string `json:"group_id" jsonschema:"the IdP group id from admin_create_group / admin_list_groups"`
}

type federateDirectoryArgs struct {
	Name          string `json:"name" jsonschema:"a label for the federation source, e.g. corp-ad"`
	Vendor        string `json:"vendor,omitempty" jsonschema:"directory kind: ad (Active Directory) | other (generic LDAP)"`
	ConnectionURL string `json:"connection_url" jsonschema:"LDAP endpoint, e.g. ldaps://dc1.corp.example:636"`
	UsersDN       string `json:"users_dn" jsonschema:"base DN to search for users, e.g. OU=Beamhall,DC=corp,DC=example"`
	BindDN        string `json:"bind_dn,omitempty" jsonschema:"service-account DN the IdP binds with"`
	BindPassword  string `json:"bind_password,omitempty" jsonschema:"service-account password (held by Beamhall; never returned)"`
}

// registerAdminTools registers the admin:it tool family. Called from
// registerTools.
func (s *Server) registerAdminTools() {
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_register_identity",
		Description: "IT only: register an external identity (IdP issuer + subject) on this appliance so it can be granted beamhall memberships. Idempotent. Returns the identity id to pass to admin_grant_membership. This is the Beamhall-side registration; it is separate from creating an account in the bundled IdP (admin_create_user).",
	}, s.adminRegisterIdentity)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_grant_membership",
		Description: "IT only: grant a registered identity a role (builder|beamhall_admin|viewer) in a beamhall. Identify the user by identity_id (from admin_register_identity) or by issuer+subject.",
	}, s.adminGrantMembership)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_list_identities",
		Description: "IT only: list the identities registered on this appliance (issuer, subject, email).",
	}, s.adminListIdentities)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_create_beamhall",
		Description: "IT only: create a beamhall (workspace) with an immutable hardening profile. runtime_class selects the isolation tier (runc default, or runsc/gVisor for regulated workloads).",
	}, s.adminCreateBeamhall)

	// Owned-IdP administration (bundled Keycloak). Disabled for bring-your-own-IdP.
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_create_user",
		Description: "IT only: create a local user account in the bundled IdP (onboarding). Idempotent on username. Pair with admin_set_user_password to hand out a first password. Only available when Beamhall runs its bundled IdP — for a corporate IdP, create users there.",
	}, s.adminCreateUser)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_list_users",
		Description: "IT only: list/search accounts in the bundled IdP.",
	}, s.adminListUsers)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_set_user_password",
		Description: "IT only: set a temporary password for a bundled-IdP user; the user must change it at next login.",
	}, s.adminSetUserPassword)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_create_group",
		Description: "IT only: create a group in the bundled IdP to organize users. Idempotent on name.",
	}, s.adminCreateGroup)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_list_groups",
		Description: "IT only: list groups in the bundled IdP.",
	}, s.adminListGroups)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_add_user_to_group",
		Description: "IT only: add a bundled-IdP user to a group.",
	}, s.adminAddUserToGroup)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_federate_directory",
		Description: "IT only, SENSITIVE: connect the bundled IdP to an existing LDAP/Active Directory so directory users authenticate without local accounts. This changes who can sign in to the whole appliance, so it requires human confirmation — it fails closed unless the sensitive-admin tier is enabled, directing you to the Admin console otherwise.",
	}, s.adminFederateDirectory)
}

func (s *Server) adminRegisterIdentity(ctx context.Context, req *sdkmcp.CallToolRequest, args registerIdentityArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	ident, err := s.bp.RegisterIdentity(ctx, actor, args.Issuer, args.Subject, args.Email, args.DisplayName)
	if err != nil {
		return nil, nil, err
	}
	return text(fmt.Sprintf("identity registered (id %s) for subject %q. Grant it access with admin_grant_membership (identity_id %s).",
		ident.ID, ident.ExternalSubject, ident.ID)), map[string]string{"identity_id": string(ident.ID)}, nil
}

func (s *Server) adminGrantMembership(ctx context.Context, req *sdkmcp.CallToolRequest, args grantMembershipArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	role, err := parseRole(args.Role)
	if err != nil {
		return nil, nil, err
	}
	bh, err := s.resolveBeamhall(ctx, args.Beamhall)
	if err != nil {
		return nil, nil, err
	}
	identID := domain.ID(args.IdentityID)
	if identID == "" {
		if args.Issuer == "" || args.Subject == "" {
			return nil, nil, fmt.Errorf("give identity_id, or both issuer and subject")
		}
		ident, err := s.dir.GetIdentityByIssuerSubject(ctx, args.Issuer, args.Subject)
		if err != nil {
			return nil, nil, fmt.Errorf("no registered identity for that issuer+subject — run admin_register_identity first")
		}
		identID = ident.ID
	}
	if err := s.bp.GrantMembership(ctx, actor, identID, bh.ID, role); err != nil {
		return nil, nil, err
	}
	return text(fmt.Sprintf("granted %s role %q in beamhall %q.", identID, role, bh.Slug)), nil, nil
}

func (s *Server) adminListIdentities(ctx context.Context, req *sdkmcp.CallToolRequest, args struct{}) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	idents, err := s.bp.AdminListIdentities(ctx, actor)
	if err != nil {
		return nil, nil, err
	}
	if len(idents) == 0 {
		return text("no identities registered yet."), nil, nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d registered identit(ies):\n", len(idents))
	out := make([]map[string]string, 0, len(idents))
	for _, id := range idents {
		fmt.Fprintf(&b, "  - %s  subject=%s  email=%s  issuer=%s\n", id.ID, id.ExternalSubject, id.Email, id.IdPIssuer)
		out = append(out, map[string]string{"identity_id": string(id.ID), "subject": id.ExternalSubject, "email": id.Email, "issuer": id.IdPIssuer})
	}
	return text(b.String()), map[string]any{"identities": out}, nil
}

func (s *Server) adminCreateBeamhall(ctx context.Context, req *sdkmcp.CallToolRequest, args createBeamhallArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	rc := domain.RuntimeRunc
	switch strings.ToLower(args.RuntimeClass) {
	case "", "runc":
		rc = domain.RuntimeRunc
	case "runsc", "gvisor":
		rc = domain.RuntimeRunsc
	default:
		return nil, nil, fmt.Errorf("runtime_class must be runc or runsc, got %q", args.RuntimeClass)
	}
	bh, err := s.bp.CreateBeamhall(ctx, actor, orch.NewBeamhallSpec{
		Slug: args.Slug, DisplayName: args.DisplayName, Department: args.Department, RuntimeClass: rc,
	})
	if err != nil {
		return nil, nil, err
	}
	return text(fmt.Sprintf("beamhall %q created (runtime_class %s). Grant builders access with admin_grant_membership.", bh.Slug, rc)),
		map[string]string{"beamhall": bh.Slug}, nil
}

func (s *Server) adminCreateUser(ctx context.Context, req *sdkmcp.CallToolRequest, args createUserArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	u, err := s.bp.AdminCreateUser(ctx, actor, identityadmin.NewUser{
		Username: args.Username, Email: args.Email, FirstName: args.FirstName, LastName: args.LastName, Enabled: true,
	})
	if err != nil {
		return nil, nil, idpErr(err)
	}
	return text(fmt.Sprintf("user %q created (id %s). Set a first password with admin_set_user_password, then have them sign in and you can admin_register_identity + admin_grant_membership for their access.",
		u.Username, u.ID)), map[string]string{"user_id": u.ID, "username": u.Username}, nil
}

func (s *Server) adminListUsers(ctx context.Context, req *sdkmcp.CallToolRequest, args listUsersArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	users, err := s.bp.AdminListUsers(ctx, actor, args.Query, args.Max)
	if err != nil {
		return nil, nil, idpErr(err)
	}
	if len(users) == 0 {
		return text("no matching users."), nil, nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d user(s):\n", len(users))
	out := make([]map[string]any, 0, len(users))
	for _, u := range users {
		fmt.Fprintf(&b, "  - %s  username=%s  email=%s  enabled=%v\n", u.ID, u.Username, u.Email, u.Enabled)
		out = append(out, map[string]any{"user_id": u.ID, "username": u.Username, "email": u.Email, "enabled": u.Enabled})
	}
	return text(b.String()), map[string]any{"users": out}, nil
}

func (s *Server) adminSetUserPassword(ctx context.Context, req *sdkmcp.CallToolRequest, args setUserPasswordArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	if err := s.bp.AdminSetUserPassword(ctx, actor, args.UserID, args.Password); err != nil {
		return nil, nil, idpErr(err)
	}
	return text(fmt.Sprintf("temporary password set for user %s; they must change it at next login.", args.UserID)), nil, nil
}

func (s *Server) adminCreateGroup(ctx context.Context, req *sdkmcp.CallToolRequest, args createGroupArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	g, err := s.bp.AdminCreateGroup(ctx, actor, args.Name)
	if err != nil {
		return nil, nil, idpErr(err)
	}
	return text(fmt.Sprintf("group %q created (id %s).", g.Name, g.ID)), map[string]string{"group_id": g.ID, "name": g.Name}, nil
}

func (s *Server) adminListGroups(ctx context.Context, req *sdkmcp.CallToolRequest, args struct{}) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	groups, err := s.bp.AdminListGroups(ctx, actor)
	if err != nil {
		return nil, nil, idpErr(err)
	}
	if len(groups) == 0 {
		return text("no groups."), nil, nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d group(s):\n", len(groups))
	out := make([]map[string]string, 0, len(groups))
	for _, g := range groups {
		fmt.Fprintf(&b, "  - %s  name=%s  path=%s\n", g.ID, g.Name, g.Path)
		out = append(out, map[string]string{"group_id": g.ID, "name": g.Name, "path": g.Path})
	}
	return text(b.String()), map[string]any{"groups": out}, nil
}

func (s *Server) adminAddUserToGroup(ctx context.Context, req *sdkmcp.CallToolRequest, args addUserToGroupArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	if err := s.bp.AdminAddUserToGroup(ctx, actor, args.UserID, args.GroupID); err != nil {
		return nil, nil, idpErr(err)
	}
	return text(fmt.Sprintf("user %s added to group %s.", args.UserID, args.GroupID)), nil, nil
}

func (s *Server) adminFederateDirectory(ctx context.Context, req *sdkmcp.CallToolRequest, args federateDirectoryArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	err = s.bp.AdminFederateDirectory(ctx, actor, identityadmin.DirectoryFederation{
		Name: args.Name, Vendor: args.Vendor, ConnectionURL: args.ConnectionURL,
		UsersDN: args.UsersDN, BindDN: args.BindDN, BindCredential: args.BindPassword,
	})
	if err != nil {
		return nil, nil, idpErr(err)
	}
	return text(fmt.Sprintf("directory %q federated; its users can now authenticate. Register the ones who should use Beamhall (admin_register_identity) and grant memberships.", args.Name)), nil, nil
}

// parseRole maps the agent-facing role string to a MembershipRole.
func parseRole(s string) (domain.MembershipRole, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case string(domain.RoleBuilder):
		return domain.RoleBuilder, nil
	case string(domain.RoleBeamhallAdmin):
		return domain.RoleBeamhallAdmin, nil
	case string(domain.RoleViewer):
		return domain.RoleViewer, nil
	default:
		return "", fmt.Errorf("role must be builder, beamhall_admin or viewer, got %q", s)
	}
}

// idpErr adds an actionable hint when an IdP-admin op fails because the
// appliance does not administer its IdP (a BYO-IdP deployment).
func idpErr(err error) error {
	if err != nil && strings.Contains(err.Error(), identityadmin.ErrNotEnabled.Error()) {
		return fmt.Errorf("%w — this appliance uses an external IdP; manage users/groups in that IdP, or run Beamhall's bundled Keycloak to administer identities here", err)
	}
	return err
}
