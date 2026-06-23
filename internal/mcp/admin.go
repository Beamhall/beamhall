package mcp

import (
	"context"
	"fmt"
	"strings"
	"time"

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
	// Quota is baked into the workspace at creation; omit for sensible defaults.
	// A zero quota would make the workspace unusable (no beams can be created).
	MaxBeams     int `json:"max_beams,omitempty" jsonschema:"max beams (preview workloads) builders may create; default 5"`
	MaxLiveSlots int `json:"max_live_slots,omitempty" jsonschema:"max beams promoted to a live URL at once; default 1"`
	MaxDatabases int `json:"max_databases,omitempty" jsonschema:"max managed Postgres databases; default 2"`
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

type showBeamhallArgs struct {
	Slug string `json:"slug" jsonschema:"beamhall (workspace) slug — from admin_list_beamhalls"`
}

type setEgressArgs struct {
	Slug      string   `json:"slug" jsonschema:"beamhall (workspace) slug"`
	Mode      string   `json:"mode" jsonschema:"egress mode: deny_all (fully isolated, default) | allowlist"`
	Allowlist []string `json:"allowlist,omitempty" jsonschema:"FQDN/CIDR[:port] entries beams in this workspace may reach (used when mode=allowlist)"`
}

type updateBeamhallArgs struct {
	Slug         string `json:"slug" jsonschema:"beamhall (workspace) slug to update"`
	MaxBeams     *int   `json:"max_beams,omitempty" jsonschema:"new cap on preview beams builders may create"`
	MaxLiveSlots *int   `json:"max_live_slots,omitempty" jsonschema:"new cap on simultaneously-live (promoted) beams"`
	MaxDatabases *int   `json:"max_databases,omitempty" jsonschema:"new cap on managed Postgres databases"`
	Status       string `json:"status,omitempty" jsonschema:"new lifecycle status: active | suspended (freeze: PEP denies all actions in the workspace) | archived (decommission)"`
	DisplayName  string `json:"display_name,omitempty" jsonschema:"new human-readable workspace name"`
	Department   string `json:"department,omitempty" jsonschema:"new owning department/team"`
}

type revokeMembershipArgs struct {
	Beamhall   string `json:"beamhall" jsonschema:"slug of the beamhall (workspace) to remove access from"`
	IdentityID string `json:"identity_id,omitempty" jsonschema:"the identity id to revoke (from admin_list_identities / admin_show_beamhall). If omitted, give issuer+subject"`
	Issuer     string `json:"issuer,omitempty" jsonschema:"identity issuer (alternative to identity_id)"`
	Subject    string `json:"subject,omitempty" jsonschema:"identity subject (alternative to identity_id)"`
}

type setIdentityStatusArgs struct {
	Status     string `json:"status" jsonschema:"active (restore access) | disabled (kill switch: the identity keeps its row but every authorization fails)"`
	IdentityID string `json:"identity_id,omitempty" jsonschema:"the identity id (from admin_list_identities). If omitted, give issuer+subject"`
	Issuer     string `json:"issuer,omitempty" jsonschema:"identity issuer (alternative to identity_id)"`
	Subject    string `json:"subject,omitempty" jsonschema:"identity subject (alternative to identity_id)"`
}

type deregisterIdentityArgs struct {
	IdentityID string `json:"identity_id,omitempty" jsonschema:"the identity id to remove (from admin_list_identities). If omitted, give issuer+subject"`
	Issuer     string `json:"issuer,omitempty" jsonschema:"identity issuer (alternative to identity_id)"`
	Subject    string `json:"subject,omitempty" jsonschema:"identity subject (alternative to identity_id)"`
}

type listReleasesArgs struct {
	Beamhall string `json:"beamhall" jsonschema:"beamhall (workspace) slug"`
	Beam     string `json:"beam" jsonschema:"beam slug"`
}

type queryAuditArgs struct {
	Beamhall string `json:"beamhall,omitempty" jsonschema:"optional workspace slug to scope the log to one beamhall; omit for appliance-wide"`
	AfterSeq int64  `json:"after_seq,omitempty" jsonschema:"return events with sequence number greater than this (pagination cursor; omit to start at the oldest retained event)"`
	Limit    int    `json:"limit,omitempty" jsonschema:"max events to return (default 100, max 1000)"`
}

type setUserEnabledArgs struct {
	UserID  string `json:"user_id" jsonschema:"the bundled-IdP user id (from admin_list_users)"`
	Enabled bool   `json:"enabled" jsonschema:"true to enable the account, false to disable it (offboard without deleting)"`
}

type setMembershipRoleArgs struct {
	Beamhall   string `json:"beamhall" jsonschema:"workspace slug"`
	Role       string `json:"role" jsonschema:"new role: builder | beamhall_admin | viewer"`
	IdentityID string `json:"identity_id,omitempty" jsonschema:"identity id (from admin_list_identities). If omitted, give issuer+subject"`
	Issuer     string `json:"issuer,omitempty" jsonschema:"identity issuer (alternative to identity_id)"`
	Subject    string `json:"subject,omitempty" jsonschema:"identity subject (alternative to identity_id)"`
}

type removeUserFromGroupArgs struct {
	UserID  string `json:"user_id" jsonschema:"the bundled-IdP user id"`
	GroupID string `json:"group_id" jsonschema:"the bundled-IdP group id (from admin_list_groups)"`
}

type deleteUserArgs struct {
	UserID string `json:"user_id" jsonschema:"the bundled-IdP user id to permanently delete (from admin_list_users)"`
}

type deleteGroupArgs struct {
	GroupID string `json:"group_id" jsonschema:"the bundled-IdP group id to permanently delete (from admin_list_groups)"`
}

type setSecurityContextArgs struct {
	Slug         string `json:"slug" jsonschema:"workspace slug"`
	RuntimeClass string `json:"runtime_class" jsonschema:"isolation tier: runc | runsc (gVisor, regulated)"`
}

type unfederateDirectoryArgs struct {
	Name string `json:"name" jsonschema:"the federation source name/label to remove (from the original admin_federate_directory)"`
}

type pruneAuditArgs struct {
	ThroughSeq int64 `json:"through_seq" jsonschema:"prune (permanently remove) audit events with sequence number ≤ this; find it via admin_query_audit"`
}

type restoreBackupArgs struct {
	Name string `json:"name" jsonschema:"the backup archive name to restore from (from admin_list_backups)"`
}

type requestUpgradeArgs struct {
	Version string `json:"version" jsonschema:"the target release version to upgrade to, e.g. v0.1.11"`
}

// registerAdminTools registers the admin:it tool family. Called from
// registerTools.
func (s *Server) registerAdminTools() {
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_register_identity",
		Description: "IT only: register an external identity (IdP issuer + subject) on this appliance so it can be granted beamhall memberships. Registration alone grants NO access — it only makes the identity known; access requires a role via admin_grant_membership. Idempotent. Returns the identity id to pass to admin_grant_membership. This is the Beamhall-side registration; it is separate from creating an account in the bundled IdP (admin_create_user).",
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
		Description: "IT only: create a beamhall (workspace) with an immutable hardening profile. A new workspace has NO members — nobody can act in it until you grant a registered identity a role with admin_grant_membership. runtime_class selects the isolation tier (runc default, or runsc/gVisor for regulated workloads).",
	}, s.adminCreateBeamhall)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_list_beamhalls",
		Description: "IT only: list every beamhall (workspace) on the appliance — appliance-wide, NOT membership-scoped (unlike list_beams). Shows slug, runtime tier, egress mode, quota, status, and beam/member counts.",
	}, s.adminListBeamhalls)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_show_beamhall",
		Description: "IT only: show one beamhall in detail — runtime tier, egress policy, quota, its members (with roles), and its beams (with state). Use admin_list_beamhalls to discover slugs.",
	}, s.adminShowBeamhall)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_set_egress",
		Description: "IT only: set a beamhall's egress policy. mode is deny_all (default isolation) or allowlist; allowlist is FQDN/CIDR[:port] entries reachable from beams in that workspace. Re-asserted on the next deploy (and immediately if egress sync is wired).",
	}, s.adminSetEgress)

	// Owned-IdP administration (bundled Keycloak). Disabled for bring-your-own-IdP.
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_create_user",
		Description: "IT only: create a local user account in the bundled IdP (onboarding). An account alone grants NO Beamhall access — this only creates a login; access requires registering the signed-in identity (admin_register_identity) and granting it a role (admin_grant_membership). Idempotent on username. Pair with admin_set_user_password to hand out a first password. Only available when Beamhall runs its bundled IdP — for a corporate IdP, create users there.",
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
		Description: "IT only, SENSITIVE (four-eyes): request connecting the bundled IdP to an existing LDAP/Active Directory so directory users authenticate without local accounts. This changes who can sign in to the whole appliance, so it does NOT execute immediately — it files a request that a DIFFERENT IT operator must approve with admin_approve_request. Requires the sensitive tier to be enabled (BEAMHALL_IDP_SENSITIVE_ADMIN=on).",
	}, s.adminFederateDirectory)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_list_pending_requests",
		Description: "IT only: list sensitive admin actions (e.g. directory federation) awaiting four-eyes approval. Shows a non-secret summary of each; secrets in the request stay sealed.",
	}, s.adminListPendingRequests)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_approve_request",
		Description: "IT only: approve and EXECUTE a pending sensitive admin action. The approver must differ from the requester (four-eyes/separation of duties).",
	}, s.adminApproveRequest)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_reject_request",
		Description: "IT only: reject a pending sensitive admin action without executing it.",
	}, s.adminRejectRequest)

	// Lifecycle / management surface (the UPDATE + DELETE half): post-create
	// edits, offboarding kill switches, the audit read surface, and release
	// history. All it_admin, all audited.
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_update_beamhall",
		Description: "IT only: change an existing workspace's quota (max_beams / max_live_slots / max_databases), lifecycle status, or metadata (display_name / department). status=suspended FREEZES the workspace (the policy engine then denies every action in it — deploys, agent calls, everything); status=archived decommissions it; status=active reactivates. Only the fields you pass change. Quota/live-slot limits are IT-owned and cannot be raised by builders — this is the path to resize a workspace after creation.",
	}, s.adminUpdateBeamhall)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_revoke_membership",
		Description: "IT only: remove an identity's access (membership) to a workspace — offboarding. Identify the user by identity_id (from admin_list_identities / admin_show_beamhall) or by issuer+subject. The grant counterpart is admin_grant_membership.",
	}, s.adminRevokeMembership)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_set_identity_status",
		Description: "IT only: enable or disable a registered identity appliance-wide — the per-principal kill switch. status=disabled keeps the identity's row and audit history but makes EVERY authorization fail (the user can sign in to the IdP but Beamhall refuses them); status=active restores access. Use admin_set_user_enabled to also disable the underlying IdP account.",
	}, s.adminSetIdentityStatus)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_list_releases",
		Description: "IT only: list a beam's PRODUCTION (live) release history, newest first, as a clean v1,v2,… sequence with the release version to pass to rollback's to_version. Use it to pick a rollback target.",
	}, s.adminListReleases)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_query_audit",
		Description: "IT only: read the hash-chained audit log — every authorization decision (allow/deny), who, what action, on which workspace/beam, and why. Appliance-wide, or scope to one workspace with `beamhall`. Paginate with after_seq (pass the next_after_seq from the previous page); limit defaults to 100 (max 1000). This is the regulated audit trail, now readable over MCP.",
	}, s.adminQueryAudit)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_verify_audit_chain",
		Description: "IT only: verify the tamper-evidence of the audit log — walk the hash chain and report whether it is intact or list any integrity violations (seq gaps, broken hash links). Use it to demonstrate the log has not been altered.",
	}, s.adminVerifyAuditChain)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_set_user_enabled",
		Description: "IT only: enable or disable a bundled-IdP account — offboarding (or re-activating) a user WITHOUT deleting the account (its history/linkage is kept). A disabled account cannot authenticate at all. Only available when Beamhall runs its bundled IdP.",
	}, s.adminSetUserEnabled)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_set_membership_role",
		Description: "IT only: change a member's role in a workspace in place (e.g. promote viewer→builder). Identify the member by identity_id (from admin_list_identities / admin_show_beamhall) or issuer+subject. Roles: builder | beamhall_admin | viewer.",
	}, s.adminSetMembershipRole)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_deregister_identity",
		Description: "IT only: remove a registered identity entirely (cleanup of an offboarded principal — the admin_register_identity inverse). Refuses while the identity still has any workspace membership — revoke those first (admin_revoke_membership). Identify by identity_id (from admin_list_identities) or issuer+subject. Audit history referencing the identity is preserved.",
	}, s.adminDeregisterIdentity)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_remove_user_from_group",
		Description: "IT only: remove a bundled-IdP user from a group (the admin_add_user_to_group inverse). Only available when Beamhall runs its bundled IdP.",
	}, s.adminRemoveUserFromGroup)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_delete_user",
		Description: "IT only: PERMANENTLY delete a bundled-IdP account. This is irreversible — prefer admin_set_user_enabled (disable) for offboarding, which is reversible and keeps the account's linkage; use delete only for genuine cleanup (e.g. a mistakenly-created account). Only available when Beamhall runs its bundled IdP.",
	}, s.adminDeleteUser)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_delete_group",
		Description: "IT only: PERMANENTLY delete a bundled-IdP group. Members are un-grouped, not deleted. Only available when Beamhall runs its bundled IdP.",
	}, s.adminDeleteGroup)

	// SENSITIVE management actions — four-eyes (a DIFFERENT IT operator approves
	// via admin_approve_request). They mutate isolation posture, sign-in, or
	// tamper-evidence, so they're never executed by the requester.
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_set_security_context",
		Description: "IT only, SENSITIVE (four-eyes): change a workspace's runtime isolation class (runc ↔ runsc/gVisor). This alters the hardening posture and can weaken the regulated gVisor tier, so it does NOT apply immediately — it files a request a DIFFERENT IT operator must approve with admin_approve_request. Applies to NEW deploys. Requires the sensitive tier (BEAMHALL_IDP_SENSITIVE_ADMIN=on).",
	}, s.adminSetSecurityContext)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_unfederate_directory",
		Description: "IT only, SENSITIVE (four-eyes): remove a directory (LDAP/AD) federation by name — its directory users lose access. The admin_federate_directory inverse. Files a request a DIFFERENT IT operator must approve. Requires the sensitive tier and the bundled IdP.",
	}, s.adminUnfederateDirectory)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_prune_audit",
		Description: "IT only, SENSITIVE (four-eyes): prune the audit log up to a sequence number (retention). It permanently removes older rows below a written checkpoint — destroying tamper-evidence — so it files a request a DIFFERENT IT operator must approve. Find the through_seq via admin_query_audit. Requires the sensitive tier.",
	}, s.adminPruneAudit)

	// Appliance backup/restore.
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_backup_now",
		Description: "IT only: take an appliance backup now — an online snapshot of the control-plane DB plus the sealed secret root key and the managed git repos, written to the backup directory. Returns the archive name + manifest. Use admin_list_backups to see them.",
	}, s.adminBackupNow)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_list_backups",
		Description: "IT only: list the appliance backups (newest first) with each archive's creation time, size, contents, and integrity-verification status.",
	}, s.adminListBackups)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_restore_backup",
		Description: "IT only, SENSITIVE (four-eyes): restore the appliance from a named backup (overwrites the WHOLE control plane). It is never applied live — it files a request a DIFFERENT IT operator must approve; on approval the backup is verified and you get the exact stop→restore→start command to run on the host (restore is a stop-the-world operation). Requires the sensitive tier. Use admin_list_backups for the name.",
	}, s.adminRestoreBackup)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "admin_request_upgrade",
		Description: "IT only, SENSITIVE (four-eyes): upgrade the appliance to a target release version (e.g. v0.1.11) — this replaces the policy-enforcing binary, so it is the most-guarded action. It files a request a DIFFERENT IT operator must approve; on approval the release is downloaded, its checksum verified, and the new binary STAGED (never applied live). You then get the exact atomic apply + rollback commands to run on the host. Requires self-upgrade to be enabled (BEAMHALL_SELF_UPGRADE=on) and the sensitive tier.",
	}, s.adminRequestUpgrade)
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

func (s *Server) adminListBeamhalls(ctx context.Context, req *sdkmcp.CallToolRequest, args struct{}) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	halls, err := s.bp.AdminListBeamhalls(ctx, actor)
	if err != nil {
		return nil, nil, err
	}
	if len(halls) == 0 {
		return text("no beamhalls (workspaces) exist yet. Create one with admin_create_beamhall."), nil, nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d beamhall(s):\n", len(halls))
	out := make([]map[string]any, 0, len(halls))
	for _, h := range halls {
		fmt.Fprintf(&b, "  - %s  status=%s  egress=%s  quota=%d beams/%d live/%d db\n",
			h.Slug, h.Status, h.NetworkPolicy.EgressMode, h.Quota.MaxBeams, h.LiveSlotLimit, h.Quota.MaxDBCount)
		out = append(out, map[string]any{
			"slug": h.Slug, "display_name": h.DisplayName, "department": h.Department,
			"status": string(h.Status), "egress_mode": string(h.NetworkPolicy.EgressMode),
			"max_beams": h.Quota.MaxBeams, "max_live_slots": h.LiveSlotLimit, "max_databases": h.Quota.MaxDBCount,
		})
	}
	return text(b.String()), map[string]any{"beamhalls": out}, nil
}

func (s *Server) adminShowBeamhall(ctx context.Context, req *sdkmcp.CallToolRequest, args showBeamhallArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	v, err := s.bp.AdminBeamhallView(ctx, actor, args.Slug)
	if err != nil {
		return nil, nil, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "beamhall %q (status %s)\n", v.Slug, v.Status)
	fmt.Fprintf(&b, "  egress: %s  allowlist=%v\n", v.NetworkPolicy.EgressMode, v.NetworkPolicy.EgressAllowlist)
	fmt.Fprintf(&b, "  quota:  %d beams / %d live slots / %d databases\n", v.Quota.MaxBeams, v.LiveSlotLimit, v.Quota.MaxDBCount)
	fmt.Fprintf(&b, "  members (%d):\n", len(v.Members))
	mem := make([]map[string]string, 0, len(v.Members))
	for _, m := range v.Members {
		fmt.Fprintf(&b, "    - %s  role=%s  email=%s\n", m.Subject, m.Role, m.Email)
		mem = append(mem, map[string]string{"subject": m.Subject, "email": m.Email, "role": m.Role, "identity_id": m.IdentityID})
	}
	fmt.Fprintf(&b, "  beams (%d):\n", len(v.Beams))
	beams := make([]map[string]string, 0, len(v.Beams))
	for _, bm := range v.Beams {
		line := fmt.Sprintf("    - %s  state=%s  mode=%s  live=%s", bm.Slug, bm.State, bm.Mode, bm.LiveState)
		if bm.PreviewURL != "" {
			line += "  preview=" + bm.PreviewURL
		}
		if bm.LiveURL != "" {
			line += "  live_url=" + bm.LiveURL
		}
		fmt.Fprintln(&b, line)
		beams = append(beams, map[string]string{"slug": bm.Slug, "state": bm.State, "mode": bm.Mode,
			"live_state": bm.LiveState, "preview_url": bm.PreviewURL, "live_url": bm.LiveURL})
	}
	return text(b.String()), map[string]any{
		"slug": v.Slug, "status": string(v.Status), "egress_mode": string(v.NetworkPolicy.EgressMode),
		"allowlist": v.NetworkPolicy.EgressAllowlist, "members": mem, "beams": beams,
	}, nil
}

func (s *Server) adminSetEgress(ctx context.Context, req *sdkmcp.CallToolRequest, args setEgressArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	var mode domain.EgressMode
	switch args.Mode {
	case "deny_all", "":
		mode = domain.EgressDenyAll
	case "allowlist", "allow_set":
		mode = domain.EgressAllowSet
	default:
		return nil, nil, fmt.Errorf("mode must be deny_all or allowlist, got %q", args.Mode)
	}
	bh, err := s.resolveBeamhall(ctx, args.Slug)
	if err != nil {
		return nil, nil, err
	}
	if err := s.bp.SetEgress(ctx, actor, bh.ID, mode, args.Allowlist); err != nil {
		return nil, nil, err
	}
	return text(fmt.Sprintf("egress for %q set to %s (%d allowlist entr%s). Re-asserted on the next deploy.",
		args.Slug, mode, len(args.Allowlist), map[bool]string{true: "y", false: "ies"}[len(args.Allowlist) == 1])), nil, nil
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
	// Default the quota so a workspace created over MCP is usable immediately;
	// a zero quota fails every create_beam ("max_beams 0 of 0"). Mirrors the
	// Admin console defaults (internal/web/actions.go).
	q := domain.ResourceQuota{MaxBeams: args.MaxBeams, MaxLiveSlots: args.MaxLiveSlots, MaxDBCount: args.MaxDatabases}
	if q.MaxBeams == 0 {
		q.MaxBeams = 5
	}
	if q.MaxLiveSlots == 0 {
		q.MaxLiveSlots = 1
	}
	if q.MaxDBCount == 0 {
		q.MaxDBCount = 2
	}
	bh, err := s.bp.CreateBeamhall(ctx, actor, orch.NewBeamhallSpec{
		Slug: args.Slug, DisplayName: args.DisplayName, Department: args.Department, RuntimeClass: rc,
		Quota: q, LiveSlots: q.MaxLiveSlots,
	})
	if err != nil {
		return nil, nil, err
	}
	return text(fmt.Sprintf("beamhall %q created (runtime_class %s; quota %d beams / %d live / %d databases). Grant builders access with admin_grant_membership.",
			bh.Slug, rc, q.MaxBeams, q.MaxLiveSlots, q.MaxDBCount)),
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
	ar, err := s.bp.RequestFederateDirectory(ctx, actor, identityadmin.DirectoryFederation{
		Name: args.Name, Vendor: args.Vendor, ConnectionURL: args.ConnectionURL,
		UsersDN: args.UsersDN, BindDN: args.BindDN, BindCredential: args.BindPassword,
	})
	if err != nil {
		return nil, nil, idpErr(err)
	}
	return text(fmt.Sprintf("federation of directory %q requested (request %s). This is a SENSITIVE change to who can sign in, so it does not take effect yet — a DIFFERENT IT operator must run admin_approve_request %s. The bind password is sealed at rest.",
		args.Name, ar.ID, ar.ID)), map[string]string{"request_id": string(ar.ID)}, nil
}

type adminRequestDecisionArgs struct {
	RequestID string `json:"request_id" jsonschema:"the request id from admin_federate_directory or admin_list_pending_requests"`
	Reason    string `json:"reason,omitempty" jsonschema:"reason for rejection (admin_reject_request only)"`
}

func (s *Server) adminListPendingRequests(ctx context.Context, req *sdkmcp.CallToolRequest, args struct{}) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	reqs, err := s.bp.ListPendingAdminActions(ctx, actor)
	if err != nil {
		return nil, nil, err
	}
	if len(reqs) == 0 {
		return text("no sensitive admin actions are pending approval."), nil, nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d sensitive action(s) awaiting four-eyes approval:\n", len(reqs))
	out := make([]map[string]string, 0, len(reqs))
	for _, r := range reqs {
		fmt.Fprintf(&b, "  - %s  type=%s  requested_by=%s  %s\n", r.ID, r.ActionType, r.RequestedBy, r.Summary)
		out = append(out, map[string]string{"request_id": string(r.ID), "type": string(r.ActionType), "requested_by": string(r.RequestedBy), "summary": r.Summary})
	}
	return text(b.String()), map[string]any{"requests": out}, nil
}

func (s *Server) adminApproveRequest(ctx context.Context, req *sdkmcp.CallToolRequest, args adminRequestDecisionArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	ar, err := s.bp.ApproveAdminAction(ctx, actor, domain.ID(args.RequestID))
	if err != nil {
		return nil, nil, idpErr(err)
	}
	msg := fmt.Sprintf("request %s approved and executed", args.RequestID)
	if ar.Result != "" {
		msg += ": " + ar.Result
	}
	return text(msg + "."), nil, nil
}

func (s *Server) adminRejectRequest(ctx context.Context, req *sdkmcp.CallToolRequest, args adminRequestDecisionArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	if err := s.bp.RejectAdminAction(ctx, actor, domain.ID(args.RequestID), args.Reason); err != nil {
		return nil, nil, err
	}
	return text(fmt.Sprintf("request %s rejected.", args.RequestID)), nil, nil
}

func (s *Server) adminSetMembershipRole(ctx context.Context, req *sdkmcp.CallToolRequest, args setMembershipRoleArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	role, err := parseRole(args.Role)
	if err != nil {
		return nil, nil, err
	}
	identID, err := s.resolveIdentityRef(ctx, args.IdentityID, args.Issuer, args.Subject)
	if err != nil {
		return nil, nil, err
	}
	bh, err := s.resolveBeamhall(ctx, args.Beamhall)
	if err != nil {
		return nil, nil, err
	}
	if err := s.bp.SetMembershipRole(ctx, actor, identID, bh.ID, role); err != nil {
		return nil, nil, err
	}
	return text(fmt.Sprintf("member %s in beamhall %q now has role %q.", identID, bh.Slug, role)),
		map[string]string{"identity_id": string(identID), "beamhall": bh.Slug, "role": string(role)}, nil
}

func (s *Server) adminDeregisterIdentity(ctx context.Context, req *sdkmcp.CallToolRequest, args deregisterIdentityArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	identID, err := s.resolveIdentityRef(ctx, args.IdentityID, args.Issuer, args.Subject)
	if err != nil {
		return nil, nil, err
	}
	if err := s.bp.DeregisterIdentity(ctx, actor, identID); err != nil {
		return nil, nil, err
	}
	return text(fmt.Sprintf("identity %s deregistered.", identID)),
		map[string]string{"identity_id": string(identID)}, nil
}

func (s *Server) adminRemoveUserFromGroup(ctx context.Context, req *sdkmcp.CallToolRequest, args removeUserFromGroupArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	if err := s.bp.AdminRemoveUserFromGroup(ctx, actor, args.UserID, args.GroupID); err != nil {
		return nil, nil, idpErr(err)
	}
	return text(fmt.Sprintf("user %s removed from group %s.", args.UserID, args.GroupID)), nil, nil
}

func (s *Server) adminDeleteUser(ctx context.Context, req *sdkmcp.CallToolRequest, args deleteUserArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	if err := s.bp.AdminDeleteUser(ctx, actor, args.UserID); err != nil {
		return nil, nil, idpErr(err)
	}
	return text(fmt.Sprintf("bundled-IdP user %s permanently deleted.", args.UserID)),
		map[string]string{"user_id": args.UserID}, nil
}

func (s *Server) adminDeleteGroup(ctx context.Context, req *sdkmcp.CallToolRequest, args deleteGroupArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	if err := s.bp.AdminDeleteGroup(ctx, actor, args.GroupID); err != nil {
		return nil, nil, idpErr(err)
	}
	return text(fmt.Sprintf("bundled-IdP group %s permanently deleted.", args.GroupID)),
		map[string]string{"group_id": args.GroupID}, nil
}

// sensitiveRequestReply renders the four-eyes "request filed, a different
// operator must approve" response shared by the sensitive management tools.
func sensitiveRequestReply(ar domain.AdminActionRequest) *sdkmcp.CallToolResult {
	return text(fmt.Sprintf("%s — SENSITIVE, so it does NOT take effect yet (request %s). A DIFFERENT IT operator must run admin_approve_request %s (the requester cannot approve their own). Review the queue with admin_list_pending_requests.",
		ar.Summary, ar.ID, ar.ID))
}

func (s *Server) adminSetSecurityContext(ctx context.Context, req *sdkmcp.CallToolRequest, args setSecurityContextArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	var rc domain.RuntimeClass
	switch strings.ToLower(args.RuntimeClass) {
	case "runc":
		rc = domain.RuntimeRunc
	case "runsc", "gvisor":
		rc = domain.RuntimeRunsc
	default:
		return nil, nil, fmt.Errorf("runtime_class must be runc or runsc, got %q", args.RuntimeClass)
	}
	ar, err := s.bp.RequestSetSecurityContext(ctx, actor, args.Slug, rc)
	if err != nil {
		return nil, nil, err
	}
	return sensitiveRequestReply(ar), map[string]string{"request_id": string(ar.ID)}, nil
}

func (s *Server) adminUnfederateDirectory(ctx context.Context, req *sdkmcp.CallToolRequest, args unfederateDirectoryArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	ar, err := s.bp.RequestUnfederateDirectory(ctx, actor, args.Name)
	if err != nil {
		return nil, nil, idpErr(err)
	}
	return sensitiveRequestReply(ar), map[string]string{"request_id": string(ar.ID)}, nil
}

func (s *Server) adminPruneAudit(ctx context.Context, req *sdkmcp.CallToolRequest, args pruneAuditArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	ar, err := s.bp.RequestPruneAudit(ctx, actor, args.ThroughSeq)
	if err != nil {
		return nil, nil, err
	}
	return sensitiveRequestReply(ar), map[string]string{"request_id": string(ar.ID)}, nil
}

func (s *Server) adminBackupNow(ctx context.Context, req *sdkmcp.CallToolRequest, args struct{}) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	info, err := s.bp.AdminBackupNow(ctx, actor, time.Now())
	if err != nil {
		return nil, nil, err
	}
	return text(fmt.Sprintf("backup written: %s (%d bytes, created %s; secret key + repos included). Verified intact. List with admin_list_backups.",
			info.Name, info.SizeBytes, info.CreatedAt)),
		map[string]any{"name": info.Name, "size_bytes": info.SizeBytes, "created_at": info.CreatedAt,
			"has_secret_key": info.HasKey, "has_repos": info.HasRepos, "valid": info.Valid}, nil
}

func (s *Server) adminListBackups(ctx context.Context, req *sdkmcp.CallToolRequest, args struct{}) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	backups, err := s.bp.AdminListBackups(ctx, actor)
	if err != nil {
		return nil, nil, err
	}
	if len(backups) == 0 {
		return text("no backups yet — take one with admin_backup_now."), map[string]any{"backups": []any{}}, nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d backup(s) (newest first):\n", len(backups))
	out := make([]map[string]any, 0, len(backups))
	for _, bk := range backups {
		status := "verified"
		if !bk.Valid {
			status = "INVALID: " + bk.Error
		}
		fmt.Fprintf(&b, "  - %s  created=%s  %d bytes  [%s]\n", bk.Name, bk.CreatedAt, bk.SizeBytes, status)
		out = append(out, map[string]any{"name": bk.Name, "created_at": bk.CreatedAt, "size_bytes": bk.SizeBytes,
			"valid": bk.Valid, "error": bk.Error, "has_secret_key": bk.HasKey, "has_repos": bk.HasRepos})
	}
	return text(b.String()), map[string]any{"backups": out}, nil
}

func (s *Server) adminRestoreBackup(ctx context.Context, req *sdkmcp.CallToolRequest, args restoreBackupArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	ar, err := s.bp.RequestRestoreBackup(ctx, actor, args.Name)
	if err != nil {
		return nil, nil, err
	}
	return sensitiveRequestReply(ar), map[string]string{"request_id": string(ar.ID)}, nil
}

func (s *Server) adminRequestUpgrade(ctx context.Context, req *sdkmcp.CallToolRequest, args requestUpgradeArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	ar, err := s.bp.RequestUpgrade(ctx, actor, args.Version)
	if err != nil {
		return nil, nil, err
	}
	return sensitiveRequestReply(ar), map[string]string{"request_id": string(ar.ID)}, nil
}

// resolveIdentityRef resolves an identity by explicit id, or by issuer+subject
// (the identity must already be registered). Shared by the revoke/disable tools.
func (s *Server) resolveIdentityRef(ctx context.Context, identityID, issuer, subject string) (domain.ID, error) {
	if identityID != "" {
		return domain.ID(identityID), nil
	}
	if issuer == "" || subject == "" {
		return "", fmt.Errorf("give identity_id, or both issuer and subject")
	}
	ident, err := s.dir.GetIdentityByIssuerSubject(ctx, issuer, subject)
	if err != nil {
		return "", fmt.Errorf("no registered identity for that issuer+subject")
	}
	return ident.ID, nil
}

func (s *Server) adminUpdateBeamhall(ctx context.Context, req *sdkmcp.CallToolRequest, args updateBeamhallArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	upd := orch.BeamhallUpdate{MaxBeams: args.MaxBeams, MaxLiveSlots: args.MaxLiveSlots, MaxDatabases: args.MaxDatabases}
	if args.Status != "" {
		st := domain.BeamhallStatus(args.Status)
		upd.Status = &st
	}
	if args.DisplayName != "" {
		dn := args.DisplayName
		upd.DisplayName = &dn
	}
	if args.Department != "" {
		dep := args.Department
		upd.Department = &dep
	}
	if upd.MaxBeams == nil && upd.MaxLiveSlots == nil && upd.MaxDatabases == nil &&
		upd.Status == nil && upd.DisplayName == nil && upd.Department == nil {
		return nil, nil, fmt.Errorf("nothing to update: set at least one of max_beams, max_live_slots, max_databases, status, display_name, department")
	}
	bh, err := s.bp.AdminUpdateBeamhall(ctx, actor, args.Slug, upd)
	if err != nil {
		return nil, nil, err
	}
	return text(fmt.Sprintf("beamhall %q updated: status=%s, quota %d beams / %d live slots / %d databases.",
			bh.Slug, bh.Status, bh.Quota.MaxBeams, bh.LiveSlotLimit, bh.Quota.MaxDBCount)),
		map[string]any{"slug": bh.Slug, "status": string(bh.Status),
			"max_beams": bh.Quota.MaxBeams, "max_live_slots": bh.LiveSlotLimit, "max_databases": bh.Quota.MaxDBCount}, nil
}

func (s *Server) adminRevokeMembership(ctx context.Context, req *sdkmcp.CallToolRequest, args revokeMembershipArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	identID, err := s.resolveIdentityRef(ctx, args.IdentityID, args.Issuer, args.Subject)
	if err != nil {
		return nil, nil, err
	}
	bh, err := s.resolveBeamhall(ctx, args.Beamhall)
	if err != nil {
		return nil, nil, err
	}
	if err := s.bp.RevokeMembership(ctx, actor, identID, bh.ID); err != nil {
		return nil, nil, err
	}
	return text(fmt.Sprintf("revoked %s access to beamhall %q.", identID, bh.Slug)),
		map[string]string{"identity_id": string(identID), "beamhall": bh.Slug}, nil
}

func (s *Server) adminSetIdentityStatus(ctx context.Context, req *sdkmcp.CallToolRequest, args setIdentityStatusArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	identID, err := s.resolveIdentityRef(ctx, args.IdentityID, args.Issuer, args.Subject)
	if err != nil {
		return nil, nil, err
	}
	if err := s.bp.SetIdentityStatus(ctx, actor, identID, args.Status); err != nil {
		return nil, nil, err
	}
	verb := "disabled (all authorization now fails)"
	if args.Status == domain.IdentityActive {
		verb = "re-enabled"
	}
	return text(fmt.Sprintf("identity %s %s.", identID, verb)),
		map[string]string{"identity_id": string(identID), "status": args.Status}, nil
}

func (s *Server) adminListReleases(ctx context.Context, req *sdkmcp.CallToolRequest, args listReleasesArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	bh, err := s.resolveBeamhall(ctx, args.Beamhall)
	if err != nil {
		return nil, nil, err
	}
	beam, err := s.resolveBeam(ctx, bh.ID, args.Beam)
	if err != nil {
		return nil, nil, err
	}
	rels, err := s.bp.AdminListReleases(ctx, actor, beam.ID)
	if err != nil {
		return nil, nil, err
	}
	if len(rels) == 0 {
		return text(fmt.Sprintf("beam %q has no production (live) releases yet — promote_to_live creates the first.", beam.Slug)),
			map[string]any{"releases": []any{}}, nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d production release(s) for beam %q (newest first):\n", len(rels), beam.Slug)
	out := make([]map[string]any, 0, len(rels))
	for _, r := range rels {
		cur := ""
		if r.Current {
			cur = "  <- current"
		}
		fmt.Fprintf(&b, "  - %s  release_id=%s  to_version=%d%s\n", r.Label, r.ReleaseID, r.Version, cur)
		out = append(out, map[string]any{"label": r.Label, "release_id": r.ReleaseID, "to_version": r.Version, "current": r.Current})
	}
	b.WriteString("Roll back with the rollback tool (to_version = the number above).")
	return text(b.String()), map[string]any{"releases": out}, nil
}

func (s *Server) adminQueryAudit(ctx context.Context, req *sdkmcp.CallToolRequest, args queryAuditArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	entries, err := s.bp.AdminQueryAudit(ctx, actor, args.Beamhall, args.AfterSeq, args.Limit)
	if err != nil {
		return nil, nil, err
	}
	if len(entries) == 0 {
		return text("no audit events match."), map[string]any{"events": []any{}}, nil
	}
	var b strings.Builder
	scope := "appliance-wide"
	if args.Beamhall != "" {
		scope = "beamhall " + args.Beamhall
	}
	fmt.Fprintf(&b, "%d audit event(s) (%s):\n", len(entries), scope)
	out := make([]map[string]any, 0, len(entries))
	var maxSeq int64
	for _, e := range entries {
		if e.Seq > maxSeq {
			maxSeq = e.Seq
		}
		fmt.Fprintf(&b, "  #%d  %s  %s  %s  actor=%s", e.Seq, e.At.UTC().Format(time.RFC3339), e.Decision, e.Action, e.Actor)
		if e.Beamhall != "" {
			fmt.Fprintf(&b, "  beamhall=%s", e.Beamhall)
		}
		if e.ResultStatus != "" {
			fmt.Fprintf(&b, "  result=%s", e.ResultStatus)
		}
		if e.Reason != "" {
			fmt.Fprintf(&b, "  reason=%s", e.Reason)
		}
		b.WriteByte('\n')
		out = append(out, map[string]any{
			"seq": e.Seq, "at": e.At.UTC().Format(time.RFC3339), "action": e.Action,
			"decision": e.Decision, "actor": e.Actor, "beamhall": e.Beamhall, "beam": e.Beam,
			"result": e.ResultStatus, "reason": e.Reason, "source_ip": e.SourceIP,
		})
	}
	fmt.Fprintf(&b, "(next_after_seq=%d to page forward)", maxSeq)
	return text(b.String()), map[string]any{"events": out, "next_after_seq": maxSeq}, nil
}

func (s *Server) adminVerifyAuditChain(ctx context.Context, req *sdkmcp.CallToolRequest, args struct{}) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	st, err := s.bp.AdminVerifyAuditChain(ctx, actor)
	if err != nil {
		return nil, nil, err
	}
	var b strings.Builder
	if st.Intact {
		b.WriteString("audit chain VERIFIED — intact, no tampering detected.")
	} else {
		fmt.Fprintf(&b, "audit chain INTEGRITY VIOLATION — %d issue(s):\n", len(st.Issues))
		for _, is := range st.Issues {
			fmt.Fprintf(&b, "  - %s\n", is)
		}
	}
	res := map[string]any{"intact": st.Intact, "issues": st.Issues}
	if st.Checkpoint != nil {
		fmt.Fprintf(&b, "\n(retention checkpoint: %d event(s) pruned through seq %d on %s; verification resumes from there)",
			st.Checkpoint.PrunedCount, st.Checkpoint.ThroughSeq, st.Checkpoint.At.UTC().Format(time.RFC3339))
		res["checkpoint"] = map[string]any{"through_seq": st.Checkpoint.ThroughSeq, "pruned_count": st.Checkpoint.PrunedCount}
	}
	return text(b.String()), res, nil
}

func (s *Server) adminSetUserEnabled(ctx context.Context, req *sdkmcp.CallToolRequest, args setUserEnabledArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	if err := s.bp.AdminSetUserEnabled(ctx, actor, args.UserID, args.Enabled); err != nil {
		return nil, nil, idpErr(err)
	}
	state := "disabled"
	if args.Enabled {
		state = "enabled"
	}
	return text(fmt.Sprintf("bundled-IdP user %s %s.", args.UserID, state)),
		map[string]any{"user_id": args.UserID, "enabled": args.Enabled}, nil
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
