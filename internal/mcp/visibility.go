package mcp

import (
	"context"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Beamhall/beamhall/internal/auth"
)

// Per-caller tool-list filtering (the "multi-level menu"). The MCP server
// registers the union of all tools once, but a single tools/list receiving
// middleware returns only the tools a given caller could actually invoke —
// derived from the caller's token (scopes + realm role) and the appliance's
// state. This keeps a builder agent's context free of the IT admin surface
// (and an it_admin's free of nothing — they get the full menu), and keeps the
// menu honest by hiding tools that would only answer "not enabled" on this
// deployment (e.g. bundled-IdP user management on a BYO-IdP appliance).
//
// IMPORTANT: this is DISCOVERY, not authorization. tools/call dispatches off the
// global registry and will run a hidden tool if invoked directly, so every
// handler must keep its resolveActor(scope) check — that is the security
// boundary; this filter is only the menu. The filter never widens access: a
// tool it shows always passes the same gate its handler enforces.
//
// The method string for tools/list (the SDK constant is unexported).
const methodListTools = "tools/list"

// toolScope maps every registered tool to the OAuth scope its handler requires
// (the exact scope it passes to resolveActor). admin:it marks the it_admin tier
// (scope admin:it OR the configured realm role), mirroring resolveActor's
// elevation. A tool absent from this table (and from alwaysVisible) fails
// CLOSED — hidden from everyone — and TestToolVisibilityTableMatchesRegistry
// fails in CI, so a newly added tool must be classified here on purpose.
var toolScope = map[string]string{
	// Builder surface (agent-facing; gated by capability scope).
	"list_beams":      auth.ScopeBeamhallsRead,
	"create_beam":     auth.ScopeBeamsWrite,
	"deploy_beam":     auth.ScopeBeamsDeploy,
	"get_repo":        auth.ScopeBeamsWrite,
	"create_database": auth.ScopeResourcesWrite,
	"provision_auth":  auth.ScopeResourcesWrite,
	"show_auth":       auth.ScopeBeamhallsRead,
	"provision_email":        auth.ScopeResourcesWrite,
	"show_email":             auth.ScopeBeamhallsRead,
	"provision_object_store": auth.ScopeResourcesWrite,
	"show_object_store":      auth.ScopeBeamhallsRead,
	"set_secret":             auth.ScopeSecretsWrite,
	"show_logs":       auth.ScopeLogsRead,
	"pause_preview":   auth.ScopeBeamsOperate,
	"resume_preview":  auth.ScopeBeamsOperate,
	"promote_to_live": auth.ScopeBeamsPromote,
	"rollback":        auth.ScopeBeamsDeploy,
	"show_metrics":    auth.ScopeMetricsRead,
	"archive_beam":    auth.ScopeBeamsOperate,
	"destroy_beam":    auth.ScopeBeamsWrite,

	// IT promotion gate (admin:it) — lives on the builder file but is IT-only.
	"list_pending_promotions": auth.ScopeAdminIT,
	"approve_promotion":       auth.ScopeAdminIT,
	"reject_promotion":        auth.ScopeAdminIT,

	// Admin family (admin:it).
	"admin_register_identity":      auth.ScopeAdminIT,
	"admin_grant_membership":       auth.ScopeAdminIT,
	"admin_revoke_membership":      auth.ScopeAdminIT,
	"admin_set_membership_role":    auth.ScopeAdminIT,
	"admin_list_identities":        auth.ScopeAdminIT,
	"admin_set_identity_status":    auth.ScopeAdminIT,
	"admin_deregister_identity":    auth.ScopeAdminIT,
	"admin_create_beamhall":        auth.ScopeAdminIT,
	"admin_list_beamhalls":         auth.ScopeAdminIT,
	"admin_show_beamhall":          auth.ScopeAdminIT,
	"admin_update_beamhall":        auth.ScopeAdminIT,
	"admin_set_egress":             auth.ScopeAdminIT,
	"admin_set_auth_groups":        auth.ScopeAdminIT,
	"admin_set_email_senders":         auth.ScopeAdminIT,
	"admin_set_email_provider":        auth.ScopeAdminIT,
	"admin_set_object_store_provider": auth.ScopeAdminIT,
	"admin_set_object_store_quota":    auth.ScopeAdminIT,
	"admin_list_releases":          auth.ScopeAdminIT,
	"admin_query_audit":            auth.ScopeAdminIT,
	"admin_verify_audit_chain":     auth.ScopeAdminIT,
	"admin_create_user":            auth.ScopeAdminIT,
	"admin_list_users":             auth.ScopeAdminIT,
	"admin_set_user_password":      auth.ScopeAdminIT,
	"admin_set_user_enabled":       auth.ScopeAdminIT,
	"admin_create_group":           auth.ScopeAdminIT,
	"admin_list_groups":            auth.ScopeAdminIT,
	"admin_add_user_to_group":      auth.ScopeAdminIT,
	"admin_remove_user_from_group": auth.ScopeAdminIT,
	"admin_delete_user":            auth.ScopeAdminIT,
	"admin_delete_group":           auth.ScopeAdminIT,
	"admin_federate_directory":     auth.ScopeAdminIT,
	"admin_unfederate_directory":   auth.ScopeAdminIT,
	"admin_set_security_context":   auth.ScopeAdminIT,
	"admin_prune_audit":            auth.ScopeAdminIT,
	"admin_backup_now":             auth.ScopeAdminIT,
	"admin_list_backups":           auth.ScopeAdminIT,
	"admin_restore_backup":         auth.ScopeAdminIT,
	"admin_request_upgrade":        auth.ScopeAdminIT,
	"admin_list_pending_requests":  auth.ScopeAdminIT,
	"admin_approve_request":        auth.ScopeAdminIT,
	"admin_reject_request":         auth.ScopeAdminIT,
}

// alwaysVisible tools have no scope gate: the fast-follow contract placeholders,
// which exist so an agent gets a clear "not enabled in this build" answer rather
// than an unknown-tool error. They carry no capability, so they're shown to all.
var alwaysVisible = map[string]bool{
	"create_queue": true,
}

// idpAdminTools require the appliance to administer its own (bundled) IdP. On a
// bring-your-own-IdP deployment these only ever return ErrNotEnabled, so they're
// kept off the menu there instead of advertising dead capabilities.
var idpAdminTools = map[string]bool{
	// Provisioned auth (PLAN §5.10) only works when Beamhall administers its own
	// IdP; on BYO-IdP these only return ErrNotEnabled, so keep them off the menu.
	"provision_auth":               true,
	"show_auth":                    true,
	"admin_set_auth_groups":        true,
	"admin_create_user":            true,
	"admin_list_users":             true,
	"admin_set_user_password":      true,
	"admin_set_user_enabled":       true,
	"admin_create_group":           true,
	"admin_list_groups":            true,
	"admin_add_user_to_group":      true,
	"admin_remove_user_from_group": true,
	"admin_delete_user":            true,
	"admin_delete_group":           true,
	"admin_federate_directory":     true,
	"admin_unfederate_directory":   true,
}

// sensitiveTierTools file a four-eyes change (auth-config, isolation posture, or
// tamper-evidence). They're only useful when the SENSITIVE tier is unlocked
// (else the request can't even be filed), so they stay off the menu until an
// operator enables the tier.
var sensitiveTierTools = map[string]bool{
	"admin_federate_directory":   true,
	"admin_unfederate_directory": true,
	"admin_set_security_context": true,
	"admin_prune_audit":          true,
	"admin_restore_backup":       true,
	"admin_request_upgrade":      true,
}

// backupTools require the appliance to have a backup directory configured
// (WithBackup); without it they only return "not configured", so they stay off
// the menu.
var backupTools = map[string]bool{
	"admin_backup_now":     true,
	"admin_list_backups":   true,
	"admin_restore_backup": true,
}

// upgradeTools require self-upgrade to be enabled (WithUpgrader / fail-closed by
// default), so the most-guarded action stays off the menu unless deliberately
// turned on.
var upgradeTools = map[string]bool{
	"admin_request_upgrade": true,
}

// emailTools require the email facility to be fully ON — a bh-mail broker AND an
// IT-configured provider. Without a provider they degrade closed, so they stay
// off the menu until admin_set_email_provider is run (PLAN §5.12).
var emailTools = map[string]bool{
	"provision_email":         true,
	"show_email":              true,
	"admin_set_email_senders": true,
}

// emailProviderTools only need the broker to be WIRED (the installer stood it
// up), not yet configured — this is the IT entry point that turns email on.
var emailProviderTools = map[string]bool{
	"admin_set_email_provider": true,
}

// objectStoreTools require the object-store facility to be enabled (a bh-objstore
// broker reporting a backend — true by default once wired, since it boots local).
var objectStoreTools = map[string]bool{
	"provision_object_store": true,
	"show_object_store":      true,
}

// objectStoreProviderTools only need the broker WIRED — the IT entry points to
// switch the backend (local↔external) and cap per-beam storage.
var objectStoreProviderTools = map[string]bool{
	"admin_set_object_store_provider": true,
	"admin_set_object_store_quota":    true,
}

// applianceState is the cheap, per-list snapshot of deployment capabilities the
// filter consults in addition to the caller's token (no DB read).
type applianceState struct {
	idpEnabled       bool
	sensitiveEnabled bool
	backupEnabled    bool
	upgradeEnabled   bool
	emailEnabled     bool // broker wired AND provider configured (builder tools)
	emailWired       bool // broker wired (IT can configure the provider)
	objStoreEnabled  bool // broker wired AND reporting a backend (builder tools)
	objStoreWired    bool // broker wired (IT can switch the backend / set quota)
}

// toolVisible reports whether a caller with the given token should see the named
// tool, given the appliance state. It mirrors resolveActor's gate exactly for
// the tier check, then applies the state gates. Fail-closed on unknown tools.
func toolVisible(name string, info *sdkauth.TokenInfo, adminRole string, st applianceState) bool {
	if alwaysVisible[name] {
		return true
	}
	scope, known := toolScope[name]
	if !known {
		return false
	}
	// Tier gate — identical to resolveActor.
	if scope == auth.ScopeAdminIT {
		if info == nil || !(auth.HasScope(info.Scopes, auth.ScopeAdminIT) || auth.HasRole(info, adminRole)) {
			return false
		}
	} else if info == nil || !auth.HasScope(info.Scopes, scope) {
		return false
	}
	// State gates — hide tools that would only answer "not enabled" here.
	if idpAdminTools[name] && !st.idpEnabled {
		return false
	}
	if sensitiveTierTools[name] && !st.sensitiveEnabled {
		return false
	}
	if backupTools[name] && !st.backupEnabled {
		return false
	}
	if upgradeTools[name] && !st.upgradeEnabled {
		return false
	}
	if emailTools[name] && !st.emailEnabled {
		return false
	}
	if emailProviderTools[name] && !st.emailWired {
		return false
	}
	if objectStoreTools[name] && !st.objStoreEnabled {
		return false
	}
	if objectStoreProviderTools[name] && !st.objStoreWired {
		return false
	}
	return true
}

// installToolFilter wraps the server's receiving handler so tools/list returns a
// per-caller subset. Other methods pass through untouched. The token rides on
// req.Extra (the Streamable HTTP transport attaches it to every request), so the
// same TokenInfo resolveActor reads is available here at list time.
func (s *Server) installToolFilter() {
	s.srv.AddReceivingMiddleware(func(next sdkmcp.MethodHandler) sdkmcp.MethodHandler {
		return func(ctx context.Context, method string, req sdkmcp.Request) (sdkmcp.Result, error) {
			res, err := next(ctx, method, req)
			if err != nil || method != methodListTools {
				return res, err
			}
			lt, ok := res.(*sdkmcp.ListToolsResult)
			if !ok {
				return res, err
			}
			var info *sdkauth.TokenInfo
			if ex := req.GetExtra(); ex != nil {
				info = ex.TokenInfo
			}
			st := applianceState{
				idpEnabled:       s.bp.IdentityAdminEnabled(),
				sensitiveEnabled: s.bp.SensitiveAdminEnabled(),
				backupEnabled:    s.bp.BackupEnabled(),
				upgradeEnabled:   s.bp.UpgradeEnabled(),
				emailEnabled:     s.bp.EmailEnabled(),
				emailWired:       s.bp.EmailBrokerWired(),
				objStoreEnabled:  s.bp.ObjectStoreEnabled(),
				objStoreWired:    s.bp.ObjectStoreBrokerWired(),
			}
			kept := make([]*sdkmcp.Tool, 0, len(lt.Tools))
			for _, t := range lt.Tools {
				if toolVisible(t.Name, info, s.adminRole, st) {
					kept = append(kept, t)
				}
			}
			out := *lt
			out.Tools = kept
			return &out, nil
		}
	})
}
