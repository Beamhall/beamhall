package mcp

import (
	"context"
	"strings"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Beamhall/beamhall/internal/auth"
)

// noToolFilter builds a server that registers every tool but skips the
// tools/list filter — so a test can enumerate the full registry.
func noToolFilter() Option { return func(s *Server) { s.skipFilter = true } }

func listToolNames(t *testing.T, cs *sdkmcp.ClientSession) map[string]bool {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, tool := range res.Tools {
		got[tool.Name] = true
	}
	return got
}

// --- the new lifecycle / audit tools ---------------------------------------

func TestAdminUpdateBeamhall(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeAdminIT, nil)

	// Raise the beam quota.
	_, txt := h.call(t, cs, "admin_update_beamhall", map[string]any{"slug": "ops", "max_beams": 20}, false)
	if !strings.Contains(txt, "20 beams") {
		t.Fatalf("update quota reply: %q", txt)
	}
	assertCalled(t, h, "AdminUpdateBeamhall:ops")

	// Suspend (a real freeze — the PEP then denies all actions).
	_, txt = h.call(t, cs, "admin_update_beamhall", map[string]any{"slug": "ops", "status": "suspended"}, false)
	if !strings.Contains(txt, "status=suspended") {
		t.Fatalf("suspend reply: %q", txt)
	}

	// No fields → a clear error, not a silent no-op.
	_, txt = h.call(t, cs, "admin_update_beamhall", map[string]any{"slug": "ops"}, true)
	if !strings.Contains(txt, "nothing to update") {
		t.Fatalf("empty update: want guard error, got %q", txt)
	}
}

func TestAdminRevokeMembership(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeAdminIT, nil)
	_, txt := h.call(t, cs, "admin_revoke_membership", map[string]any{
		"beamhall": "ops", "identity_id": "ident-1",
	}, false)
	if !strings.Contains(txt, "revoked") {
		t.Fatalf("revoke reply: %q", txt)
	}
	assertCalled(t, h, "RevokeMembership:ident-1:hall-1")
}

func TestAdminSetIdentityStatusByIssuerSubject(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeAdminIT, nil)
	// Resolve by issuer+subject (user-1 → ident-1) and disable.
	_, txt := h.call(t, cs, "admin_set_identity_status", map[string]any{
		"issuer": "https://idp.test", "subject": "user-1", "status": "disabled",
	}, false)
	if !strings.Contains(txt, "disabled") {
		t.Fatalf("disable reply: %q", txt)
	}
	assertCalled(t, h, "SetIdentityStatus:ident-1:disabled")
}

func TestAdminListReleases(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeAdminIT, nil)
	_, txt := h.call(t, cs, "admin_list_releases", map[string]any{"beamhall": "ops", "beam": "tracker"}, false)
	if !strings.Contains(txt, "v2") || !strings.Contains(txt, "to_version=2") || !strings.Contains(txt, "current") {
		t.Fatalf("release history reply: %q", txt)
	}
	assertCalled(t, h, "AdminListReleases:beam-1")
}

func TestAdminQueryAudit(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeAdminIT, nil)
	res, txt := h.call(t, cs, "admin_query_audit", map[string]any{"limit": 50}, false)
	if !strings.Contains(txt, "admin_create_beamhall") || !strings.Contains(txt, "deny") || !strings.Contains(txt, "next_after_seq") {
		t.Fatalf("audit query reply: %q", txt)
	}
	// Structured output must carry the pagination cursor for the agent.
	if res.StructuredContent == nil {
		t.Fatal("audit query: no structured content")
	}
	assertCalled(t, h, "AdminQueryAudit::0:50")
}

func TestAdminVerifyAuditChain(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeAdminIT, nil)

	// Default fake → a violation is reported.
	_, txt := h.call(t, cs, "admin_verify_audit_chain", map[string]any{}, false)
	if !strings.Contains(txt, "INTEGRITY VIOLATION") {
		t.Fatalf("verify (broken) reply: %q", txt)
	}

	h.bp.auditIntact = true
	_, txt = h.call(t, cs, "admin_verify_audit_chain", map[string]any{}, false)
	if !strings.Contains(txt, "VERIFIED") {
		t.Fatalf("verify (intact) reply: %q", txt)
	}
}

func TestAdminSetUserEnabled(t *testing.T) {
	h := newHarness(t)
	h.bp.idpEnabled = true
	cs := h.connect(t, auth.ScopeAdminIT, nil)
	_, txt := h.call(t, cs, "admin_set_user_enabled", map[string]any{"user_id": "u-1", "enabled": false}, false)
	if !strings.Contains(txt, "disabled") {
		t.Fatalf("disable user reply: %q", txt)
	}
	assertCalled(t, h, "AdminSetUserEnabled:u-1:false")

	// BYO-IdP appliance → actionable hint.
	h2 := newHarness(t)
	cs2 := h2.connect(t, auth.ScopeAdminIT, nil)
	_, txt = h2.call(t, cs2, "admin_set_user_enabled", map[string]any{"user_id": "u-1", "enabled": true}, true)
	if !strings.Contains(txt, "external IdP") {
		t.Fatalf("BYO-IdP set_user_enabled: want hint, got %q", txt)
	}
}

func TestNewAdminToolsRequireAdminScope(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeBeamsWrite, nil) // builder, no admin:it
	for tool, args := range map[string]map[string]any{
		"admin_update_beamhall":        {"slug": "ops", "max_beams": 1},
		"admin_revoke_membership":      {"beamhall": "ops", "identity_id": "ident-1"},
		"admin_set_membership_role":    {"beamhall": "ops", "role": "builder", "identity_id": "ident-1"},
		"admin_set_identity_status":    {"identity_id": "ident-1", "status": "disabled"},
		"admin_deregister_identity":    {"identity_id": "ident-1"},
		"admin_query_audit":            {},
		"admin_verify_audit_chain":     {},
		"admin_list_releases":          {"beamhall": "ops", "beam": "tracker"},
		"admin_set_user_enabled":       {"user_id": "u-1", "enabled": false},
		"admin_remove_user_from_group": {"user_id": "u-1", "group_id": "g-1"},
		"admin_set_security_context":   {"slug": "ops", "runtime_class": "runsc"},
		"admin_unfederate_directory":   {"name": "corp-ad"},
		"admin_prune_audit":            {"through_seq": 100},
		"admin_backup_now":             {},
		"admin_list_backups":           {},
		"admin_restore_backup":         {"name": "b.tar.gz"},
		"admin_delete_user":            {"user_id": "u-1"},
		"admin_delete_group":           {"group_id": "g-1"},
		"admin_request_upgrade":        {"version": "v0.1.11"},
	} {
		_, txt := h.call(t, cs, tool, args, true)
		if !strings.Contains(txt, "insufficient_scope") {
			t.Fatalf("%s without admin:it: want insufficient_scope, got %q", tool, txt)
		}
	}
}

// --- tools/list filtering (the multi-level menu) ----------------------------

func TestToolListTierFiltering(t *testing.T) {
	h := newHarness(t)
	h.bp.idpEnabled = true
	h.bp.sensitiveTier = true

	// it_admin (admin:it scope only, no builder scopes) sees the admin menu but
	// not the builder write tools.
	admin := listToolNames(t, h.connect(t, auth.ScopeAdminIT, nil))
	for _, want := range []string{"admin_create_beamhall", "admin_update_beamhall",
		"admin_query_audit", "admin_revoke_membership", "admin_set_identity_status",
		"list_pending_promotions", "approve_promotion"} {
		if !admin[want] {
			t.Errorf("it_admin menu missing %q", want)
		}
	}
	for _, hidden := range []string{"create_beam", "deploy_beam", "list_beams", "set_secret"} {
		if admin[hidden] {
			t.Errorf("builder tool %q leaked into the it_admin menu", hidden)
		}
	}

	// it_admin via the realm role (no admin:it scope) + a builder scope sees both
	// the admin menu and the builder tools its scope grants.
	role := listToolNames(t, h.connect(t, "roles=beamhall-it;"+auth.ScopeBeamsWrite, nil))
	if !role["admin_query_audit"] || !role["create_beam"] {
		t.Errorf("role-gated admin: want admin + beams:write tools, got %v", keys(role))
	}
}

func TestToolListIdpAndSensitiveGating(t *testing.T) {
	// BYO-IdP, sensitive tier off: bundled-IdP and federation tools stay off the
	// menu (they would only answer "not enabled"); core admin tools stay on.
	h := newHarness(t) // idpEnabled=false, sensitiveTier=false
	off := listToolNames(t, h.connect(t, auth.ScopeAdminIT, nil))
	for _, hidden := range []string{"admin_create_user", "admin_list_users", "admin_set_user_enabled",
		"admin_remove_user_from_group", "admin_federate_directory", "admin_unfederate_directory",
		"admin_set_security_context", "admin_prune_audit"} {
		if off[hidden] {
			t.Errorf("state-gated tool %q shown on a BYO-IdP / sensitive-off appliance", hidden)
		}
	}
	if !off["admin_update_beamhall"] || !off["admin_query_audit"] {
		t.Error("core admin tools should remain visible regardless of IdP/sensitive state")
	}

	// Bundled IdP + sensitive tier on: the gated tools appear.
	h2 := newHarness(t)
	h2.bp.idpEnabled = true
	h2.bp.sensitiveTier = true
	on := listToolNames(t, h2.connect(t, auth.ScopeAdminIT, nil))
	for _, want := range []string{"admin_create_user", "admin_set_user_enabled", "admin_remove_user_from_group",
		"admin_federate_directory", "admin_unfederate_directory", "admin_set_security_context", "admin_prune_audit"} {
		if !on[want] {
			t.Errorf("state-gated tool %q hidden even though IdP+sensitive are enabled", want)
		}
	}
}

func TestAdminDeregisterIdentity(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeAdminIT, nil)
	// By issuer+subject (user-1 → ident-1).
	_, txt := h.call(t, cs, "admin_deregister_identity", map[string]any{
		"issuer": "https://idp.test", "subject": "user-1",
	}, false)
	if !strings.Contains(txt, "deregistered") {
		t.Fatalf("deregister reply: %q", txt)
	}
	assertCalled(t, h, "DeregisterIdentity:ident-1")
}

func TestAdminSetMembershipRole(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeAdminIT, nil)
	_, txt := h.call(t, cs, "admin_set_membership_role", map[string]any{
		"beamhall": "ops", "role": "builder", "identity_id": "ident-1",
	}, false)
	if !strings.Contains(txt, "builder") {
		t.Fatalf("set role reply: %q", txt)
	}
	assertCalled(t, h, "SetMembershipRole:ident-1:hall-1:builder")
}

func TestAdminRemoveUserFromGroup(t *testing.T) {
	h := newHarness(t)
	h.bp.idpEnabled = true
	cs := h.connect(t, auth.ScopeAdminIT, nil)
	_, txt := h.call(t, cs, "admin_remove_user_from_group", map[string]any{"user_id": "u-1", "group_id": "g-1"}, false)
	if !strings.Contains(txt, "removed") {
		t.Fatalf("remove-from-group reply: %q", txt)
	}
	assertCalled(t, h, "AdminRemoveUserFromGroup:u-1:g-1")

	h2 := newHarness(t) // BYO-IdP
	cs2 := h2.connect(t, auth.ScopeAdminIT, nil)
	_, txt = h2.call(t, cs2, "admin_remove_user_from_group", map[string]any{"user_id": "u-1", "group_id": "g-1"}, true)
	if !strings.Contains(txt, "external IdP") {
		t.Fatalf("BYO-IdP remove-from-group: want hint, got %q", txt)
	}
}

func TestSensitiveManagementToolsFileFourEyes(t *testing.T) {
	h := newHarness(t)
	h.bp.idpEnabled = true
	h.bp.sensitiveTier = true
	cs := h.connect(t, auth.ScopeAdminIT, nil)
	cases := []struct {
		tool string
		args map[string]any
		call string
	}{
		{"admin_set_security_context", map[string]any{"slug": "ops", "runtime_class": "runsc"}, "RequestSetSecurityContext:ops:runsc"},
		{"admin_unfederate_directory", map[string]any{"name": "corp-ad"}, "RequestUnfederateDirectory:corp-ad"},
		{"admin_prune_audit", map[string]any{"through_seq": 100}, "RequestPruneAudit:100"},
	}
	for _, c := range cases {
		_, txt := h.call(t, cs, c.tool, c.args, false)
		if !strings.Contains(txt, "DIFFERENT IT operator") || !strings.Contains(txt, "admin_approve_request") {
			t.Errorf("%s: want four-eyes reply, got %q", c.tool, txt)
		}
		assertCalled(t, h, c.call)
	}

	// admin_set_security_context validates the runtime class.
	_, txt := h.call(t, cs, "admin_set_security_context", map[string]any{"slug": "ops", "runtime_class": "firecracker"}, true)
	if !strings.Contains(txt, "runtime_class must be") {
		t.Fatalf("bad runtime_class: want validation error, got %q", txt)
	}
}

func TestAdminBackupTools(t *testing.T) {
	h := newHarness(t)
	h.bp.backupEnabled = true
	cs := h.connect(t, auth.ScopeAdminIT, nil)

	_, txt := h.call(t, cs, "admin_backup_now", map[string]any{}, false)
	if !strings.Contains(txt, "backup written") || !strings.Contains(txt, ".tar.gz") {
		t.Fatalf("backup_now reply: %q", txt)
	}
	assertCalled(t, h, "AdminBackupNow")

	_, txt = h.call(t, cs, "admin_list_backups", map[string]any{}, false)
	if !strings.Contains(txt, "verified") || !strings.Contains(txt, "INVALID") {
		t.Fatalf("list_backups reply (want one verified + one invalid): %q", txt)
	}

	// Restore is four-eyes (sensitive tier also on for visibility, but the gate is
	// in the backplane).
	h.bp.sensitiveTier = true
	_, txt = h.call(t, cs, "admin_restore_backup", map[string]any{"name": "beamhall-20260102T000000Z.tar.gz"}, false)
	if !strings.Contains(txt, "DIFFERENT IT operator") || !strings.Contains(txt, "admin_approve_request") {
		t.Fatalf("restore four-eyes reply: %q", txt)
	}
	assertCalled(t, h, "RequestRestoreBackup:beamhall-20260102T000000Z.tar.gz")
}

func TestAdminDeleteUserAndGroupTools(t *testing.T) {
	h := newHarness(t)
	h.bp.idpEnabled = true
	cs := h.connect(t, auth.ScopeAdminIT, nil)
	_, txt := h.call(t, cs, "admin_delete_user", map[string]any{"user_id": "u-9"}, false)
	if !strings.Contains(txt, "permanently deleted") {
		t.Fatalf("delete_user reply: %q", txt)
	}
	assertCalled(t, h, "AdminDeleteUser:u-9")
	_, txt = h.call(t, cs, "admin_delete_group", map[string]any{"group_id": "g-9"}, false)
	if !strings.Contains(txt, "permanently deleted") {
		t.Fatalf("delete_group reply: %q", txt)
	}
	assertCalled(t, h, "AdminDeleteGroup:g-9")

	// BYO-IdP → actionable hint.
	h2 := newHarness(t)
	cs2 := h2.connect(t, auth.ScopeAdminIT, nil)
	_, txt = h2.call(t, cs2, "admin_delete_user", map[string]any{"user_id": "u-9"}, true)
	if !strings.Contains(txt, "external IdP") {
		t.Fatalf("BYO-IdP delete_user: want hint, got %q", txt)
	}
}

func TestAdminRequestUpgradeFourEyes(t *testing.T) {
	h := newHarness(t)
	h.bp.sensitiveTier = true
	h.bp.upgradeEnabled = true
	cs := h.connect(t, auth.ScopeAdminIT, nil)
	_, txt := h.call(t, cs, "admin_request_upgrade", map[string]any{"version": "v0.1.11"}, false)
	if !strings.Contains(txt, "DIFFERENT IT operator") || !strings.Contains(txt, "admin_approve_request") {
		t.Fatalf("upgrade four-eyes reply: %q", txt)
	}
	assertCalled(t, h, "RequestUpgrade:v0.1.11")
}

func TestToolListUpgradeGating(t *testing.T) {
	// Self-upgrade disabled → admin_request_upgrade off the menu even with the
	// sensitive tier on.
	h := newHarness(t)
	h.bp.sensitiveTier = true
	if listToolNames(t, h.connect(t, auth.ScopeAdminIT, nil))["admin_request_upgrade"] {
		t.Error("admin_request_upgrade shown when self-upgrade is disabled")
	}
	// Enabled (+ sensitive on) → it appears.
	h2 := newHarness(t)
	h2.bp.sensitiveTier = true
	h2.bp.upgradeEnabled = true
	if !listToolNames(t, h2.connect(t, auth.ScopeAdminIT, nil))["admin_request_upgrade"] {
		t.Error("admin_request_upgrade hidden when self-upgrade is enabled")
	}
}

func TestToolListBackupGating(t *testing.T) {
	// Backups unconfigured → the backup tools stay off the menu.
	h := newHarness(t)
	h.bp.sensitiveTier = true // restore would otherwise pass the sensitive gate
	off := listToolNames(t, h.connect(t, auth.ScopeAdminIT, nil))
	for _, hidden := range []string{"admin_backup_now", "admin_list_backups", "admin_restore_backup"} {
		if off[hidden] {
			t.Errorf("backup tool %q shown when backups are unconfigured", hidden)
		}
	}
	// Backups configured (and sensitive on for restore) → they appear.
	h2 := newHarness(t)
	h2.bp.backupEnabled = true
	h2.bp.sensitiveTier = true
	on := listToolNames(t, h2.connect(t, auth.ScopeAdminIT, nil))
	for _, want := range []string{"admin_backup_now", "admin_list_backups", "admin_restore_backup"} {
		if !on[want] {
			t.Errorf("backup tool %q hidden even though backups are configured", want)
		}
	}
}

// Drift guard: every registered tool must be classified in the visibility table
// (toolScope ∪ alwaysVisible) and vice-versa, and a fully-privileged it_admin
// must actually see the entire registry. Fail-closed filtering would otherwise
// hide a newly added tool silently.
func TestToolVisibilityTableMatchesRegistry(t *testing.T) {
	// Full registry via an unfiltered server.
	raw := newHarness(t, noToolFilter())
	all := listToolNames(t, raw.connect(t, auth.ScopeBeamsWrite, nil))
	if len(all) < 20 {
		t.Fatalf("unfiltered registry looks too small (%d) — enumeration broke", len(all))
	}
	for name := range all {
		if _, ok := toolScope[name]; !ok && !alwaysVisible[name] {
			t.Errorf("registered tool %q is not classified in the visibility table", name)
		}
	}
	for name := range toolScope {
		if !all[name] {
			t.Errorf("visibility table names %q, which is not a registered tool", name)
		}
	}
	for name := range alwaysVisible {
		if !all[name] {
			t.Errorf("alwaysVisible names %q, which is not a registered tool", name)
		}
	}

	// A maximally-privileged it_admin (all scopes + admin:it, every appliance-
	// state gate on) must see exactly the full registry.
	full := newHarness(t)
	full.bp.idpEnabled = true
	full.bp.sensitiveTier = true
	full.bp.backupEnabled = true
	full.bp.upgradeEnabled = true
	full.bp.emailEnabled = true
	full.bp.emailWired = true
	full.bp.objStoreEnabled = true
	full.bp.objStoreWired = true
	token := strings.Join(auth.AllScopes(), ",") + "," + auth.ScopeAdminIT
	seen := listToolNames(t, full.connect(t, token, nil))
	for name := range all {
		if !seen[name] {
			t.Errorf("fully-privileged it_admin cannot see registered tool %q", name)
		}
	}
	if len(seen) != len(all) {
		t.Errorf("fully-privileged it_admin sees %d tools, registry has %d", len(seen), len(all))
	}
}

func TestProvisionedAuthToolVisibility(t *testing.T) {
	builderScopes := strings.Join(auth.AllScopes(), ",") // capability scopes, no admin:it

	// Bundled IdP: a builder sees provision_auth + show_auth, never the IT group tool.
	h := newHarness(t)
	h.bp.idpEnabled = true
	seen := listToolNames(t, h.connect(t, builderScopes, nil))
	if !seen["provision_auth"] || !seen["show_auth"] {
		t.Fatalf("builder should see provision_auth + show_auth (provision=%v show=%v)", seen["provision_auth"], seen["show_auth"])
	}
	if seen["admin_set_auth_groups"] {
		t.Fatal("builder must NOT see admin_set_auth_groups (IT-only)")
	}
	itSeen := listToolNames(t, h.connect(t, builderScopes+","+auth.ScopeAdminIT, nil))
	if !itSeen["admin_set_auth_groups"] {
		t.Fatal("it_admin should see admin_set_auth_groups")
	}

	// BYO-IdP: the provisioned-auth tools are off the menu entirely.
	byo := newHarness(t)
	byo.bp.idpEnabled = false
	bseen := listToolNames(t, byo.connect(t, builderScopes, nil))
	if bseen["provision_auth"] || bseen["show_auth"] {
		t.Fatal("BYO-IdP must hide provision_auth/show_auth")
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
