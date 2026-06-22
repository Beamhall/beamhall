package mcp

import (
	"strings"
	"testing"

	"github.com/Beamhall/beamhall/internal/auth"
)

// admin_* tools require the admin:it scope and route through the backplane.

func TestAdminToolsRequireAdminScope(t *testing.T) {
	h := newHarness(t)
	// A builder-scoped token (no admin:it) must be refused with insufficient_scope.
	// Args are schema-valid so the call reaches the scope check, not arg validation.
	cs := h.connect(t, auth.ScopeBeamsWrite, nil)
	cases := map[string]map[string]any{
		"admin_register_identity":  {"issuer": "https://idp.test", "subject": "x"},
		"admin_create_user":        {"username": "x"},
		"admin_list_identities":    {},
		"admin_federate_directory": {"name": "ad", "connection_url": "ldaps://d:636", "users_dn": "DC=x"},
	}
	for tool, args := range cases {
		_, txt := h.call(t, cs, tool, args, true)
		if !strings.Contains(txt, "insufficient_scope") {
			t.Fatalf("%s without admin:it: want insufficient_scope, got %q", tool, txt)
		}
	}
}

func TestAdminRegisterIdentityAndGrant(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeAdminIT, nil)

	_, txt := h.call(t, cs, "admin_register_identity", map[string]any{
		"issuer": "https://idp.test", "subject": "newbie", "email": "newbie@corp",
	}, false)
	if !strings.Contains(txt, "ident-new") {
		t.Fatalf("register identity: want id in reply, got %q", txt)
	}

	_, txt = h.call(t, cs, "admin_grant_membership", map[string]any{
		"beamhall": "ops", "role": "builder", "identity_id": "ident-new",
	}, false)
	if !strings.Contains(txt, "ops") {
		t.Fatalf("grant membership reply: %q", txt)
	}
	assertCalled(t, h, "RegisterIdentity:newbie")
	assertCalled(t, h, "GrantMembership:ident-new:hall-1:builder")
}

func TestAdminGrantMembershipRejectsBadRole(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeAdminIT, nil)
	_, txt := h.call(t, cs, "admin_grant_membership", map[string]any{
		"beamhall": "hall-1", "role": "superuser", "identity_id": "ident-new",
	}, true)
	if !strings.Contains(txt, "role must be") {
		t.Fatalf("want role validation error, got %q", txt)
	}
}

func TestAdminCreateBeamhallRuntimeClass(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeAdminIT, nil)
	_, txt := h.call(t, cs, "admin_create_beamhall", map[string]any{
		"slug": "research", "runtime_class": "runsc",
	}, false)
	if !strings.Contains(txt, "runsc") {
		t.Fatalf("create beamhall reply: %q", txt)
	}
	assertCalled(t, h, "CreateBeamhall:research:runsc")
}

func TestAdminCreateUserWhenIdpEnabled(t *testing.T) {
	h := newHarness(t)
	h.bp.idpEnabled = true
	cs := h.connect(t, auth.ScopeAdminIT, nil)
	_, txt := h.call(t, cs, "admin_create_user", map[string]any{
		"username": "alice", "email": "alice@corp",
	}, false)
	if !strings.Contains(txt, "u-1") {
		t.Fatalf("create user reply: %q", txt)
	}
	assertCalled(t, h, "AdminCreateUser:alice")
}

func TestAdminCreateUserBYOIdpHint(t *testing.T) {
	h := newHarness(t) // idpEnabled defaults to false → Disabled-equivalent
	cs := h.connect(t, auth.ScopeAdminIT, nil)
	_, txt := h.call(t, cs, "admin_create_user", map[string]any{"username": "alice"}, true)
	if !strings.Contains(txt, "external IdP") {
		t.Fatalf("want BYO-IdP hint, got %q", txt)
	}
}

func TestAdminFederateDirectoryReachesBackplane(t *testing.T) {
	h := newHarness(t)
	h.bp.idpEnabled = true
	cs := h.connect(t, auth.ScopeAdminIT, nil)
	_, txt := h.call(t, cs, "admin_federate_directory", map[string]any{
		"name": "corp-ad", "vendor": "ad",
		"connection_url": "ldaps://dc1.corp:636", "users_dn": "OU=x,DC=corp",
	}, false)
	if !strings.Contains(txt, "corp-ad") {
		t.Fatalf("federate reply: %q", txt)
	}
	assertCalled(t, h, "AdminFederateDirectory:corp-ad")
}

func assertCalled(t *testing.T, h *harness, want string) {
	t.Helper()
	h.bp.mu.Lock()
	defer h.bp.mu.Unlock()
	for _, c := range h.bp.calls {
		if c == want {
			return
		}
	}
	t.Fatalf("expected backplane call %q; got %v", want, h.bp.calls)
}
