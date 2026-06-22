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

func TestAdminFederateDirectoryFilesRequest(t *testing.T) {
	h := newHarness(t)
	h.bp.idpEnabled = true
	cs := h.connect(t, auth.ScopeAdminIT, nil)
	_, txt := h.call(t, cs, "admin_federate_directory", map[string]any{
		"name": "corp-ad", "vendor": "ad",
		"connection_url": "ldaps://dc1.corp:636", "users_dn": "OU=x,DC=corp",
		"bind_password": "s3cret",
	}, false)
	// It files a request (does not execute) and tells the operator a second IT
	// person must approve. The reply must not echo the bind password.
	if !strings.Contains(txt, "areq-1") || !strings.Contains(txt, "approve") {
		t.Fatalf("expected a four-eyes request reply, got %q", txt)
	}
	if strings.Contains(txt, "s3cret") {
		t.Fatalf("reply leaked the bind password: %q", txt)
	}
	assertCalled(t, h, "RequestFederateDirectory:corp-ad")
}

func TestAdminApproveAndRejectRequest(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeAdminIT, nil)

	_, txt := h.call(t, cs, "admin_list_pending_requests", map[string]any{}, false)
	if !strings.Contains(txt, "areq-1") {
		t.Fatalf("pending list: %q", txt)
	}
	_, txt = h.call(t, cs, "admin_approve_request", map[string]any{"request_id": "areq-1"}, false)
	if !strings.Contains(txt, "approved") {
		t.Fatalf("approve reply: %q", txt)
	}
	assertCalled(t, h, "ApproveAdminAction:areq-1")

	_, _ = h.call(t, cs, "admin_reject_request", map[string]any{"request_id": "areq-2", "reason": "nope"}, false)
	assertCalled(t, h, "RejectAdminAction:areq-2")
}

func TestSensitiveToolsRequireAdminScope(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeBeamsWrite, nil)
	for tool, args := range map[string]map[string]any{
		"admin_list_pending_requests": {},
		"admin_approve_request":       {"request_id": "areq-1"},
		"admin_reject_request":        {"request_id": "areq-1"},
	} {
		_, txt := h.call(t, cs, tool, args, true)
		if !strings.Contains(txt, "insufficient_scope") {
			t.Fatalf("%s without admin:it: want insufficient_scope, got %q", tool, txt)
		}
	}
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
