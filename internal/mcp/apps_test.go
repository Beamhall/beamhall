package mcp

import (
	"context"
	"strings"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Beamhall/beamhall/internal/auth"
	"github.com/Beamhall/beamhall/internal/orch"
)

func TestListAppsRequiresBeamsUse(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeLogsRead, nil)
	res, err := cs.CallTool(context.Background(), &sdkmcp.CallToolParams{Name: "list_apps"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(callText(t, res), "insufficient_scope") {
		t.Fatalf("want insufficient_scope, got %q", callText(t, res))
	}
	if len(h.bp.calls) != 0 {
		t.Errorf("backplane reached despite missing scope: %v", h.bp.calls)
	}
}

func TestListAppsEmptySendsUserToIT(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeBeamsUse, nil)
	_, txt := h.call(t, cs, "list_apps", nil, false)
	if !strings.Contains(txt, "admin_set_app_audience") ||
		!strings.Contains(txt, "does not mean the app is missing") {
		t.Fatalf("empty-list text = %q", txt)
	}
}

func TestListAppsPopulatedTeachesUse(t *testing.T) {
	h := newHarness(t)
	h.bp.apps = []orch.AppView{
		{App: "expenses", Description: "Submit and approve expense claims", Workspace: "team-blue",
			URL: "https://expenses.team-blue.beamhall.test", Live: true, SignIn: "company_sso",
			PublishedAt: time.Now()},
		{App: "leave", Description: "Book and track time off", Workspace: "team-green",
			Live: false, SignIn: "app_managed", PublishedAt: time.Now()},
	}
	cs := h.connect(t, auth.ScopeBeamsUse, nil)
	_, txt := h.call(t, cs, "list_apps", nil, false)
	for _, want := range []string{
		"https://expenses.team-blue.beamhall.test",
		"sign in with your company account",
		"not live yet",
		"describe_app",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("list text missing %q: %s", want, txt)
		}
	}
}

// The not-published answer must carry no hint of whether the app exists — the
// same text either way, with no workspace or URL leaking.
func TestDescribeAppNotPublishedIsUniformAndLeakFree(t *testing.T) {
	h := newHarness(t)
	h.bp.apps = nil
	cs := h.connect(t, auth.ScopeBeamsUse, nil)
	res, err := cs.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name: "describe_app", Arguments: map[string]any{"app": "expenses"}})
	if err != nil {
		t.Fatal(err)
	}
	txt := callText(t, res)
	if !res.IsError || !strings.Contains(txt, `no app named "expenses" is published to you`) {
		t.Fatalf("want the uniform refusal, got %q", txt)
	}
	if strings.Contains(txt, "team-") || strings.Contains(txt, "https://") {
		t.Fatalf("refusal leaks detail: %q", txt)
	}
}

func TestDescribeAppAmbiguousNamesWorkspaces(t *testing.T) {
	h := newHarness(t)
	now := time.Now()
	h.bp.apps = []orch.AppView{
		{App: "tracker", Workspace: "team-blue", PublishedAt: now},
		{App: "tracker", Workspace: "team-green", PublishedAt: now},
	}
	cs := h.connect(t, auth.ScopeBeamsUse, nil)
	res, err := cs.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name: "describe_app", Arguments: map[string]any{"app": "tracker"}})
	if err != nil {
		t.Fatal(err)
	}
	txt := callText(t, res)
	if !res.IsError || !strings.Contains(txt, "team-blue") || !strings.Contains(txt, "team-green") ||
		!strings.Contains(txt, "workspace") {
		t.Fatalf("ambiguity text = %q", txt)
	}
	// Disambiguated, it resolves.
	_, txt = h.call(t, cs, "describe_app", map[string]any{"app": "tracker", "workspace": "team-green"}, false)
	if !strings.Contains(txt, "team-green") {
		t.Fatalf("disambiguated describe = %q", txt)
	}
}

func TestAdminSetAppAudienceRequiresIT(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, strings.Join(auth.AllScopes(), ","), nil)
	res, err := cs.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name: "admin_set_app_audience", Arguments: map[string]any{
			"beamhall": "ops", "beam": "tracker", "everyone": true}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatalf("builder scopes reached admin_set_app_audience: %q", callText(t, res))
	}
	if len(h.bp.calls) != 0 {
		t.Errorf("backplane reached: %v", h.bp.calls)
	}
}

func TestAdminSetAppAudienceRejectsEmptyAudience(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeAdminIT, nil)
	res, err := cs.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name: "admin_set_app_audience", Arguments: map[string]any{"beamhall": "ops", "beam": "tracker"}})
	if err != nil {
		t.Fatal(err)
	}
	txt := callText(t, res)
	if !res.IsError || !strings.Contains(txt, "audience of nobody") {
		t.Fatalf("want the empty-audience rejection, got %q", txt)
	}
	for _, c := range h.bp.calls {
		if strings.HasPrefix(c, "SetAppAudience") {
			t.Fatalf("backplane reached with an empty audience: %v", h.bp.calls)
		}
	}
}

func TestAdminSetAppAudienceHappyPathAndClear(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeAdminIT, nil)

	// Publish to a union; the fake beam has no live channel, so the copy must
	// carry the promote_to_live warning; group audiences are disabled on this
	// appliance, so the groups warning must fire too.
	_, txt := h.call(t, cs, "admin_set_app_audience", map[string]any{
		"beamhall": "ops", "beam": "tracker", "everyone": true, "groups": []string{"finance"}}, false)
	for _, want := range []string{"published to", "everyone", "finance", "NOT live yet",
		"promote_to_live", "BEAMHALL_OAUTH_GROUPS_CLAIM"} {
		if !strings.Contains(txt, want) {
			t.Errorf("publish text missing %q: %s", want, txt)
		}
	}
	if got := h.bp.calls[len(h.bp.calls)-1]; got != "SetAppAudience:beam-1:everyone=true:groups=1:ids=0:clear=false" {
		t.Fatalf("backplane call = %q", got)
	}

	// With the claim configured, no warning.
	h.bp.groupAudiences = true
	_, txt = h.call(t, cs, "admin_set_app_audience", map[string]any{
		"beamhall": "ops", "beam": "tracker", "groups": []string{"finance"}}, false)
	if strings.Contains(txt, "BEAMHALL_OAUTH_GROUPS_CLAIM") {
		t.Fatalf("groups warning fired despite a configured claim: %q", txt)
	}

	// Unpublish.
	_, txt = h.call(t, cs, "admin_set_app_audience", map[string]any{
		"beamhall": "ops", "beam": "tracker", "clear": true}, false)
	if !strings.Contains(txt, "UNPUBLISHED") || !strings.Contains(txt, "controls discovery, not the network") {
		t.Fatalf("clear text = %q", txt)
	}
}

// Auto-registration is scoped to the using tier: an unknown subject with
// beams:use gets an identity row; the same subject with a builder scope gets
// today's "ask IT" refusal, and so does a user when the switch is off.
func TestAutoRegisterFiresOnlyForBeamsUse(t *testing.T) {
	h := newHarness(t)
	h.bp.autoRegister = true

	cs := h.connect(t, "as=user-new;"+auth.ScopeBeamsUse, nil)
	_, _ = h.call(t, cs, "list_apps", nil, false)
	var registered, listed bool
	for _, c := range h.bp.calls {
		if c == "RegisterUserIdentity:user-new" {
			registered = true
		}
		if c == "ListApps" {
			listed = true
		}
	}
	if !registered || !listed {
		t.Fatalf("auto-register did not run before the tool: %v", h.bp.calls)
	}

	// A builder scope on the same unknown subject: no auto-register, the
	// message stays exactly today's.
	h.bp.calls = nil
	cs2 := h.connect(t, "as=user-new;"+auth.ScopeBeamhallsRead, nil)
	res, err := cs2.CallTool(context.Background(), &sdkmcp.CallToolParams{Name: "list_beams"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(callText(t, res), "ask IT to register it") {
		t.Fatalf("builder-scope refusal = %q", callText(t, res))
	}
	for _, c := range h.bp.calls {
		if strings.HasPrefix(c, "RegisterUserIdentity") {
			t.Fatalf("auto-register fired for a builder scope: %v", h.bp.calls)
		}
	}

	// Switch off: the user gets the refusal too.
	h.bp.autoRegister = false
	cs3 := h.connect(t, "as=user-newer;"+auth.ScopeBeamsUse, nil)
	res, err = cs3.CallTool(context.Background(), &sdkmcp.CallToolParams{Name: "list_apps"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(callText(t, res), "ask IT to register it") {
		t.Fatalf("switched-off refusal = %q", callText(t, res))
	}
}
