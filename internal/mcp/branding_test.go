package mcp

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Beamhall/beamhall/internal/auth"
)

func TestShowBrandingRequiresBeamhallsRead(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeLogsRead, nil)
	res, err := cs.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name: "show_branding", Arguments: map[string]any{"beamhall": "ops"}})
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

func TestShowBrandingUnconfiguredTellsAgentItMayDesignFreely(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeBeamhallsRead, nil)
	_, txt := h.call(t, cs, "show_branding", map[string]any{"beamhall": "ops"}, false)
	if !strings.Contains(txt, "no company branding configured") || !strings.Contains(txt, "admin_set_branding") {
		t.Fatalf("unconfigured text = %q", txt)
	}
}

func TestShowBrandingConfiguredTeachesApplication(t *testing.T) {
	h := newHarness(t)
	h.bp.brandingConfigured = true
	cs := h.connect(t, auth.ScopeBeamhallsRead, nil)
	_, txt := h.call(t, cs, "show_branding", map[string]any{"beamhall": "ops"}, false)
	for _, want := range []string{"--brand-", "brand.css", "logo-abcd1234.png", "/run/beamhall/brand.json", "admin_set_branding"} {
		if !strings.Contains(txt, want) {
			t.Errorf("configured text missing %q: %s", want, txt)
		}
	}
}

func TestAdminSetBrandingRequiresIT(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, strings.Join(auth.AllScopes(), ","), nil)
	res, err := cs.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name: "admin_set_branding", Arguments: map[string]any{"primary_color": "#fff"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatalf("builder scopes reached admin_set_branding: %q", callText(t, res))
	}
	if len(h.bp.calls) != 0 {
		t.Errorf("backplane reached: %v", h.bp.calls)
	}
}

func TestAdminSetBrandingRejectsOversizeLogoOnEncodedLengthBeforeDecoding(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeAdminIT, nil)
	huge := strings.Repeat("!", 2<<20) // ~2MiB of base64, over the 1MB cap
	res, err := cs.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name: "admin_set_branding", Arguments: map[string]any{"logo_png_base64": huge}})
	if err != nil {
		t.Fatal(err)
	}
	got := callText(t, res)
	if !res.IsError || !strings.Contains(got, "exceeds") {
		t.Fatalf("want the size-cap rejection, got %q", got)
	}
	if strings.Contains(got, "not valid base64") {
		t.Fatalf("oversized logo was decoded before its size was checked: %q", got)
	}
	if len(h.bp.calls) != 0 {
		t.Errorf("backplane reached with an oversized logo: %v", h.bp.calls)
	}
}

func TestAdminSetBrandingHappyPath(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeAdminIT, nil)
	logo := base64.StdEncoding.EncodeToString([]byte("\x89PNG\r\n\x1a\nbody"))

	// Facility-wide default, with a logo.
	_, txt := h.call(t, cs, "admin_set_branding", map[string]any{
		"primary_color": "#0B5FFF", "header_html": "<div>ACME</div>", "logo_png_base64": logo}, false)
	if !strings.Contains(txt, "company-wide default") || !strings.Contains(txt, "show_branding") ||
		!strings.Contains(txt, "logo replaced") {
		t.Fatalf("set text = %q", txt)
	}
	if got := h.bp.calls[len(h.bp.calls)-1]; got != "SetBranding::logo=12" {
		t.Fatalf("backplane call = %q", got)
	}

	// Per-beamhall override, no logo (kept).
	_, txt = h.call(t, cs, "admin_set_branding", map[string]any{
		"beamhall": "ops", "primary_color": "#00AA00"}, false)
	if !strings.Contains(txt, `beamhall "ops"`) || !strings.Contains(txt, "logo kept") {
		t.Fatalf("override text = %q", txt)
	}

	// Clear the override.
	_, txt = h.call(t, cs, "admin_set_branding", map[string]any{"beamhall": "ops", "clear": true}, false)
	if !strings.Contains(txt, "inherits the company-wide default") {
		t.Fatalf("clear text = %q", txt)
	}
}
