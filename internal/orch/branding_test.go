package orch

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Beamhall/beamhall/internal/domain"
)

// tinyPNG is a minimal payload carrying the PNG signature the validator checks.
var tinyPNG = append([]byte("\x89PNG\r\n\x1a\n"), []byte("body")...)

func TestSetBrandingRequiresITAndPersists(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()

	spec := BrandingSpec{Branding: domain.Branding{PrimaryColor: "#0B5FFF", HeaderHTML: "<div>ACME</div>"}}
	if err := w.o.SetBranding(ctx, w.build, w.bh.ID, spec); err == nil {
		t.Fatal("builder should not be able to set branding")
	}
	recs, _ := w.st.ListAuditEvents(ctx, 0, 50)
	var denied bool
	for _, rec := range recs {
		if rec.Event.Action == "admin_set_branding" && rec.Event.Decision == domain.DecisionDeny {
			denied = true
		}
	}
	if !denied {
		t.Fatal("denied admin_set_branding not on the audit chain")
	}

	it := Actor{ITAdmin: true}
	if err := w.o.SetBranding(ctx, it, w.bh.ID, spec); err != nil {
		t.Fatalf("SetBranding (IT): %v", err)
	}
	info, err := w.o.ShowBranding(ctx, w.build, w.bh.ID)
	if err != nil {
		t.Fatalf("ShowBranding: %v", err)
	}
	if !info.Configured || info.PrimaryColor != "#0B5FFF" || info.HeaderHTML != "<div>ACME</div>" {
		t.Fatalf("ShowBranding = %+v", info)
	}
	if info.Scope != "beamhall" {
		t.Errorf("scope = %q, want beamhall", info.Scope)
	}
	if !strings.Contains(info.CSSURL, "https://bh.example/brand/ops/brand.css") {
		t.Errorf("css url = %q", info.CSSURL)
	}
}

func TestBrandingResolutionMergesFieldWise(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	it := Actor{ITAdmin: true}

	if err := w.o.SetBranding(ctx, it, domain.FacilityScope, BrandingSpec{
		Branding: domain.Branding{
			PrimaryColor: "#111111", SecondaryColor: "#222222", TextColor: "#333333",
			FooterHTML: "<footer>legal</footer>",
		},
		LogoPNG: tinyPNG,
	}); err != nil {
		t.Fatalf("SetBranding facility: %v", err)
	}
	if err := w.o.SetBranding(ctx, it, w.bh.ID, BrandingSpec{
		Branding: domain.Branding{PrimaryColor: "#00AA00"},
	}); err != nil {
		t.Fatalf("SetBranding override: %v", err)
	}

	info, err := w.o.ShowBranding(ctx, w.build, w.bh.ID)
	if err != nil {
		t.Fatalf("ShowBranding: %v", err)
	}
	if info.PrimaryColor != "#00AA00" {
		t.Errorf("primary = %q, want the override", info.PrimaryColor)
	}
	if info.SecondaryColor != "#222222" || info.TextColor != "#333333" || info.FooterHTML != "<footer>legal</footer>" {
		t.Errorf("facility fields did not fall through: %+v", info)
	}
	if info.Scope != "beamhall" {
		t.Errorf("scope = %q", info.Scope)
	}
	// The facility logo falls through; the URL stays under the hall's owner
	// segment so it never changes when the override does.
	if !strings.Contains(info.LogoURL, "/brand/ops/logo-") || !strings.HasSuffix(info.LogoURL, ".png") {
		t.Errorf("logo url = %q", info.LogoURL)
	}

	// A hall with no override of its own reports the facility scope.
	bh2 := &domain.Beamhall{Slug: "plain", DisplayName: "Plain", Status: domain.BeamhallActive,
		NetworkPolicy: domain.NetworkPolicy{EgressMode: domain.EgressDenyAll},
		Quota:         domain.ResourceQuota{MaxBeams: 1}, LiveSlotLimit: 1}
	sc2 := &domain.SecurityContext{RuntimeClass: domain.RuntimeRunsc, Template: domain.TemplateWebApp}
	if err := w.st.CreateBeamhall(ctx, bh2, sc2); err != nil {
		t.Fatal(err)
	}
	got, err := w.o.ResolveBrandingByOwner(ctx, "plain")
	if err != nil {
		t.Fatalf("ResolveBrandingByOwner: %v", err)
	}
	if got.Scope != "facility" || got.PrimaryColor != "#111111" {
		t.Errorf("plain hall = %+v, want pure facility values", got)
	}
}

func TestSetBrandingRejectsOversizeAndNonPNGLogo(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	it := Actor{ITAdmin: true}

	big := append(append([]byte{}, tinyPNG...), bytes.Repeat([]byte{0}, maxLogoBytes)...)
	if err := w.o.SetBranding(ctx, it, domain.FacilityScope, BrandingSpec{LogoPNG: big}); err == nil {
		t.Error("oversize logo accepted")
	}
	if err := w.o.SetBranding(ctx, it, domain.FacilityScope, BrandingSpec{LogoPNG: []byte("\xff\xd8\xffJPEG")}); err == nil {
		t.Error("non-PNG logo accepted")
	}
	if err := w.o.SetBranding(ctx, it, domain.FacilityScope, BrandingSpec{LogoPNG: []byte("<svg xmlns='x'/>")}); err == nil {
		t.Error("SVG logo accepted")
	}
	if _, err := w.st.GetBrandingLogo(ctx, domain.FacilityScope); err == nil {
		t.Error("a rejected logo was persisted")
	}
}

func TestSetBrandingRejectsMalformedColor(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	it := Actor{ITAdmin: true}
	for _, bad := range []string{"#fff;}", "red;background:url(x)", "url(javascript:1)", "#ggg"} {
		if err := w.o.SetBranding(ctx, it, domain.FacilityScope,
			BrandingSpec{Branding: domain.Branding{PrimaryColor: bad}}); err == nil {
			t.Errorf("colour %q accepted", bad)
		}
	}
	for _, good := range []string{"#fff", "#0B5FFF", "#0b5fffcc", "hotpink", "rgb(11, 95, 255)", "hsl(220, 100%, 52%)"} {
		if err := w.o.SetBranding(ctx, it, domain.FacilityScope,
			BrandingSpec{Branding: domain.Branding{PrimaryColor: good}}); err != nil {
			t.Errorf("colour %q rejected: %v", good, err)
		}
	}
}

func TestSetBrandingKeepsLogoWhenOmittedAndClearsOnRequest(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	it := Actor{ITAdmin: true}

	if err := w.o.SetBranding(ctx, it, domain.FacilityScope, BrandingSpec{
		Branding: domain.Branding{PrimaryColor: "#111111"}, LogoPNG: tinyPNG,
	}); err != nil {
		t.Fatal(err)
	}
	// Text-only update: the logo survives.
	if err := w.o.SetBranding(ctx, it, domain.FacilityScope, BrandingSpec{
		Branding: domain.Branding{PrimaryColor: "#222222"},
	}); err != nil {
		t.Fatal(err)
	}
	info, _ := w.o.ResolveBrandingByOwner(ctx, "_")
	if info.LogoURL == "" || info.PrimaryColor != "#222222" {
		t.Fatalf("logo lost on text update: %+v", info)
	}
	// clear_logo removes it, text stays.
	if err := w.o.SetBranding(ctx, it, domain.FacilityScope, BrandingSpec{
		Branding: domain.Branding{PrimaryColor: "#222222"}, ClearLogo: true,
	}); err != nil {
		t.Fatal(err)
	}
	info, _ = w.o.ResolveBrandingByOwner(ctx, "_")
	if info.LogoURL != "" || info.PrimaryColor != "#222222" {
		t.Fatalf("clear_logo: %+v", info)
	}
	// clear drops the whole scope.
	if err := w.o.SetBranding(ctx, it, domain.FacilityScope, BrandingSpec{Clear: true}); err != nil {
		t.Fatal(err)
	}
	info, _ = w.o.ResolveBrandingByOwner(ctx, "_")
	if info.Configured {
		t.Fatalf("clear left branding behind: %+v", info)
	}
}

func TestDeployMountsBrandingBinding(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()

	// No branding configured: no binding.
	w.deployed(t, "bare")
	if got := w.drv.deploys[0].Bindings; len(got) != 0 {
		t.Fatalf("unbranded deploy got bindings: %+v", got)
	}

	it := Actor{ITAdmin: true}
	if err := w.o.SetBranding(ctx, it, domain.FacilityScope, BrandingSpec{
		Branding: domain.Branding{PrimaryColor: "#0B5FFF", HeaderHTML: "<div>ACME</div>"},
	}); err != nil {
		t.Fatal(err)
	}
	w.deployed(t, "branded")
	bindings := w.drv.deploys[1].Bindings
	if len(bindings) != 1 || bindings[0].Alias != "brand.json" || bindings[0].MountPath != "/run/beamhall/brand.json" {
		t.Fatalf("bindings = %+v", bindings)
	}
	var info BrandingInfo
	if err := json.Unmarshal(bindings[0].Value, &info); err != nil {
		t.Fatalf("brand.json not JSON: %v", err)
	}
	if info.PrimaryColor != "#0B5FFF" || info.HeaderHTML != "<div>ACME</div>" || info.CSSURL == "" {
		t.Fatalf("brand.json = %+v", info)
	}
}

func TestRollbackUsesCurrentBranding(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	it := Actor{ITAdmin: true}

	if err := w.o.SetBranding(ctx, it, domain.FacilityScope, BrandingSpec{
		Branding: domain.Branding{PrimaryColor: "#111111"},
	}); err != nil {
		t.Fatal(err)
	}
	beam := w.deployed(t, "tracker")
	if _, err := w.o.PromoteToLive(ctx, w.admin, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("promote v1: %v", err)
	}
	got, _ := w.st.GetBeam(ctx, beam.ID)
	liveRel1 := got.LiveReleaseID
	if _, err := w.o.DeployBeam(ctx, w.build, w.bh.ID, beam.ID,
		DeployRequest{ImageRef: "reg/beam:2", ImageDigest: "sha256:def"}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.o.PromoteToLive(ctx, w.admin, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("promote v2: %v", err)
	}

	// Branding changes after every release was cut; rollback must wear it.
	if err := w.o.SetBranding(ctx, it, domain.FacilityScope, BrandingSpec{
		Branding: domain.Branding{PrimaryColor: "#999999"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.o.RollbackBeam(ctx, w.admin, w.bh.ID, beam.ID, liveRel1); err != nil {
		t.Fatalf("RollbackBeam: %v", err)
	}
	last := w.drv.deploys[len(w.drv.deploys)-1]
	if len(last.Bindings) != 1 {
		t.Fatalf("rollback deploy bindings = %+v", last.Bindings)
	}
	var info BrandingInfo
	if err := json.Unmarshal(last.Bindings[0].Value, &info); err != nil {
		t.Fatal(err)
	}
	if info.PrimaryColor != "#999999" {
		t.Fatalf("rollback wore stale branding: %+v", info)
	}
}
