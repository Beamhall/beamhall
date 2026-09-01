package brand

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/orch"
	"github.com/Beamhall/beamhall/internal/store"
)

type stubReader struct {
	info  map[string]orch.BrandingInfo
	logos map[string]domain.BrandingLogo
}

func (s stubReader) ResolveBrandingByOwner(_ context.Context, owner string) (orch.BrandingInfo, error) {
	if i, ok := s.info[owner]; ok {
		return i, nil
	}
	return orch.BrandingInfo{}, store.ErrNotFound
}

func (s stubReader) BrandingLogoByOwner(_ context.Context, owner string) (domain.BrandingLogo, error) {
	if l, ok := s.logos[owner]; ok {
		return l, nil
	}
	return domain.BrandingLogo{}, store.ErrNotFound
}

func testHandler() http.Handler {
	return New(stubReader{
		info: map[string]orch.BrandingInfo{
			"ops": {Configured: true, PrimaryColor: "#0B5FFF", TextColor: "#111111"},
			"_":   {Configured: true, PrimaryColor: "#222222"},
			"nix": {Configured: false},
		},
		logos: map[string]domain.BrandingLogo{
			"ops": {Bytes: []byte("PNGBYTES"), MIME: "image/png", ETag: "abcd1234"},
		},
	}, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler()
}

func get(t *testing.T, h http.Handler, path string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestBrandCSS(t *testing.T) {
	h := testHandler()

	rec := get(t, h, "/brand/ops/brand.css", nil)
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, ":root{") || !strings.Contains(body, "--brand-primary:#0B5FFF;") ||
		!strings.Contains(body, "--brand-text:#111111;") {
		t.Errorf("css body = %q", body)
	}
	if strings.Contains(body, "--brand-secondary") {
		t.Errorf("unset colour emitted: %q", body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/css") {
		t.Errorf("content-type = %q", ct)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing nosniff")
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "max-age=300") {
		t.Errorf("cache-control = %q", cc)
	}

	// Facility scope serves under the "_" owner.
	if rec := get(t, h, "/brand/_/brand.css", nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "#222222") {
		t.Errorf("facility css: %d %q", rec.Code, rec.Body.String())
	}
	// Unconfigured and unknown owners 404.
	if rec := get(t, h, "/brand/nix/brand.css", nil); rec.Code != 404 {
		t.Errorf("unconfigured = %d", rec.Code)
	}
	if rec := get(t, h, "/brand/ghost/brand.css", nil); rec.Code != 404 {
		t.Errorf("unknown owner = %d", rec.Code)
	}
	if rec := get(t, h, "/brand/UPPER/brand.css", nil); rec.Code != 404 {
		t.Errorf("invalid owner = %d", rec.Code)
	}
}

func TestBrandLogo(t *testing.T) {
	h := testHandler()

	rec := get(t, h, "/brand/ops/logo-abcd1234.png", nil)
	if rec.Code != 200 || rec.Body.String() != "PNGBYTES" {
		t.Fatalf("logo: %d %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "image/png" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("headers = %v", rec.Header())
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Errorf("current etag should be immutable: %q", cc)
	}

	// A stale hash still serves the current image, briefly cached.
	rec = get(t, h, "/brand/ops/logo-00000000.png", nil)
	if rec.Code != 200 || rec.Body.String() != "PNGBYTES" {
		t.Fatalf("stale etag: %d %q", rec.Code, rec.Body.String())
	}
	if cc := rec.Header().Get("Cache-Control"); strings.Contains(cc, "immutable") {
		t.Errorf("stale etag must not be immutable: %q", cc)
	}

	// Conditional revalidation.
	rec = get(t, h, "/brand/ops/logo-abcd1234.png", map[string]string{"If-None-Match": `"abcd1234"`})
	if rec.Code != http.StatusNotModified {
		t.Errorf("if-none-match = %d", rec.Code)
	}

	// No logo, bad filenames, other paths: 404.
	if rec := get(t, h, "/brand/_/logo-abcd1234.png", nil); rec.Code != 404 {
		t.Errorf("no logo = %d", rec.Code)
	}
	for _, p := range []string{"/brand/ops/logo-XYZ.png", "/brand/ops/evil.html", "/brand/ops/logo-abcd1234.svg", "/brand/ops", "/other"} {
		if rec := get(t, h, p, nil); rec.Code != 404 {
			t.Errorf("%s = %d, want 404", p, rec.Code)
		}
	}
}
