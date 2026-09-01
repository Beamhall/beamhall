// Package brand serves the public company-branding assets on the appliance's
// base domain: a beamhall's resolved palette as CSS custom properties
// (hot-linkable, so an IT palette change reaches running apps without a
// redeploy) and the logo image under an immutable content-hash URL. The
// routes are read-only and unauthenticated — branding appears on public app
// pages by design. This handler shares the control origin with /admin and
// /mcp, so it serves ONLY text/css and image/png (never HTML or SVG), always
// with nosniff.
package brand

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/orch"
	"github.com/Beamhall/beamhall/internal/store"
)

// Reader resolves branding for a URL owner segment (a beamhall slug, or "_"
// for the facility default). *orch.Orchestrator satisfies it.
type Reader interface {
	ResolveBrandingByOwner(ctx context.Context, owner string) (orch.BrandingInfo, error)
	BrandingLogoByOwner(ctx context.Context, owner string) (domain.BrandingLogo, error)
}

// Service is the /brand/ handler.
type Service struct {
	r   Reader
	log *slog.Logger
}

func New(r Reader, log *slog.Logger) *Service {
	return &Service{r: r, log: log}
}

func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /brand/{owner}/brand.css", s.css)
	mux.HandleFunc("GET /brand/{owner}/{file}", s.logo)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	return mux
}

var (
	ownerRe    = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?|_)$`)
	logoFileRe = regexp.MustCompile(`^logo-([0-9a-f]{1,64})\.png$`)
)

func (s *Service) css(w http.ResponseWriter, r *http.Request) {
	owner := r.PathValue("owner")
	if !ownerRe.MatchString(owner) {
		http.NotFound(w, r)
		return
	}
	info, err := s.r.ResolveBrandingByOwner(r.Context(), owner)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !info.Configured {
		http.NotFound(w, r)
		return
	}
	var b strings.Builder
	b.WriteString(":root{")
	for _, v := range []struct{ name, val string }{
		{"--brand-primary", info.PrimaryColor},
		{"--brand-secondary", info.SecondaryColor},
		{"--brand-accent", info.AccentColor},
		{"--brand-background", info.BackgroundColor},
		{"--brand-text", info.TextColor},
	} {
		if v.val != "" {
			fmt.Fprintf(&b, "%s:%s;", v.name, v.val)
		}
	}
	b.WriteString("}\n")
	h := w.Header()
	h.Set("Content-Type", "text/css; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write([]byte(b.String()))
}

func (s *Service) logo(w http.ResponseWriter, r *http.Request) {
	owner := r.PathValue("owner")
	m := logoFileRe.FindStringSubmatch(r.PathValue("file"))
	if !ownerRe.MatchString(owner) || m == nil {
		http.NotFound(w, r)
		return
	}
	logo, err := s.r.BrandingLogoByOwner(r.Context(), owner)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	h := w.Header()
	h.Set("Content-Type", logo.MIME)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("ETag", `"`+logo.ETag+`"`)
	if m[1] == logo.ETag {
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		// A stale hash means the logo changed after this URL was handed out
		// (a running app's brand.json predates the change). Serve the current
		// image briefly cached rather than leaving a broken <img> until the
		// app's next deploy.
		h.Set("Cache-Control", "public, max-age=300")
	}
	if r.Header.Get("If-None-Match") == `"`+logo.ETag+`"` {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write(logo.Bytes)
}

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	s.log.Error("brand read failed", "path", r.URL.Path, "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}
