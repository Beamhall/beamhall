package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Beamhall/beamhall/internal/auth"
	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/orch"
	"github.com/Beamhall/beamhall/internal/store"
)

// Backplane is the slice of the orchestrator the console's IT actions call —
// each audited behind the it_admin gate (*orch.Orchestrator satisfies it).
type Backplane interface {
	EnsureOperator(ctx context.Context, issuer, subject, email string) (domain.ID, error)
	CreateBeamhall(ctx context.Context, actor orch.Actor, spec orch.NewBeamhallSpec) (*domain.Beamhall, error)
	RegisterIdentity(ctx context.Context, actor orch.Actor, issuer, subject, email, displayName string) (*domain.Identity, error)
	GrantMembership(ctx context.Context, actor orch.Actor, identityID, beamhallID domain.ID, role domain.MembershipRole) error
	SetEgress(ctx context.Context, actor orch.Actor, beamhallID domain.ID, mode domain.EgressMode, allowlist []string) error
	PromoteToLive(ctx context.Context, actor orch.Actor, beamhallID, beamID domain.ID) (string, error)
	RollbackBeam(ctx context.Context, actor orch.Actor, beamhallID, beamID, targetReleaseID domain.ID) (string, error)
	DestroyBeam(ctx context.Context, actor orch.Actor, beamhallID, beamID domain.ID) error
	PausePreview(ctx context.Context, actor orch.Actor, beamhallID, beamID domain.ID) error
	ResumePreview(ctx context.Context, actor orch.Actor, beamhallID, beamID domain.ID) (string, error)
	PromoteApprovalEnabled() bool
	ListPendingPromotions(ctx context.Context, actor orch.Actor, beamhallID domain.ID) ([]domain.PromotionRequest, error)
	ApprovePromotion(ctx context.Context, actor orch.Actor, requestID domain.ID) (string, error)
	RejectPromotion(ctx context.Context, actor orch.Actor, requestID domain.ID, reason string) error
}

// Compile-time check that the orchestrator satisfies the console's Backplane.
var _ Backplane = (*orch.Orchestrator)(nil)

// Config configures the Admin console.
type Config struct {
	BaseURL      string // external base, e.g. https://beamhall.acme.internal
	Issuer       string // OIDC issuer (same IdP the MCP layer trusts)
	ClientID     string // admin OAuth client
	ClientSecret string
	Scopes       []string // requested at login (must include openid + admin:it)

	Verifier   *auth.Verifier // validates the exchanged access token (admin:it)
	SessionKey []byte         // HMAC key for session cookies
	SessionTTL time.Duration  // default 8h
	Secure     bool           // Secure cookies (false only for plain-HTTP lab)
	HTTPClient *http.Client   // OIDC discovery/token client (tests)
	Logger     *slog.Logger
}

// Server is the Admin console. It serves /admin/*.
type Server struct {
	st    *store.Store
	bp    Backplane
	cfg   Config
	codec *sessionCodec
	tmpl  *template.Template
	log   *slog.Logger

	pmu      sync.Mutex
	provider *oidcProvider // lazily resolved (see oidc); may be nil until first login
}

// New builds the console and discovers the IdP's OIDC endpoints.
func New(ctx context.Context, st *store.Store, bp Backplane, cfg Config) (*Server, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 8 * time.Hour
	}
	tmpl, err := parseTemplates()
	if err != nil {
		return nil, err
	}
	s := &Server{
		st: st, bp: bp, cfg: cfg, codec: newSessionCodec(cfg.SessionKey),
		tmpl: tmpl, log: cfg.Logger,
	}
	// Best-effort eager discovery; if the IdP isn't up yet (a co-located bundled
	// IdP starting alongside us), the console mounts anyway and resolves the
	// endpoints lazily on first login rather than disabling itself for the run.
	s.provider, _ = discover(ctx, s.oidcCfg())
	return s, nil
}

// oidcCfg builds the discovery input from the server config.
func (s *Server) oidcCfg() oidcConfig {
	return oidcConfig{
		Issuer: s.cfg.Issuer, ClientID: s.cfg.ClientID, ClientSecret: s.cfg.ClientSecret,
		Scopes: s.cfg.Scopes, HTTPClient: s.cfg.HTTPClient,
	}
}

// oidc returns the IdP provider, resolving its endpoints via OIDC discovery on
// first use (and caching the result). Lets the console survive an IdP that
// wasn't reachable at boot.
func (s *Server) oidc(ctx context.Context) (*oidcProvider, error) {
	s.pmu.Lock()
	defer s.pmu.Unlock()
	if s.provider != nil {
		return s.provider, nil
	}
	p, err := discover(ctx, s.oidcCfg())
	if err != nil {
		return nil, err
	}
	s.provider = p
	return p, nil
}

// Handler returns the /admin mux (mount it on the main server).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/login", s.handleLogin)
	mux.HandleFunc("GET /admin/callback", s.handleCallback)
	mux.HandleFunc("POST /admin/logout", s.handleLogout)

	// Authenticated views + actions.
	mux.Handle("GET /admin/{$}", s.requireAdmin(s.handleDashboard))
	mux.Handle("GET /admin", s.requireAdmin(s.handleDashboard))
	mux.Handle("GET /admin/beamhalls/{slug}", s.requireAdmin(s.handleBeamhall))
	mux.Handle("GET /admin/audit", s.requireAdmin(s.handleAudit))
	mux.Handle("POST /admin/beamhalls", s.requireAdmin(s.actionCreateBeamhall))
	mux.Handle("POST /admin/identities", s.requireAdmin(s.actionRegisterIdentity))
	mux.Handle("POST /admin/memberships", s.requireAdmin(s.actionGrantMembership))
	mux.Handle("POST /admin/beamhalls/{slug}/egress", s.requireAdmin(s.actionSetEgress))
	mux.Handle("POST /admin/beams/{id}/promote", s.requireAdmin(s.actionPromote))
	mux.Handle("POST /admin/beams/{id}/pause", s.requireAdmin(s.actionPause))
	mux.Handle("POST /admin/beams/{id}/resume", s.requireAdmin(s.actionResume))
	mux.Handle("POST /admin/beams/{id}/rollback", s.requireAdmin(s.actionRollback))
	mux.Handle("POST /admin/beams/{id}/destroy", s.requireAdmin(s.actionDestroy))
	mux.Handle("POST /admin/promotions/{id}/approve", s.requireAdmin(s.actionApprovePromotion))
	mux.Handle("POST /admin/promotions/{id}/reject", s.requireAdmin(s.actionRejectPromotion))
	return mux
}

// --- auth flow ------------------------------------------------------------

const stateCookie = "bh_admin_oauth_state"

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Landing page with a sign-in button unless ?start=1 kicks off the flow.
	if r.URL.Query().Get("start") == "" {
		s.render(w, "page-login", map[string]string{"Error": r.URL.Query().Get("error")})
		return
	}
	state, err := randomToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	prov, err := s.oidc(r.Context())
	if err != nil {
		s.log.Warn("admin login: OIDC discovery failed", "err", err)
		http.Error(w, "identity provider unavailable — try again shortly", http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: stateCookie, Value: state, Path: "/admin", HttpOnly: true,
		Secure: s.cfg.Secure, SameSite: http.SameSiteLaxMode, MaxAge: 600,
	})
	http.Redirect(w, r, prov.authCodeURL(state, s.redirectURI(r)), http.StatusFound)
}

// redirectURI is this appliance's OIDC callback, derived from the request so
// it works behind a reverse proxy. BaseURL overrides it when set (a fixed
// externally-registered redirect).
func (s *Server) redirectURI(r *http.Request) string {
	if s.cfg.BaseURL != "" {
		return strings.TrimRight(s.cfg.BaseURL, "/") + "/admin/callback"
	}
	scheme := "https"
	if !s.cfg.Secure {
		scheme = "http"
	}
	if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
		scheme = p
	}
	return scheme + "://" + r.Host + "/admin/callback"
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	stateC, err := r.Cookie(stateCookie)
	if err != nil || stateC.Value == "" || stateC.Value != r.URL.Query().Get("state") {
		http.Error(w, "invalid OAuth state — restart the login", http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}
	prov, err := s.oidc(r.Context())
	if err != nil {
		http.Error(w, "identity provider unavailable — try again shortly", http.StatusServiceUnavailable)
		return
	}
	tok, err := prov.exchange(r.Context(), code, s.redirectURI(r))
	if err != nil {
		s.log.Warn("admin token exchange failed", "err", err)
		http.Error(w, "login failed at the identity provider", http.StatusBadGateway)
		return
	}
	info, err := s.cfg.Verifier.Verify(r.Context(), tok, r)
	if err != nil {
		s.log.Warn("admin token validation failed", "err", err)
		http.Error(w, "the identity provider returned an invalid token", http.StatusBadGateway)
		return
	}
	if !auth.HasScope(info.Scopes, auth.ScopeAdminIT) {
		http.Error(w, "your account is not an IT administrator (missing the admin:it scope)", http.StatusForbidden)
		return
	}
	issuer, _ := info.Extra[auth.ExtraIssuer].(string)
	subject, _ := info.Extra[auth.ExtraSubject].(string)
	email, _ := info.Extra[auth.ExtraEmail].(string)
	identID, err := s.bp.EnsureOperator(r.Context(), issuer, subject, email)
	if err != nil {
		s.log.Error("ensure operator identity", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sess := session{Subject: subject, Issuer: issuer, Email: email,
		Identity: string(identID), ExpiresAt: time.Now().Add(s.cfg.SessionTTL).Unix()}
	if err := s.codec.setSession(w, sess, s.cfg.Secure); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	clearCookie(w, stateCookie, s.cfg.Secure)
	http.Redirect(w, r, "/admin", http.StatusFound)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	clearSession(w, s.cfg.Secure)
	http.Redirect(w, r, "/admin/login", http.StatusFound)
}

// --- middleware -----------------------------------------------------------

type ctxKey int

const operatorKey ctxKey = 0

func (s *Server) requireAdmin(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			http.Redirect(w, r, "/admin/login", http.StatusFound)
			return
		}
		sess, err := s.codec.decode(c.Value)
		if err != nil || sess.expired(time.Now()) {
			clearSession(w, s.cfg.Secure)
			http.Redirect(w, r, "/admin/login", http.StatusFound)
			return
		}
		ctx := context.WithValue(r.Context(), operatorKey, sess)
		h(w, r.WithContext(ctx))
	})
}

func operatorOf(r *http.Request) session {
	s, _ := r.Context().Value(operatorKey).(session)
	return s
}

// actor builds the it_admin Actor for backplane calls from the logged-in
// operator's session.
func (s *Server) actor(r *http.Request) orch.Actor {
	op := operatorOf(r)
	return orch.Actor{ID: domain.ID(op.Identity), ITAdmin: true, SourceIP: clientIP(r)}
}

// csrfToken is a per-session token bound to the operator's subject. Forms
// embed it; mutating handlers verify it (defense beyond SameSite=Lax).
func (s *Server) csrfToken(r *http.Request) string {
	return s.codec.sign("csrf:" + operatorOf(r).Subject)
}

func (s *Server) checkCSRF(r *http.Request) error {
	if r.FormValue("csrf") != s.csrfToken(r) {
		return errors.New("CSRF token mismatch — reload the page and retry")
	}
	return nil
}

// --- helpers --------------------------------------------------------------

func randomToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func clearCookie(w http.ResponseWriter, name string, secure bool) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/admin",
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	return r.RemoteAddr
}
