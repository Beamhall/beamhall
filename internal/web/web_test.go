package web

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Beamhall/beamhall/internal/audit"
	"github.com/Beamhall/beamhall/internal/auth"
	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/orch"
	"github.com/Beamhall/beamhall/internal/store"
)

const (
	testIssuerAud = "https://beamhall.test/mcp"
	adminClientID = "beamhall-admin"
)

// fakeIdP implements the slice of OIDC the console uses: discovery, authorize
// (auto-consent, issues a code), token (code → access token), and JWKS.
type fakeIdP struct {
	t       *testing.T
	key     *rsa.PrivateKey
	srv     *httptest.Server
	scopes  string // scopes granted to the next issued token
	subject string
	email   string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &fakeIdP{t: t, key: key, scopes: "openid admin:it", subject: "it-1", email: "it@acme.test"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		b := idp.srv.URL
		json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 b,
			"authorization_endpoint": b + "/authorize",
			"token_endpoint":         b + "/token",
			"jwks_uri":               b + "/jwks.json",
		})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		// Auto-consent: bounce straight back to redirect_uri with a code.
		redir := r.URL.Query().Get("redirect_uri")
		state := r.URL.Query().Get("state")
		http.Redirect(w, r, redir+"?code=test-code&state="+url.QueryEscape(state), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("code") != "test-code" {
			http.Error(w, "bad code", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": idp.mint(), "token_type": "Bearer", "expires_in": 3600,
		})
	})
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		pub := &idp.key.PublicKey
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

func (i *fakeIdP) mint() string {
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": i.srv.URL, "aud": testIssuerAud, "sub": i.subject, "email": i.email,
		"scope": i.scopes, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(i.key)
	if err != nil {
		i.t.Fatal(err)
	}
	return s
}

func newTestServer(t *testing.T, idp *fakeIdP, orchOpts ...orch.Option) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	verifier, err := auth.NewVerifier(auth.Config{
		Issuer: idp.srv.URL, Audience: testIssuerAud, JWKSURL: idp.srv.URL + "/jwks.json",
		HTTPClient: idp.srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Real orchestrator so IT actions exercise the audited path.
	o := orch.New(st, nil, nil, nil, nil, nil, audit.New(st), "beamhall.test", orchOpts...)
	srv, err := New(context.Background(), st, o, Config{
		Issuer: idp.srv.URL, ClientID: adminClientID,
		ClientSecret: "secret", Scopes: []string{"openid", "admin:it"},
		Verifier: verifier, SessionKey: []byte("test-session-key-0123456789abcdef"),
		Secure: false, HTTPClient: idp.srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv, st
}

// loginClient runs the full OIDC flow against the console and returns a client
// whose cookie jar holds the admin session.
func loginClient(t *testing.T, ts *httptest.Server) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return nil }}
	resp, err := client.Get(ts.URL + "/admin/login?start=1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// After following the IdP bounce + callback, the session cookie is set.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login flow ended at HTTP %d", resp.StatusCode)
	}
	if u := resp.Request.URL.Path; u != "/admin" && u != "/admin/" {
		t.Fatalf("login did not land on /admin, got %s", u)
	}
	return client
}

func TestLoginFlowAndDashboard(t *testing.T) {
	idp := newFakeIdP(t)
	srv, _ := newTestServer(t, idp)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := loginClient(t, ts)
	resp, err := client.Get(ts.URL + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	if resp.StatusCode != 200 || !strings.Contains(body, "Beamhalls") {
		t.Fatalf("dashboard: HTTP %d\n%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "it@acme.test") {
		t.Errorf("operator email not shown")
	}
}

func TestNonAdminRejected(t *testing.T) {
	idp := newFakeIdP(t)
	idp.scopes = "openid" // no admin:it
	srv, _ := newTestServer(t, idp)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	resp, err := client.Get(ts.URL + "/admin/login?start=1")
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "not an IT administrator") {
		t.Fatalf("non-admin got HTTP %d: %s", resp.StatusCode, body)
	}
}

func TestUnauthenticatedRedirectsToLogin(t *testing.T) {
	idp := newFakeIdP(t)
	srv, _ := newTestServer(t, idp)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(ts.URL + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || !strings.HasSuffix(resp.Header.Get("Location"), "/admin/login") {
		t.Fatalf("want redirect to login, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestCreateBeamhallAndRegisterIdentity(t *testing.T) {
	idp := newFakeIdP(t)
	srv, st := newTestServer(t, idp)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client := loginClient(t, ts)

	csrf := csrfFromDashboard(t, client, ts)

	// Create a beamhall.
	form := url.Values{"csrf": {csrf}, "slug": {"ops"}, "display_name": {"Operations"},
		"department": {"IT"}, "runtime_class": {"runc"}, "live_slots": {"2"}, "max_beams": {"5"}, "max_db": {"1"}}
	post(t, client, ts.URL+"/admin/beamhalls", form)
	bh, err := st.GetBeamhallBySlug(context.Background(), "ops")
	if err != nil {
		t.Fatalf("beamhall not created: %v", err)
	}
	if bh.LiveSlotLimit != 2 {
		t.Errorf("live slots = %d", bh.LiveSlotLimit)
	}
	sc, _ := st.GetSecurityContext(context.Background(), bh.ID)
	if sc.RuntimeClass != domain.RuntimeRunc || !sc.ReadOnlyRootfs {
		t.Errorf("security context not hardened: %+v", sc)
	}

	// Register an identity.
	form = url.Values{"csrf": {csrf}, "issuer": {"https://idp.test"}, "subject": {"builder-1"},
		"email": {"builder@acme.test"}, "display_name": {"Builder"}}
	post(t, client, ts.URL+"/admin/identities", form)
	ident, err := st.GetIdentityByIssuerSubject(context.Background(), "https://idp.test", "builder-1")
	if err != nil {
		t.Fatalf("identity not registered: %v", err)
	}

	// Grant membership.
	form = url.Values{"csrf": {csrf}, "slug": {"ops"}, "beamhall_id": {string(bh.ID)},
		"identity_id": {string(ident.ID)}, "role": {"builder"}}
	post(t, client, ts.URL+"/admin/memberships", form)
	m, err := st.GetMembership(context.Background(), ident.ID, bh.ID)
	if err != nil || m.Role != domain.RoleBuilder {
		t.Fatalf("membership not granted: %v %+v", err, m)
	}

	// All three IT actions are on the audit chain.
	recs, _ := st.ListAuditEvents(context.Background(), 0, 100)
	seen := map[string]bool{}
	for _, e := range recs {
		seen[e.Event.Action] = true
	}
	for _, want := range []string{"admin_create_beamhall", "admin_register_identity", "admin_grant_membership"} {
		if !seen[want] {
			t.Errorf("audit chain missing %q", want)
		}
	}
}

func TestCSRFRequired(t *testing.T) {
	idp := newFakeIdP(t)
	srv, st := newTestServer(t, idp)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client := loginClient(t, ts)

	// POST without the CSRF token is refused.
	resp := post(t, client, ts.URL+"/admin/beamhalls", url.Values{"slug": {"nope"}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("missing CSRF: HTTP %d", resp.StatusCode)
	}
	if _, err := st.GetBeamhallBySlug(context.Background(), "nope"); err == nil {
		t.Fatal("beamhall created despite missing CSRF")
	}
}

// --- helpers --------------------------------------------------------------

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return b.String()
}

func csrfFromDashboard(t *testing.T, client *http.Client, ts *httptest.Server) string {
	t.Helper()
	resp, err := client.Get(ts.URL + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	const marker = `name="csrf" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatal("no CSRF token on dashboard")
	}
	rest := body[i+len(marker):]
	return rest[:strings.IndexByte(rest, '"')]
}

func post(t *testing.T, client *http.Client, u string, form url.Values) *http.Response {
	t.Helper()
	resp, err := client.PostForm(u, form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

// TestPromoteApprovalConsole: with the IT-approval gate on, the beamhall page
// surfaces pending promotions (approve/reject) and hides the direct promote
// button; reject wires through to the store.
func TestPromoteApprovalConsole(t *testing.T) {
	idp := newFakeIdP(t)
	srv, st := newTestServer(t, idp, orch.WithPromoteApproval(true))
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	ctx := context.Background()

	bh := &domain.Beamhall{Slug: "ops", DisplayName: "Ops", Status: domain.BeamhallActive,
		NetworkPolicy: domain.NetworkPolicy{EgressMode: domain.EgressDenyAll}, LiveSlotLimit: 1}
	if err := st.CreateBeamhall(ctx, bh, &domain.SecurityContext{Template: domain.TemplateWebApp}); err != nil {
		t.Fatal(err)
	}
	requester := &domain.Identity{ExternalSubject: "dev", Email: "dev@acme.test", IdPIssuer: "idp", Status: domain.IdentityActive}
	if err := st.CreateIdentity(ctx, requester); err != nil {
		t.Fatal(err)
	}
	beam := &domain.Beam{BeamhallID: bh.ID, Slug: "tracker", Mode: domain.ModePreview, State: domain.StateRunning, Status: domain.BeamActive}
	if err := st.CreateBeam(ctx, beam); err != nil {
		t.Fatal(err)
	}
	req := &domain.PromotionRequest{BeamhallID: bh.ID, BeamID: beam.ID, RequestedBy: requester.ID, Status: domain.PromotionPending}
	if err := st.CreatePromotionRequest(ctx, req); err != nil {
		t.Fatal(err)
	}

	client := loginClient(t, ts)
	resp, err := client.Get(ts.URL + "/admin/beamhalls/ops")
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	for _, want := range []string{"Pending promotions", "dev@acme.test", "/admin/promotions/" + string(req.ID) + "/approve"} {
		if !strings.Contains(body, want) {
			t.Errorf("beamhall page missing %q", want)
		}
	}
	if strings.Contains(body, "/admin/beams/"+string(beam.ID)+"/promote") {
		t.Error("direct promote button should be hidden when the approval gate is on")
	}

	// Reject wires through (store-only; no runtime deps needed).
	const marker = `name="csrf" value="`
	ci := strings.Index(body, marker)
	if ci < 0 {
		t.Fatal("no csrf token on the page")
	}
	csrf := body[ci+len(marker):]
	csrf = csrf[:strings.IndexByte(csrf, '"')]
	form := url.Values{"csrf": {csrf}, "slug": {"ops"}, "reason": {"nope"}}
	rr, err := client.PostForm(ts.URL+"/admin/promotions/"+string(req.ID)+"/reject", form)
	if err != nil {
		t.Fatal(err)
	}
	rr.Body.Close()
	got, _ := st.GetPromotionRequest(ctx, req.ID)
	if got.Status != domain.PromotionRejected {
		t.Fatalf("request status = %s, want rejected", got.Status)
	}
}

// The console shows resume for a paused preview and pause for a running one
// (the pause↔resume toggle), so IT can bring a paused beam back up.
func TestBeamhallConsolePauseResumeToggle(t *testing.T) {
	idp := newFakeIdP(t)
	srv, st := newTestServer(t, idp)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	ctx := context.Background()

	bh := &domain.Beamhall{Slug: "ops", DisplayName: "Ops", Status: domain.BeamhallActive,
		NetworkPolicy: domain.NetworkPolicy{EgressMode: domain.EgressDenyAll}, LiveSlotLimit: 1}
	if err := st.CreateBeamhall(ctx, bh, &domain.SecurityContext{Template: domain.TemplateWebApp}); err != nil {
		t.Fatal(err)
	}
	paused := &domain.Beam{BeamhallID: bh.ID, Slug: "sleepy", Mode: domain.ModePreview, State: domain.StatePaused, Status: domain.BeamActive}
	running := &domain.Beam{BeamhallID: bh.ID, Slug: "awake", Mode: domain.ModePreview, State: domain.StateRunning, Status: domain.BeamActive}
	for _, b := range []*domain.Beam{paused, running} {
		if err := st.CreateBeam(ctx, b); err != nil {
			t.Fatal(err)
		}
	}

	resp, err := loginClient(t, ts).Get(ts.URL + "/admin/beamhalls/ops")
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)

	if !strings.Contains(body, "/admin/beams/"+string(paused.ID)+"/resume") {
		t.Error("paused beam should show a resume button")
	}
	if strings.Contains(body, "/admin/beams/"+string(paused.ID)+"/pause") {
		t.Error("paused beam should not also show a pause button")
	}
	if !strings.Contains(body, "/admin/beams/"+string(running.ID)+"/pause") {
		t.Error("running beam should show a pause button")
	}
	if strings.Contains(body, "/admin/beams/"+string(running.ID)+"/resume") {
		t.Error("running beam should not show a resume button")
	}
}

func TestBeamhallConsoleProductionHistoryAndRollback(t *testing.T) {
	idp := newFakeIdP(t)
	srv, st := newTestServer(t, idp)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	ctx := context.Background()

	bh := &domain.Beamhall{Slug: "ops", DisplayName: "Ops", Status: domain.BeamhallActive,
		NetworkPolicy: domain.NetworkPolicy{EgressMode: domain.EgressDenyAll}, LiveSlotLimit: 1}
	if err := st.CreateBeamhall(ctx, bh, &domain.SecurityContext{Template: domain.TemplateWebApp}); err != nil {
		t.Fatal(err)
	}
	// A promoted beam (Mode=live) with two live releases — v1 (prior) and v2 (current).
	beam := &domain.Beam{BeamhallID: bh.ID, Slug: "shop", Mode: domain.ModeLive, State: domain.StateRunning, Status: domain.BeamActive}
	if err := st.CreateBeam(ctx, beam); err != nil {
		t.Fatal(err)
	}
	build := &domain.Build{BeamID: beam.ID, Status: domain.BuildSucceeded}
	if err := st.CreateBuild(ctx, build); err != nil {
		t.Fatal(err)
	}
	mkLive := func(pull string) domain.ID {
		r := &domain.Release{BeamID: beam.ID, BuildID: build.ID, Channel: domain.ChannelLive,
			ConfigSnapshot: map[string]string{"pull_ref": pull}, Status: domain.ReleaseActive}
		if err := st.CreateRelease(ctx, r); err != nil {
			t.Fatal(err)
		}
		return r.ID
	}
	v1 := mkLive("reg/shop@sha256:aaaaaaaaaaaa1111")
	v2 := mkLive("reg/shop@sha256:bbbbbbbbbbbb2222")
	beam.LiveReleaseID = v2 // v2 currently serves production
	if err := st.UpdateBeam(ctx, beam); err != nil {
		t.Fatal(err)
	}

	resp, err := loginClient(t, ts).Get(ts.URL + "/admin/beamhalls/ops")
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)

	if !strings.Contains(body, "Production history") {
		t.Error("promoted beam should render the production-history panel")
	}
	// The current release (v2) offers no rollback; the prior one (v1) does.
	rollbackV1 := `action="/admin/beams/` + string(beam.ID) + `/rollback"`
	if !strings.Contains(body, rollbackV1) || !strings.Contains(body, `value="`+string(v1)+`"`) {
		t.Error("prior live release v1 should offer a rollback button targeting its release id")
	}
	if strings.Contains(body, `value="`+string(v2)+`"`) {
		t.Error("the current live release v2 must not be a rollback target")
	}
	if !strings.Contains(body, "(current)") {
		t.Error("the serving release should be marked current")
	}
}
