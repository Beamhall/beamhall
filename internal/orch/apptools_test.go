package orch

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Beamhall/beamhall/internal/apptools"
	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/driver"
)

// beamToolServer plays the beam side of the app-tools contract.
type beamToolServer struct {
	srv *httptest.Server

	mu         sync.Mutex
	assertions []string // raw JWTs, in arrival order
	noTools    bool
	leakValue  string // returned by the "leak" tool (scrubber test)
}

func newBeamToolServer(t *testing.T) *beamToolServer {
	t.Helper()
	b := &beamToolServer{}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		b.assertions = append(b.assertions, r.Header.Get(apptools.HeaderAssertion))
		noTools, leak := b.noTools, b.leakValue
		b.mu.Unlock()
		if noTools || !strings.HasPrefix(r.URL.Path, apptools.PathTools) {
			http.NotFound(w, r)
			return
		}
		switch r.URL.Path {
		case apptools.PathTools:
			fmt.Fprint(w, `{"version":1,"tools":[`+
				`{"name":"whoami","description":"who is calling","input_schema":{"type":"object"}},`+
				`{"name":"leak","description":"echoes a secret"}]}`)
		case apptools.PathTools + "/whoami":
			// Echo the assertion's payload claims back (unverified — signature
			// correctness is asserted in the tests, which hold the public key).
			parts := strings.Split(r.Header.Get(apptools.HeaderAssertion), ".")
			payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
			w.Write(payload)
		case apptools.PathTools + "/leak":
			fmt.Fprintf(w, `{"secret":%q}`, leak)
		case apptools.PathTools + "/broken":
			http.Error(w, "tool exploded: "+leak, http.StatusBadGateway)
		default:
			http.Error(w, "no such tool", http.StatusNotFound)
		}
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func (b *beamToolServer) addr() string { return strings.TrimPrefix(b.srv.URL, "http://") }

func (b *beamToolServer) lastAssertion(t *testing.T) string {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.assertions) == 0 {
		t.Fatal("the beam server saw no request")
	}
	return b.assertions[len(b.assertions)-1]
}

// appToolsWorld builds a world wired for app tools, with the fake driver
// reporting the test beam server as every workload's backend.
func appToolsWorld(t *testing.T, cfg AppToolsConfig) (*world, *beamToolServer, *apptools.Signer) {
	t.Helper()
	key, err := apptools.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := apptools.NewSigner(key, "https://bh.example/mcp")
	if err != nil {
		t.Fatal(err)
	}
	beamSrv := newBeamToolServer(t)
	w := newWorldOpts(t, WithAppTools(signer, apptools.NewClient(2*time.Second, 2*time.Second), cfg))
	w.drv.backendAddr = beamSrv.addr()
	return w, beamSrv, signer
}

func jwkToPub(x, y string) (*ecdsa.PublicKey, error) {
	xb, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		return nil, err
	}
	yb, err := base64.RawURLEncoding.DecodeString(y)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}, nil
}

func parseAssertion(t *testing.T, signer *apptools.Signer, raw string) jwt.MapClaims {
	t.Helper()
	var set struct {
		Keys []struct{ X, Y string } `json:"keys"`
	}
	if err := json.Unmarshal(signer.JWKS(), &set); err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.Parse(raw, func(tk *jwt.Token) (any, error) {
		return jwkToPub(set.Keys[0].X, set.Keys[0].Y)
	}, jwt.WithValidMethods([]string{"ES256"}), jwt.WithIssuer("https://bh.example/mcp"),
		jwt.WithExpirationRequired())
	if err != nil {
		t.Fatalf("assertion did not verify against the signer's JWKS: %v", err)
	}
	return tok.Claims.(jwt.MapClaims)
}

func TestAppToolsDeployBindingAndProbe(t *testing.T) {
	w, beamSrv, signer := appToolsWorld(t, AppToolsConfig{})
	ctx := context.Background()
	beam := w.deployed(t, "handbook")

	// The workload got the verification file, addressed to this beam.
	var binding *driver.ResourceBinding
	for _, d := range w.drv.deploys {
		for i, b := range d.Bindings {
			if b.MountPath == apptools.MountPath {
				binding = &d.Bindings[i]
			}
		}
	}
	if binding == nil {
		t.Fatal("assertion.json binding missing from the deploy")
	}
	var bound struct {
		Version  int             `json:"version"`
		Issuer   string          `json:"issuer"`
		Audience string          `json:"audience"`
		JWKS     json.RawMessage `json:"jwks"`
	}
	if err := json.Unmarshal(binding.Value, &bound); err != nil {
		t.Fatalf("binding is not valid JSON: %v", err)
	}
	if bound.Audience != string(beam.ID) || bound.Issuer != "https://bh.example/mcp" || len(bound.JWKS) == 0 {
		t.Fatalf("unexpected binding: %+v", bound)
	}

	// The probe ran with the reserved subject and stamped the release.
	claims := parseAssertion(t, signer, beamSrv.lastAssertion(t))
	if claims["sub"] != apptools.ProbeSubject || claims["channel"] != "preview" {
		t.Fatalf("probe assertion claims: %+v", claims)
	}
	rel, err := w.st.GetRelease(ctx, beam.CurrentReleaseID)
	if err != nil {
		t.Fatal(err)
	}
	if rel.ConfigSnapshot["agent_tools"] != "true" {
		t.Fatalf("probe did not stamp the release: %+v", rel.ConfigSnapshot)
	}
}

func TestAppToolsProbeMissesQuietly(t *testing.T) {
	w, beamSrv, _ := appToolsWorld(t, AppToolsConfig{})
	beamSrv.mu.Lock()
	beamSrv.noTools = true
	beamSrv.mu.Unlock()
	beam := w.deployed(t, "plain-site")
	rel, err := w.st.GetRelease(context.Background(), beam.CurrentReleaseID)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := rel.ConfigSnapshot["agent_tools"]; present {
		t.Fatalf("a 404 must not stamp the flag: %+v", rel.ConfigSnapshot)
	}
}

func TestAppToolsInertWithoutOption(t *testing.T) {
	w := newWorld(t)
	beam := w.deployed(t, "handbook")
	for _, d := range w.drv.deploys {
		for _, b := range d.Bindings {
			if b.MountPath == apptools.MountPath {
				t.Fatal("assertion binding injected without WithAppTools")
			}
		}
	}
	rel, err := w.st.GetRelease(context.Background(), beam.CurrentReleaseID)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := rel.ConfigSnapshot["agent_tools"]; present {
		t.Fatal("probe ran without WithAppTools")
	}
}

// publishLive promotes the beam and publishes it to a fresh user actor.
func publishLive(t *testing.T, w *world, beam *domain.Beam) Actor {
	t.Helper()
	ctx := context.Background()
	if _, err := w.o.PromoteToLive(ctx, w.admin, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("PromoteToLive: %v", err)
	}
	user := userActor(t, w, "finance")
	user.Email = "erin@corp.test"
	if err := w.o.SetAppAudience(ctx, Actor{ITAdmin: true}, w.bh.ID, beam.ID, AudienceSpec{
		Audience: domain.Audience{Identities: []domain.ID{user.ID}},
	}); err != nil {
		t.Fatalf("SetAppAudience: %v", err)
	}
	return user
}

func TestUseAppMenuAndInvoke(t *testing.T) {
	w, beamSrv, signer := appToolsWorld(t, AppToolsConfig{})
	ctx := context.Background()
	beam := w.deployed(t, "handbook")
	user := publishLive(t, w, beam)

	// Menu: the caller's identity rides even the menu fetch, so an app can
	// tailor what it offers.
	res, err := w.o.UseApp(ctx, user, UseAppRequest{App: "handbook"})
	if err != nil {
		t.Fatalf("UseApp menu: %v", err)
	}
	if res.Menu == nil || len(res.Menu.Tools) != 2 || res.Menu.Tools[0].Name != "whoami" {
		t.Fatalf("unexpected menu: %+v", res.Menu)
	}
	claims := parseAssertion(t, signer, beamSrv.lastAssertion(t))
	if claims["sub"] != string(user.ID) || claims["channel"] != "live" || claims["tool"] != "" {
		t.Fatalf("menu assertion claims: %+v", claims)
	}

	// Invoke: the app hears who the user is via verified claims.
	res, err = w.o.UseApp(ctx, user, UseAppRequest{App: "handbook", Tool: "whoami", Arguments: []byte(`{}`)})
	if err != nil {
		t.Fatalf("UseApp invoke: %v", err)
	}
	var echoed struct {
		Sub     string   `json:"sub"`
		Email   string   `json:"email"`
		Groups  []string `json:"groups"`
		Aud     string   `json:"aud"`
		Channel string   `json:"channel"`
		Tool    string   `json:"tool"`
	}
	if err := json.Unmarshal(res.Result, &echoed); err != nil {
		t.Fatalf("result not JSON: %v (%s)", err, res.Result)
	}
	if echoed.Sub != string(user.ID) || echoed.Email != "erin@corp.test" ||
		len(echoed.Groups) != 1 || echoed.Groups[0] != "finance" ||
		echoed.Aud != string(beam.ID) || echoed.Channel != "live" || echoed.Tool != "whoami" {
		t.Fatalf("assertion did not carry the caller's identity: %+v", echoed)
	}

	// Both calls audited: one menu, one tool digest, both carrying the beam.
	recs, _ := w.st.ListAuditEvents(ctx, 0, 200)
	var menuEv, toolEv int
	for _, rec := range recs {
		if rec.Event.Action != "use_app" {
			continue
		}
		if rec.Event.BeamID != beam.ID || rec.Event.ActorID != user.ID {
			t.Errorf("use_app event missing beam/actor: %+v", rec.Event)
		}
		switch {
		case rec.Event.RequestDigest == "menu":
			menuEv++
		case strings.HasPrefix(rec.Event.RequestDigest, "tool=whoami args_sha256="):
			toolEv++
		}
	}
	if menuEv != 1 || toolEv != 1 {
		t.Fatalf("use_app audit events: menu=%d tool=%d", menuEv, toolEv)
	}
}

func TestUseAppScrubsRelayedBodies(t *testing.T) {
	w, beamSrv, _ := appToolsWorld(t, AppToolsConfig{})
	ctx := context.Background()
	beam := w.deployed(t, "handbook")
	if err := w.o.SetSecret(ctx, w.build, w.bh.ID, beam.ID, "API_TOKEN", []byte("sup3r-s3cret-value")); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}
	beamSrv.mu.Lock()
	beamSrv.leakValue = "sup3r-s3cret-value"
	beamSrv.mu.Unlock()
	user := publishLive(t, w, beam)

	res, err := w.o.UseApp(ctx, user, UseAppRequest{App: "handbook", Tool: "leak"})
	if err != nil {
		t.Fatalf("UseApp leak: %v", err)
	}
	if strings.Contains(string(res.Result), "sup3r-s3cret-value") {
		t.Fatalf("secret value crossed the boundary: %s", res.Result)
	}

	// App-error bodies are scrubbed too.
	_, err = w.o.UseApp(ctx, user, UseAppRequest{App: "handbook", Tool: "broken"})
	var ate *AppToolError
	if !errors.As(err, &ate) {
		t.Fatalf("want *AppToolError, got %v", err)
	}
	if strings.Contains(ate.Body, "sup3r-s3cret-value") {
		t.Fatalf("secret value crossed in the error body: %s", ate.Body)
	}
}

func TestUseAppRefusals(t *testing.T) {
	w, beamSrv, _ := appToolsWorld(t, AppToolsConfig{})
	ctx := context.Background()
	it := Actor{ITAdmin: true}
	beam := w.deployed(t, "handbook")
	user := userActor(t, w)

	// Unpublished (or nonexistent — same sentinel as DescribeApp).
	if _, err := w.o.UseApp(ctx, user, UseAppRequest{App: "handbook"}); !errors.Is(err, ErrAppNotPublished) {
		t.Fatalf("unpublished: want ErrAppNotPublished, got %v", err)
	}
	if _, err := w.o.UseApp(ctx, user, UseAppRequest{App: "no-such-app"}); !errors.Is(err, ErrAppNotPublished) {
		t.Fatalf("nonexistent: want ErrAppNotPublished, got %v", err)
	}

	// Published but not promoted: users only reach production.
	if err := w.o.SetAppAudience(ctx, it, w.bh.ID, beam.ID, AudienceSpec{
		Audience: domain.Audience{Identities: []domain.ID{user.ID}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.o.UseApp(ctx, user, UseAppRequest{App: "handbook"}); !errors.Is(err, ErrAppNotLive) {
		t.Fatalf("not live: want ErrAppNotLive, got %v", err)
	}

	// Live but the app serves no tools.
	if _, err := w.o.PromoteToLive(ctx, w.admin, w.bh.ID, beam.ID); err != nil {
		t.Fatal(err)
	}
	beamSrv.mu.Lock()
	beamSrv.noTools = true
	beamSrv.mu.Unlock()
	if _, err := w.o.UseApp(ctx, user, UseAppRequest{App: "handbook"}); !errors.Is(err, ErrAppNoTools) {
		t.Fatalf("no tools: want ErrAppNoTools, got %v", err)
	}

	// The refusals are on the audit chain as denies (except rate limiting).
	recs, _ := w.st.ListAuditEvents(ctx, 0, 200)
	var denies int
	for _, rec := range recs {
		if rec.Event.Action == "use_app" && rec.Event.Decision == domain.DecisionDeny {
			denies++
		}
	}
	if denies != 4 {
		t.Fatalf("want 4 use_app deny events, got %d", denies)
	}
}

func TestUseAppRateLimit(t *testing.T) {
	w, _, _ := appToolsWorld(t, AppToolsConfig{RatePerMinute: 1, Burst: 1})
	ctx := context.Background()
	beam := w.deployed(t, "handbook")
	user := publishLive(t, w, beam)

	if _, err := w.o.UseApp(ctx, user, UseAppRequest{App: "handbook"}); err != nil {
		t.Fatalf("first call: %v", err)
	}
	before, _ := w.st.MaxAuditSeq(ctx)
	_, err := w.o.UseApp(ctx, user, UseAppRequest{App: "handbook"})
	if err == nil || !strings.Contains(err.Error(), "faster than this appliance allows") {
		t.Fatalf("want rate-limit refusal, got %v", err)
	}
	// The limiter protects audit growth: rejected attempts append nothing.
	after, _ := w.st.MaxAuditSeq(ctx)
	if after != before {
		t.Fatalf("rate-limited call appended %d audit events", after-before)
	}
	// A different identity has its own bucket: widen the audience and the
	// other user's first call passes.
	other := userActor(t, w)
	if err := w.o.SetAppAudience(ctx, Actor{ITAdmin: true}, w.bh.ID, beam.ID, AudienceSpec{
		Audience: domain.Audience{Identities: []domain.ID{user.ID, other.ID}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.o.UseApp(ctx, other, UseAppRequest{App: "handbook"}); err != nil {
		t.Fatalf("other identity should not share the bucket: %v", err)
	}
}

func TestTryBeamTool(t *testing.T) {
	w, beamSrv, signer := appToolsWorld(t, AppToolsConfig{})
	ctx := context.Background()

	// Never deployed → teach the next step.
	created, err := w.o.CreateBeam(ctx, w.build, w.bh.ID, "fresh", "Fresh", "", "node")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.o.TryBeamTool(ctx, w.build, w.bh.ID, created.ID, "", nil); err == nil || !strings.Contains(err.Error(), "deploy_beam first") {
		t.Fatalf("undeployed: %v", err)
	}

	beam := w.deployed(t, "handbook")

	// Menu on the preview channel, with the builder's identity.
	res, err := w.o.TryBeamTool(ctx, w.build, w.bh.ID, beam.ID, "", nil)
	if err != nil {
		t.Fatalf("TryBeamTool menu: %v", err)
	}
	if res.Menu == nil || len(res.Menu.Tools) != 2 {
		t.Fatalf("unexpected menu: %+v", res.Menu)
	}
	claims := parseAssertion(t, signer, beamSrv.lastAssertion(t))
	if claims["sub"] != string(w.build.ID) || claims["channel"] != "preview" {
		t.Fatalf("try assertion claims: %+v", claims)
	}

	// Invoke.
	res, err = w.o.TryBeamTool(ctx, w.build, w.bh.ID, beam.ID, "whoami", []byte(`{}`))
	if err != nil {
		t.Fatalf("TryBeamTool invoke: %v", err)
	}
	if !strings.Contains(string(res.Result), `"channel":"preview"`) {
		t.Fatalf("invoke did not reach the preview channel: %s", res.Result)
	}

	// Paused preview → teach resume_preview.
	w.drv.setStatusState(driver.WorkloadPaused)
	if _, err := w.o.TryBeamTool(ctx, w.build, w.bh.ID, beam.ID, "", nil); err == nil || !strings.Contains(err.Error(), "resume_preview first") {
		t.Fatalf("paused: %v", err)
	}
	w.drv.setStatusState("")

	// A viewer holds no try_beam_tool grant — the PEP denies and audits.
	viewer := func() Actor {
		ident := &domain.Identity{ExternalSubject: string(beam.ID) + "-viewer", Email: "v@x",
			DisplayName: "v", IdPIssuer: "idp", Status: domain.IdentityActive}
		if err := w.st.CreateIdentity(ctx, ident); err != nil {
			t.Fatal(err)
		}
		m := &domain.Membership{IdentityID: ident.ID, BeamhallID: w.bh.ID, Role: domain.RoleViewer, GrantedBy: ident.ID}
		if err := w.st.CreateMembership(ctx, m); err != nil {
			t.Fatal(err)
		}
		return Actor{ID: ident.ID}
	}()
	if _, err := w.o.TryBeamTool(ctx, viewer, w.bh.ID, beam.ID, "", nil); err == nil {
		t.Fatal("viewer reached try_beam_tool")
	}
}

func TestUpdateBeam(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	beam := w.deployed(t, "handbook")

	desc := "Company policies, for every employee"
	name := "Staff Handbook"
	got, err := w.o.UpdateBeam(ctx, w.build, w.bh.ID, beam.ID, BeamUpdate{Description: &desc, DisplayName: &name})
	if err != nil {
		t.Fatalf("UpdateBeam: %v", err)
	}
	if got.Description != desc || got.DisplayName != name {
		t.Fatalf("update not applied: %+v", got)
	}

	// Users see the new catalog copy once published.
	if err := w.o.SetAppAudience(ctx, Actor{ITAdmin: true}, w.bh.ID, beam.ID, AudienceSpec{
		Audience: domain.Audience{Everyone: true},
	}); err != nil {
		t.Fatal(err)
	}
	view, err := w.o.DescribeApp(ctx, userActor(t, w), "handbook", "")
	if err != nil {
		t.Fatal(err)
	}
	if view.Description != desc || view.DisplayName != name {
		t.Fatalf("view did not pick up the edit: %+v", view)
	}

	// Nothing-to-change and empty display_name are refused.
	if _, err := w.o.UpdateBeam(ctx, w.build, w.bh.ID, beam.ID, BeamUpdate{}); err == nil {
		t.Fatal("empty update accepted")
	}
	empty := ""
	if _, err := w.o.UpdateBeam(ctx, w.build, w.bh.ID, beam.ID, BeamUpdate{DisplayName: &empty}); err == nil {
		t.Fatal("empty display_name accepted")
	}
}
