package mcp

// End-to-end tests over the real HTTP stack: Streamable HTTP transport,
// bearer-token middleware, scope gates, tool dispatch, tarball transport, and
// build progress notifications — with the backplane and directory faked. The
// orchestrator/PEP behavior behind the Backplane seam has its own suites.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Beamhall/beamhall/internal/auth"
	"github.com/Beamhall/beamhall/internal/build"
	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/driver"
	"github.com/Beamhall/beamhall/internal/identityadmin"
	"github.com/Beamhall/beamhall/internal/orch"
	"github.com/Beamhall/beamhall/internal/store"
)

// --- fakes ---------------------------------------------------------------

type fakeBackplane struct {
	mu              sync.Mutex
	calls           []string
	lastActor       orch.Actor
	srcCheck        func(srcDir string) error
	failWith        error
	logs            []byte
	promoteApproval bool
	idpEnabled      bool
}

func (f *fakeBackplane) record(call string, actor orch.Actor) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
	f.lastActor = actor
}

func (f *fakeBackplane) CreateBeam(ctx context.Context, actor orch.Actor, beamhallID domain.ID, slug, displayName, runtimeHint string) (*domain.Beam, error) {
	f.record("CreateBeam:"+string(beamhallID)+":"+slug, actor)
	if f.failWith != nil {
		return nil, f.failWith
	}
	return &domain.Beam{ID: "beam-1", BeamhallID: beamhallID, Slug: slug,
		State: domain.StateCreated, Mode: domain.ModePreview}, nil
}

func (f *fakeBackplane) DeployBeam(ctx context.Context, actor orch.Actor, beamhallID, beamID domain.ID, req orch.DeployRequest) (*domain.Beam, error) {
	f.record("DeployBeam:"+req.ImageDigest, actor)
	return &domain.Beam{ID: beamID, BeamhallID: beamhallID, Slug: "tracker",
		State: domain.StateRunning, Mode: domain.ModePreview}, nil
}

func (f *fakeBackplane) DeployBeamFromSource(ctx context.Context, actor orch.Actor, beamhallID, beamID domain.ID, srcDir string) (*domain.Beam, error) {
	f.record("DeployBeamFromSource", actor)
	if f.srcCheck != nil {
		if err := f.srcCheck(srcDir); err != nil {
			return nil, err
		}
	}
	// Stream like the real pipeline does: pack output → per-call writer.
	if w := build.ProgressWriter(ctx); w != nil {
		fmt.Fprintln(w, "===> DETECTING")
		fmt.Fprintln(w, "===> BUILDING")
		fmt.Fprintln(w, "===> EXPORTING")
	}
	return &domain.Beam{ID: beamID, BeamhallID: beamhallID, Slug: "tracker",
		State: domain.StateRunning, Mode: domain.ModePreview}, nil
}

func (f *fakeBackplane) SetSecret(ctx context.Context, actor orch.Actor, beamhallID, beamID domain.ID, key string, value []byte) error {
	f.record("SetSecret:"+string(beamID)+":"+key, actor)
	return nil
}

func (f *fakeBackplane) CreateDatabase(ctx context.Context, actor orch.Actor, beamhallID, beamID domain.ID, name string) (string, error) {
	f.record("CreateDatabase:"+name, actor)
	return "MAIN_URL", nil
}

func (f *fakeBackplane) ShowLogs(ctx context.Context, actor orch.Actor, beamhallID, beamID domain.ID, opts driver.LogOptions) ([]byte, error) {
	f.record(fmt.Sprintf("ShowLogs:%d", opts.TailN), actor)
	if f.logs != nil {
		return f.logs, nil
	}
	return []byte("scrubbed log line\n"), nil
}

func (f *fakeBackplane) PausePreview(ctx context.Context, actor orch.Actor, beamhallID, beamID domain.ID) error {
	f.record("PausePreview", actor)
	return nil
}

func (f *fakeBackplane) ResumePreview(ctx context.Context, actor orch.Actor, beamhallID, beamID domain.ID) (string, error) {
	f.record("ResumePreview", actor)
	return "fresh1234.preview.beamhall.test", nil
}

func (f *fakeBackplane) PromoteToLive(ctx context.Context, actor orch.Actor, beamhallID, beamID domain.ID) (string, error) {
	f.record("PromoteToLive", actor)
	return "tracker.ops.beamhall.test", nil
}

func (f *fakeBackplane) RollbackBeam(ctx context.Context, actor orch.Actor, beamhallID, beamID, target domain.ID) (string, error) {
	f.record("RollbackBeam:"+string(target), actor)
	return "rb1234.preview.beamhall.test", nil
}

func (f *fakeBackplane) PromoteApprovalEnabled() bool { return f.promoteApproval }

func (f *fakeBackplane) RequestPromotion(ctx context.Context, actor orch.Actor, beamhallID, beamID domain.ID) (domain.PromotionRequest, error) {
	f.record("RequestPromotion", actor)
	return domain.PromotionRequest{ID: "req-1", BeamhallID: beamhallID, BeamID: beamID, RequestedBy: actor.ID, Status: domain.PromotionPending}, nil
}

func (f *fakeBackplane) ListPendingPromotions(ctx context.Context, actor orch.Actor, beamhallID domain.ID) ([]domain.PromotionRequest, error) {
	f.record("ListPendingPromotions", actor)
	return nil, nil
}

func (f *fakeBackplane) ApprovePromotion(ctx context.Context, actor orch.Actor, requestID domain.ID) (string, error) {
	f.record("ApprovePromotion:"+string(requestID), actor)
	return "tracker.ops.beamhall.test", nil
}

func (f *fakeBackplane) RejectPromotion(ctx context.Context, actor orch.Actor, requestID domain.ID, reason string) error {
	f.record("RejectPromotion:"+string(requestID), actor)
	return nil
}

func (f *fakeBackplane) DestroyBeam(ctx context.Context, actor orch.Actor, beamhallID, beamID domain.ID) error {
	f.record("DestroyBeam:"+string(beamID), actor)
	return nil
}

func (f *fakeBackplane) ArchiveBeam(ctx context.Context, actor orch.Actor, beamhallID, beamID domain.ID) error {
	f.record("ArchiveBeam:"+string(beamID), actor)
	return nil
}

func (f *fakeBackplane) ShowMetrics(ctx context.Context, actor orch.Actor, beamhallID, beamID domain.ID) (driver.Stats, error) {
	f.record("ShowMetrics", actor)
	return driver.Stats{CPUPct: 7.5, MemBytes: 32 << 20, MemLimit: 256 << 20}, nil
}

func (f *fakeBackplane) CreateBeamhall(ctx context.Context, actor orch.Actor, spec orch.NewBeamhallSpec) (*domain.Beamhall, error) {
	f.record("CreateBeamhall:"+spec.Slug+":"+string(spec.RuntimeClass), actor)
	if f.failWith != nil {
		return nil, f.failWith
	}
	return &domain.Beamhall{ID: "hall-new", Slug: spec.Slug, DisplayName: spec.DisplayName}, nil
}

func (f *fakeBackplane) RegisterIdentity(ctx context.Context, actor orch.Actor, issuer, subject, email, displayName string) (*domain.Identity, error) {
	f.record("RegisterIdentity:"+subject, actor)
	if f.failWith != nil {
		return nil, f.failWith
	}
	return &domain.Identity{ID: "ident-new", ExternalSubject: subject, IdPIssuer: issuer, Email: email}, nil
}

func (f *fakeBackplane) GrantMembership(ctx context.Context, actor orch.Actor, identityID, beamhallID domain.ID, role domain.MembershipRole) error {
	f.record(fmt.Sprintf("GrantMembership:%s:%s:%s", identityID, beamhallID, role), actor)
	return f.failWith
}

func (f *fakeBackplane) AdminListIdentities(ctx context.Context, actor orch.Actor) ([]domain.Identity, error) {
	f.record("AdminListIdentities", actor)
	return []domain.Identity{{ID: "ident-1", ExternalSubject: "user-1", Email: "u1@x"}}, nil
}

func (f *fakeBackplane) IdentityAdminEnabled() bool { return f.idpEnabled }

func (f *fakeBackplane) AdminCreateUser(ctx context.Context, actor orch.Actor, u identityadmin.NewUser) (identityadmin.User, error) {
	f.record("AdminCreateUser:"+u.Username, actor)
	if !f.idpEnabled {
		return identityadmin.User{}, identityadmin.ErrNotEnabled
	}
	return identityadmin.User{ID: "u-1", Username: u.Username, Email: u.Email, Enabled: true}, nil
}

func (f *fakeBackplane) AdminListUsers(ctx context.Context, actor orch.Actor, query string, max int) ([]identityadmin.User, error) {
	f.record("AdminListUsers:"+query, actor)
	if !f.idpEnabled {
		return nil, identityadmin.ErrNotEnabled
	}
	return []identityadmin.User{{ID: "u-1", Username: "alice", Enabled: true}}, nil
}

func (f *fakeBackplane) AdminSetUserPassword(ctx context.Context, actor orch.Actor, userID, password string) error {
	f.record("AdminSetUserPassword:"+userID, actor)
	if !f.idpEnabled {
		return identityadmin.ErrNotEnabled
	}
	return nil
}

func (f *fakeBackplane) AdminCreateGroup(ctx context.Context, actor orch.Actor, name string) (identityadmin.Group, error) {
	f.record("AdminCreateGroup:"+name, actor)
	if !f.idpEnabled {
		return identityadmin.Group{}, identityadmin.ErrNotEnabled
	}
	return identityadmin.Group{ID: "g-1", Name: name, Path: "/" + name}, nil
}

func (f *fakeBackplane) AdminListGroups(ctx context.Context, actor orch.Actor) ([]identityadmin.Group, error) {
	f.record("AdminListGroups", actor)
	if !f.idpEnabled {
		return nil, identityadmin.ErrNotEnabled
	}
	return []identityadmin.Group{{ID: "g-1", Name: "builders", Path: "/builders"}}, nil
}

func (f *fakeBackplane) AdminAddUserToGroup(ctx context.Context, actor orch.Actor, userID, groupID string) error {
	f.record(fmt.Sprintf("AdminAddUserToGroup:%s:%s", userID, groupID), actor)
	if !f.idpEnabled {
		return identityadmin.ErrNotEnabled
	}
	return nil
}

func (f *fakeBackplane) AdminFederateDirectory(ctx context.Context, actor orch.Actor, d identityadmin.DirectoryFederation) error {
	f.record("AdminFederateDirectory:"+d.Name, actor)
	if f.failWith != nil {
		return f.failWith
	}
	return nil
}

type fakeDirectory struct{}

func (fakeDirectory) GetIdentityByIssuerSubject(ctx context.Context, issuer, subject string) (domain.Identity, error) {
	// user-1 is a hall-1 member; user-2 is registered but a member of nothing.
	switch subject {
	case "user-1":
		return domain.Identity{ID: "ident-1", ExternalSubject: subject, IdPIssuer: issuer, Status: domain.IdentityActive}, nil
	case "user-2":
		return domain.Identity{ID: "ident-2", ExternalSubject: subject, IdPIssuer: issuer, Status: domain.IdentityActive}, nil
	default:
		return domain.Identity{}, store.ErrNotFound
	}
}

func (fakeDirectory) GetBeamhall(ctx context.Context, id domain.ID) (domain.Beamhall, error) {
	if id != "hall-1" {
		return domain.Beamhall{}, store.ErrNotFound
	}
	return domain.Beamhall{ID: "hall-1", Slug: "ops"}, nil
}

func (fakeDirectory) GetBeamhallBySlug(ctx context.Context, slug string) (domain.Beamhall, error) {
	if slug != "ops" {
		return domain.Beamhall{}, store.ErrNotFound
	}
	return domain.Beamhall{ID: "hall-1", Slug: "ops"}, nil
}

func (fakeDirectory) ListMembershipsByIdentity(ctx context.Context, identityID domain.ID) ([]domain.Membership, error) {
	if identityID != "ident-1" {
		return nil, nil // ident-2 (and anyone else) belongs to no beamhall
	}
	return []domain.Membership{{IdentityID: identityID, BeamhallID: "hall-1", Role: domain.RoleBuilder}}, nil
}

func (fakeDirectory) ListBeamsByBeamhall(ctx context.Context, beamhallID domain.ID) ([]domain.Beam, error) {
	if beamhallID != "hall-1" {
		return nil, nil
	}
	return []domain.Beam{{ID: "beam-1", BeamhallID: beamhallID, Slug: "tracker",
		Mode: domain.ModePreview, State: domain.StateRunning, Status: domain.BeamActive}}, nil
}

func (fakeDirectory) GetBeamBySlug(ctx context.Context, beamhallID domain.ID, slug string) (domain.Beam, error) {
	if slug != "tracker" {
		return domain.Beam{}, store.ErrNotFound
	}
	// A promoted beam: live channel on "live-2" (v4), preview on "prev-2" (v3);
	// "live-1" (v2) is the prior production release rollback should target.
	return domain.Beam{ID: "beam-1", BeamhallID: beamhallID, Slug: slug,
		Mode: domain.ModeLive, CurrentReleaseID: "prev-2", LiveReleaseID: "live-2"}, nil
}

func (fakeDirectory) ListRoutesByBeam(ctx context.Context, beamID domain.ID) ([]domain.Route, error) {
	return []domain.Route{
		{BeamID: beamID, Hostname: "old.preview.beamhall.test", Status: domain.RouteRetired},
		{BeamID: beamID, Hostname: "abc123.preview.beamhall.test", Status: domain.RouteActive},
	}, nil
}

func (fakeDirectory) ListReleasesByBeam(ctx context.Context, beamID domain.ID) ([]domain.Release, error) {
	// Newest-version-first, like the store, with interleaved preview+live history.
	return []domain.Release{
		{ID: "live-2", BeamID: beamID, Version: 4, Channel: domain.ChannelLive},
		{ID: "prev-2", BeamID: beamID, Version: 3, Channel: domain.ChannelPreview},
		{ID: "live-1", BeamID: beamID, Version: 2, Channel: domain.ChannelLive},
		{ID: "prev-1", BeamID: beamID, Version: 1, Channel: domain.ChannelPreview},
	}, nil
}

// stubVerifier authenticates any "Bearer <scopes-csv>" token, standing in for
// the JWT verifier (which has its own suite in internal/auth).
func stubVerifier(ctx context.Context, token string, _ *http.Request) (*sdkauth.TokenInfo, error) {
	if token == "invalid" {
		return nil, sdkauth.ErrInvalidToken
	}
	// Token format: "<scopes-csv>" for user-1, or "as=<subject>;<scopes-csv>".
	subject := "user-1"
	if rest, ok := strings.CutPrefix(token, "as="); ok {
		subject, token, _ = strings.Cut(rest, ";")
	}
	return &sdkauth.TokenInfo{
		Scopes:     strings.Split(token, ","),
		Expiration: time.Now().Add(time.Hour),
		UserID:     "https://idp.test|" + subject,
		Extra: map[string]any{
			auth.ExtraIssuer:  "https://idp.test",
			auth.ExtraSubject: subject,
			auth.ExtraJTI:     "jti-42",
		},
	}, nil
}

// --- harness ---------------------------------------------------------------

type harness struct {
	bp  *fakeBackplane
	url string
}

// call invokes a tool on a session and asserts the error expectation.
func (h *harness) call(t *testing.T, cs *sdkmcp.ClientSession, name string, args map[string]any, wantErr bool) (*sdkmcp.CallToolResult, string) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &sdkmcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: transport error: %v", name, err)
	}
	txt := callText(t, res)
	if res.IsError != wantErr {
		t.Fatalf("%s: IsError=%v want %v — %s", name, res.IsError, wantErr, txt)
	}
	return res, txt
}

func newHarness(t *testing.T, opts ...Option) *harness {
	t.Helper()
	bp := &fakeBackplane{}
	s := New(bp, fakeDirectory{}, "test", opts...)
	mux := http.NewServeMux()
	mux.Handle("/mcp", s.Handler(stubVerifier, "https://beamhall.test/.well-known/oauth-protected-resource", []string{"beamhall.test"}))
	mux.Handle("/.well-known/oauth-protected-resource", MetadataHandler("https://beamhall.test/mcp", []string{"https://idp.test"}))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &harness{bp: bp, url: srv.URL}
}

// fakeMinter stands in for *gitserver.TokenStore.
type fakeMinter struct{}

func (fakeMinter) Mint(beamhall, beam, actor domain.ID) (string, error)     { return "push-tok", nil }
func (fakeMinter) MintRead(beamhall, beam, actor domain.ID) (string, error) { return "read-tok", nil }

type bearerTransport struct{ token string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

// connect opens an MCP session presenting the given scopes as the token.
func (h *harness) connect(t *testing.T, scopes string, opts *sdkmcp.ClientOptions) *sdkmcp.ClientSession {
	t.Helper()
	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "test-agent", Version: "1"}, opts)
	cs, err := client.Connect(context.Background(), &sdkmcp.StreamableClientTransport{
		Endpoint:   h.url + "/mcp",
		HTTPClient: &http.Client{Transport: bearerTransport{scopes}},
	}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func callText(t *testing.T, res *sdkmcp.CallToolResult) string {
	t.Helper()
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*sdkmcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

func tarGz(t *testing.T, files map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(content))
	}
	tw.Close()
	gz.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// --- tests -------------------------------------------------------------

func TestUnauthenticatedRejected(t *testing.T) {
	h := newHarness(t)
	resp, err := http.Post(h.url+"/mcp", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: got HTTP %d, want 401", resp.StatusCode)
	}
	if www := resp.Header.Get("WWW-Authenticate"); !strings.Contains(www, "resource_metadata") {
		t.Errorf("WWW-Authenticate %q does not point at the resource metadata", www)
	}
}

func TestProtectedResourceMetadata(t *testing.T) {
	h := newHarness(t)
	resp, err := http.Get(h.url + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	body := buf.String()
	for _, want := range []string{`"resource":"https://beamhall.test/mcp"`, `https://idp.test`, auth.ScopeBeamsDeploy} {
		if !strings.Contains(body, want) {
			t.Errorf("metadata missing %q:\n%s", want, body)
		}
	}
}

func TestToolListMatchesContract(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeBeamsWrite, nil)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, tool := range res.Tools {
		got[tool.Name] = true
	}
	for _, want := range []string{"list_beams", "create_beam", "deploy_beam", "get_repo",
		"create_database", "set_secret", "show_logs", "pause_preview", "resume_preview",
		"promote_to_live", "create_object_store", "create_queue"} {
		if !got[want] {
			t.Errorf("tool %q missing from the contract", want)
		}
	}
}

// Regression: the no-source git path must carry the push remote + token in
// STRUCTURED output, not only in the text block — some MCP clients surface only
// structuredContent to the model, and the agent must still get the write remote.
func TestDeployBeamNoSourceSurfacesPushRemoteInStructured(t *testing.T) {
	h := newHarness(t, WithGitTransport(fakeMinter{}, "https://beamhall.test"))
	cs := h.connect(t, auth.ScopeBeamsDeploy, nil)
	res, txt := h.call(t, cs, "deploy_beam", map[string]any{"beamhall": "ops", "beam": "tracker"}, false)

	sc, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"push_command"`, "git ", "push", "push-tok", "/git/ops/tracker.git", `"git_remote"`} {
		if !strings.Contains(string(sc), want) {
			t.Errorf("structuredContent missing %q:\n%s", want, sc)
		}
	}
	// Delta-free push so go-git's receive-pack can decode the pack.
	if !strings.Contains(string(sc), "pack.window=0") {
		t.Errorf("push_command should disable delta compression (pack.window=0):\n%s", sc)
	}
	// The text block keeps it too (for clients that show text).
	if !strings.Contains(txt, "git ") || !strings.Contains(txt, "push") {
		t.Errorf("text missing push command:\n%s", txt)
	}
}

func TestListBeamsMembershipScoped(t *testing.T) {
	h := newHarness(t)

	// A member sees their beamhall and its active beam.
	cs := h.connect(t, auth.ScopeBeamhallsRead, nil)
	_, txt := h.call(t, cs, "list_beams", map[string]any{}, false)
	if !strings.Contains(txt, "ops") || !strings.Contains(txt, "tracker") {
		t.Errorf("member list missing hall/beam:\n%s", txt)
	}

	// A registered identity with no memberships sees nothing — not even that
	// the "ops" beamhall exists (EscapeItsBeamhall isolation).
	cs2 := h.connect(t, "as=user-2;"+auth.ScopeBeamhallsRead, nil)
	_, txt2 := h.call(t, cs2, "list_beams", map[string]any{}, false)
	if strings.Contains(txt2, "ops") || strings.Contains(txt2, "tracker") {
		t.Errorf("non-member saw another team's beamhall:\n%s", txt2)
	}
	if !strings.Contains(txt2, "not a member") {
		t.Errorf("expected a not-a-member message:\n%s", txt2)
	}

	// list_beams requires beamhalls:read.
	cs3 := h.connect(t, auth.ScopeBeamsWrite, nil)
	h.call(t, cs3, "list_beams", map[string]any{}, true)
}

func TestCreateBeamHappyPath(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeBeamsWrite, nil)
	res, err := cs.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name:      "create_beam",
		Arguments: map[string]any{"beamhall": "ops", "slug": "tracker"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool error: %s", callText(t, res))
	}
	if !strings.Contains(callText(t, res), `"tracker" created`) {
		t.Errorf("text: %s", callText(t, res))
	}
	if h.bp.calls[0] != "CreateBeam:hall-1:tracker" {
		t.Errorf("backplane calls: %v", h.bp.calls)
	}
	if h.bp.lastActor.ID != "ident-1" || h.bp.lastActor.TokenJTI != "jti-42" || h.bp.lastActor.ITAdmin {
		t.Errorf("actor: %+v", h.bp.lastActor)
	}
}

func TestInsufficientScope(t *testing.T) {
	h := newHarness(t)
	// logs:read only — create_beam and promote must refuse before the backplane.
	cs := h.connect(t, auth.ScopeLogsRead, nil)
	calls := []struct {
		tool string
		args map[string]any
	}{
		{"create_beam", map[string]any{"beamhall": "ops", "slug": "x"}},
		{"promote_to_live", map[string]any{"beamhall": "ops", "beam": "tracker"}},
	}
	for _, c := range calls {
		res, err := cs.CallTool(context.Background(), &sdkmcp.CallToolParams{Name: c.tool, Arguments: c.args})
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError || !strings.Contains(callText(t, res), "insufficient_scope") {
			t.Errorf("%s: want insufficient_scope error, got %q", c.tool, callText(t, res))
		}
	}
	if len(h.bp.calls) != 0 {
		t.Errorf("backplane reached despite missing scope: %v", h.bp.calls)
	}
}

func TestITAdminScopeMapsToActor(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeBeamsPromote+","+auth.ScopeAdminIT, nil)
	if _, err := cs.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name:      "promote_to_live",
		Arguments: map[string]any{"beamhall": "ops", "beam": "tracker"},
	}); err != nil {
		t.Fatal(err)
	}
	if !h.bp.lastActor.ITAdmin {
		t.Error("admin:it scope did not set Actor.ITAdmin")
	}
}

func TestUnknownIdentityRejected(t *testing.T) {
	h := newHarness(t)
	// Valid token, but the subject is not registered on this appliance.
	cs := h.connect(t, "as=stranger;"+auth.ScopeBeamsWrite, nil)
	res, err := cs.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name: "create_beam", Arguments: map[string]any{"beamhall": "ops", "slug": "x"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(callText(t, res), "not registered") {
		t.Errorf("unknown identity: %q", callText(t, res))
	}
	if len(h.bp.calls) != 0 {
		t.Errorf("backplane reached by unregistered identity: %v", h.bp.calls)
	}
}

func TestDeployBeamFromTarballWithProgress(t *testing.T) {
	h := newHarness(t)
	h.bp.srcCheck = func(srcDir string) error {
		b, err := os.ReadFile(filepath.Join(srcDir, "app", "server.js"))
		if err != nil {
			return fmt.Errorf("extracted tree incomplete: %w", err)
		}
		if string(b) != "console.log('hi')" {
			return fmt.Errorf("content mangled: %q", b)
		}
		return nil
	}

	var mu sync.Mutex
	var progress []string
	cs := h.connect(t, auth.ScopeBeamsDeploy, &sdkmcp.ClientOptions{
		ProgressNotificationHandler: func(_ context.Context, req *sdkmcp.ProgressNotificationClientRequest) {
			mu.Lock()
			progress = append(progress, req.Params.Message)
			mu.Unlock()
		},
	})

	params := &sdkmcp.CallToolParams{
		Name: "deploy_beam",
		Arguments: map[string]any{
			"beamhall": "ops", "beam": "tracker",
			"source_tarball": tarGz(t, map[string]string{"app/server.js": "console.log('hi')"}),
		},
	}
	params.SetProgressToken("tok-1")
	res, err := cs.CallTool(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool error: %s", callText(t, res))
	}
	text := callText(t, res)
	if !strings.Contains(text, "https://abc123.preview.beamhall.test") {
		t.Errorf("deploy text has no preview URL: %s", text)
	}

	// Progress notifications are delivered asynchronously over the connection,
	// so they can still be in flight when CallTool returns. Wait for the build
	// phases to arrive before asserting (deterministic; a genuine miss still
	// fails after the deadline).
	want := []string{"DETECTING", "BUILDING", "EXPORTING"}
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		joined := strings.Join(progress, "\n")
		mu.Unlock()
		missing := false
		for _, w := range want {
			if !strings.Contains(joined, w) {
				missing = true
				break
			}
		}
		if !missing || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	joined := strings.Join(progress, "\n")
	for _, w := range want {
		if !strings.Contains(joined, w) {
			t.Errorf("progress stream missing %q: %v", w, progress)
		}
	}
}

func TestDeployBeamInputValidation(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeBeamsDeploy, nil)
	cases := []struct {
		name string
		args map[string]any
		want string
	}{
		{"no source", map[string]any{"beamhall": "ops", "beam": "tracker"}, "needs source_tarball"},
		{"both sources", map[string]any{"beamhall": "ops", "beam": "tracker",
			"source_tarball": "eA==", "image_digest": "sha256:x"}, "not both"},
		{"bad base64", map[string]any{"beamhall": "ops", "beam": "tracker",
			"source_tarball": "!!!"}, "base64"},
		{"unknown hall", map[string]any{"beamhall": "ghost", "beam": "tracker",
			"image_digest": "sha256:x"}, `no beamhall named "ghost"`},
		{"unknown beam", map[string]any{"beamhall": "ops", "beam": "ghost",
			"image_digest": "sha256:x"}, `no beam named "ghost"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := cs.CallTool(context.Background(), &sdkmcp.CallToolParams{Name: "deploy_beam", Arguments: tc.args})
			if err != nil {
				t.Fatal(err)
			}
			if !res.IsError || !strings.Contains(callText(t, res), tc.want) {
				t.Errorf("want error containing %q, got %q", tc.want, callText(t, res))
			}
		})
	}
}

func TestTarballEscapeRejected(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeBeamsDeploy, nil)

	// Hand-build a tarball with a path-escape entry.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: "../../evil.sh", Mode: 0o755, Size: 4})
	tw.Write([]byte("boom"))
	tw.Close()
	gz.Close()

	res, err := cs.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name: "deploy_beam",
		Arguments: map[string]any{"beamhall": "ops", "beam": "tracker",
			"source_tarball": base64.StdEncoding.EncodeToString(buf.Bytes())},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(callText(t, res), "escapes") {
		t.Errorf("escape not rejected: %q", callText(t, res))
	}
	if len(h.bp.calls) != 0 {
		t.Errorf("backplane reached with hostile tarball: %v", h.bp.calls)
	}
}

func TestCreateDatabaseReturnsKeyNotDSN(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeResourcesWrite, nil)
	res, err := cs.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name:      "create_database",
		Arguments: map[string]any{"beamhall": "ops", "beam": "tracker", "name": "main"},
	})
	if err != nil {
		t.Fatal(err)
	}
	text := callText(t, res)
	if !strings.Contains(text, "/run/secrets/MAIN_URL") {
		t.Errorf("no injection plan in: %s", text)
	}
	if strings.Contains(text, "postgres://") {
		t.Errorf("connection string leaked: %s", text)
	}
}

func TestSecretLifecycleAndOperateTools(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, strings.Join([]string{auth.ScopeSecretsWrite, auth.ScopeBeamsOperate,
		auth.ScopeLogsRead}, ","), nil)

	// Beam-scoped and hall-wide secrets.
	for _, args := range []map[string]any{
		{"beamhall": "ops", "beam": "tracker", "key": "API_TOKEN", "value": "s3cr3t"},
		{"beamhall": "ops", "key": "HALL_WIDE", "value": "v"},
	} {
		res, err := cs.CallTool(context.Background(), &sdkmcp.CallToolParams{Name: "set_secret", Arguments: args})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("set_secret: %s", callText(t, res))
		}
	}

	res, err := cs.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name: "show_logs", Arguments: map[string]any{"beamhall": "ops", "beam": "tracker"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(callText(t, res), "scrubbed log line") {
		t.Errorf("logs: %s", callText(t, res))
	}

	if _, err := cs.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name: "pause_preview", Arguments: map[string]any{"beamhall": "ops", "beam": "tracker"}}); err != nil {
		t.Fatal(err)
	}
	res, err = cs.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name: "resume_preview", Arguments: map[string]any{"beamhall": "ops", "beam": "tracker"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(callText(t, res), "https://fresh1234.preview.beamhall.test") {
		t.Errorf("resume did not surface the new URL: %s", callText(t, res))
	}

	want := []string{"SetSecret:beam-1:API_TOKEN", "SetSecret::HALL_WIDE", "ShowLogs:200", "PausePreview", "ResumePreview"}
	if len(h.bp.calls) != len(want) {
		t.Fatalf("calls: %v", h.bp.calls)
	}
	for i := range want {
		if h.bp.calls[i] != want[i] {
			t.Errorf("call %d = %q, want %q", i, h.bp.calls[i], want[i])
		}
	}
}

func TestFastFollowToolsRefuse(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeResourcesWrite, nil)
	for _, tool := range []string{"create_object_store", "create_queue"} {
		res, err := cs.CallTool(context.Background(), &sdkmcp.CallToolParams{Name: tool, Arguments: map[string]any{}})
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError || !strings.Contains(callText(t, res), "not enabled in this build") {
			t.Errorf("%s: %q", tool, callText(t, res))
		}
	}
}

func TestBackplaneErrorSurfacesVerbatim(t *testing.T) {
	h := newHarness(t)
	h.bp.failWith = fmt.Errorf("denied: builders may not create beams in this beamhall (role viewer)")
	cs := h.connect(t, auth.ScopeBeamsWrite, nil)
	res, err := cs.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name: "create_beam", Arguments: map[string]any{"beamhall": "ops", "slug": "tracker"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(callText(t, res), "role viewer") {
		t.Errorf("PEP denial not surfaced: %q", callText(t, res))
	}
}

func TestShowLogsAppendsConstraintHint(t *testing.T) {
	h := newHarness(t)
	h.bp.logs = []byte("Error: getaddrinfo EAI_AGAIN api.stripe.com\n")
	cs := h.connect(t, auth.ScopeLogsRead, nil)
	res, err := cs.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name: "show_logs", Arguments: map[string]any{"beamhall": "ops", "beam": "tracker"}})
	if err != nil {
		t.Fatal(err)
	}
	text := callText(t, res)
	if !strings.Contains(text, "DENIED BY DEFAULT") || !strings.Contains(text, "[beamhall]") {
		t.Errorf("egress hint not appended:\n%s", text)
	}
}

func TestRollbackDefaultsToPreviousVersion(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeBeamsDeploy, nil)
	res, err := cs.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name: "rollback", Arguments: map[string]any{"beamhall": "ops", "beam": "tracker"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("rollback: %s", callText(t, res))
	}
	// Default rollback targets the most recent PRIOR live release (live-1, v2) —
	// skipping the current live release (live-2) and all preview releases.
	if h.bp.calls[0] != "RollbackBeam:live-1" {
		t.Errorf("rollback target: %v", h.bp.calls)
	}
}

func TestRollbackToNamedVersionAndMissing(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeBeamsDeploy, nil)
	res, _ := h.call(t, cs, "rollback", map[string]any{"beamhall": "ops", "beam": "tracker", "to_version": 2}, false)
	_ = res
	// to_version names a prior LIVE release version (2 → live-1).
	if h.bp.calls[0] != "RollbackBeam:live-1" {
		t.Errorf("named-version target: %v", h.bp.calls)
	}
	// A preview-only or unknown version is rejected and names the live ones.
	_, txt := h.call(t, cs, "rollback", map[string]any{"beamhall": "ops", "beam": "tracker", "to_version": 99}, true)
	if !strings.Contains(txt, "version 99") || !strings.Contains(txt, "available: [2]") {
		t.Errorf("missing-version error: %s", txt)
	}
}

func TestShowMetricsTool(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeMetricsRead, nil)
	_, txt := h.call(t, cs, "show_metrics", map[string]any{"beamhall": "ops", "beam": "tracker"}, false)
	if !strings.Contains(txt, "CPU 7.5%") {
		t.Errorf("metrics text: %s", txt)
	}
	if !strings.Contains(txt, "33554432") {
		t.Errorf("missing mem bytes: %s", txt)
	}
}

func TestDestroyBeamTool(t *testing.T) {
	h := newHarness(t)
	cs := h.connect(t, auth.ScopeBeamsWrite, nil)
	_, txt := h.call(t, cs, "destroy_beam", map[string]any{"beamhall": "ops", "beam": "tracker"}, false)
	if !strings.Contains(txt, "destroyed") {
		t.Errorf("destroy text: %s", txt)
	}
	if h.bp.calls[0] != "DestroyBeam:beam-1" {
		t.Errorf("destroy call: %v", h.bp.calls)
	}
}

func TestArchiveBeamTool(t *testing.T) {
	h := newHarness(t)
	// archive_beam is operate-scoped (builder-accessible), not write/destroy.
	cs := h.connect(t, auth.ScopeBeamsOperate, nil)
	_, txt := h.call(t, cs, "archive_beam", map[string]any{"beamhall": "ops", "beam": "tracker"}, false)
	if !strings.Contains(txt, "archived") {
		t.Errorf("archive text: %s", txt)
	}
	if h.bp.calls[0] != "ArchiveBeam:beam-1" {
		t.Errorf("archive call: %v", h.bp.calls)
	}
}
