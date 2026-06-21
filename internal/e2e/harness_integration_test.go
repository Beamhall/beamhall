package e2e

// Shared lab harness: a seeded control plane + a real beamhalld process + a
// local JWKS/token mint, used by the demo-flow E2E and the negative-security
// suite. Same package so the suites share the probe helpers.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Beamhall/beamhall/internal/audit"
	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/store"
)

type appliance struct {
	t        *testing.T
	ctx      context.Context
	dataDir  string
	mint     func(sub, scopes string) string
	hallID   domain.ID // "e2e": the builder's hall
	fortID   domain.ID // "fort": a hall the builder has NO membership in
	daemon   *exec.Cmd
	stopOnce sync.Once
}

// stop shuts the daemon down (idempotent; also runs in cleanup). Call before
// opening the store directly — e.g. for the audit-chain verification.
func (a *appliance) stop() {
	a.stopOnce.Do(func() {
		a.daemon.Process.Signal(os.Interrupt)
		if err := a.daemon.Wait(); err != nil {
			a.t.Logf("daemon exit: %v", err)
		}
	})
}

// launchAppliance seeds the control plane (hall "e2e" with a builder member
// + an IT identity without membership; hall "fort" with nobody), starts a
// real beamhalld against it, and returns the handles the suites need.
func launchAppliance(t *testing.T, ctx context.Context) *appliance {
	t.Helper()
	binary := os.Getenv("BEAMHALL_E2E_BINARY")
	if binary == "" {
		binary = "/tmp/beamhalld"
	}

	// Lab IdP: JWKS endpoint + local token mint.
	idpKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": "e2e-1", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(idpKey.PublicKey.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(idpKey.PublicKey.E)).Bytes()),
	}}})
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(jwks)
	}))
	t.Cleanup(idp.Close)
	issuer := idp.URL
	mint := func(sub, scopes string) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": issuer, "aud": audience, "sub": sub, "jti": "e2e-" + sub,
			"scope": scopes, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		})
		tok.Header["kid"] = "e2e-1"
		s, err := tok.SignedString(idpKey)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	// Seed the control plane (IT bootstrap; the Admin UI is Phase 3 item 3).
	dataDir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dataDir, "beamhall.db"))
	if err != nil {
		t.Fatal(err)
	}
	sc := func() *domain.SecurityContext {
		return &domain.SecurityContext{
			RuntimeClass: domain.RuntimeRunc, CapDrop: []string{"ALL"}, CapAdd: []string{"NET_BIND_SERVICE"},
			NoNewPrivileges: true, ReadOnlyRootfs: true, Tmpfs: []string{"/tmp"},
			CgroupLimits: domain.ResourceLimits{MemBytes: 512 << 20, PidsMax: 256, CPUQuota: 50000},
			Template:     domain.TemplateWebApp,
		}
	}
	hall := &domain.Beamhall{
		Slug: "e2e", DisplayName: "E2E", Status: domain.BeamhallActive,
		NetworkPolicy: domain.NetworkPolicy{EgressMode: domain.EgressDenyAll},
		Quota:         domain.ResourceQuota{MaxBeams: 2, MaxLiveSlots: 1, MaxDBCount: 1},
		LiveSlotLimit: 1,
	}
	if err := st.CreateBeamhall(ctx, hall, sc()); err != nil {
		t.Fatal(err)
	}
	fort := &domain.Beamhall{
		Slug: "fort", DisplayName: "Fort (no members)", Status: domain.BeamhallActive,
		NetworkPolicy: domain.NetworkPolicy{EgressMode: domain.EgressDenyAll},
		Quota:         domain.ResourceQuota{MaxBeams: 1, MaxLiveSlots: 1, MaxDBCount: 1},
		LiveSlotLimit: 1,
	}
	if err := st.CreateBeamhall(ctx, fort, sc()); err != nil {
		t.Fatal(err)
	}
	builder := &domain.Identity{ExternalSubject: "e2e-builder", Email: "builder@e2e",
		DisplayName: "Builder", IdPIssuer: issuer, Status: domain.IdentityActive}
	itAdmin := &domain.Identity{ExternalSubject: "e2e-it", Email: "it@e2e",
		DisplayName: "IT", IdPIssuer: issuer, Status: domain.IdentityActive}
	for _, id := range []*domain.Identity{builder, itAdmin} {
		if err := st.CreateIdentity(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	// Builder is a member of "e2e" only — deliberately short of promote
	// rights there and a stranger to "fort". IT has NO membership anywhere:
	// admin:it bypasses membership.
	if err := st.CreateMembership(ctx, &domain.Membership{IdentityID: builder.ID,
		BeamhallID: hall.ID, Role: domain.RoleBuilder, GrantedBy: itAdmin.ID}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	// Launch the appliance.
	pgDSN := os.Getenv("BEAMHALL_PG_ADMIN_DSN")
	if pgDSN == "" {
		pgDSN = "postgres://postgres:beamhall-lab-admin@127.0.0.1:5433/postgres?sslmode=disable"
	}
	// Start Caddy ONLY if its admin API is down. A second `caddy start` does
	// NOT fail — Caddy's listeners use SO_REUSEPORT, so two instances split
	// the admin endpoint and config pushes round-robin between them (lab
	// gotcha: flaky routes with no errors anywhere).
	if resp, err := http.Get("http://127.0.0.1:2019/config/"); err != nil {
		exec.Command("caddy", "start").Run()
		time.Sleep(time.Second)
	} else {
		resp.Body.Close()
	}
	daemon := exec.CommandContext(ctx, binary)
	daemon.Env = append(os.Environ(),
		"BEAMHALL_DATA_DIR="+dataDir,
		"BEAMHALL_HTTP_ADDR="+httpAddr,
		"BEAMHALL_BASE_DOMAIN="+baseDomain,
		"BEAMHALL_LOG_LEVEL=debug",
		"BEAMHALL_OAUTH_ISSUER="+issuer,
		"BEAMHALL_OAUTH_JWKS_URL="+issuer,
		"BEAMHALL_OAUTH_AUDIENCE="+audience,
		"BEAMHALL_GATEWAY_LISTEN=:"+gatewayPort,
		"BEAMHALL_GATEWAY_TLS=off",
		"BEAMHALL_PG_ADMIN_DSN="+pgDSN,
		"BEAMHALL_GIT_BASE_URL=http://"+httpAddr, // git-push remote reachable in-test
	)
	daemon.Stdout = testWriter{t, "beamhalld"}
	daemon.Stderr = testWriter{t, "beamhalld"}
	if err := daemon.Start(); err != nil {
		t.Fatalf("start beamhalld: %v", err)
	}
	hallID, fortID := hall.ID, fort.ID
	a := &appliance{t: t, ctx: ctx, dataDir: dataDir, mint: mint,
		hallID: hallID, fortID: fortID, daemon: daemon}
	t.Cleanup(func() {
		a.stop()
		// Lab hygiene: tear down what the suites create.
		for _, db := range []string{"bh_e2e_tracker_main", "bh_e2e_probe_main"} {
			exec.Command("docker", "exec", "bh-postgres", "psql", "-U", "postgres", "-c",
				`DROP DATABASE IF EXISTS `+db+` WITH (FORCE)`).Run()
			exec.Command("docker", "exec", "bh-postgres", "psql", "-U", "postgres", "-c",
				`DROP ROLE IF EXISTS `+db+`_rw`).Run()
		}
		exec.Command("bash", "-c",
			`docker rm -f $(docker ps -aq --filter label=beamhall.beam) 2>/dev/null`).Run()
		for _, id := range []domain.ID{hallID, fortID} {
			exec.Command("docker", "network", "disconnect", "bh-"+string(id), "bh-postgres").Run()
			exec.Command("docker", "network", "rm", "bh-"+string(id)).Run()
		}
	})
	waitHealthy(t, "http://"+httpAddr+"/healthz")
	return a
}

// connect opens an MCP session as sub with the given scopes.
func (a *appliance) connect(sub, scopes string, opts *sdkmcp.ClientOptions) *sdkmcp.ClientSession {
	a.t.Helper()
	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "e2e-agent-" + sub, Version: "1"}, opts)
	cs, err := client.Connect(a.ctx, &sdkmcp.StreamableClientTransport{
		Endpoint:   "http://" + httpAddr + "/mcp",
		HTTPClient: &http.Client{Transport: bearer{a.mint(sub, scopes)}},
	}, nil)
	if err != nil {
		a.t.Fatalf("MCP connect (%s): %v", sub, err)
	}
	a.t.Cleanup(func() { cs.Close() })
	return cs
}

// callTool invokes one tool and asserts the error expectation.
func callTool(ctx context.Context, t *testing.T, cs *sdkmcp.ClientSession,
	name string, args map[string]any, wantErr bool) (*sdkmcp.CallToolResult, string) {
	t.Helper()
	params := &sdkmcp.CallToolParams{Name: name, Arguments: args}
	params.SetProgressToken(name)
	res, err := cs.CallTool(ctx, params)
	if err != nil {
		t.Fatalf("%s: transport error: %v", name, err)
	}
	txt := resultText(res)
	if res.IsError != wantErr {
		t.Fatalf("%s: IsError=%v, want %v — %s", name, res.IsError, wantErr, txt)
	}
	t.Logf("%s → %s", name, txt)
	return res, txt
}

// openAndVerifyAudit re-opens the store (call appliance.stop first) and runs
// the chain verification, returning everything a suite needs to assert on.
func openAndVerifyAudit(t *testing.T, dataDir string) (*store.Store, []audit.Issue, []store.AuditRecord) {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(dataDir, "beamhall.db"))
	if err != nil {
		t.Fatal(err)
	}
	issues, err := audit.New(st).Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	events, err := st.ListAuditEvents(context.Background(), 0, 10000)
	if err != nil {
		t.Fatal(err)
	}
	return st, issues, events
}
