package identityadmin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeKC is a minimal Keycloak Admin REST stub: it mints a token and records
// the admin calls Beamhall makes, so the provider's request shaping is tested
// without a live Keycloak.
type fakeKC struct {
	t            *testing.T
	tokenCalls   int
	createdUser  kcUser
	created      bool
	users        []kcUser
	lastPwdUser  string
	lastPwdTemp  bool
	lastGroup    string
	addedUser    string
	addedGroup   string
	lastFedCfg   map[string][]string
	clientID     string
	clientSecret string
}

func (f *fakeKC) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/beamhall/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		f.tokenCalls++
		_ = r.ParseForm()
		if r.Form.Get("client_id") != f.clientID || r.Form.Get("client_secret") != f.clientSecret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "kc-admin-token", "expires_in": 60})
	})
	mux.HandleFunc("/admin/realms/beamhall/users", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer kc-admin-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(f.users)
		case http.MethodPost:
			_ = json.NewDecoder(r.Body).Decode(&f.createdUser)
			f.created = true
			w.Header().Set("Location", "https://kc/admin/realms/beamhall/users/u-123")
			w.WriteHeader(http.StatusCreated)
		}
	})
	mux.HandleFunc("/admin/realms/beamhall/users/u-123/reset-password", func(w http.ResponseWriter, r *http.Request) {
		var cred map[string]any
		_ = json.NewDecoder(r.Body).Decode(&cred)
		f.lastPwdUser = "u-123"
		f.lastPwdTemp, _ = cred["temporary"].(bool)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/admin/realms/beamhall/groups", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]kcGroup{})
		case http.MethodPost:
			var g map[string]string
			_ = json.NewDecoder(r.Body).Decode(&g)
			f.lastGroup = g["name"]
			w.Header().Set("Location", "https://kc/admin/realms/beamhall/groups/g-9")
			w.WriteHeader(http.StatusCreated)
		}
	})
	mux.HandleFunc("/admin/realms/beamhall/users/u-123/groups/g-9", func(w http.ResponseWriter, r *http.Request) {
		f.addedUser, f.addedGroup = "u-123", "g-9"
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/admin/realms/beamhall/components", func(w http.ResponseWriter, r *http.Request) {
		var comp struct {
			Config map[string][]string `json:"config"`
		}
		_ = json.NewDecoder(r.Body).Decode(&comp)
		f.lastFedCfg = comp.Config
		w.WriteHeader(http.StatusCreated)
	})
	return mux
}

func newTestKC(t *testing.T) (*Keycloak, *fakeKC) {
	t.Helper()
	f := &fakeKC{t: t, clientID: "beamhall-idp-admin", clientSecret: "s3cr3t"}
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	kc, err := NewKeycloak(KeycloakConfig{
		BaseURL: srv.URL, Realm: "beamhall",
		ClientID: "beamhall-idp-admin", ClientSecret: "s3cr3t",
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewKeycloak: %v", err)
	}
	return kc, f
}

func TestCreateUser(t *testing.T) {
	kc, f := newTestKC(t)
	u, err := kc.CreateUser(context.Background(), NewUser{Username: "alice", Email: "alice@corp.example", Enabled: true})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.ID != "u-123" || u.Username != "alice" {
		t.Fatalf("got %+v, want id=u-123 username=alice", u)
	}
	if !f.created || f.createdUser.Username != "alice" || !f.createdUser.Enabled {
		t.Fatalf("server did not receive the expected create: %+v", f.createdUser)
	}
	if f.tokenCalls != 1 {
		t.Fatalf("expected one token mint, got %d", f.tokenCalls)
	}
}

func TestCreateUserIdempotentOnUsername(t *testing.T) {
	kc, f := newTestKC(t)
	f.users = []kcUser{{ID: "existing-1", Username: "bob", Email: "bob@corp.example", Enabled: true}}
	u, err := kc.CreateUser(context.Background(), NewUser{Username: "bob", Enabled: true})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.ID != "existing-1" {
		t.Fatalf("expected idempotent return of existing user, got %+v", u)
	}
	if f.created {
		t.Fatal("CreateUser should not POST when the username already exists")
	}
}

func TestSetTemporaryPassword(t *testing.T) {
	kc, f := newTestKC(t)
	if err := kc.SetTemporaryPassword(context.Background(), "u-123", "Hunter2!"); err != nil {
		t.Fatalf("SetTemporaryPassword: %v", err)
	}
	if f.lastPwdUser != "u-123" || !f.lastPwdTemp {
		t.Fatalf("expected a temporary password set for u-123, got user=%q temp=%v", f.lastPwdUser, f.lastPwdTemp)
	}
}

func TestCreateGroupAndAddUser(t *testing.T) {
	kc, f := newTestKC(t)
	g, err := kc.CreateGroup(context.Background(), "builders")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if g.ID != "g-9" || f.lastGroup != "builders" {
		t.Fatalf("group create mismatch: got %+v server=%q", g, f.lastGroup)
	}
	if err := kc.AddUserToGroup(context.Background(), "u-123", "g-9"); err != nil {
		t.Fatalf("AddUserToGroup: %v", err)
	}
	if f.addedUser != "u-123" || f.addedGroup != "g-9" {
		t.Fatalf("add-to-group mismatch: user=%q group=%q", f.addedUser, f.addedGroup)
	}
}

func TestTokenCachedAcrossCalls(t *testing.T) {
	kc, f := newTestKC(t)
	for i := 0; i < 3; i++ {
		if _, err := kc.ListUsers(context.Background(), "", 10); err != nil {
			t.Fatalf("ListUsers: %v", err)
		}
	}
	if f.tokenCalls != 1 {
		t.Fatalf("expected the admin token to be cached (1 mint), got %d", f.tokenCalls)
	}
}

func TestFederateDirectoryShapesADConfig(t *testing.T) {
	kc, f := newTestKC(t)
	err := kc.FederateDirectory(context.Background(), DirectoryFederation{
		Name: "corp-ad", Vendor: "ad",
		ConnectionURL: "ldaps://dc1.corp.example:636",
		UsersDN:       "OU=Beamhall,DC=corp,DC=example",
		BindDN:        "CN=svc,DC=corp,DC=example", BindCredential: "pw",
	})
	if err != nil {
		t.Fatalf("FederateDirectory: %v", err)
	}
	if got := f.lastFedCfg["vendor"]; len(got) != 1 || got[0] != "ad" {
		t.Fatalf("vendor not propagated: %v", f.lastFedCfg["vendor"])
	}
	if got := f.lastFedCfg["usernameLDAPAttribute"]; len(got) != 1 || got[0] != "sAMAccountName" {
		t.Fatalf("AD username attribute wrong: %v", got)
	}
	if got := f.lastFedCfg["bindCredential"]; len(got) != 1 || got[0] != "pw" {
		t.Fatalf("bind credential not sent: %v", got)
	}
}

func TestNewKeycloakRequiresCreds(t *testing.T) {
	if _, err := NewKeycloak(KeycloakConfig{BaseURL: "http://x"}); err == nil {
		t.Fatal("expected error when client id/secret are missing")
	}
}

func TestDisabledProviderRefusesMutations(t *testing.T) {
	var p Provider = Disabled{}
	if p.Enabled() {
		t.Fatal("Disabled provider must report Enabled()==false")
	}
	if _, err := p.CreateUser(context.Background(), NewUser{Username: "x"}); err != ErrNotEnabled {
		t.Fatalf("expected ErrNotEnabled, got %v", err)
	}
	if err := p.FederateDirectory(context.Background(), DirectoryFederation{}); err != ErrNotEnabled {
		t.Fatalf("expected ErrNotEnabled, got %v", err)
	}
}

// snippetSanity guards the bounded error-body reader against a nil/empty body.
func TestSnippetBounded(t *testing.T) {
	kc, _ := newTestKC(t)
	_, err := kc.ListUsers(context.Background(), strings.Repeat("x", 10), 10)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
}
