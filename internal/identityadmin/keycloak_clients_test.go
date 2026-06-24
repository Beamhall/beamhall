package identityadmin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// clientStub is a minimal Keycloak Admin REST stub for the OIDC-client surface
// (PLAN §5.10): it mints a token and answers just the endpoints CreateClient /
// SyncRedirectURIs / DeleteClient touch, recording what Beamhall sent so the
// request shaping + the audience-isolation post-assertion are tested without a
// live Keycloak.
type clientStub struct {
	// inputs
	existing     []kcClient         // GET /clients?clientId=
	effMappers   []kcProtocolMapper // GET .../evaluate-scopes/protocol-mappers
	deleteStatus int                // status for DELETE /clients/{uuid} (default 204)
	// recordings
	postBody    kcClient
	posted      bool
	putBody     map[string]any
	deletedUUID string
}

func (s *clientStub) handler(uuid string) http.Handler {
	mux := http.NewServeMux()
	base := "/admin/realms/beamhall/clients"
	mux.HandleFunc("/realms/beamhall/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "kc-admin-token", "expires_in": 60})
	})
	mux.HandleFunc(base, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet: // find by clientId
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(s.existing)
		case http.MethodPost: // create
			_ = json.NewDecoder(r.Body).Decode(&s.postBody)
			s.posted = true
			w.Header().Set("Location", base+"/"+uuid)
			w.WriteHeader(http.StatusCreated)
		}
	})
	mux.HandleFunc(base+"/"+uuid, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodDelete:
			s.deletedUUID = uuid
			st := s.deleteStatus
			if st == 0 {
				st = http.StatusNoContent
			}
			w.WriteHeader(st)
		case http.MethodPut:
			_ = json.NewDecoder(r.Body).Decode(&s.putBody)
			w.WriteHeader(http.StatusNoContent)
		}
	})
	mux.HandleFunc(base+"/"+uuid+"/default-client-scopes", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]any{})
	})
	mux.HandleFunc(base+"/"+uuid+"/optional-client-scopes", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]any{})
	})
	mux.HandleFunc(base+"/"+uuid+"/evaluate-scopes/protocol-mappers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.effMappers)
	})
	mux.HandleFunc(base+"/"+uuid+"/client-secret", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "sealed-secret"})
	})
	return mux
}

func newClientTestKC(t *testing.T, s *clientStub, uuid string) *Keycloak {
	t.Helper()
	srv := httptest.NewServer(s.handler(uuid))
	t.Cleanup(srv.Close)
	kc, err := NewKeycloak(KeycloakConfig{
		BaseURL: srv.URL, Realm: "beamhall",
		ClientID: "beamhall-idp-admin", ClientSecret: "s3cr3t",
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewKeycloak: %v", err)
	}
	return kc
}

func TestCreateClientWildcardRejected(t *testing.T) {
	kc := newClientTestKC(t, &clientStub{}, "c-1")
	_, err := kc.CreateClient(context.Background(), ClientSpec{
		ClientID:     "beam-blue-app-preview",
		RedirectURIs: []string{"https://*.preview.beamhall.internal/callback"},
	})
	if err == nil || !strings.Contains(err.Error(), "wildcard") {
		t.Fatalf("expected wildcard rejection, got %v", err)
	}
}

func TestCreateClientHappyPath(t *testing.T) {
	// evaluate-scopes returns only the client's own audience mapper -> clean.
	s := &clientStub{effMappers: []kcProtocolMapper{audienceMapper("beam-blue-app-preview")}}
	kc := newClientTestKC(t, s, "c-1")
	got, err := kc.CreateClient(context.Background(), ClientSpec{
		ClientID:              "beam-blue-app-preview",
		RedirectURIs:          []string{"https://abc.preview.beamhall.internal/auth/callback"},
		WebOrigins:            []string{"https://abc.preview.beamhall.internal"},
		AccessTokenTTLSeconds: 300,
		ForbiddenAudience:     "https://beamhall.internal/mcp",
	})
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	if got.UUID != "c-1" || got.ClientID != "beam-blue-app-preview" || got.Secret != "sealed-secret" {
		t.Fatalf("unexpected client: %+v", got)
	}
	// Confidential, code+PKCE only, no service/direct/implicit, scope locked down.
	if s.postBody.PublicClient || !s.postBody.StandardFlowEnabled || s.postBody.DirectAccessGrants ||
		s.postBody.ImplicitFlowEnabled || s.postBody.ServiceAccountsEnabled || s.postBody.FullScopeAllowed {
		t.Fatalf("client flags not locked down: %+v", s.postBody)
	}
	if s.postBody.Attributes["pkce.code.challenge.method"] != "S256" {
		t.Fatalf("PKCE S256 not set: %+v", s.postBody.Attributes)
	}
	if s.postBody.Attributes["access.token.lifespan"] != "300" {
		t.Fatalf("token TTL not set: %+v", s.postBody.Attributes)
	}
	// The audience mapper injects the client's OWN id, never the backplane URI.
	var aud *kcProtocolMapper
	for i := range s.postBody.ProtocolMappers {
		if s.postBody.ProtocolMappers[i].ProtocolMapper == "oidc-audience-mapper" {
			aud = &s.postBody.ProtocolMappers[i]
		}
	}
	if aud == nil || aud.Config["included.client.audience"] != "beam-blue-app-preview" {
		t.Fatalf("audience mapper missing/wrong: %+v", s.postBody.ProtocolMappers)
	}
}

func TestCreateClientRefusesForbiddenAudience(t *testing.T) {
	// A scope-injected mapper would put the Beamhall resource URI into the token.
	s := &clientStub{effMappers: []kcProtocolMapper{{
		Name: "leak", Protocol: "openid-connect", ProtocolMapper: "oidc-audience-mapper",
		Config: map[string]string{"included.custom.audience": "https://beamhall.internal/mcp"},
	}}}
	kc := newClientTestKC(t, s, "c-1")
	_, err := kc.CreateClient(context.Background(), ClientSpec{
		ClientID:          "beam-blue-app-preview",
		RedirectURIs:      []string{"https://abc.preview.beamhall.internal/auth/callback"},
		ForbiddenAudience: "https://beamhall.internal/mcp",
	})
	if err == nil || !strings.Contains(err.Error(), "backplane replay") {
		t.Fatalf("expected audience-isolation refusal, got %v", err)
	}
	if s.deletedUUID != "c-1" {
		t.Fatalf("a refused client must be deleted; deletedUUID=%q", s.deletedUUID)
	}
}

func TestSyncRedirectURIsReplaces(t *testing.T) {
	s := &clientStub{}
	kc := newClientTestKC(t, s, "c-1")
	if err := kc.SyncRedirectURIs(context.Background(), "c-1",
		[]string{"https://new.preview.beamhall.internal/auth/callback"},
		[]string{"https://new.preview.beamhall.internal"}); err != nil {
		t.Fatalf("SyncRedirectURIs: %v", err)
	}
	ru, _ := s.putBody["redirectUris"].([]any)
	if len(ru) != 1 || ru[0] != "https://new.preview.beamhall.internal/auth/callback" {
		t.Fatalf("redirectUris not replaced: %+v", s.putBody)
	}
	// Empty allowlist (preview paused) must clear, not no-op.
	s.putBody = nil
	if err := kc.SyncRedirectURIs(context.Background(), "c-1", nil, nil); err != nil {
		t.Fatalf("SyncRedirectURIs empty: %v", err)
	}
	if ru, ok := s.putBody["redirectUris"].([]any); !ok || len(ru) != 0 {
		t.Fatalf("empty allowlist should send []: %+v", s.putBody)
	}
}

func TestSyncRedirectURIsWildcardRejected(t *testing.T) {
	kc := newClientTestKC(t, &clientStub{}, "c-1")
	if err := kc.SyncRedirectURIs(context.Background(), "c-1",
		[]string{"https://*.preview.beamhall.internal/cb"}, nil); err == nil {
		t.Fatal("expected wildcard rejection in SyncRedirectURIs")
	}
}

func TestDeleteClientIdempotent(t *testing.T) {
	s := &clientStub{deleteStatus: http.StatusNotFound}
	kc := newClientTestKC(t, s, "c-1")
	if err := kc.DeleteClient(context.Background(), "c-1"); err != nil {
		t.Fatalf("DeleteClient on absent client should be nil, got %v", err)
	}
	if err := kc.DeleteClient(context.Background(), ""); err != nil {
		t.Fatalf("DeleteClient(\"\") should be nil, got %v", err)
	}
}

func TestCreateClientIdempotentReturnsExisting(t *testing.T) {
	s := &clientStub{existing: []kcClient{{ID: "c-1", ClientID: "beam-blue-app-preview"}}}
	kc := newClientTestKC(t, s, "c-1")
	got, err := kc.CreateClient(context.Background(), ClientSpec{ClientID: "beam-blue-app-preview"})
	if err != nil {
		t.Fatalf("CreateClient idempotent: %v", err)
	}
	if got.UUID != "c-1" || got.Secret != "sealed-secret" {
		t.Fatalf("idempotent create should return existing client + secret: %+v", got)
	}
	if s.posted {
		t.Fatal("idempotent create must NOT POST a second client")
	}
}
