package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func discoveryServer(t *testing.T, issuerFn func(self string) string, jwksURI string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		// issuerFn lets a test return a mismatching issuer on purpose.
		iss := issuerFn(srv.URL)
		w.Write([]byte(`{"issuer":"` + iss + `","jwks_uri":"` + jwksURI + `"}`))
	})
	t.Cleanup(srv.Close)
	return srv
}

func TestDiscoverJWKS_OK(t *testing.T) {
	srv := discoveryServer(t, func(self string) string { return self }, "https://idp.example/keys")
	got, err := discoverJWKS(context.Background(), srv.URL, "", srv.Client())
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if got != "https://idp.example/keys" {
		t.Fatalf("jwks_uri = %q", got)
	}
}

func TestDiscoverJWKS_IssuerMismatchRejected(t *testing.T) {
	// A document whose `issuer` differs from the configured one is rejected —
	// the defense against pointing at a look-alike discovery endpoint.
	srv := discoveryServer(t, func(self string) string { return "https://evil.example" }, "https://idp.example/keys")
	_, err := discoverJWKS(context.Background(), srv.URL, "", srv.Client())
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected issuer-mismatch error, got %v", err)
	}
}

func TestDiscoverJWKS_NoJWKSURI(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"issuer":"` + srv.URL + `"}`))
	})
	_, err := discoverJWKS(context.Background(), srv.URL, "", srv.Client())
	if err == nil || !strings.Contains(err.Error(), "no jwks_uri") {
		t.Fatalf("expected missing jwks_uri error, got %v", err)
	}
}

func TestDiscoverJWKS_HTTPError(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux) // no discovery handler → 404
	defer srv.Close()
	_, err := discoverJWKS(context.Background(), srv.URL, "", srv.Client())
	if err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Fatalf("expected HTTP 404 error, got %v", err)
	}
}

func TestNewVerifier_ResolvesJWKSViaDiscovery(t *testing.T) {
	srv := discoveryServer(t, func(self string) string { return self }, "https://idp.example/keys")
	v, err := NewVerifier(Config{
		Issuer:     srv.URL,
		Audience:   "https://beamhall.test/mcp",
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewVerifier with discovery: %v", err)
	}
	if v.cfg.JWKSURL != "https://idp.example/keys" {
		t.Fatalf("discovery did not populate JWKSURL: %q", v.cfg.JWKSURL)
	}
	if v.jwks.url != "https://idp.example/keys" {
		t.Fatalf("cache JWKS url not seeded: %q", v.jwks.url)
	}
}

// TestNewVerifier_IdPDownDoesNotFailBoot covers the co-located-bundled-IdP race:
// the IdP isn't reachable when NewVerifier runs, but the appliance must still
// boot — discovery is retried lazily by the JWKS cache on first token use.
func TestNewVerifier_IdPDownDoesNotFailBoot(t *testing.T) {
	v, err := NewVerifier(Config{
		Issuer:     "http://127.0.0.1:1/realms/down", // nothing listening
		Audience:   "https://beamhall.test/mcp",
		HTTPClient: &http.Client{Timeout: time.Second},
	})
	if err != nil {
		t.Fatalf("NewVerifier must not fail when the IdP is down: %v", err)
	}
	if v.jwks.url != "" {
		t.Fatalf("JWKS url should be unresolved (lazy), got %q", v.jwks.url)
	}
	if v.jwks.issuer != "http://127.0.0.1:1/realms/down" {
		t.Fatalf("cache should retain the issuer for lazy discovery: %q", v.jwks.issuer)
	}
}
