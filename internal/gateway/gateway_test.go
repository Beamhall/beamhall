package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// captureCaddy is a fake Caddy admin endpoint that records the last POST /load body.
func captureCaddy(t *testing.T) (url string, last func() *caddyConfig) {
	t.Helper()
	var mu sync.Mutex
	var cfg *caddyConfig
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/load" || r.Method != http.MethodPost {
			http.Error(w, "unexpected", http.StatusNotFound)
			return
		}
		b, _ := io.ReadAll(r.Body)
		var c caddyConfig
		if err := json.Unmarshal(b, &c); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		cfg = &c
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, func() *caddyConfig { mu.Lock(); defer mu.Unlock(); return cfg }
}

func TestUpsertAndRetireReconcileCaddy(t *testing.T) {
	url, last := captureCaddy(t)
	g := New(WithAdminURL(url), WithAskEndpoint("http://localhost:2099/ask"))

	if err := g.Upsert(context.Background(), Route{Hostname: "beam.ops.wc.local", BackendAddr: "172.18.0.2:8080", Kind: Live}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	cfg := last()
	if cfg == nil {
		t.Fatal("caddy received no config")
	}
	// Admin block must be present so POST /load doesn't kill the Admin API.
	if cfg.Admin == nil || cfg.Admin.Listen == "" {
		t.Fatalf("admin block missing: %+v", cfg.Admin)
	}
	srv, ok := cfg.Apps.HTTP.Servers["beamhall"]
	if !ok || len(srv.Routes) != 1 {
		t.Fatalf("expected 1 route, got %+v", srv.Routes)
	}
	rt := srv.Routes[0]
	if rt.Match[0].Host[0] != "beam.ops.wc.local" || rt.Handle[0].Upstreams[0].Dial != "172.18.0.2:8080" {
		t.Fatalf("route wrong: %+v", rt)
	}
	if rt.Handle[0].Handler != "reverse_proxy" {
		t.Fatalf("handler = %q", rt.Handle[0].Handler)
	}

	if err := g.Retire(context.Background(), "beam.ops.wc.local"); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if srv := last().Apps.HTTP.Servers["beamhall"]; len(srv.Routes) != 0 {
		t.Fatalf("route not retired: %+v", srv.Routes)
	}
}

func TestRenderOnDemandTLS(t *testing.T) {
	g := New(WithAskEndpoint("http://localhost:2099/ask"))
	g.Restore([]Route{{Hostname: "a.wc.local", BackendAddr: "10.0.0.5:8080", Kind: Live}})
	cfg := g.render()

	if cfg.Apps.TLS == nil {
		t.Fatal("expected tls beam with on-demand")
	}
	od := cfg.Apps.TLS.Automation.OnDemand
	if od == nil || od.Permission.Module != "http" || od.Permission.Endpoint != "http://localhost:2099/ask" {
		t.Fatalf("on_demand permission wrong: %+v", od)
	}
	pols := cfg.Apps.TLS.Automation.Policies
	if len(pols) != 1 || !pols[0].OnDemand {
		t.Fatalf("expected one on_demand:true policy, got %+v", pols)
	}
	if ah := cfg.Apps.HTTP.Servers["beamhall"].AutomaticHTTPS; ah == nil || !ah.DisableRedirects || ah.Disable {
		t.Fatalf("automatic_https = %+v (want disable_redirects only)", ah)
	}
}

func TestRenderInternalTLS(t *testing.T) {
	g := New(WithAskEndpoint("http://localhost:2099/ask"), WithInternalTLS())
	g.Restore([]Route{{Hostname: "a.beamhall.internal", BackendAddr: "10.0.0.5:8080", Kind: Live}})
	cfg := g.render()
	if cfg.Apps.TLS == nil {
		t.Fatal("expected tls app")
	}
	pols := cfg.Apps.TLS.Automation.Policies
	if len(pols) != 1 || !pols[0].OnDemand {
		t.Fatalf("expected one on_demand policy, got %+v", pols)
	}
	if len(pols[0].Issuers) != 1 || pols[0].Issuers[0].Module != "internal" {
		t.Fatalf("expected internal issuer, got %+v", pols[0].Issuers)
	}
	if cfg.Apps.PKI == nil || cfg.Apps.PKI.CertificateAuthorities["local"].RootCommonName != "Beamhall Internal Root CA" {
		t.Fatalf("expected Beamhall-branded local CA, got %+v", cfg.Apps.PKI)
	}
	// on-demand gating must still be present (ask endpoint).
	if od := cfg.Apps.TLS.Automation.OnDemand; od == nil || od.Permission.Endpoint != "http://localhost:2099/ask" {
		t.Fatalf("on_demand permission missing/wrong: %+v", od)
	}
}

func TestRenderWithoutTLS(t *testing.T) {
	g := New(WithoutTLS())
	cfg := g.render()
	if cfg.Apps.TLS != nil {
		t.Fatal("WithoutTLS should omit the tls beam")
	}
	if ah := cfg.Apps.HTTP.Servers["beamhall"].AutomaticHTTPS; ah == nil || !ah.Disable {
		t.Fatalf("automatic_https = %+v (want disable:true)", ah)
	}
}

func TestAskHandler(t *testing.T) {
	g := New()
	g.Restore([]Route{{Hostname: "known.wc.local", BackendAddr: "10.0.0.9:8080"}})
	h := g.AskHandler()

	for _, tc := range []struct {
		domain string
		want   int
	}{
		{"known.wc.local", http.StatusOK},
		{"evil.example.com", http.StatusForbidden},
		{"", http.StatusForbidden},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/ask?domain="+tc.domain, nil)
		h.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("ask domain=%q: got %d want %d", tc.domain, rec.Code, tc.want)
		}
	}
}

func TestSnapshotSorted(t *testing.T) {
	g := New()
	g.Restore([]Route{
		{Hostname: "b.wc.local"}, {Hostname: "a.wc.local"}, {Hostname: "c.wc.local"},
	})
	snap := g.Snapshot()
	if len(snap) != 3 || snap[0].Hostname != "a.wc.local" || snap[2].Hostname != "c.wc.local" {
		t.Fatalf("snapshot not sorted: %+v", snap)
	}
}

func TestRandomPreviewHost(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		host, token := RandomPreviewHost("wc.local")
		if host != token+".preview.wc.local" {
			t.Fatalf("host format: %q (token %q)", host, token)
		}
		if seen[token] {
			t.Fatalf("duplicate token %q", token)
		}
		seen[token] = true
	}
}
