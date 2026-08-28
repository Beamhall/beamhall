package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Beamhall/beamhall/internal/domain"
)

// TestTrustedSourceIP is a regression test:
// the audit trail's
// "source IP" must come from the real TCP peer when the request didn't
// arrive via the trusted loopback proxy, and from Caddy's own observed peer
// (the last X-Forwarded-For entry) when it did — never from an untrusted
// client-supplied header taken verbatim.
func TestTrustedSourceIP(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		xff        string
		want       string
	}{
		{
			name:       "direct non-loopback peer ignores a spoofed header",
			remoteAddr: "203.0.113.7:54321",
			xff:        "10.0.0.99",
			want:       "203.0.113.7",
		},
		{
			name:       "direct non-loopback peer, no header at all",
			remoteAddr: "203.0.113.7:54321",
			xff:        "",
			want:       "203.0.113.7",
		},
		{
			name:       "loopback peer (Caddy) trusts the last XFF entry",
			remoteAddr: "127.0.0.1:12345",
			xff:        "198.51.100.5, 127.0.0.1",
			want:       "127.0.0.1",
		},
		{
			name:       "loopback peer, client-prepended spoof still yields Caddy's own appended hop",
			remoteAddr: "127.0.0.1:12345",
			xff:        "10.0.0.99, 203.0.113.7",
			want:       "203.0.113.7",
		},
		{
			name:       "loopback peer with no header falls back to the peer itself",
			remoteAddr: "127.0.0.1:12345",
			xff:        "",
			want:       "127.0.0.1",
		},
		{
			name:       "IPv6 loopback peer",
			remoteAddr: "[::1]:12345",
			xff:        "203.0.113.7",
			want:       "203.0.113.7",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/mcp", nil)
			r.RemoteAddr = c.remoteAddr
			if c.xff != "" {
				r.Header.Set("X-Forwarded-For", c.xff)
			}
			if got := trustedSourceIP(r); got != c.want {
				t.Errorf("trustedSourceIP(remoteAddr=%q, xff=%q) = %q, want %q", c.remoteAddr, c.xff, got, c.want)
			}
		})
	}
}

// TestNormalizeSourceIPRewritesHeaderForDownstream confirms the middleware
// actually overwrites X-Forwarded-For on the request downstream handlers see
// — internal/web and internal/mcp both just read that header as-is, so this
// is what makes their existing code trustworthy without changing either.
func TestNormalizeSourceIPRewritesHeaderForDownstream(t *testing.T) {
	var seen string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("X-Forwarded-For")
	})
	r := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	r.RemoteAddr = "203.0.113.7:54321"
	r.Header.Set("X-Forwarded-For", "10.0.0.99")
	normalizeSourceIP(next).ServeHTTP(httptest.NewRecorder(), r)
	if seen != "203.0.113.7" {
		t.Fatalf("downstream saw X-Forwarded-For = %q, want the real peer 203.0.113.7 (spoofed header not overwritten)", seen)
	}
}

type failingRouteLister struct{ err error }

func (f failingRouteLister) ListRoutesByBeam(ctx context.Context, beamID domain.ID) ([]domain.Route, error) {
	return nil, f.err
}

// TestResolveDeployedURLSurfacesRouteLookupFailure is a regression test: a deploy that succeeded but
// whose subsequent route lookup failed must not be silently reported as a
// blank-URL success — the failure must be logged, and the returned string
// must say so rather than being empty.
func TestResolveDeployedURLSurfacesRouteLookupFailure(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	lookupErr := errors.New("database is closed")

	got := resolveDeployedURL(context.Background(), failingRouteLister{err: lookupErr}, "beam-1", logger)

	if got == "" {
		t.Fatal("route lookup failure reported as a blank-URL success")
	}
	if !strings.Contains(got, "could not be determined") {
		t.Fatalf("returned string does not explain the failure: %q", got)
	}
	if !strings.Contains(logBuf.String(), "database is closed") {
		t.Fatalf("route lookup error was not logged: %q", logBuf.String())
	}
}
