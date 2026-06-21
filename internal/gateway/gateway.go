// Package gateway programs a single Caddy instance (via its Admin API) to route
// preview and live beam URLs to backend containers. The backplane is the single
// route writer: it Upserts a route when a beam starts/resumes/promotes and
// Retires it on pause/destroy. The full desired route set is reconciled to Caddy
// with an atomic POST /load on every change (the gateway owns Caddy's entire
// config), and the in-memory set is the source of truth rebuilt on restart from
// persisted Routes. See docs/PLAN.md §5.6.
//
//   - preview: <random>.preview.<base>  (a fresh random host on every resume)
//   - live:    <beam>.<beamhall>.<base>  (stable)
//
// On-demand TLS is gated by an ask/permission endpoint (AskHandler): Caddy only
// issues a certificate for a hostname the backplane currently routes, which
// prevents ACME-abuse via unbounded unknown-host handshakes.
package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"sync"
)

// RouteKind distinguishes ephemeral preview routes from stable live routes.
type RouteKind string

const (
	Preview RouteKind = "preview"
	Live    RouteKind = "live"
)

// Route is a hostname -> backend mapping the gateway serves.
type Route struct {
	Hostname    string
	BackendAddr string // container addr:port on the per-Beamhall bridge, e.g. 172.18.0.2:8080
	Kind        RouteKind
}

// Gateway reconciles routes into a Caddy instance via its Admin API.
type Gateway struct {
	adminURL    string
	serverName  string
	listen      []string
	askEndpoint string
	disableTLS  bool
	internalTLS bool
	hc          *http.Client
	log         *slog.Logger

	mu     sync.Mutex
	routes map[string]Route

	// static routes are always present in the rendered config and the on-demand
	// TLS allowlist — used for bundled infrastructure the gateway fronts (e.g.
	// the bundled Keycloak IdP), not beam traffic. Set at construction.
	static map[string]Route
}

// Option configures a Gateway.
type Option func(*Gateway)

func WithAdminURL(u string) Option      { return func(g *Gateway) { g.adminURL = u } }
func WithServerName(n string) Option    { return func(g *Gateway) { g.serverName = n } }
func WithListen(addrs ...string) Option { return func(g *Gateway) { g.listen = addrs } }
func WithAskEndpoint(u string) Option   { return func(g *Gateway) { g.askEndpoint = u } }
func WithLogger(l *slog.Logger) Option  { return func(g *Gateway) { g.log = l } }

// WithoutTLS serves plain HTTP only (no automatic/on-demand HTTPS). Useful for
// internal/offline or test deployments.
func WithoutTLS() Option { return func(g *Gateway) { g.disableTLS = true } }

// WithInternalTLS issues certificates from Caddy's built-in local CA instead of
// public ACME — for internal domains (*.beamhall.internal) that can't get public
// certs. On-demand issuance is still gated by the ask endpoint. Operators install
// the gateway's root CA on client workstations to trust the certs.
func WithInternalTLS() Option { return func(g *Gateway) { g.internalTLS = true } }

// WithStaticRoute fronts a fixed upstream at hostname through the gateway —
// always present in the rendered config and the on-demand TLS allowlist. Used
// for bundled infrastructure (the bundled Keycloak IdP), so it gets the same
// TLS + hostname treatment as beams and survives every route reconcile.
func WithStaticRoute(hostname, backendAddr string) Option {
	return func(g *Gateway) {
		if g.static == nil {
			g.static = make(map[string]Route)
		}
		g.static[hostname] = Route{Hostname: hostname, BackendAddr: backendAddr, Kind: Live}
	}
}

// New builds a Gateway. Caddy must already be running with its Admin API
// reachable at adminURL; Apply (or the first Upsert) pushes the full config.
func New(opts ...Option) *Gateway {
	g := &Gateway{
		adminURL:    "http://localhost:2019",
		serverName:  "beamhall",
		listen:      []string{":80", ":443"},
		askEndpoint: "http://localhost:2099/ask",
		hc:          &http.Client{},
		log:         slog.Default(),
		routes:      make(map[string]Route),
	}
	for _, o := range opts {
		o(g)
	}
	return g
}

// Apply reconciles the current route set into Caddy. Call once on startup (after
// loading persisted routes via Restore) and after any change.
func (g *Gateway) Apply(ctx context.Context) error {
	g.mu.Lock()
	cfg := g.render()
	g.mu.Unlock()
	return g.load(ctx, cfg)
}

// Restore seeds the in-memory route set (e.g. from persisted Routes on boot)
// without touching Caddy; follow with Apply.
func (g *Gateway) Restore(routes []Route) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, r := range routes {
		g.routes[r.Hostname] = r
	}
}

// Upsert adds or replaces a route and reconciles Caddy.
func (g *Gateway) Upsert(ctx context.Context, r Route) error {
	g.mu.Lock()
	g.routes[r.Hostname] = r
	cfg := g.render()
	g.mu.Unlock()
	return g.load(ctx, cfg)
}

// Retire removes a route and reconciles Caddy.
func (g *Gateway) Retire(ctx context.Context, hostname string) error {
	g.mu.Lock()
	delete(g.routes, hostname)
	cfg := g.render()
	g.mu.Unlock()
	return g.load(ctx, cfg)
}

// Snapshot returns the current routes, sorted by hostname (for the Admin UI and
// restart rebuild).
func (g *Gateway) Snapshot() []Route {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]Route, 0, len(g.routes))
	for _, r := range g.routes {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	return out
}

// AskHandler authorizes Caddy's on-demand TLS: it permits (200) issuance only
// for a hostname the gateway currently routes, and denies (403) everything else.
// Mount it where askEndpoint points.
func (g *Gateway) AskHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		domain := r.URL.Query().Get("domain")
		g.mu.Lock()
		_, ok := g.routes[domain]
		if !ok {
			_, ok = g.static[domain]
		}
		g.mu.Unlock()
		if ok {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Error(w, "unknown host", http.StatusForbidden)
	})
}

// load POSTs the full config to Caddy's /load endpoint (atomic replace).
func (g *Gateway) load(ctx context.Context, cfg *caddyConfig) error {
	body, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal caddy config: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.adminURL+"/load", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.hc.Do(req)
	if err != nil {
		return fmt.Errorf("caddy /load: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("caddy /load status %d: %s", resp.StatusCode, bytes.TrimSpace(b))
	}
	return nil
}

// render builds the full Caddy config from the current route set plus any static
// routes (bundled infra). Caller holds mu.
func (g *Gateway) render() *caddyConfig {
	merged := make(map[string]Route, len(g.routes)+len(g.static))
	for h, r := range g.static {
		merged[h] = r
	}
	for h, r := range g.routes { // beam routes win on a hostname clash
		merged[h] = r
	}
	hosts := make([]string, 0, len(merged))
	for h := range merged {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	routes := make([]routeCfg, 0, len(hosts))
	for _, h := range hosts {
		r := merged[h]
		routes = append(routes, routeCfg{
			ID:    "bh_" + sanitizeID(h),
			Match: []matchCfg{{Host: []string{h}}},
			Handle: []handleCfg{{
				Handler:   "reverse_proxy",
				Upstreams: []upstreamCfg{{Dial: r.BackendAddr}},
			}},
			Terminal: true,
		})
	}

	srv := serverCfg{Listen: g.listen, Routes: routes}
	if g.disableTLS {
		srv.AutomaticHTTPS = &autoHTTPS{Disable: true}
	} else {
		srv.AutomaticHTTPS = &autoHTTPS{DisableRedirects: true}
	}

	cfg := &caddyConfig{
		Admin:   &adminCfg{Listen: adminListen(g.adminURL)},
		Logging: &logCfg{Logs: map[string]logLevel{"default": {Level: "ERROR"}}},
		Apps: appsCfg{
			HTTP: httpApp{Servers: map[string]serverCfg{g.serverName: srv}},
		},
	}
	if !g.disableTLS {
		policy := policyCfg{OnDemand: true}
		if g.internalTLS {
			// Mint from Caddy's local CA (internal domain, no public ACME), and
			// brand that CA as Beamhall so the root installed on workstations
			// reads as Beamhall rather than the Caddy default.
			policy.Issuers = []issuerCfg{{Module: "internal"}}
			cfg.Apps.PKI = &pkiApp{CertificateAuthorities: map[string]caCfg{
				"local": {
					Name:                   "Beamhall Internal Authority",
					RootCommonName:         "Beamhall Internal Root CA",
					IntermediateCommonName: "Beamhall Internal Intermediate CA",
				},
			}}
		}
		cfg.Apps.TLS = &tlsApp{Automation: automationCfg{
			OnDemand: &onDemandCfg{Permission: permissionCfg{Module: "http", Endpoint: g.askEndpoint}},
			Policies: []policyCfg{policy},
		}}
	}
	return cfg
}

// RandomPreviewHost returns a fresh random preview hostname under base and the
// token used (regenerated on every resume). Uses crypto/rand.
func RandomPreviewHost(base string) (host, token string) {
	token = randomToken(8)
	return token + ".preview." + base, token
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// rand.Read never fails on supported platforms; fall back defensively.
		return "x" + hex.EncodeToString(b)
	}
	return hex.EncodeToString(b)
}
