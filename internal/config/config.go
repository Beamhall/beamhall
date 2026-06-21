// Package config loads beamhalld configuration from environment variables with
// sane appliance defaults. Kept dependency-free; richer validation lands with
// the install/preflight work.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config is the beamhalld runtime configuration.
type Config struct {
	// HTTPAddr is the single inbound listener for the backplane API, the Admin
	// UI, and the MCP /mcp endpoint.
	HTTPAddr string
	// BaseDomain anchors preview (*.preview.<base>) and live
	// (*.<beamhall>.<base>) hostnames.
	BaseDomain string
	// DataDir holds the SQLite control-plane store, the sealed secret root,
	// the managed git repos, and the driver's secret tmpfs staging.
	DataDir string
	// SecretKeyFile, when set, is the path to the age root key supplied
	// out-of-band (systemd LoadCredential / KMS). It is loaded read-only and
	// never generated — production must set this. Empty falls back to
	// generate-if-absent at <DataDir>/secret.key (dev/lab only).
	SecretKeyFile string
	// LogLevel is one of debug|info|warn|error.
	LogLevel string

	// AuditRetentionDays, when > 0, bounds the append-only audit log: the daemon
	// prunes events older than this many days on boot and once daily, recording
	// an integrity checkpoint so the surviving chain still verifies. 0 (default)
	// keeps the full log. Manual one-off pruning is `beamhalld admin prune-audit`.
	AuditRetentionDays int

	// OAuth resource-server settings (PLAN §6). The issuer is required for the
	// MCP endpoint to serve — there is no insecure mode.
	// OAuthIssuer is the IdP's issuer identifier (`iss`).
	OAuthIssuer string
	// OAuthAudience is the Beamhall resource URI tokens must carry in `aud`.
	// Defaults to https://<base-domain>/mcp.
	OAuthAudience string
	// OAuthJWKSURL is the IdP's JWKS endpoint. Optional: when empty it is
	// resolved from the issuer's OIDC discovery document.
	OAuthJWKSURL string
	// OAuthDiscoveryURL overrides the OIDC discovery endpoint (default
	// <issuer>/.well-known/openid-configuration). Only used when JWKS is empty.
	OAuthDiscoveryURL string

	// Admin console (OIDC Authorization Code flow). Empty AdminClientID
	// disables /admin. The console requires the admin:it scope.
	AdminClientID     string
	AdminClientSecret string
	// AdminScopes requested at login (must include admin:it + openid).
	AdminScopes []string
	// AdminBaseURL is the appliance's externally-reachable base (the OIDC
	// redirect is <base>/admin/callback). Defaults to https://<base-domain>.
	AdminBaseURL string

	// CaddyAdminURL is the gateway's Admin API.
	CaddyAdminURL string
	// GatewayListen are the Caddy listener addresses for beam routes.
	GatewayListen []string
	// BundledIDPUpstream, when set (host:port), fronts a bundled Keycloak IdP
	// through the gateway at idp.<base-domain> so browser-based OIDC flows work.
	// Empty unless the bundled-IdP pilot setup is installed.
	BundledIDPUpstream string
	// GatewayTLS disables on-demand TLS when false (offline HTTP mode).
	GatewayTLS bool
	// GatewayTLSInternal issues certs from Caddy's built-in local CA instead of
	// public ACME — for internal domains (*.beamhall.internal). Set via
	// BEAMHALL_GATEWAY_TLS=internal. Operators install the gateway root CA on clients.
	GatewayTLSInternal bool

	// PromoteApproval enables the explicit IT-approval gate (PLAN §10): when on,
	// promote_to_live records a pending request that a different IT operator must
	// approve (four-eyes) before the beam goes live. Off = promote immediately.
	PromoteApproval bool

	// Build pipeline (PLAN §4): pack on the dedicated non-remapped build
	// daemon, publishing to the internal registry.
	PackBin         string
	BuildDockerHost string
	CNBBuilder      string
	RegistryAddr    string
	// PackPullPolicy / CNBRunImage support air-gapped builds: set pull policy to
	// "if-not-present" and point the builder/run image at internal-registry
	// mirrors loaded by scripts/airgap-load.sh (see docs/air-gapped.md).
	PackPullPolicy string
	CNBRunImage    string

	// Managed Postgres (create_database). Empty PGAdminDSN disables the tool.
	PGAdminDSN string
	PGBeamHost string

	// EgressAlwaysDeny is a comma-separated list of extra CIDRs denied for
	// every beamhall regardless of allowlists (host IP, management subnet) —
	// merged with the built-in link-local/metadata set.
	EgressAlwaysDeny []string
}

// Load reads configuration from the environment, applying defaults.
func Load() (Config, error) {
	c := Config{
		HTTPAddr:      envOr("BEAMHALL_HTTP_ADDR", ":8443"),
		BaseDomain:    envOr("BEAMHALL_BASE_DOMAIN", "beamhall.internal"),
		DataDir:       envOr("BEAMHALL_DATA_DIR", "/var/lib/beamhall"),
		LogLevel:      strings.ToLower(envOr("BEAMHALL_LOG_LEVEL", "info")),
		SecretKeyFile: os.Getenv("BEAMHALL_SECRET_KEY_FILE"),

		AuditRetentionDays: envInt("BEAMHALL_AUDIT_RETENTION_DAYS", 0),

		OAuthIssuer:       os.Getenv("BEAMHALL_OAUTH_ISSUER"),
		OAuthJWKSURL:      os.Getenv("BEAMHALL_OAUTH_JWKS_URL"),
		OAuthDiscoveryURL: os.Getenv("BEAMHALL_OAUTH_DISCOVERY_URL"),

		AdminClientID:     os.Getenv("BEAMHALL_ADMIN_CLIENT_ID"),
		AdminClientSecret: os.Getenv("BEAMHALL_ADMIN_CLIENT_SECRET"),

		CaddyAdminURL:      envOr("BEAMHALL_CADDY_ADMIN", "http://127.0.0.1:2019"),
		GatewayTLS:         envOr("BEAMHALL_GATEWAY_TLS", "on") != "off",
		GatewayTLSInternal: envOr("BEAMHALL_GATEWAY_TLS", "on") == "internal",
		BundledIDPUpstream: os.Getenv("BEAMHALL_BUNDLED_IDP_UPSTREAM"),
		PromoteApproval:    envOr("BEAMHALL_PROMOTE_APPROVAL", "off") == "on",

		PackBin:         envOr("BEAMHALL_PACK_BIN", "pack"),
		BuildDockerHost: envOr("BEAMHALL_BUILD_DOCKER_HOST", "unix:///run/docker-build.sock"),
		CNBBuilder:      envOr("BEAMHALL_CNB_BUILDER", "paketobuildpacks/builder-jammy-base:latest"),
		RegistryAddr:    envOr("BEAMHALL_REGISTRY", "127.0.0.1:5000"),
		PackPullPolicy:  os.Getenv("BEAMHALL_PACK_PULL_POLICY"),
		CNBRunImage:     os.Getenv("BEAMHALL_CNB_RUN_IMAGE"),

		PGAdminDSN: os.Getenv("BEAMHALL_PG_ADMIN_DSN"),
		PGBeamHost: envOr("BEAMHALL_PG_BEAM_HOST", "bh-postgres"),
	}
	c.OAuthAudience = envOr("BEAMHALL_OAUTH_AUDIENCE", "https://"+c.BaseDomain+"/mcp")
	for _, sc := range strings.Fields(envOr("BEAMHALL_ADMIN_SCOPES", "openid admin:it")) {
		c.AdminScopes = append(c.AdminScopes, sc)
	}
	c.AdminBaseURL = envOr("BEAMHALL_ADMIN_BASE_URL", "https://"+c.BaseDomain)
	for _, addr := range strings.Split(envOr("BEAMHALL_GATEWAY_LISTEN", ":80,:443"), ",") {
		if addr = strings.TrimSpace(addr); addr != "" {
			c.GatewayListen = append(c.GatewayListen, addr)
		}
	}
	if v := os.Getenv("BEAMHALL_EGRESS_ALWAYS_DENY"); v != "" {
		for _, cidr := range strings.Split(v, ",") {
			if cidr = strings.TrimSpace(cidr); cidr != "" {
				c.EgressAlwaysDeny = append(c.EgressAlwaysDeny, cidr)
			}
		}
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return Config{}, fmt.Errorf("invalid BEAMHALL_LOG_LEVEL %q (want debug|info|warn|error)", c.LogLevel)
	}
	if c.HTTPAddr == "" {
		return Config{}, fmt.Errorf("BEAMHALL_HTTP_ADDR must not be empty")
	}
	return c, nil
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return def
}
