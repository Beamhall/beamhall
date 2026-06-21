package gateway

import (
	"net/url"
	"regexp"
)

// Typed subset of Caddy v2 JSON config (v2.8+). Only the fields Beamhall sets are
// modeled; everything else is left to Caddy defaults. The on-demand TLS gate uses
// the current `on_demand.permission` http module (the old `ask` string field is
// deprecated/removed).

type caddyConfig struct {
	Admin   *adminCfg `json:"admin,omitempty"`
	Logging *logCfg   `json:"logging,omitempty"`
	Apps    appsCfg   `json:"apps"`
}

type adminCfg struct {
	Listen string `json:"listen"`
}

type logCfg struct {
	Logs map[string]logLevel `json:"logs"`
}

type logLevel struct {
	Level string `json:"level"`
}

type appsCfg struct {
	HTTP httpApp `json:"http"`
	TLS  *tlsApp `json:"tls,omitempty"`
	PKI  *pkiApp `json:"pki,omitempty"`
}

// pkiApp configures Caddy's certificate authorities. Beamhall overrides the
// built-in "local" CA's display/common names so the internal root installed on
// client workstations reads as Beamhall, not the Caddy default.
type pkiApp struct {
	CertificateAuthorities map[string]caCfg `json:"certificate_authorities"`
}

type caCfg struct {
	Name                   string `json:"name,omitempty"`
	RootCommonName         string `json:"root_common_name,omitempty"`
	IntermediateCommonName string `json:"intermediate_common_name,omitempty"`
}

type httpApp struct {
	Servers map[string]serverCfg `json:"servers"`
}

type serverCfg struct {
	Listen         []string   `json:"listen"`
	Routes         []routeCfg `json:"routes"`
	AutomaticHTTPS *autoHTTPS `json:"automatic_https,omitempty"`
}

type autoHTTPS struct {
	Disable          bool `json:"disable,omitempty"`
	DisableRedirects bool `json:"disable_redirects,omitempty"`
}

type routeCfg struct {
	ID       string      `json:"@id,omitempty"`
	Match    []matchCfg  `json:"match"`
	Handle   []handleCfg `json:"handle"`
	Terminal bool        `json:"terminal,omitempty"`
}

type matchCfg struct {
	Host []string `json:"host"`
}

type handleCfg struct {
	Handler   string        `json:"handler"`
	Upstreams []upstreamCfg `json:"upstreams"`
}

type upstreamCfg struct {
	Dial string `json:"dial"`
}

type tlsApp struct {
	Automation automationCfg `json:"automation"`
}

type automationCfg struct {
	OnDemand *onDemandCfg `json:"on_demand,omitempty"`
	Policies []policyCfg  `json:"policies,omitempty"`
}

type onDemandCfg struct {
	Permission permissionCfg `json:"permission"`
}

type permissionCfg struct {
	Module   string `json:"module"`   // "http"
	Endpoint string `json:"endpoint"` // ask URL; Caddy appends ?domain=<host>
}

type policyCfg struct {
	OnDemand bool        `json:"on_demand"`
	Issuers  []issuerCfg `json:"issuers,omitempty"`
}

// issuerCfg selects a Caddy certificate issuer. Module "internal" mints certs
// from Caddy's built-in local CA — used for internal domains (*.beamhall.internal)
// that cannot obtain public ACME certificates.
type issuerCfg struct {
	Module string `json:"module"`
}

var idSanitizer = regexp.MustCompile(`[^a-zA-Z0-9_.-]`)

func sanitizeID(s string) string { return idSanitizer.ReplaceAllString(s, "_") }

// adminListen derives Caddy's admin "listen" address (host:port) from the admin
// URL so a POST /load keeps the Admin API alive.
func adminListen(adminURL string) string {
	if u, err := url.Parse(adminURL); err == nil && u.Host != "" {
		return u.Host
	}
	return "localhost:2019"
}
