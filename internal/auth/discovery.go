package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// discoveryDoc is the subset of the OIDC discovery document (OpenID Connect
// Discovery 1.0 / RFC 8414) Beamhall needs.
type discoveryDoc struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// discoverJWKS resolves an IdP's JWKS endpoint from its discovery document so
// the operator only has to configure the issuer — the JWKS path differs per IdP
// (Keycloak /protocol/openid-connect/certs, Okta /v1/keys, Entra /discovery/...)
// and OIDC discovery is the one portable way to find it.
//
// discoveryURL may be given explicitly; otherwise it is the issuer's
// .well-known/openid-configuration. The document's `issuer` MUST equal the
// configured issuer (RFC 8414 §3.3) — a mismatch is a misconfiguration or an
// issuer-spoofing attempt, not something to paper over.
func discoverJWKS(ctx context.Context, issuer, discoveryURL string, client *http.Client) (string, error) {
	if discoveryURL == "" {
		discoveryURL = strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch OIDC discovery %s: %w", discoveryURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OIDC discovery %s: HTTP %d", discoveryURL, resp.StatusCode)
	}
	var doc discoveryDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("parse OIDC discovery %s: %w", discoveryURL, err)
	}
	if doc.Issuer != issuer {
		return "", fmt.Errorf("OIDC discovery issuer %q does not match configured issuer %q (copy the issuer from the discovery document verbatim — trailing slashes matter)", doc.Issuer, issuer)
	}
	if doc.JWKSURI == "" {
		return "", fmt.Errorf("OIDC discovery %s has no jwks_uri", discoveryURL)
	}
	return doc.JWKSURI, nil
}
