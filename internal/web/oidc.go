package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// oidcConfig describes the interactive (browser) OIDC relationship for the
// Admin console. It is the same IdP the MCP layer validates tokens from; here
// we run the Authorization Code flow to log an operator in.
type oidcConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string // <base>/admin/callback
	Scopes       []string
	HTTPClient   *http.Client
}

// oidcProvider holds discovered endpoints.
type oidcProvider struct {
	cfg     oidcConfig
	authURL string
	tokURL  string
	jwksURL string
	client  *http.Client
}

// discover fetches the issuer's OIDC metadata (RFC 8414 /
// openid-configuration) for the authorization, token, and JWKS endpoints.
func discover(ctx context.Context, cfg oidcConfig) (*oidcProvider, error) {
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	u := strings.TrimRight(cfg.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery %s: HTTP %d", u, resp.StatusCode)
	}
	var meta struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		JWKSURI               string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, fmt.Errorf("OIDC discovery decode: %w", err)
	}
	if meta.AuthorizationEndpoint == "" || meta.TokenEndpoint == "" || meta.JWKSURI == "" {
		return nil, fmt.Errorf("OIDC discovery %s: incomplete metadata", u)
	}
	return &oidcProvider{cfg: cfg, authURL: meta.AuthorizationEndpoint,
		tokURL: meta.TokenEndpoint, jwksURL: meta.JWKSURI, client: client}, nil
}

// authCodeURL builds the authorization redirect. state ties the callback to
// this browser; redirectURI is derived from the incoming request so the flow
// works behind any proxy. The access token (not the id token) carries the
// scopes the console authorizes on, so we always request admin:it.
func (p *oidcProvider) authCodeURL(state, redirectURI string) string {
	v := url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", p.cfg.ClientID)
	v.Set("redirect_uri", redirectURI)
	v.Set("scope", strings.Join(p.cfg.Scopes, " "))
	v.Set("state", state)
	return p.authURL + "?" + v.Encode()
}

// exchange swaps an authorization code for tokens and returns the raw access
// token (a JWT for our IdPs) — the caller validates it for admin:it and
// extracts the operator's identity. redirectURI must match the one used at
// authorization.
func (p *oidcProvider) exchange(ctx context.Context, code, redirectURI string) (accessToken string, err error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", p.cfg.ClientID)
	form.Set("client_secret", p.cfg.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token exchange: HTTP %d", resp.StatusCode)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", fmt.Errorf("token response decode: %w", err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("token response had no access_token")
	}
	return tok.AccessToken, nil
}
