// Package auth is Beamhall's OAuth 2.1 resource-server layer (PLAN §6):
// token validation at the MCP boundary, authorization in the backplane PEP.
// It validates JWT access tokens — signature against the IdP's JWKS, iss,
// aud == the Beamhall resource URI (confused-deputy defense), exp/nbf — and
// extracts the coarse capability scopes. It is IdP-agnostic: anything that
// publishes an RFC 7517 JWKS and mints RS256/ES256 JWTs works (bundled
// Keycloak, Okta, Entra, ...). Beamhall never issues tokens itself.
package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
)

// Config describes the IdP relationship.
type Config struct {
	// Issuer is the exact `iss` the IdP mints (its RFC 8414 issuer
	// identifier).
	Issuer string
	// Audience is the Beamhall resource URI; `aud` must contain it. This is
	// what stops a token minted for another service being replayed here.
	Audience string
	// JWKSURL is the IdP's key-set endpoint. Optional when the issuer supports
	// OIDC discovery (the common case): leave it empty and NewVerifier resolves
	// jwks_uri from the discovery document. Set it to pin a specific endpoint or
	// for an IdP without a discovery doc.
	JWKSURL string
	// DiscoveryURL overrides where the OIDC discovery document is fetched from.
	// Empty means the standard <issuer>/.well-known/openid-configuration. Only
	// consulted when JWKSURL is empty.
	DiscoveryURL string
	// Algorithms whitelists JWS algs; empty means RS256 + ES256. `none` and
	// HMAC are never accepted (a shared-secret alg would let anyone who can
	// read the config mint tokens).
	Algorithms []string
	// Leeway absorbs IdP/appliance clock skew on exp/nbf (default 30s).
	Leeway time.Duration
	// HTTPClient overrides the JWKS fetch client (tests).
	HTTPClient *http.Client
}

// Extra* are the keys of the claims the verifier copies into TokenInfo.Extra
// for the MCP layer (actor identity resolution + audit correlation).
const (
	ExtraIssuer  = "iss"
	ExtraSubject = "sub"
	ExtraJTI     = "jti"
	ExtraEmail   = "email"
)

// Verifier validates bearer tokens. Its Verify method satisfies the MCP
// SDK's auth.TokenVerifier, so it plugs straight into RequireBearerToken.
type Verifier struct {
	cfg    Config
	parser *jwt.Parser
	jwks   *jwksCache
}

// NewVerifier builds a Verifier for one IdP. When JWKSURL is empty it resolves
// the IdP's JWKS endpoint via OIDC discovery (a network call at construction,
// so a misconfigured/unreachable IdP fails the boot loudly rather than every
// request later).
func NewVerifier(cfg Config) (*Verifier, error) {
	if cfg.Issuer == "" || cfg.Audience == "" {
		return nil, fmt.Errorf("auth config requires issuer and audience")
	}
	if cfg.JWKSURL == "" {
		// Best-effort eager discovery so a healthy IdP is resolved immediately and
		// misconfiguration is visible early. On failure we do NOT fail boot — the
		// IdP may simply not be up yet (a co-located bundled IdP starting
		// alongside us); the JWKS cache retries discovery lazily on first token.
		if jwksURL, err := discoverJWKS(context.Background(), cfg.Issuer, cfg.DiscoveryURL, cfg.HTTPClient); err == nil {
			cfg.JWKSURL = jwksURL
		}
	}
	if len(cfg.Algorithms) == 0 {
		cfg.Algorithms = []string{"RS256", "ES256"}
	}
	for _, alg := range cfg.Algorithms {
		if strings.HasPrefix(strings.ToUpper(alg), "HS") || strings.EqualFold(alg, "none") {
			return nil, fmt.Errorf("symmetric/none JWS algorithm %q is not allowed", alg)
		}
	}
	if cfg.Leeway == 0 {
		cfg.Leeway = 30 * time.Second
	}
	return &Verifier{
		cfg: cfg,
		parser: jwt.NewParser(
			jwt.WithValidMethods(cfg.Algorithms),
			jwt.WithIssuer(cfg.Issuer),
			jwt.WithAudience(cfg.Audience),
			jwt.WithExpirationRequired(),
			jwt.WithLeeway(cfg.Leeway),
		),
		jwks: newJWKSCache(cfg.JWKSURL, cfg.Issuer, cfg.DiscoveryURL, cfg.HTTPClient),
	}, nil
}

// Verify validates one bearer token and maps it to the SDK's TokenInfo.
// Errors wrap sdkauth.ErrInvalidToken so RequireBearerToken answers 401 with
// the proper WWW-Authenticate challenge.
func (v *Verifier) Verify(ctx context.Context, token string, _ *http.Request) (*sdkauth.TokenInfo, error) {
	claims := jwt.MapClaims{}
	_, err := v.parser.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("token has no kid header")
		}
		return v.jwks.Key(ctx, kid)
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", sdkauth.ErrInvalidToken, err)
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, fmt.Errorf("%w: token has no sub claim", sdkauth.ErrInvalidToken)
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return nil, fmt.Errorf("%w: token has no exp claim", sdkauth.ErrInvalidToken)
	}

	info := &sdkauth.TokenInfo{
		Scopes:     scopesOf(claims),
		Expiration: exp.Time,
		// UserID keys the transport's session-hijack defense: every request
		// on one MCP session must present a token for the same principal.
		UserID: v.cfg.Issuer + "|" + sub,
		Extra: map[string]any{
			ExtraIssuer:  v.cfg.Issuer,
			ExtraSubject: sub,
		},
	}
	if jti, _ := claims["jti"].(string); jti != "" {
		info.Extra[ExtraJTI] = jti
	}
	if email, _ := claims["email"].(string); email != "" {
		info.Extra[ExtraEmail] = email
	}
	return info, nil
}

// scopesOf reads granted scopes IdP-agnostically: the RFC 8693 `scope`
// space-separated string (Keycloak, Okta) or the `scp` array (Entra).
func scopesOf(claims jwt.MapClaims) []string {
	if s, ok := claims["scope"].(string); ok {
		return strings.Fields(s)
	}
	if arr, ok := claims["scp"].([]any); ok {
		out := make([]string, 0, len(arr))
		for _, v := range arr {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// CheckOrigin is the DNS-rebinding defense (PLAN §6): browser-originated
// requests must carry an Origin from the allowlist. Requests without an
// Origin header (CLI MCP clients, curl) pass — the header is the browser's
// statement of provenance, and its absence means no rebinding vector.
func CheckOrigin(allowedHosts []string, next http.Handler) http.Handler {
	allowed := map[string]bool{}
	for _, h := range allowedHosts {
		allowed[strings.ToLower(h)] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" && origin != "null" {
			u, err := url.Parse(origin)
			if err != nil || !allowed[strings.ToLower(u.Hostname())] {
				http.Error(w, "origin not allowed", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
