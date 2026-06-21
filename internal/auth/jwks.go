package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// jwksCache fetches and caches the IdP's JSON Web Key Set. Keys are looked up
// by `kid`; an unknown kid triggers a refetch (key rotation) bounded by a
// cooldown so a flood of bad tokens cannot hammer the IdP.
type jwksCache struct {
	url          string // resolved JWKS endpoint; may be empty until lazily discovered
	issuer       string // for lazy OIDC discovery when url is empty
	discoveryURL string
	client       *http.Client

	mu        sync.Mutex
	keys      map[string]any // kid → *rsa.PublicKey | *ecdsa.PublicKey
	lastFetch time.Time
}

// refetchCooldown bounds how often an unknown kid may force a JWKS fetch.
const refetchCooldown = 30 * time.Second

func newJWKSCache(url, issuer, discoveryURL string, client *http.Client) *jwksCache {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &jwksCache{url: url, issuer: issuer, discoveryURL: discoveryURL, client: client, keys: map[string]any{}}
}

// Key returns the public key for kid, refetching the set once if the kid is
// unknown and the cooldown allows.
func (c *jwksCache) Key(ctx context.Context, kid string) (any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if k, ok := c.keys[kid]; ok {
		return k, nil
	}
	if time.Since(c.lastFetch) < refetchCooldown {
		return nil, fmt.Errorf("unknown key id %q (JWKS refresh on cooldown)", kid)
	}
	if err := c.fetchLocked(ctx); err != nil {
		return nil, err
	}
	if k, ok := c.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("unknown key id %q after JWKS refresh", kid)
}

// jwk is the subset of RFC 7517 we accept: RSA and EC signature keys.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	// RSA
	N string `json:"n"`
	E string `json:"e"`
	// EC
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (c *jwksCache) fetchLocked(ctx context.Context) error {
	c.lastFetch = time.Now()
	// Lazily resolve the JWKS endpoint via OIDC discovery if it wasn't known at
	// construction (e.g. the IdP wasn't up yet — a co-located bundled IdP, or an
	// IdP restart). This keeps the appliance bootable when the IdP is briefly
	// unavailable; the first token after the IdP is back resolves it.
	if c.url == "" {
		u, err := discoverJWKS(ctx, c.issuer, c.discoveryURL, c.client)
		if err != nil {
			return err
		}
		c.url = u
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch JWKS %s: %w", c.url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch JWKS %s: HTTP %d", c.url, resp.StatusCode)
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return fmt.Errorf("decode JWKS %s: %w", c.url, err)
	}
	keys := map[string]any{}
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := k.publicKey()
		if err != nil {
			// One malformed key must not poison the whole set.
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return fmt.Errorf("JWKS %s contains no usable signature keys", c.url)
	}
	c.keys = keys
	return nil
}

func (k jwk) publicKey() (any, error) {
	switch k.Kty {
	case "RSA":
		n, err := b64Int(k.N)
		if err != nil {
			return nil, err
		}
		e, err := b64Int(k.E)
		if err != nil {
			return nil, err
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve %q", k.Crv)
		}
		x, err := b64Int(k.X)
		if err != nil {
			return nil, err
		}
		y, err := b64Int(k.Y)
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	default:
		return nil, fmt.Errorf("unsupported key type %q", k.Kty)
	}
}

func b64Int(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}
