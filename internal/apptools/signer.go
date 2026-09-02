package apptools

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AssertionTTL bounds how long a minted assertion is honored. Assertions are
// minted per request and used immediately; a short window is the replay
// defense (paired with jti and the per-beam audience).
const AssertionTTL = 60 * time.Second

// ProbeSubject is the `sub` of the capability probe the orchestrator runs at
// workload start — a reserved name no identity can collide with (identity IDs
// are UUID-shaped, and ":" is outside the tool/slug alphabets).
const ProbeSubject = "beamhall:probe"

// Caller types carried in the `caller_type` claim, so an app can tell a
// person's agent from another beam (or the capability probe) without parsing
// the subject's shape. Apps that authorize on identity should branch on it.
const (
	CallerUser  = "user"
	CallerBeam  = "beam"
	CallerProbe = "probe"
)

// Assertion is what the backplane attests about one brokered request.
type Assertion struct {
	Subject    string
	CallerType string // CallerUser | CallerBeam | CallerProbe; "" defaults to CallerUser
	Email      string
	Groups     []string
	Audience   string // the target beam's ID
	Channel    string // "live" | "preview"
	Tool       string // invoked tool name; "" for a menu fetch or probe
}

// Signer mints ES256 assertions under a stable kid. The private key lives
// vault-sealed in the control-plane store (see LoadOrCreateSigner) — it must
// survive restarts AND restores, because every deployed workload verifies
// against a JWKS injected at deploy time.
type Signer struct {
	key    *ecdsa.PrivateKey
	kid    string
	issuer string
}

// GenerateKey mints a fresh P-256 assertion-signing key.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// NewSigner wraps an existing key. issuer is the appliance's resource URI —
// the same string echoed in every injected assertion.json, so apps compare
// rather than guess.
func NewSigner(key *ecdsa.PrivateKey, issuer string) (*Signer, error) {
	if key == nil || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("assertion signer requires a P-256 key")
	}
	if issuer == "" {
		return nil, fmt.Errorf("assertion signer requires an issuer")
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(pub)
	return &Signer{key: key, kid: hex.EncodeToString(sum[:8]), issuer: issuer}, nil
}

// Issuer returns the assertion issuer string.
func (s *Signer) Issuer() string { return s.issuer }

// Mint signs one assertion.
func (s *Signer) Mint(a Assertion) (string, error) {
	jti := make([]byte, 12)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	groups := a.Groups
	if groups == nil {
		groups = []string{}
	}
	ct := a.CallerType
	if ct == "" {
		ct = CallerUser
	}
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": s.issuer, "aud": a.Audience, "sub": a.Subject,
		"caller_type": ct, "email": a.Email, "groups": groups,
		"channel": a.Channel, "tool": a.Tool,
		"jti": hex.EncodeToString(jti),
		"iat": now.Unix(), "exp": now.Add(AssertionTTL).Unix(),
	})
	tok.Header["kid"] = s.kid
	return tok.SignedString(s.key)
}

// JWKS returns the public key set apps verify against.
func (s *Signer) JWKS() []byte {
	x := make([]byte, 32)
	y := make([]byte, 32)
	s.key.PublicKey.X.FillBytes(x)
	s.key.PublicKey.Y.FillBytes(y)
	b, _ := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "kid": s.kid, "use": "sig", "alg": "ES256",
		"x": base64.RawURLEncoding.EncodeToString(x),
		"y": base64.RawURLEncoding.EncodeToString(y),
	}}})
	return b
}

// BindingJSON renders the per-beam verification file mounted at MountPath.
func (s *Signer) BindingJSON(beamID string) []byte {
	b, _ := json.Marshal(map[string]any{
		"version":  Version,
		"issuer":   s.issuer,
		"audience": beamID,
		"jwks":     json.RawMessage(s.JWKS()),
	})
	return b
}

// KeyStore is the slice of the control-plane store the signer needs.
type KeyStore interface {
	GetControlKey(ctx context.Context, kind string) ([]byte, bool, error)
	PutControlKey(ctx context.Context, kind string, sealed []byte) error
}

// Sealer is the slice of the vault the signer needs.
type Sealer interface {
	Seal(plain []byte) ([]byte, error)
	Open(ct []byte) ([]byte, error)
}

const keyKind = "app_assertion_es256"

// LoadOrCreateSigner loads the sealed assertion key from the store, or mints
// and persists one on first boot. Returns created=true when a key was minted.
func LoadOrCreateSigner(ctx context.Context, ks KeyStore, sealer Sealer, issuer string) (*Signer, bool, error) {
	sealed, ok, err := ks.GetControlKey(ctx, keyKind)
	if err != nil {
		return nil, false, err
	}
	if ok {
		s, err := signerFromSealed(sealed, sealer, issuer)
		return s, false, err
	}
	key, err := GenerateKey()
	if err != nil {
		return nil, false, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, false, err
	}
	ct, err := sealer.Seal(der)
	if err != nil {
		return nil, false, err
	}
	if err := ks.PutControlKey(ctx, keyKind, ct); err != nil {
		// Lost a race to another writer: use whatever won.
		if sealed, ok, gerr := ks.GetControlKey(ctx, keyKind); gerr == nil && ok {
			s, serr := signerFromSealed(sealed, sealer, issuer)
			return s, false, serr
		}
		return nil, false, err
	}
	s, err := NewSigner(key, issuer)
	return s, true, err
}

func signerFromSealed(sealed []byte, sealer Sealer, issuer string) (*Signer, error) {
	der, err := sealer.Open(sealed)
	if err != nil {
		return nil, fmt.Errorf("unseal assertion key: %w", err)
	}
	key, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse assertion key: %w", err)
	}
	return NewSigner(key, issuer)
}
