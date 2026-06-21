package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
)

// testIdP is a minimal in-process IdP: keys + a JWKS endpoint + token minting.
type testIdP struct {
	t       *testing.T
	rsaKey  *rsa.PrivateKey
	ecKey   *ecdsa.PrivateKey
	srv     *httptest.Server
	fetches atomic.Int64
	// hidden keys are signed with but not published (rotation simulation)
	hideRSA atomic.Bool
}

func newTestIdP(t *testing.T) *testIdP {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	idp := &testIdP{t: t, rsaKey: rsaKey, ecKey: ecKey}
	idp.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idp.fetches.Add(1)
		b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
		keys := []map[string]string{}
		if !idp.hideRSA.Load() {
			pub := &idp.rsaKey.PublicKey
			keys = append(keys, map[string]string{
				"kty": "RSA", "kid": "rsa-1", "use": "sig",
				"n": b64(pub.N.Bytes()), "e": b64(big.NewInt(int64(pub.E)).Bytes()),
			})
		}
		ec := &idp.ecKey.PublicKey
		keys = append(keys, map[string]string{
			"kty": "EC", "kid": "ec-1", "use": "sig", "crv": "P-256",
			"x": b64(ec.X.FillBytes(make([]byte, 32))), "y": b64(ec.Y.FillBytes(make([]byte, 32))),
		})
		json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	}))
	t.Cleanup(idp.srv.Close)
	return idp
}

const (
	testIssuer   = "https://idp.test"
	testAudience = "https://beamhall.test/mcp"
)

// mint signs a token; mutate tweaks the default-good claims.
func (i *testIdP) mint(kid string, mutate func(jwt.MapClaims)) string {
	i.t.Helper()
	claims := jwt.MapClaims{
		"iss":   testIssuer,
		"aud":   testAudience,
		"sub":   "user-1",
		"jti":   "jti-1",
		"email": "dev@acme.test",
		"scope": "beams:write beams:deploy secrets:write",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	}
	if mutate != nil {
		mutate(claims)
	}
	var tok *jwt.Token
	var key any
	switch kid {
	case "rsa-1", "rsa-hidden":
		tok = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		key = i.rsaKey
	case "ec-1":
		tok = jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		key = i.ecKey
	default:
		i.t.Fatalf("unknown kid %q", kid)
	}
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		i.t.Fatal(err)
	}
	return s
}

func newVerifier(t *testing.T, idp *testIdP) *Verifier {
	t.Helper()
	v, err := NewVerifier(Config{
		Issuer:   testIssuer,
		Audience: testAudience,
		JWKSURL:  idp.srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerifyValidToken(t *testing.T) {
	idp := newTestIdP(t)
	v := newVerifier(t, idp)
	for _, kid := range []string{"rsa-1", "ec-1"} {
		info, err := v.Verify(context.Background(), idp.mint(kid, nil), nil)
		if err != nil {
			t.Fatalf("valid %s token rejected: %v", kid, err)
		}
		if info.UserID != testIssuer+"|user-1" {
			t.Errorf("UserID = %q", info.UserID)
		}
		if !HasScope(info.Scopes, ScopeBeamsDeploy) || HasScope(info.Scopes, ScopeAdminIT) {
			t.Errorf("scopes = %v", info.Scopes)
		}
		if info.Extra[ExtraSubject] != "user-1" || info.Extra[ExtraJTI] != "jti-1" || info.Extra[ExtraEmail] != "dev@acme.test" {
			t.Errorf("extra = %v", info.Extra)
		}
	}
}

func TestVerifyRejections(t *testing.T) {
	idp := newTestIdP(t)
	v := newVerifier(t, idp)
	cases := []struct {
		name   string
		mutate func(jwt.MapClaims)
	}{
		{"wrong issuer", func(c jwt.MapClaims) { c["iss"] = "https://evil.test" }},
		{"wrong audience", func(c jwt.MapClaims) { c["aud"] = "https://other-api.test" }},
		{"expired", func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() }},
		{"not yet valid", func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(time.Hour).Unix() }},
		{"no exp", func(c jwt.MapClaims) { delete(c, "exp") }},
		{"no sub", func(c jwt.MapClaims) { delete(c, "sub") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Verify(context.Background(), idp.mint("rsa-1", tc.mutate), nil)
			if err == nil {
				t.Fatal("token accepted")
			}
		})
	}
}

func TestVerifyRejectsGarbageAndForgedAlg(t *testing.T) {
	idp := newTestIdP(t)
	v := newVerifier(t, idp)

	if _, err := v.Verify(context.Background(), "not.a.jwt", nil); err == nil {
		t.Fatal("garbage accepted")
	}

	// alg=none forgery.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"rsa-1"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(
		`{"iss":"` + testIssuer + `","aud":"` + testAudience + `","sub":"u","exp":` +
			"9999999999" + `}`))
	if _, err := v.Verify(context.Background(), header+"."+payload+".", nil); err == nil {
		t.Fatal("alg=none accepted")
	}

	// HS256 with a guessable "key" must be rejected by the alg whitelist
	// before any key lookup.
	hs := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": testIssuer, "aud": testAudience, "sub": "u",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	hs.Header["kid"] = "rsa-1"
	signed, err := hs.SignedString([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), signed, nil); err == nil {
		t.Fatal("HS256 accepted")
	}
}

func TestVerifierConfigRejectsSymmetricAlgs(t *testing.T) {
	for _, alg := range []string{"HS256", "none"} {
		_, err := NewVerifier(Config{
			Issuer: testIssuer, Audience: testAudience, JWKSURL: "http://x",
			Algorithms: []string{alg},
		})
		if err == nil {
			t.Errorf("config with alg %s accepted", alg)
		}
	}
}

func TestVerifyErrorWrapsSDKInvalidToken(t *testing.T) {
	idp := newTestIdP(t)
	v := newVerifier(t, idp)
	_, err := v.Verify(context.Background(), idp.mint("rsa-1", func(c jwt.MapClaims) {
		c["aud"] = "https://other.test"
	}), nil)
	if err == nil || !strings.Contains(err.Error(), sdkauth.ErrInvalidToken.Error()) {
		t.Fatalf("error %v does not wrap auth.ErrInvalidToken (RequireBearerToken needs it for the 401)", err)
	}
}

func TestJWKSKeyRotationRefetch(t *testing.T) {
	idp := newTestIdP(t)
	v := newVerifier(t, idp)

	// Prime the cache with the EC key only (RSA hidden).
	idp.hideRSA.Store(true)
	if _, err := v.Verify(context.Background(), idp.mint("ec-1", nil), nil); err != nil {
		t.Fatalf("prime: %v", err)
	}

	// "Rotate": the RSA key appears in the set; an unknown kid must refetch.
	idp.hideRSA.Store(false)
	v.jwks.lastFetch = time.Time{} // age the cache past the cooldown
	if _, err := v.Verify(context.Background(), idp.mint("rsa-1", nil), nil); err != nil {
		t.Fatalf("token with newly published kid rejected: %v", err)
	}

	// Unknown kid inside the cooldown must NOT refetch (DoS bound).
	before := idp.fetches.Load()
	tok := idp.mint("rsa-1", nil)
	parts := strings.SplitN(tok, ".", 2)
	hdr := `{"alg":"RS256","kid":"ghost"}`
	forged := base64.RawURLEncoding.EncodeToString([]byte(hdr)) + "." + parts[1]
	if _, err := v.Verify(context.Background(), forged, nil); err == nil {
		t.Fatal("ghost kid accepted")
	}
	if got := idp.fetches.Load(); got != before {
		t.Fatalf("unknown kid inside cooldown caused %d extra JWKS fetches", got-before)
	}
}

func TestScopesEntraScpArray(t *testing.T) {
	idp := newTestIdP(t)
	v := newVerifier(t, idp)
	info, err := v.Verify(context.Background(), idp.mint("rsa-1", func(c jwt.MapClaims) {
		delete(c, "scope")
		c["scp"] = []string{"logs:read", "admin:it"}
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !HasScope(info.Scopes, ScopeLogsRead) || !HasScope(info.Scopes, ScopeAdminIT) {
		t.Fatalf("scp array not parsed: %v", info.Scopes)
	}
}

func TestCheckOrigin(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	h := CheckOrigin([]string{"beamhall.test"}, next)

	cases := []struct {
		origin string
		want   int
	}{
		{"", 200},                           // CLI/MCP client: no Origin header
		{"https://beamhall.test", 200},      // allowed
		{"https://beamhall.test:8443", 200}, /* port irrelevant */
		{"https://evil.test", 403},          // rebinding attempt
		{"https://beamhall.test.evil.test", 403},
		{"::garbage::", 403},
	}
	for _, tc := range cases {
		r := httptest.NewRequest("POST", "/mcp", nil)
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Errorf("origin %q: got %d want %d", tc.origin, w.Code, tc.want)
		}
	}
}
