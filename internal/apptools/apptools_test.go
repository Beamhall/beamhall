package apptools

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newTestSigner(t *testing.T) *Signer {
	t.Helper()
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner(key, "https://beamhall.test/mcp")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// pubFromJWKS reconstructs the public key from the signer's own JWKS output,
// so a passing verification proves the JWKS an app receives actually works.
func pubFromJWKS(t *testing.T, jwks []byte) (*ecdsa.PublicKey, string) {
	t.Helper()
	var set struct {
		Keys []struct {
			Kty, Crv, Kid, Use, Alg, X, Y string
		} `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &set); err != nil {
		t.Fatalf("JWKS does not parse: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("want 1 key, got %d", len(set.Keys))
	}
	k := set.Keys[0]
	if k.Kty != "EC" || k.Crv != "P-256" || k.Alg != "ES256" || k.Use != "sig" {
		t.Fatalf("unexpected JWK shape: %+v", k)
	}
	xb, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		t.Fatal(err)
	}
	yb, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		t.Fatal(err)
	}
	if len(xb) != 32 || len(yb) != 32 {
		t.Fatalf("EC coordinates must be fixed-width 32 bytes, got %d/%d", len(xb), len(yb))
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}, k.Kid
}

func TestMintVerifiesAgainstOwnJWKS(t *testing.T) {
	s := newTestSigner(t)
	tok, err := s.Mint(Assertion{
		Subject: "id-123", Email: "erin@corp.test", Groups: []string{"finance"},
		Audience: "beam-9", Channel: "live", Tool: "whoami",
	})
	if err != nil {
		t.Fatal(err)
	}
	pub, kid := pubFromJWKS(t, s.JWKS())
	parsed, err := jwt.Parse(tok, func(tk *jwt.Token) (any, error) {
		if tk.Header["kid"] != kid {
			return nil, fmt.Errorf("kid mismatch: %v", tk.Header["kid"])
		}
		return pub, nil
	}, jwt.WithValidMethods([]string{"ES256"}), jwt.WithIssuer("https://beamhall.test/mcp"),
		jwt.WithAudience("beam-9"), jwt.WithExpirationRequired())
	if err != nil {
		t.Fatalf("assertion did not verify: %v", err)
	}
	claims := parsed.Claims.(jwt.MapClaims)
	for k, want := range map[string]string{
		"sub": "id-123", "email": "erin@corp.test", "channel": "live", "tool": "whoami",
	} {
		if claims[k] != want {
			t.Errorf("claim %s = %v, want %s", k, claims[k], want)
		}
	}
	if claims["jti"] == "" || claims["jti"] == nil {
		t.Error("jti missing")
	}
	exp, _ := claims.GetExpirationTime()
	if until := time.Until(exp.Time); until > AssertionTTL+time.Second {
		t.Errorf("exp too far out: %v", until)
	}
}

func TestMintEmptyGroupsIsArray(t *testing.T) {
	s := newTestSigner(t)
	tok, err := s.Mint(Assertion{Subject: ProbeSubject, Audience: "b", Channel: "preview"})
	if err != nil {
		t.Fatal(err)
	}
	// Apps must always see a groups array, never null/absent.
	payload := strings.Split(tok, ".")[1]
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Groups []string `json:"groups"`
		Tool   *string  `json:"tool"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	if c.Groups == nil {
		t.Error("groups claim absent or null")
	}
	if c.Tool == nil {
		t.Error("tool claim absent")
	}
}

func TestBindingJSON(t *testing.T) {
	s := newTestSigner(t)
	var b struct {
		Version  int             `json:"version"`
		Issuer   string          `json:"issuer"`
		Audience string          `json:"audience"`
		JWKS     json.RawMessage `json:"jwks"`
	}
	if err := json.Unmarshal(s.BindingJSON("beam-42"), &b); err != nil {
		t.Fatal(err)
	}
	if b.Version != Version || b.Issuer != "https://beamhall.test/mcp" || b.Audience != "beam-42" {
		t.Fatalf("unexpected binding: %+v", b)
	}
	pub, _ := pubFromJWKS(t, b.JWKS)
	if pub.X.Cmp(s.key.PublicKey.X) != 0 {
		t.Error("binding JWKS carries a different key")
	}
}

func TestParseManifest(t *testing.T) {
	tool := func(name string) string {
		return fmt.Sprintf(`{"name":%q,"description":"d","input_schema":{"type":"object"}}`, name)
	}
	many := make([]string, MaxTools+1)
	for i := range many {
		many[i] = tool(fmt.Sprintf("t%d", i))
	}
	cases := []struct {
		name, body string
		wantErr    string
	}{
		{"valid", `{"version":1,"tools":[` + tool("whoami") + `]}`, ""},
		{"empty tools", `{"version":1,"tools":[]}`, ""},
		{"no schema", `{"version":1,"tools":[{"name":"a","description":"d"}]}`, ""},
		{"bad version", `{"version":2,"tools":[]}`, "version 2"},
		{"not json", `nope`, "not valid JSON"},
		{"bad name", `{"version":1,"tools":[` + tool("Bad Name") + `]}`, "invalid"},
		{"dup name", `{"version":1,"tools":[` + tool("a") + `,` + tool("a") + `]}`, "twice"},
		{"schema not object", `{"version":1,"tools":[{"name":"a","description":"d","input_schema":[1]}]}`, "JSON object"},
		{"too many", `{"version":1,"tools":[` + strings.Join(many, ",") + `]}`, "maximum"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseManifest([]byte(tc.body))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func addrOf(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	return strings.TrimPrefix(srv.URL, "http://")
}

func TestFetchManifest(t *testing.T) {
	var gotAssertion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAssertion = r.Header.Get(HeaderAssertion)
		switch r.URL.Path {
		case PathTools:
			fmt.Fprint(w, `{"version":1,"tools":[{"name":"whoami","description":"d"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := NewClient(time.Second, time.Second)
	m, err := c.FetchManifest(context.Background(), addrOf(t, srv), "tok-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Tools) != 1 || m.Tools[0].Name != "whoami" {
		t.Fatalf("unexpected manifest: %+v", m)
	}
	if gotAssertion != "tok-1" {
		t.Errorf("assertion header not sent (got %q)", gotAssertion)
	}
}

func TestFetchManifestNoTools(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	c := NewClient(time.Second, time.Second)
	if _, err := c.FetchManifest(context.Background(), addrOf(t, srv), "t"); !errors.Is(err, ErrNoAgentTools) {
		t.Fatalf("want ErrNoAgentTools, got %v", err)
	}
}

func TestFetchManifestOversize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"version":1,"tools":[`))
		filler := strings.Repeat(" ", MaxManifestBytes)
		w.Write([]byte(filler))
	}))
	defer srv.Close()
	c := NewClient(time.Second, time.Second)
	if _, err := c.FetchManifest(context.Background(), addrOf(t, srv), "t"); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("want size-limit error, got %v", err)
	}
}

func TestFetchManifestTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()
	c := NewClient(time.Second, 50*time.Millisecond)
	start := time.Now()
	_, err := c.FetchManifest(context.Background(), addrOf(t, srv), "t")
	if err == nil {
		t.Fatal("want timeout error")
	}
	if time.Since(start) > time.Second {
		t.Fatalf("manifest fetch was not bounded by its own timeout")
	}
}

func TestInvoke(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != PathTools+"/add" {
			http.NotFound(w, r)
			return
		}
		var args struct{ A, B int }
		json.NewDecoder(r.Body).Decode(&args)
		fmt.Fprintf(w, `{"sum":%d}`, args.A+args.B)
	}))
	defer srv.Close()
	c := NewClient(time.Second, time.Second)
	out, err := c.Invoke(context.Background(), addrOf(t, srv), "add", "tok", []byte(`{"a":2,"b":3}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"sum":5}` {
		t.Fatalf("unexpected result: %s", out)
	}
}

func TestInvokeAppError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no such leave balance", http.StatusUnprocessableEntity)
	}))
	defer srv.Close()
	c := NewClient(time.Second, time.Second)
	_, err := c.Invoke(context.Background(), addrOf(t, srv), "x", "tok", nil)
	var ie *InvokeError
	if !errors.As(err, &ie) {
		t.Fatalf("want *InvokeError, got %v", err)
	}
	if ie.Status != http.StatusUnprocessableEntity || !strings.Contains(string(ie.Body), "leave balance") {
		t.Fatalf("unexpected InvokeError: %d %s", ie.Status, ie.Body)
	}
}

func TestInvokeArgumentCap(t *testing.T) {
	c := NewClient(time.Second, time.Second)
	big := []byte(`{"a":"` + strings.Repeat("x", MaxArgumentBytes) + `"}`)
	if _, err := c.Invoke(context.Background(), "127.0.0.1:1", "t", "tok", big); err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("want argument-cap error, got %v", err)
	}
}

// xorSealer is a stand-in for the vault: reversible, and different from the
// plaintext so an unsealed read would fail parsing.
type xorSealer struct{}

func (xorSealer) Seal(p []byte) ([]byte, error) { return xorBytes(p), nil }
func (xorSealer) Open(c []byte) ([]byte, error) { return xorBytes(c), nil }

func xorBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i, v := range b {
		out[i] = v ^ 0x5a
	}
	return out
}

type memKeyStore struct{ m map[string][]byte }

func (s *memKeyStore) GetControlKey(_ context.Context, kind string) ([]byte, bool, error) {
	v, ok := s.m[kind]
	return v, ok, nil
}

func (s *memKeyStore) PutControlKey(_ context.Context, kind string, sealed []byte) error {
	if s.m == nil {
		s.m = map[string][]byte{}
	}
	s.m[kind] = sealed
	return nil
}

func TestLoadOrCreateSignerPersists(t *testing.T) {
	ks := &memKeyStore{}
	ctx := context.Background()
	s1, created, err := LoadOrCreateSigner(ctx, ks, xorSealer{}, "https://a.test/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("first load must create")
	}
	s2, created, err := LoadOrCreateSigner(ctx, ks, xorSealer{}, "https://a.test/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("second load must not create")
	}
	if s1.kid != s2.kid {
		t.Fatalf("kid changed across loads: %s vs %s", s1.kid, s2.kid)
	}
}
