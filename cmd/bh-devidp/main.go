// Command bh-devidp is a LAB/DEV-ONLY identity provider: it generates an RSA
// key, serves a JWKS, and mints OAuth access tokens so beamhalld's resource
// server can be exercised before a real IdP (bundled Keycloak / customer
// Okta/Entra) is connected. It has no authentication of its own — NEVER
// expose it beyond a lab network and never use it in production.
//
//	bh-devidp -addr 127.0.0.1:9081 -audience https://beamhall.internal/mcp
//
// Endpoints:
//
//	GET /jwks.json                            the key set (BEAMHALL_OAUTH_JWKS_URL)
//	GET /mint?sub=NAME&scopes=a,b&ttl=1h      a signed access token (plain text)
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9081", "listen address")
	issuer := flag.String("issuer", "", "issuer identifier (default http://<addr>)")
	audience := flag.String("audience", "https://beamhall.internal/mcp", "audience (the Beamhall resource URI)")
	flag.Parse()
	if *issuer == "" {
		*issuer = "http://" + *addr
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	const kid = "devidp-1"

	jwks, err := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": kid, "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
	}}})
	if err != nil {
		log.Fatal(err)
	}

	mint := func(sub, scopes string, ttl time.Duration) string {
		now := time.Now()
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": *issuer, "aud": *audience, "sub": sub, "email": sub + "@lab.test",
			"jti": fmt.Sprintf("devidp-%d", now.UnixNano()), "scope": scopes,
			"iat": now.Unix(), "exp": now.Add(ttl).Unix(),
		})
		tok.Header["kid"] = kid
		signed, _ := tok.SignedString(key)
		return signed
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwks)
	})

	// OIDC discovery + a minimal Authorization Code flow for the Admin console.
	// LAB ONLY: /authorize auto-consents and grants the scopes named by the
	// `sub` query (sub carries scopes too, e.g. ?sub=it&scopes=...), or the
	// requested scope param. There is NO authentication — never expose this.
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 *issuer,
			"authorization_endpoint": *issuer + "/authorize",
			"token_endpoint":         *issuer + "/token",
			"jwks_uri":               *issuer + "/jwks.json",
		})
	})
	// codes maps an issued auth code → (sub, scope).
	codes := map[string][2]string{}
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		sub := q.Get("login_sub")
		if sub == "" {
			sub = "lab-operator"
		}
		scope := q.Get("scope")
		if scope == "" {
			scope = "openid admin:it"
		}
		code := fmt.Sprintf("code-%d", time.Now().UnixNano())
		codes[code] = [2]string{sub, scope}
		redir := q.Get("redirect_uri") + "?code=" + code + "&state=" + url.QueryEscape(q.Get("state"))
		log.Printf("authorize: sub=%s scope=%q -> %s", sub, scope, redir)
		http.Redirect(w, r, redir, http.StatusFound)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		c := codes[r.FormValue("code")]
		if c[0] == "" {
			http.Error(w, "unknown code", http.StatusBadRequest)
			return
		}
		delete(codes, r.FormValue("code"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": mint(c[0], c[1], time.Hour), "token_type": "Bearer", "expires_in": 3600,
		})
	})
	mux.HandleFunc("GET /mint", func(w http.ResponseWriter, r *http.Request) {
		sub := r.URL.Query().Get("sub")
		if sub == "" {
			http.Error(w, "sub query parameter required", http.StatusBadRequest)
			return
		}
		ttl := time.Hour
		if v := r.URL.Query().Get("ttl"); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				http.Error(w, "bad ttl: "+err.Error(), http.StatusBadRequest)
				return
			}
			ttl = d
		}
		scopes := strings.ReplaceAll(r.URL.Query().Get("scopes"), ",", " ")
		fmt.Fprintln(w, mint(sub, scopes, ttl))
		log.Printf("minted token: sub=%s scopes=%q ttl=%s", sub, scopes, ttl)
	})

	log.Printf("bh-devidp (LAB ONLY) listening on %s", *addr)
	log.Printf("  issuer:   %s", *issuer)
	log.Printf("  audience: %s", *audience)
	log.Printf("  JWKS:     http://%s/jwks.json", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
