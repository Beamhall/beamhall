// Package web is Beamhall's read-mostly IT Admin console (PLAN §4/§8): a thin
// html/template + htmx server, same binary, mounted at /admin. It authenticates
// operators with the same OIDC IdP as the MCP layer — only a token carrying the
// admin:it scope opens the console — and keeps the session in a signed cookie.
// Every state-changing action goes through the backplane (the single PEP and
// audit writer), never around it.
package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const sessionCookie = "bh_admin_session"

// session is the authenticated operator, carried in a signed cookie. It holds
// no secret material — just who they are and when the session expires.
type session struct {
	Subject   string `json:"sub"`
	Issuer    string `json:"iss"`
	Email     string `json:"email"`
	Identity  string `json:"id"`  // resolved Beamhall Identity id
	ExpiresAt int64  `json:"exp"` // unix seconds
}

func (s session) expired(now time.Time) bool { return now.Unix() >= s.ExpiresAt }

// sessionCodec signs and verifies session cookies with HMAC-SHA256. The cookie
// is value.signature; tampering or a wrong key fails verification. It is not
// encrypted — the contents are not secret — only authenticated.
type sessionCodec struct{ key []byte }

func newSessionCodec(key []byte) *sessionCodec { return &sessionCodec{key: key} }

func (c *sessionCodec) encode(s session) (string, error) {
	payload, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	v := base64.RawURLEncoding.EncodeToString(payload)
	return v + "." + c.sign(v), nil
}

func (c *sessionCodec) decode(cookie string) (session, error) {
	dot := -1
	for i := len(cookie) - 1; i >= 0; i-- {
		if cookie[i] == '.' {
			dot = i
			break
		}
	}
	if dot < 0 {
		return session{}, fmt.Errorf("malformed session cookie")
	}
	v, sig := cookie[:dot], cookie[dot+1:]
	if subtle.ConstantTimeCompare([]byte(sig), []byte(c.sign(v))) != 1 {
		return session{}, fmt.Errorf("session signature mismatch")
	}
	payload, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return session{}, err
	}
	var s session
	if err := json.Unmarshal(payload, &s); err != nil {
		return session{}, err
	}
	return s, nil
}

func (c *sessionCodec) sign(v string) string {
	mac := hmac.New(sha256.New, c.key)
	mac.Write([]byte(v))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// setSession writes the signed session cookie (HttpOnly, SameSite=Lax so the
// OIDC redirect back to /admin/callback carries it; Secure unless TLS is off).
func (c *sessionCodec) setSession(w http.ResponseWriter, s session, secure bool) error {
	val, err := c.encode(s)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    val,
		Path:     "/admin",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(s.ExpiresAt, 0),
	})
	return nil
}

func clearSession(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/admin",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}
