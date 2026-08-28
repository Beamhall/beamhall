package gitserver

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"sync"
	"time"

	"github.com/Beamhall/beamhall/internal/domain"
)

// A git token is a short-TTL credential scoped to exactly one beam's repo
// (PLAN §5.5: it never carries Docker/registry/DB creds — it can touch one
// repo and nothing else). Two kinds:
//
//	push (kindPush) — one-time, builds+deploys the pushed commit (15m default).
//	read (kindRead) — clone/fetch the beam's source; reusable within its TTL
//	                  (a clone is info/refs + upload-pack, so it can't be
//	                  single-use), longer-lived so a `git clone` has time to run.
//
// Both are minted via MCP (OAuth-gated), so "no standing credentials" holds:
// the token expires and the agent re-mints when it needs one. The plaintext is
// returned once at mint time; only its hash is stored.
type tokenKind string

const (
	kindPush tokenKind = "push"
	kindRead tokenKind = "read"
)

type grant struct {
	hash      [32]byte
	kind      tokenKind
	beamhall  domain.ID
	beam      domain.ID
	actor     domain.ID
	expiresAt time.Time
	used      bool
}

// TokenStore mints and validates git tokens in memory. Tokens are short-lived,
// so a restart simply invalidates any in-flight push/clone (the agent
// re-requests one) — no persistence needed.
type TokenStore struct {
	mu      sync.Mutex
	grants  map[string]*grant // key: "<kind>/<beamhall>/<beam>" → most recent grant
	ttl     time.Duration     // push token TTL
	readTTL time.Duration     // read (clone) token TTL
	now     func() time.Time
}

// NewTokenStore returns a store issuing push tokens valid for ttl (default 15m)
// and read tokens valid for a longer window (default 1h).
func NewTokenStore(ttl time.Duration) *TokenStore {
	if ttl == 0 {
		ttl = 15 * time.Minute
	}
	return &TokenStore{grants: map[string]*grant{}, ttl: ttl, readTTL: time.Hour, now: time.Now}
}

func grantKey(kind tokenKind, beamhall, beam domain.ID) string {
	return string(kind) + "/" + string(beamhall) + "/" + string(beam)
}

// Mint issues a fresh one-time push token for a beam, replacing any prior
// outstanding push token for it. Returns the plaintext token (shown once).
func (s *TokenStore) Mint(beamhall, beam, actor domain.ID) (string, error) {
	return s.mint(kindPush, beamhall, beam, actor, s.ttl)
}

// MintRead issues a fresh read (clone/fetch) token for a beam, replacing any
// prior outstanding read token for it. Returns the plaintext token (shown once).
func (s *TokenStore) MintRead(beamhall, beam, actor domain.ID) (string, error) {
	return s.mint(kindRead, beamhall, beam, actor, s.readTTL)
}

func (s *TokenStore) mint(kind tokenKind, beamhall, beam, actor domain.ID, ttl time.Duration) (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.grants[grantKey(kind, beamhall, beam)] = &grant{
		hash: sha256.Sum256([]byte(tok)), kind: kind, beamhall: beamhall, beam: beam,
		actor: actor, expiresAt: s.now().Add(ttl),
	}
	return tok, nil
}

// Principal is the resolved push identity after a token validates.
type Principal struct {
	Beamhall domain.ID
	Beam     domain.ID
	Actor    domain.ID
	// pushGrant is the EXACT grant Validate matched (push tokens only; nil
	// for read). Claim/Unclaim act on this captured pointer rather than a
	// fresh (beamhall,beam) map lookup, so a concurrent Mint that replaces
	// the map slot mid-deploy can never cause them to touch the wrong,
	// freshly-minted grant.
	pushGrant *grant
}

// Validate checks a push token against the grant for (beamhall, beam) and, on
// success, returns the exact matched grant embedded in Principal for a later
// Claim/Unclaim. It has no side effects itself — AdvertisedReferences may
// validate it repeatedly (git does info/refs then receive-pack) — so the
// actual push handler must call Claim before starting the build/deploy.
func (s *TokenStore) Validate(beamhall, beam domain.ID, token string) (Principal, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.grants[grantKey(kindPush, beamhall, beam)]
	if g == nil || g.used || s.now().After(g.expiresAt) {
		return Principal{}, false
	}
	want := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(g.hash[:], want[:]) != 1 {
		return Principal{}, false
	}
	return Principal{Beamhall: g.beamhall, Beam: g.beam, Actor: g.actor, pushGrant: g}, true
}

// ValidateRead checks a read token against the grant for (beamhall, beam). Read
// tokens are reusable within their TTL (a clone is info/refs then upload-pack),
// so they are never consumed — only TTL bounds them.
func (s *TokenStore) ValidateRead(beamhall, beam domain.ID, token string) (Principal, bool) {
	return s.validate(kindRead, beamhall, beam, token)
}

func (s *TokenStore) validate(kind tokenKind, beamhall, beam domain.ID, token string) (Principal, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.grants[grantKey(kind, beamhall, beam)]
	if g == nil || g.used || s.now().After(g.expiresAt) {
		return Principal{}, false
	}
	want := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(g.hash[:], want[:]) != 1 {
		return Principal{}, false
	}
	return Principal{Beamhall: g.beamhall, Beam: g.beam, Actor: g.actor}, true
}

// Claim atomically marks princ's push token used — CAS-style: succeeds only
// if it is still unused and unexpired. Call this right before starting the
// build/deploy, not from Validate: two concurrent receive-pack requests
// presenting the identical valid token would otherwise both pass Validate
// and both proceed to deploy, since neither observes the other's consumption
// until after the (slow) deploy completes. Only
// one Claim call for a given grant can ever succeed.
func (s *TokenStore) Claim(princ Principal) bool {
	if princ.pushGrant == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if princ.pushGrant.used || s.now().After(princ.pushGrant.expiresAt) {
		return false
	}
	princ.pushGrant.used = true
	return true
}

// Unclaim reverts a successful Claim after a failed deploy: the pushed
// commit already landed on main, so the token stays valid for the same
// fix-and-retry push instead of forcing a re-mint.
func (s *TokenStore) Unclaim(princ Principal) {
	if princ.pushGrant == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	princ.pushGrant.used = false
}
