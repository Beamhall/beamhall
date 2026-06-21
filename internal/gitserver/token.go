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
}

// Validate checks a push token against the grant for (beamhall, beam). It is
// single-use for build triggering: AdvertisedReferences may validate it
// repeatedly (git does info/refs then receive-pack), so consumption is
// explicit via Consume after a successful push.
func (s *TokenStore) Validate(beamhall, beam domain.ID, token string) (Principal, bool) {
	return s.validate(kindPush, beamhall, beam, token)
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

// Consume marks the push token spent (after a successful push+build), so it
// cannot be replayed.
func (s *TokenStore) Consume(beamhall, beam domain.ID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if g := s.grants[grantKey(kindPush, beamhall, beam)]; g != nil {
		g.used = true
	}
}
