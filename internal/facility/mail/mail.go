// Package mail is the email-delivery facility broker (PLAN §5.11 facility
// brokers; §5.12 email delivery). A beam inherits outbound email the way it
// inherits a database: one provision call mints per-beam SMTP submission
// credentials, the app speaks stock SMTP to an in-hall relay, and the relay
// forwards to a configured smarthost (an external provider like Mailgun/SES, or
// an internal corporate relay). The provider credential lives only in the relay
// — never in the beam — and the app never learns which provider sends.
//
// This is the cleanest §5.11 case: the relay fully terminates SMTP, so the beam
// holds only a capability valid *inside* the hall (an SMTP login against
// mail.internal), never a credential valid outside it. The relay is the in-path
// policy + audit chokepoint: it enforces a per-beam sender allowlist
// (anti-spoof across beams), a per-beam rate limit (mail-bomb defense; protects
// the shared smarthost's IP reputation), and emits a per-message audit event.
//
// This file holds the Provisioner (the registration/lifecycle seam) and its
// helpers; relay.go wires the go-smtp Backend/Session; forward.go is the
// south-side SMTP forwarder.
package mail

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	netmail "net/mail"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Errors returned by the facility.
var (
	// ErrNotEnabled means no south-side delivery provider is configured, so the
	// facility degrades closed (the orchestrator surfaces the set_secret
	// fallback recipe, mirroring provisioned-auth on BYO-IdP).
	ErrNotEnabled = errors.New("mail: no delivery provider configured")
	// ErrUnknownBeam means the beam has no email registration.
	ErrUnknownBeam = errors.New("mail: beam not registered for email")
	// ErrRateLimited means the beam exceeded its per-beam send rate.
	ErrRateLimited = errors.New("mail: rate limit exceeded")
)

// ProviderConfig is the south-side smarthost the relay forwards to. One
// SMTP-smarthost adapter covers external providers (Mailgun/SendGrid/SES/
// Postmark) and internal corporate relays alike; switching provider is config.
type ProviderConfig struct {
	// Smarthost is the upstream "host:port" (e.g. "smtp.mailgun.org:587").
	Smarthost string
	// Username/Password authenticate to the smarthost (empty = no AUTH, for an
	// open internal relay). Held only here, never injected into a beam.
	Username string
	Password string
	// HeloName is the EHLO name the relay presents upstream (default "beamhall").
	HeloName string
	// DisableStartTLS skips the STARTTLS upgrade (only for a trusted internal
	// relay that doesn't offer it). Default: STARTTLS when the smarthost offers it.
	DisableStartTLS bool
	// InsecureSkipVerify skips upstream TLS verification (prefer trusting the
	// CA instead; here for an internal smarthost with a private CA).
	InsecureSkipVerify bool
}

// Credentials are the per-beam SMTP submission credentials minted at provision
// time. The orchestrator seals these into the vault (SMTP_USER/SMTP_PASS) for
// file-injection into the beam; they are valid only against the in-hall relay.
type Credentials struct {
	Username string
	Password string
}

// Limits bounds a beam's outbound volume.
type Limits struct {
	// PerDay is the sustained message budget; Burst is the short-term allowance.
	PerDay int
	Burst  int
}

// ProvisionRequest asks for email for one beam.
type ProvisionRequest struct {
	BeamID         string
	AllowedSenders []string // addresses ("noreply@x.com"), "@domain", or "domain"
	Limits         Limits
}

// Registration restores a beam's email binding on boot from persisted state
// (the password is read back from the vault), so the in-memory relay registry
// survives restarts without re-minting credentials.
type Registration struct {
	BeamID         string
	Username       string
	Password       string
	AllowedSenders []string
	Limits         Limits
}

// Envelope is one message handed to the south-side forwarder.
type Envelope struct {
	From string
	To   []string
	Data []byte
}

// Forwarder delivers a message to the south side. The real impl is
// *SMTPForwarder; tests inject a fake.
type Forwarder interface {
	Forward(ctx context.Context, env Envelope) error
}

// Event is the per-message audit record the relay emits (envelope metadata
// only — never the body). Result is "sent" | "rejected" | "failed".
type Event struct {
	BeamID    string
	From      string
	To        []string
	Size      int
	Subject   string
	MessageID string
	Result    string
	Err       string
}

// registration is one beam's live relay binding.
type registration struct {
	beamID   string
	username string
	passHash [32]byte // sha256 of the high-entropy password (constant-time compare)

	mu      sync.Mutex
	allowed []string
	limiter *rate.Limiter
}

func (r *registration) checkPassword(pw string) bool {
	h := sha256.Sum256([]byte(pw))
	return subtle.ConstantTimeCompare(h[:], r.passHash[:]) == 1
}

func (r *registration) allowedSnapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.allowed...)
}

func (r *registration) setAllowed(a []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.allowed = append([]string(nil), a...)
}

// Provisioner is the email facility's registration/lifecycle seam and the
// go-smtp Backend (NewSession lives in relay.go). It holds the in-memory
// registry of per-beam bindings and the south-side provider/forwarder.
type Provisioner struct {
	mu               sync.RWMutex
	byUser           map[string]*registration
	byBeam           map[string]*registration
	provider         *ProviderConfig
	forwarder        Forwarder
	pinForwarder     bool
	forwarderFactory func(ProviderConfig) Forwarder

	audit          func(Event)
	defaults       Limits
	forwardTimeout time.Duration
}

// Option configures a Provisioner.
type Option func(*Provisioner)

// WithAuditSink wires the per-message audit callback (the orchestrator points
// it at the hash-chained audit log).
func WithAuditSink(fn func(Event)) Option { return func(p *Provisioner) { p.audit = fn } }

// WithForwarder pins the south-side forwarder (tests inject a fake; also makes
// Enabled() report true without a real provider).
func WithForwarder(f Forwarder) Option {
	return func(p *Provisioner) { p.forwarder = f; p.pinForwarder = true }
}

// WithDefaultLimits overrides the default per-beam limits applied when a
// provision request leaves them unset.
func WithDefaultLimits(l Limits) Option {
	return func(p *Provisioner) {
		if l.PerDay > 0 {
			p.defaults.PerDay = l.PerDay
		}
		if l.Burst > 0 {
			p.defaults.Burst = l.Burst
		}
	}
}

// WithForwardTimeout bounds a single upstream delivery attempt.
func WithForwardTimeout(d time.Duration) Option {
	return func(p *Provisioner) {
		if d > 0 {
			p.forwardTimeout = d
		}
	}
}

// New builds a Provisioner. Until a provider is configured (SetProvider) or a
// forwarder is pinned, the facility is disabled (degrades closed).
func New(opts ...Option) *Provisioner {
	p := &Provisioner{
		byUser:           map[string]*registration{},
		byBeam:           map[string]*registration{},
		forwarderFactory: func(c ProviderConfig) Forwarder { return NewSMTPForwarder(c) },
		defaults:         Limits{PerDay: 300, Burst: 20},
		forwardTimeout:   30 * time.Second,
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Enabled reports whether a south-side provider (or a pinned forwarder) is
// configured. The orchestrator uses this to degrade provision_email closed.
func (p *Provisioner) Enabled() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.forwarder != nil
}

// SetProvider configures the south-side smarthost (admin_set_email_provider).
// It (re)builds the real forwarder unless one was pinned for tests.
func (p *Provisioner) SetProvider(cfg ProviderConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c := cfg
	p.provider = &c
	if !p.pinForwarder {
		p.forwarder = p.forwarderFactory(c)
	}
}

// Provision mints per-beam submission credentials and registers the beam's
// sender policy with the relay. Returns the credentials to seal into the vault.
// The orchestrator gates idempotency (it won't call this when a resource row
// already exists), so a repeat call here rotates the password.
func (p *Provisioner) Provision(ctx context.Context, req ProvisionRequest) (Credentials, error) {
	if !p.Enabled() {
		return Credentials{}, ErrNotEnabled
	}
	if req.BeamID == "" {
		return Credentials{}, errors.New("mail: empty beam id")
	}
	pw, err := randomPassword()
	if err != nil {
		return Credentials{}, err
	}
	username := beamUsername(req.BeamID)
	p.register(req.BeamID, username, pw, req.AllowedSenders, req.Limits)
	return Credentials{Username: username, Password: pw}, nil
}

// Restore re-registers a beam from persisted state on boot (password read back
// from the vault); no new credentials are minted.
func (p *Provisioner) Restore(reg Registration) error {
	if reg.BeamID == "" || reg.Username == "" {
		return errors.New("mail: incomplete registration")
	}
	p.register(reg.BeamID, reg.Username, reg.Password, reg.AllowedSenders, reg.Limits)
	return nil
}

// SetSenders replaces a beam's allowed-sender list (admin_set_email_senders).
func (p *Provisioner) SetSenders(beamID string, allowed []string) error {
	p.mu.RLock()
	r, ok := p.byBeam[beamID]
	p.mu.RUnlock()
	if !ok {
		return ErrUnknownBeam
	}
	r.setAllowed(allowed)
	return nil
}

// Deregister removes a beam's email binding (reclaim on archive/destroy).
func (p *Provisioner) Deregister(beamID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if r, ok := p.byBeam[beamID]; ok {
		delete(p.byUser, r.username)
		delete(p.byBeam, beamID)
	}
}

func (p *Provisioner) register(beamID, username, password string, allowed []string, limits Limits) {
	p.registerHashed(beamID, username, sha256.Sum256([]byte(password)), allowed, limits)
}

// RegisterHashed registers (or replaces) a beam from a hex-encoded password
// hash — the control-channel path. beamhalld mints the password, seals the
// plaintext in the vault for injection, and pushes only the hash here, so the
// relay container never holds the plaintext yet can still authenticate.
func (p *Provisioner) RegisterHashed(beamID, username, passHashHex string, allowed []string, limits Limits) error {
	h, err := hex.DecodeString(passHashHex)
	if err != nil || len(h) != 32 {
		return errors.New("mail: invalid password hash")
	}
	var ph [32]byte
	copy(ph[:], h)
	p.registerHashed(beamID, username, ph, allowed, limits)
	return nil
}

func (p *Provisioner) registerHashed(beamID, username string, passHash [32]byte, allowed []string, limits Limits) {
	if limits.PerDay <= 0 {
		limits.PerDay = p.defaults.PerDay
	}
	if limits.Burst <= 0 {
		limits.Burst = p.defaults.Burst
	}
	r := &registration{
		beamID:   beamID,
		username: username,
		passHash: passHash,
		allowed:  append([]string(nil), allowed...),
		limiter:  rate.NewLimiter(rate.Limit(float64(limits.PerDay)/86400.0), limits.Burst),
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if old, ok := p.byBeam[beamID]; ok {
		delete(p.byUser, old.username)
	}
	p.byUser[username] = r
	p.byBeam[beamID] = r
}

// PasswordHashHex returns the hex SHA-256 of a password — beamhalld computes
// this to persist in the resource row and to push over the control channel.
func PasswordHashHex(password string) string {
	h := sha256.Sum256([]byte(password))
	return hex.EncodeToString(h[:])
}

func (p *Provisioner) lookup(username string) (*registration, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	r, ok := p.byUser[username]
	return r, ok
}

func (p *Provisioner) emit(ev Event) {
	if p.audit != nil {
		p.audit(ev)
	}
}

// deliver enforces the rate limit, forwards to the south side, and audits.
// Returns nil on success, ErrRateLimited, ErrNotEnabled, or a wrapped upstream
// error; relay.go maps these to SMTP reply codes. The sender allowlist is
// enforced earlier (at MAIL FROM) so a rejected sender never spends a token.
func (p *Provisioner) deliver(reg *registration, from string, to []string, data []byte) error {
	ev := Event{
		BeamID: reg.beamID,
		From:   from,
		To:     append([]string(nil), to...),
		Size:   len(data),
	}
	ev.Subject, ev.MessageID = parseHeaders(data)

	if !reg.limiter.Allow() {
		ev.Result = "rejected"
		ev.Err = "rate limit exceeded"
		p.emit(ev)
		return ErrRateLimited
	}

	p.mu.RLock()
	fwd := p.forwarder
	timeout := p.forwardTimeout
	p.mu.RUnlock()
	if fwd == nil {
		ev.Result = "failed"
		ev.Err = "no provider configured"
		p.emit(ev)
		return ErrNotEnabled
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := fwd.Forward(ctx, Envelope{From: from, To: to, Data: data}); err != nil {
		ev.Result = "failed"
		ev.Err = err.Error()
		p.emit(ev)
		return fmt.Errorf("upstream delivery: %w", err)
	}
	ev.Result = "sent"
	p.emit(ev)
	return nil
}

// beamUsername is the stable per-beam SMTP username (injected as SMTP_USER).
func beamUsername(beamID string) string { return "beam-" + beamID }

// senderAllowed reports whether the envelope sender is permitted. allowed
// entries may be a full address ("noreply@x.com"), a domain ("x.com"), or a
// "@domain" form. An empty list rejects all (fail closed).
func senderAllowed(from string, allowed []string) bool {
	from = strings.ToLower(strings.Trim(strings.TrimSpace(from), "<>"))
	if from == "" || len(allowed) == 0 {
		return false
	}
	at := strings.LastIndex(from, "@")
	if at < 0 {
		return false
	}
	dom := from[at+1:]
	for _, a := range allowed {
		a = strings.ToLower(strings.TrimSpace(a))
		switch {
		case a == "":
			continue
		case strings.HasPrefix(a, "@"):
			if dom == a[1:] {
				return true
			}
		case strings.Contains(a, "@"):
			if from == a {
				return true
			}
		default:
			if dom == a {
				return true
			}
		}
	}
	return false
}

// parseHeaders best-effort extracts Subject/Message-Id for the audit record.
func parseHeaders(data []byte) (subject, messageID string) {
	m, err := netmail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return "", ""
	}
	return m.Header.Get("Subject"), m.Header.Get("Message-Id")
}

// randomPassword is 192 bits of hex (matches the Postgres provisioner's scheme).
func randomPassword() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
