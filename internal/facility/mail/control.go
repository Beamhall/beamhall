package mail

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"sync"
)

// The control channel (PLAN §5.11 facility brokers): beamhalld drives the
// shared bh-mail service container over this small HTTP API on the broker's
// loopback-published control port. It is one-directional — beamhalld→broker —
// to avoid any container→host hop: beamhalld config-pushes the provider and the
// per-beam registrations, and audit-pulls per-message events from a ring buffer
// the broker keeps. Every call is bearer-token authenticated.

type providerWire struct {
	Smarthost          string `json:"smarthost"`
	Username           string `json:"username,omitempty"`
	Password           string `json:"password,omitempty"`
	HeloName           string `json:"helo_name,omitempty"`
	DisableStartTLS    bool   `json:"disable_starttls,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
}

type registerWire struct {
	BeamID      string   `json:"beam_id"`
	Username    string   `json:"username"`
	PassHashHex string   `json:"pass_hash"`
	Allowed     []string `json:"allowed"`
	PerDay      int      `json:"per_day"`
	Burst       int      `json:"burst"`
}

type sendersWire struct {
	BeamID  string   `json:"beam_id"`
	Allowed []string `json:"allowed"`
}

type beamWire struct {
	BeamID string `json:"beam_id"`
}

// SeqEvent is an audit Event with the broker's monotonic sequence number, so
// beamhalld can pull incrementally and append to the hash chain in order.
type SeqEvent struct {
	Seq int64 `json:"seq"`
	Event
}

type eventsWire struct {
	Events []SeqEvent `json:"events"`
	Next   int64      `json:"next"` // high-water: the seq the next event will get
}

type statusWire struct {
	Enabled bool  `json:"enabled"`
	Next    int64 `json:"next"`
}

// ControlServer is the broker-side HTTP control API wrapping a Provisioner. It
// also buffers audit events in a ring for beamhalld to pull.
type ControlServer struct {
	p       *Provisioner
	token   string
	maxRing int

	mu      sync.Mutex
	ring    []SeqEvent
	next    int64
	certPEM []byte // the broker's STARTTLS cert, served for beamhalld to inject as SMTP_CA
}

// NewControlServer builds the control API. Wire it to a Provisioner whose audit
// sink is this server's Record method (so emitted events land in the ring).
func NewControlServer(token string, maxRing int) *ControlServer {
	if maxRing <= 0 {
		maxRing = 8192
	}
	return &ControlServer{token: token, maxRing: maxRing, next: 1}
}

// Attach binds the Provisioner the control API drives.
func (c *ControlServer) Attach(p *Provisioner) { c.p = p }

// SetCert publishes the broker's STARTTLS certificate (public PEM) so beamhalld
// can pull it and inject it to beams as SMTP_CA.
func (c *ControlServer) SetCert(certPEM []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.certPEM = certPEM
}

// Record is the audit sink: buffer the event with a sequence number.
func (c *ControlServer) Record(ev Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ring = append(c.ring, SeqEvent{Seq: c.next, Event: ev})
	c.next++
	if len(c.ring) > c.maxRing {
		c.ring = c.ring[len(c.ring)-c.maxRing:]
	}
}

func (c *ControlServer) eventsAfter(after int64) ([]SeqEvent, int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]SeqEvent, 0, len(c.ring))
	for _, se := range c.ring {
		if se.Seq > after {
			out = append(out, se)
		}
	}
	return out, c.next - 1
}

// Handler returns the control API mux.
func (c *ControlServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /control/provider", c.guard(c.handleProvider))
	mux.HandleFunc("POST /control/register", c.guard(c.handleRegister))
	mux.HandleFunc("POST /control/deregister", c.guard(c.handleDeregister))
	mux.HandleFunc("POST /control/senders", c.guard(c.handleSenders))
	mux.HandleFunc("GET /control/events", c.guard(c.handleEvents))
	mux.HandleFunc("GET /control/status", c.guard(c.handleStatus))
	mux.HandleFunc("GET /control/tls-cert", c.guard(c.handleTLSCert))
	return mux
}

func (c *ControlServer) handleTLSCert(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	pem := c.certPEM
	c.mu.Unlock()
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(pem)
}

func (c *ControlServer) guard(h http.HandlerFunc) http.HandlerFunc {
	want := "Bearer " + c.token
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		if c.token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

func (c *ControlServer) handleProvider(w http.ResponseWriter, r *http.Request) {
	var pw providerWire
	if err := json.NewDecoder(r.Body).Decode(&pw); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c.p.SetProvider(ProviderConfig{
		Smarthost:          pw.Smarthost,
		Username:           pw.Username,
		Password:           pw.Password,
		HeloName:           pw.HeloName,
		DisableStartTLS:    pw.DisableStartTLS,
		InsecureSkipVerify: pw.InsecureSkipVerify,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (c *ControlServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	var rw registerWire
	if err := json.NewDecoder(r.Body).Decode(&rw); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := c.p.RegisterHashed(rw.BeamID, rw.Username, rw.PassHashHex, rw.Allowed, Limits{PerDay: rw.PerDay, Burst: rw.Burst}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *ControlServer) handleDeregister(w http.ResponseWriter, r *http.Request) {
	var bw beamWire
	if err := json.NewDecoder(r.Body).Decode(&bw); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c.p.Deregister(bw.BeamID)
	w.WriteHeader(http.StatusNoContent)
}

func (c *ControlServer) handleSenders(w http.ResponseWriter, r *http.Request) {
	var sw sendersWire
	if err := json.NewDecoder(r.Body).Decode(&sw); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := c.p.SetSenders(sw.BeamID, sw.Allowed); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *ControlServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	after := parseInt(r.URL.Query().Get("after"))
	events, next := c.eventsAfter(after)
	writeJSON(w, eventsWire{Events: events, Next: next})
}

func (c *ControlServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	next := c.next - 1
	c.mu.Unlock()
	writeJSON(w, statusWire{Enabled: c.p.Enabled(), Next: next})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func parseInt(s string) int64 {
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int64(c-'0')
	}
	return n
}
