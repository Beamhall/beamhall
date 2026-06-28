package s3

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"sync"
)

// The control channel (PLAN §5.11 facility brokers): beamhalld drives the shared
// bh-objstore service container over this small HTTP API on the broker's
// loopback-published control port. It is one-directional — beamhalld→broker — to
// avoid any container→host hop: beamhalld config-pushes the provider and the
// per-beam registrations (with the PLAINTEXT secret, which SigV4 requires), and
// audit-pulls per-request events from a ring buffer the broker keeps. Every call
// is bearer-token authenticated. Unlike bh-mail there is no tls-cert endpoint —
// the S3 endpoint is plain HTTP on the private bridge (SigV4 gives request auth).

type providerWire struct {
	Endpoint       string `json:"endpoint"`
	Region         string `json:"region,omitempty"`
	Bucket         string `json:"bucket,omitempty"`
	AccessKey      string `json:"access_key,omitempty"`
	SecretKey      string `json:"secret_key,omitempty"`
	ForcePathStyle bool   `json:"force_path_style,omitempty"`
	UseSSL         bool   `json:"use_ssl,omitempty"`
}

type registerWire struct {
	BeamID    string `json:"beam_id"`
	Channel   string `json:"channel"`
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
	Bucket    string `json:"bucket"`
	MaxBytes  int64  `json:"max_bytes"`
}

type deregisterWire struct {
	BeamID  string `json:"beam_id"`
	Channel string `json:"channel"`
	Purge   bool   `json:"purge"`
}

type quotaWire struct {
	BeamID   string `json:"beam_id"`
	Channel  string `json:"channel"`
	MaxBytes int64  `json:"max_bytes"`
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

	mu   sync.Mutex
	ring []SeqEvent
	next int64
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
	mux.HandleFunc("POST /control/quota", c.guard(c.handleQuota))
	mux.HandleFunc("GET /control/events", c.guard(c.handleEvents))
	mux.HandleFunc("GET /control/status", c.guard(c.handleStatus))
	return mux
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
	if err := c.p.SetProvider(ProviderConfig{
		Endpoint:       pw.Endpoint,
		Region:         pw.Region,
		Bucket:         pw.Bucket,
		AccessKey:      pw.AccessKey,
		SecretKey:      pw.SecretKey,
		ForcePathStyle: pw.ForcePathStyle,
		UseSSL:         pw.UseSSL,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *ControlServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	var rw registerWire
	if err := json.NewDecoder(r.Body).Decode(&rw); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := c.p.RegisterKey(Registration{
		BeamID:    rw.BeamID,
		Channel:   rw.Channel,
		AccessKey: rw.AccessKey,
		SecretKey: rw.SecretKey,
		Bucket:    rw.Bucket,
		Limits:    Limits{MaxBytes: rw.MaxBytes},
	}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *ControlServer) handleDeregister(w http.ResponseWriter, r *http.Request) {
	var dw deregisterWire
	if err := json.NewDecoder(r.Body).Decode(&dw); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c.p.Deregister(dw.BeamID, dw.Channel, dw.Purge)
	w.WriteHeader(http.StatusNoContent)
}

func (c *ControlServer) handleQuota(w http.ResponseWriter, r *http.Request) {
	var qw quotaWire
	if err := json.NewDecoder(r.Body).Decode(&qw); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := c.p.SetQuota(qw.BeamID, qw.Channel, qw.MaxBytes); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *ControlServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	events, next := c.eventsAfter(parseInt(r.URL.Query().Get("after")))
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
