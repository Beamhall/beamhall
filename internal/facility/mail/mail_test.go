package mail

import (
	"context"
	"errors"
	"io"
	"net"
	netsmtp "net/smtp"
	"strings"
	"sync"
	"testing"
)

// fakeForwarder captures forwarded envelopes (and can inject a failure).
type fakeForwarder struct {
	mu  sync.Mutex
	got []Envelope
	err error
}

func (f *fakeForwarder) Forward(_ context.Context, env Envelope) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	cp := env
	cp.Data = append([]byte(nil), env.Data...)
	f.got = append(f.got, cp)
	return nil
}

func (f *fakeForwarder) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.got)
}

type auditCapture struct {
	mu     sync.Mutex
	events []Event
}

func (a *auditCapture) sink() func(Event) {
	return func(e Event) {
		a.mu.Lock()
		defer a.mu.Unlock()
		a.events = append(a.events, e)
	}
}

func (a *auditCapture) snapshot() []Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]Event(nil), a.events...)
}

// startRelay runs the relay on a random localhost port and returns its address.
func startRelay(t *testing.T, p *Provisioner) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := p.NewServer("", nil)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return l.Addr().String()
}

const sampleMsg = "From: noreply@app.example.com\r\n" +
	"To: user@dest.example\r\n" +
	"Subject: Hello there\r\n" +
	"Message-Id: <abc123@app.example.com>\r\n" +
	"\r\n" +
	"body line\r\n"

// sendVia performs one full SMTP submission and returns the first error.
func sendVia(addr, user, pass, from, to, body string) error {
	c, err := netsmtp.Dial(addr)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Hello("test-client"); err != nil {
		return err
	}
	if err := c.Auth(netsmtp.PlainAuth("", user, pass, "127.0.0.1")); err != nil {
		return err
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, body); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func TestRelayForwardsAuthorizedMessage(t *testing.T) {
	fwd := &fakeForwarder{}
	audit := &auditCapture{}
	p := New(WithForwarder(fwd), WithAuditSink(audit.sink()))
	creds, err := p.Provision(context.Background(), ProvisionRequest{
		BeamID:         "BEAM1",
		AllowedSenders: []string{"app.example.com"},
	})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if creds.Username != "beam-BEAM1" || creds.Password == "" {
		t.Fatalf("unexpected creds: %+v", creds)
	}

	addr := startRelay(t, p)
	if err := sendVia(addr, creds.Username, creds.Password, "noreply@app.example.com", "user@dest.example", sampleMsg); err != nil {
		t.Fatalf("send: %v", err)
	}

	if fwd.count() != 1 {
		t.Fatalf("forwarder got %d messages, want 1", fwd.count())
	}
	env := fwd.got[0]
	if env.From != "noreply@app.example.com" {
		t.Errorf("forwarded From = %q", env.From)
	}
	if len(env.To) != 1 || env.To[0] != "user@dest.example" {
		t.Errorf("forwarded To = %v", env.To)
	}
	if !strings.Contains(string(env.Data), "body line") {
		t.Errorf("forwarded body missing content: %q", env.Data)
	}

	events := audit.snapshot()
	if len(events) != 1 {
		t.Fatalf("got %d audit events, want 1", len(events))
	}
	ev := events[0]
	if ev.Result != "sent" || ev.BeamID != "BEAM1" {
		t.Errorf("audit event = %+v", ev)
	}
	if ev.Subject != "Hello there" || ev.MessageID != "<abc123@app.example.com>" {
		t.Errorf("audit headers = subject %q msgid %q", ev.Subject, ev.MessageID)
	}
	if ev.Size == 0 {
		t.Errorf("audit size not recorded")
	}
}

func TestRelayRejectsWrongPassword(t *testing.T) {
	fwd := &fakeForwarder{}
	p := New(WithForwarder(fwd))
	creds, err := p.Provision(context.Background(), ProvisionRequest{BeamID: "B", AllowedSenders: []string{"app.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	addr := startRelay(t, p)
	err = sendVia(addr, creds.Username, "not-the-password", "noreply@app.example.com", "u@dest.example", sampleMsg)
	if err == nil {
		t.Fatal("expected auth failure, got nil")
	}
	if fwd.count() != 0 {
		t.Fatalf("forwarder should have received nothing, got %d", fwd.count())
	}
}

func TestRelayRejectsDisallowedSender(t *testing.T) {
	fwd := &fakeForwarder{}
	audit := &auditCapture{}
	p := New(WithForwarder(fwd), WithAuditSink(audit.sink()))
	creds, err := p.Provision(context.Background(), ProvisionRequest{BeamID: "B", AllowedSenders: []string{"app.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	addr := startRelay(t, p)
	err = sendVia(addr, creds.Username, creds.Password, "evil@other.example", "u@dest.example", sampleMsg)
	if err == nil {
		t.Fatal("expected sender rejection, got nil")
	}
	if fwd.count() != 0 {
		t.Fatalf("forwarder should have received nothing, got %d", fwd.count())
	}
	events := audit.snapshot()
	if len(events) != 1 || events[0].Result != "rejected" {
		t.Fatalf("expected one rejected audit event, got %+v", events)
	}
}

func TestRelayRateLimit(t *testing.T) {
	fwd := &fakeForwarder{}
	p := New(WithForwarder(fwd))
	creds, err := p.Provision(context.Background(), ProvisionRequest{
		BeamID:         "B",
		AllowedSenders: []string{"app.example.com"},
		Limits:         Limits{PerDay: 100, Burst: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := startRelay(t, p)

	// Burst of 2 allowed; the 3rd is rate-limited (refill over a few ms is
	// negligible at 100/day).
	for i := 0; i < 2; i++ {
		if err := sendVia(addr, creds.Username, creds.Password, "noreply@app.example.com", "u@dest.example", sampleMsg); err != nil {
			t.Fatalf("message %d should succeed: %v", i+1, err)
		}
	}
	if err := sendVia(addr, creds.Username, creds.Password, "noreply@app.example.com", "u@dest.example", sampleMsg); err == nil {
		t.Fatal("3rd message should be rate-limited")
	}
	if fwd.count() != 2 {
		t.Fatalf("forwarder got %d, want 2", fwd.count())
	}
}

func TestProvisionDisabledWithoutProvider(t *testing.T) {
	p := New()
	if p.Enabled() {
		t.Fatal("Enabled() should be false without a provider")
	}
	if _, err := p.Provision(context.Background(), ProvisionRequest{BeamID: "B"}); !errors.Is(err, ErrNotEnabled) {
		t.Fatalf("want ErrNotEnabled, got %v", err)
	}

	// SetProvider with a pinned forwarder via SetProvider path: pin instead.
	fwd := &fakeForwarder{}
	p2 := New(WithForwarder(fwd))
	if !p2.Enabled() {
		t.Fatal("Enabled() should be true with a pinned forwarder")
	}
}

func TestSetProviderEnables(t *testing.T) {
	p := New()
	if p.Enabled() {
		t.Fatal("should start disabled")
	}
	p.SetProvider(ProviderConfig{Smarthost: "smtp.example.com:587", Username: "u", Password: "p"})
	if !p.Enabled() {
		t.Fatal("SetProvider should enable the facility")
	}
}

func TestDeregisterRevokesAuth(t *testing.T) {
	fwd := &fakeForwarder{}
	p := New(WithForwarder(fwd))
	creds, err := p.Provision(context.Background(), ProvisionRequest{BeamID: "B", AllowedSenders: []string{"app.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	addr := startRelay(t, p)
	if err := sendVia(addr, creds.Username, creds.Password, "noreply@app.example.com", "u@dest.example", sampleMsg); err != nil {
		t.Fatalf("pre-deregister send should work: %v", err)
	}
	p.Deregister("B")
	if err := sendVia(addr, creds.Username, creds.Password, "noreply@app.example.com", "u@dest.example", sampleMsg); err == nil {
		t.Fatal("post-deregister send should fail auth")
	}
}

func TestRestoreRegistersKnownCreds(t *testing.T) {
	fwd := &fakeForwarder{}
	p := New(WithForwarder(fwd))
	if err := p.Restore(Registration{
		BeamID:         "B",
		Username:       "beam-B",
		Password:       "deadbeefdeadbeef",
		AllowedSenders: []string{"app.example.com"},
	}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	addr := startRelay(t, p)
	if err := sendVia(addr, "beam-B", "deadbeefdeadbeef", "noreply@app.example.com", "u@dest.example", sampleMsg); err != nil {
		t.Fatalf("send with restored creds: %v", err)
	}
	if fwd.count() != 1 {
		t.Fatalf("forwarder got %d, want 1", fwd.count())
	}
}

func TestSetSendersUpdatesPolicy(t *testing.T) {
	fwd := &fakeForwarder{}
	p := New(WithForwarder(fwd))
	creds, err := p.Provision(context.Background(), ProvisionRequest{BeamID: "B", AllowedSenders: []string{"old.example"}})
	if err != nil {
		t.Fatal(err)
	}
	addr := startRelay(t, p)
	// New domain not yet allowed.
	if err := sendVia(addr, creds.Username, creds.Password, "x@new.example", "u@dest.example", sampleMsg); err == nil {
		t.Fatal("send from new.example should be rejected before SetSenders")
	}
	if err := p.SetSenders("B", []string{"new.example"}); err != nil {
		t.Fatalf("set senders: %v", err)
	}
	if err := sendVia(addr, creds.Username, creds.Password, "x@new.example", "u@dest.example", sampleMsg); err != nil {
		t.Fatalf("send from new.example should work after SetSenders: %v", err)
	}
	if err := p.SetSenders("UNKNOWN", []string{"x"}); !errors.Is(err, ErrUnknownBeam) {
		t.Fatalf("want ErrUnknownBeam, got %v", err)
	}
}

func TestSenderAllowed(t *testing.T) {
	cases := []struct {
		from    string
		allowed []string
		want    bool
	}{
		{"noreply@app.example.com", []string{"app.example.com"}, true},
		{"noreply@app.example.com", []string{"@app.example.com"}, true},
		{"noreply@app.example.com", []string{"noreply@app.example.com"}, true},
		{"NoReply@App.Example.Com", []string{"app.example.com"}, true},
		{"<noreply@app.example.com>", []string{"app.example.com"}, true},
		{"other@app.example.com", []string{"noreply@app.example.com"}, false},
		{"noreply@evil.com", []string{"app.example.com"}, false},
		{"noreply@app.example.com", nil, false},
		{"", []string{"app.example.com"}, false},
		{"malformed", []string{"app.example.com"}, false},
		{"a@b.com", []string{"", "b.com"}, true},
	}
	for _, c := range cases {
		if got := senderAllowed(c.from, c.allowed); got != c.want {
			t.Errorf("senderAllowed(%q, %v) = %v, want %v", c.from, c.allowed, got, c.want)
		}
	}
}
