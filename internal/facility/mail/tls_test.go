package mail

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	netsmtp "net/smtp"
	"testing"
)

// TestRelaySTARTTLSAllowsStrictAuth proves the lab finding is fixed: a strict
// client (Go's net/smtp, which refuses plaintext AUTH off-localhost) can
// STARTTLS against the broker's cert and then authenticate with stock PlainAuth.
func TestRelaySTARTTLSAllowsStrictAuth(t *testing.T) {
	cert, certPEM, err := LoadOrGenerateCert("", []string{"bh-mail"})
	if err != nil {
		t.Fatalf("gen cert: %v", err)
	}
	fwd := &fakeForwarder{}
	p := New(WithForwarder(fwd))
	creds, err := p.Provision(context.Background(), ProvisionRequest{BeamID: "B", AllowedSenders: []string{"app.example.com"}})
	if err != nil {
		t.Fatal(err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := p.NewServer("", &tls.Config{Certificates: []tls.Certificate{cert}})
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	addr := l.Addr().String()
	host, _, _ := net.SplitHostPort(addr)

	c, err := netsmtp.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Hello("test"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := c.Extension("STARTTLS"); !ok {
		t.Fatal("server did not advertise STARTTLS")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("could not load broker cert into pool")
	}
	// Verify the broker cert by its SAN ("bh-mail"); the dial IP is irrelevant.
	if err := c.StartTLS(&tls.Config{ServerName: "bh-mail", RootCAs: pool}); err != nil {
		t.Fatalf("STARTTLS: %v", err)
	}
	// Stock PlainAuth now proceeds because the connection is TLS. host must match
	// the dialed server name.
	if err := c.Auth(netsmtp.PlainAuth("", creds.Username, creds.Password, host)); err != nil {
		t.Fatalf("PlainAuth after STARTTLS: %v", err)
	}
	if err := c.Mail("noreply@app.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := c.Rcpt("u@dest.example"); err != nil {
		t.Fatal(err)
	}
	w, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w, sampleMsg)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	_ = c.Quit()
	if fwd.count() != 1 {
		t.Fatalf("forwarder got %d, want 1", fwd.count())
	}
}
