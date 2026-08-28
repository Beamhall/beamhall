package mail

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeSmarthost is a minimal raw SMTP server that greets and answers EHLO
// without ever advertising STARTTLS — simulating either an upstream that
// genuinely lacks TLS support or a network attacker stripping the
// "250-STARTTLS" capability line from the EHLO response. It records every
// command it receives after EHLO so the test can prove AUTH (and therefore
// the smarthost credential) was never sent.
type fakeSmarthost struct {
	ln       net.Listener
	commands chan string
}

func newFakeSmarthost(t *testing.T) *fakeSmarthost {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeSmarthost{ln: ln, commands: make(chan string, 8)}
	t.Cleanup(func() { _ = ln.Close() })
	go s.serveOne(t)
	return s
}

func (s *fakeSmarthost) serveOne(t *testing.T) {
	conn, err := s.ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	r := bufio.NewReader(conn)
	if _, err := conn.Write([]byte("220 fake.smarthost ESMTP\r\n")); err != nil {
		return
	}
	line, err := r.ReadString('\n')
	if err != nil || !strings.HasPrefix(strings.ToUpper(line), "EHLO") {
		return
	}
	// AUTH is advertised but STARTTLS is not — the exact shape of the attack:
	// a stripped STARTTLS capability line, with AUTH still present so the
	// pre-fix code happily sends the credential in cleartext.
	if _, err := conn.Write([]byte("250-fake.smarthost\r\n250 AUTH PLAIN\r\n")); err != nil {
		return
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		s.commands <- strings.TrimSpace(line)
	}
}

func (s *fakeSmarthost) addr() string { return s.ln.Addr().String() }

// TestForwardAbortsWhenSmarthostDoesNotAdvertiseSTARTTLS proves the fix:
// when the smarthost's EHLO response omits STARTTLS (missing support, or a
// stripped capability line), Forward must abort delivery instead of silently
// sending AUTH PLAIN with the shared credential in cleartext.
func TestForwardAbortsWhenSmarthostDoesNotAdvertiseSTARTTLS(t *testing.T) {
	sh := newFakeSmarthost(t)

	f := NewSMTPForwarder(ProviderConfig{
		Smarthost: sh.addr(),
		Username:  "provider-user",
		Password:  "provider-secret",
	})

	err := f.Forward(context.Background(), Envelope{
		From: "noreply@app.example.com",
		To:   []string{"u@dest.example"},
		Data: []byte(sampleMsg),
	})
	if err == nil {
		t.Fatal("Forward succeeded against a smarthost with no STARTTLS; want it to fail closed")
	}
	if !strings.Contains(err.Error(), "starttls") && !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("Forward failed for the wrong reason: %v", err)
	}

	select {
	case cmd := <-sh.commands:
		t.Fatalf("smarthost received command %q after EHLO; want the connection abandoned before any AUTH/credential exposure", cmd)
	case <-time.After(200 * time.Millisecond):
	}
}
