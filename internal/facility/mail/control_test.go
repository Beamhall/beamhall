package mail

import (
	"context"
	"net/http/httptest"
	"testing"
)

func TestControlChannelRoundTrip(t *testing.T) {
	token := "secret-token"
	cs := NewControlServer(token, 0)
	fwd := &fakeForwarder{}
	p := New(WithForwarder(fwd), WithAuditSink(cs.Record))
	cs.Attach(p)
	ts := httptest.NewServer(cs.Handler())
	defer ts.Close()
	client := NewClient(ts.URL, token)
	ctx := context.Background()

	enabled, _, err := client.Status(ctx)
	if err != nil || !enabled {
		t.Fatalf("status: enabled=%v err=%v", enabled, err)
	}

	creds, err := client.Provision(ctx, ProvisionRequest{BeamID: "B1", AllowedSenders: []string{"app.example.com"}})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if creds.Username != "beam-B1" || creds.Password == "" {
		t.Fatalf("creds = %+v", creds)
	}

	addr := startRelay(t, p)
	if err := sendVia(addr, creds.Username, creds.Password, "noreply@app.example.com", "u@dest.example", sampleMsg); err != nil {
		t.Fatalf("send: %v", err)
	}
	if fwd.count() != 1 {
		t.Fatalf("forwarder got %d, want 1", fwd.count())
	}

	events, hi, err := client.PullEvents(ctx, 0)
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if len(events) != 1 || events[0].Result != "sent" || events[0].BeamID != "B1" || events[0].Seq != 1 {
		t.Fatalf("events = %+v", events)
	}
	if hi < 1 {
		t.Fatalf("high-water = %d", hi)
	}
	more, _, err := client.PullEvents(ctx, hi)
	if err != nil {
		t.Fatal(err)
	}
	if len(more) != 0 {
		t.Fatalf("expected no new events after cursor, got %d", len(more))
	}

	if err := client.SetSenders(ctx, "B1", []string{"new.example"}); err != nil {
		t.Fatalf("set senders: %v", err)
	}
	if err := sendVia(addr, creds.Username, creds.Password, "x@old.example", "u@dest.example", sampleMsg); err == nil {
		t.Fatal("old sender should now be rejected")
	}
	if err := sendVia(addr, creds.Username, creds.Password, "x@new.example", "u@dest.example", sampleMsg); err != nil {
		t.Fatalf("new sender should work: %v", err)
	}

	if err := client.Deregister(ctx, "B1"); err != nil {
		t.Fatalf("deregister: %v", err)
	}
	if err := sendVia(addr, creds.Username, creds.Password, "x@new.example", "u@dest.example", sampleMsg); err == nil {
		t.Fatal("after deregister, auth should fail")
	}
}

func TestControlChannelAuth(t *testing.T) {
	cs := NewControlServer("right-token", 0)
	p := New(WithForwarder(&fakeForwarder{}))
	cs.Attach(p)
	ts := httptest.NewServer(cs.Handler())
	defer ts.Close()
	bad := NewClient(ts.URL, "wrong-token")
	if _, _, err := bad.Status(context.Background()); err == nil {
		t.Fatal("expected auth failure with wrong token")
	}
}

func TestRegisterHashedValidatesHash(t *testing.T) {
	p := New(WithForwarder(&fakeForwarder{}))
	if err := p.RegisterHashed("B", "beam-B", "nothex!!", nil, Limits{}); err == nil {
		t.Fatal("expected invalid-hash error")
	}
	if err := p.RegisterHashed("B", "beam-B", PasswordHashHex("pw"), []string{"x.com"}, Limits{}); err != nil {
		t.Fatalf("valid hash should register: %v", err)
	}
}
