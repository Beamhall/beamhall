package orch

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/facility/mail"
)

// fakeEmailProv satisfies EmailProvisioner, recording control-channel calls
// without a real bh-mail broker.
type fakeEmailProv struct {
	provisioned  []string
	deregistered []string
	senders      map[string][]string
}

func (f *fakeEmailProv) Provision(_ context.Context, req mail.ProvisionRequest) (mail.Credentials, error) {
	f.provisioned = append(f.provisioned, req.BeamID)
	return mail.Credentials{Username: "beam-" + req.BeamID, Password: "pw-" + req.BeamID}, nil
}
func (f *fakeEmailProv) RegisterHashed(_ context.Context, _, _, _ string, _ []string, _ mail.Limits) error {
	return nil
}
func (f *fakeEmailProv) Deregister(_ context.Context, beamID string) error {
	f.deregistered = append(f.deregistered, beamID)
	return nil
}
func (f *fakeEmailProv) SetSenders(_ context.Context, beamID string, allowed []string) error {
	if f.senders == nil {
		f.senders = map[string][]string{}
	}
	f.senders[beamID] = allowed
	return nil
}
func (f *fakeEmailProv) SetProvider(_ context.Context, _ mail.ProviderConfig) error { return nil }
func (f *fakeEmailProv) PullEvents(_ context.Context, after int64) ([]mail.SeqEvent, int64, error) {
	return nil, after, nil
}
func (f *fakeEmailProv) Status(_ context.Context) (bool, int64, error) { return true, 0, nil }
func (f *fakeEmailProv) CACert(_ context.Context) (string, error) {
	return "-----BEGIN CERTIFICATE-----\nFAKECERT\n-----END CERTIFICATE-----\n", nil
}

func enableEmail(w *world, fe *fakeEmailProv) {
	WithEmail(fe, EmailConfig{
		BeamHost: "bh-mail",
		BeamPort: 587,
		Provider: mail.ProviderConfig{Smarthost: "smtp.example.com:587", Username: "u", Password: "p"},
		Limits:   mail.Limits{PerDay: 300, Burst: 20},
		Attach:   func(_ context.Context, _ string) error { return nil },
	})(w.o)
}

func TestProvisionEmailSealsCredsAndInjects(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	fe := &fakeEmailProv{}
	enableEmail(w, fe)

	if !w.o.EmailEnabled() {
		t.Fatal("email facility should be enabled")
	}

	beam, err := w.o.CreateBeam(ctx, w.build, w.bh.ID, "tracker", "Tracker", "node")
	if err != nil {
		t.Fatal(err)
	}

	keys, err := w.o.ProvisionEmail(ctx, w.build, w.bh.ID, beam.ID)
	if err != nil {
		t.Fatalf("ProvisionEmail: %v", err)
	}
	if len(keys) != 5 {
		t.Fatalf("keys = %v", keys)
	}
	if len(fe.provisioned) != 1 {
		t.Fatalf("broker provisioned = %v", fe.provisioned)
	}

	// Idempotent: re-provision returns keys without a second broker mint.
	if _, err := w.o.ProvisionEmail(ctx, w.build, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("re-provision: %v", err)
	}
	if len(fe.provisioned) != 1 {
		t.Fatalf("idempotency broke: %v", fe.provisioned)
	}

	// Resource row: ResourceEmail, ChannelShared, hash + username in Spec.
	resources, err := w.st.ListResourcesByBeam(ctx, beam.ID)
	if err != nil || len(resources) != 1 {
		t.Fatalf("resources = %v err %v", resources, err)
	}
	r := resources[0]
	if r.Type != domain.ResourceEmail || r.Channel != domain.ChannelShared || r.Status != domain.ResourceReady {
		t.Fatalf("resource row = %+v", r)
	}
	if r.Spec["username"] != "beam-"+string(beam.ID) || r.Spec["pass_hash"] == "" {
		t.Fatalf("resource spec = %+v", r.Spec)
	}
	// The password hash is the SHA-256 of the minted password (not the plaintext).
	if r.Spec["pass_hash"] != mail.PasswordHashHex("pw-"+string(beam.ID)) {
		t.Fatalf("pass_hash mismatch: %q", r.Spec["pass_hash"])
	}

	// The four SMTP_* secrets inject as file mounts on the next deploy (both
	// channels, since ChannelShared).
	if _, err := w.o.DeployBeam(ctx, w.build, w.bh.ID, beam.ID, DeployRequest{ImageDigest: "sha256:x"}); err != nil {
		t.Fatal(err)
	}
	spec := w.drv.deploys[len(w.drv.deploys)-1]
	mounts := map[string]string{}
	for _, m := range spec.Secrets {
		mounts[m.MountPath] = string(m.Value)
	}
	if mounts["/run/secrets/SMTP_HOST"] != "bh-mail" || mounts["/run/secrets/SMTP_PORT"] != "587" {
		t.Fatalf("smtp endpoint mounts = %+v", mounts)
	}
	if mounts["/run/secrets/SMTP_USER"] != "beam-"+string(beam.ID) || mounts["/run/secrets/SMTP_PASS"] != "pw-"+string(beam.ID) {
		t.Fatalf("smtp cred mounts = %+v", mounts)
	}
	if !strings.Contains(mounts["/run/secrets/SMTP_CA"], "BEGIN CERTIFICATE") {
		t.Fatalf("SMTP_CA not injected: %q", mounts["/run/secrets/SMTP_CA"])
	}

	// The SMTP password never appears in the audit chain.
	recs, _ := w.st.ListAuditEvents(ctx, 0, 50)
	for _, rec := range recs {
		if rec.Event.Reason == "pw-"+string(beam.ID) {
			t.Fatalf("password leaked into audit: %+v", rec.Event)
		}
	}
}

func TestSetEmailSendersRequiresITAndPersists(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	fe := &fakeEmailProv{}
	enableEmail(w, fe)

	beam, err := w.o.CreateBeam(ctx, w.build, w.bh.ID, "tracker", "Tracker", "node")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.o.ProvisionEmail(ctx, w.build, w.bh.ID, beam.ID); err != nil {
		t.Fatal(err)
	}

	// A builder (no it_admin) cannot set senders.
	if err := w.o.SetEmailSenders(ctx, w.build, w.bh.ID, beam.ID, []string{"app.example.com"}); err == nil {
		t.Fatal("builder should not be able to set email senders")
	}

	// IT can; the broker is updated and the allowlist persists in the resource row.
	it := Actor{ITAdmin: true}
	if err := w.o.SetEmailSenders(ctx, it, w.bh.ID, beam.ID, []string{"app.example.com", "noreply@app.example.com"}); err != nil {
		t.Fatalf("SetEmailSenders (IT): %v", err)
	}
	if got := fe.senders[string(beam.ID)]; len(got) != 2 {
		t.Fatalf("broker senders = %v", got)
	}
	resources, _ := w.st.ListResourcesByBeam(ctx, beam.ID)
	if resources[0].Spec["senders"] != "app.example.com,noreply@app.example.com" {
		t.Fatalf("persisted senders = %q", resources[0].Spec["senders"])
	}

	info, err := w.o.ShowEmail(ctx, w.build, w.bh.ID, beam.ID)
	if err != nil || !info.Provisioned || len(info.AllowedSenders) != 2 || info.Host != "bh-mail" {
		t.Fatalf("ShowEmail = %+v err %v", info, err)
	}
}

func TestDestroyReclaimsEmail(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	fe := &fakeEmailProv{}
	enableEmail(w, fe)

	beam := w.deployed(t, "tracker")
	if _, err := w.o.ProvisionEmail(ctx, w.build, w.bh.ID, beam.ID); err != nil {
		t.Fatal(err)
	}
	if err := w.o.DestroyBeam(ctx, w.admin, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("DestroyBeam: %v", err)
	}
	if len(fe.deregistered) != 1 || fe.deregistered[0] != string(beam.ID) {
		t.Fatalf("broker deregister = %v", fe.deregistered)
	}
}

func TestProvisionEmailDegradesClosed(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	// Wired broker but no smarthost configured → facility disabled.
	WithEmail(&fakeEmailProv{}, EmailConfig{BeamHost: "bh-mail", BeamPort: 587})(w.o)
	if w.o.EmailEnabled() {
		t.Fatal("email should be disabled without a smarthost")
	}
	beam, err := w.o.CreateBeam(ctx, w.build, w.bh.ID, "tracker", "Tracker", "node")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.o.ProvisionEmail(ctx, w.build, w.bh.ID, beam.ID); !errors.Is(err, mail.ErrNotEnabled) {
		t.Fatalf("want mail.ErrNotEnabled, got %v", err)
	}
}
