package secret

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/store"
)

func newVault(t *testing.T) (*Vault, *store.Store, domain.ID) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	w := &domain.Beamhall{Slug: "eng", DisplayName: "Eng", Status: domain.BeamhallActive, CreatedBy: store.NewID()}
	sc := &domain.SecurityContext{RuntimeClass: domain.RuntimeRunsc, Template: domain.TemplateWebApp}
	if err := st.CreateBeamhall(ctx, w, sc); err != nil {
		t.Fatalf("CreateBeamhall: %v", err)
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity: %v", err)
	}
	return NewVault(id, st), st, w.ID
}

func TestSetInjectRoundTrip(t *testing.T) {
	ctx := context.Background()
	v, st, wc := newVault(t)

	ref := domain.SecretRef{BeamhallID: wc, BeamID: "beam-1", Key: "DATABASE_URL"}
	want := []byte("postgres://user:p@ss@db:5432/beam")

	sec, err := v.Set(ctx, ref, want, store.NewID())
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if sec.Version != 1 {
		t.Fatalf("first write version = %d, want 1", sec.Version)
	}

	// At rest it is ciphertext, not plaintext.
	ct, err := st.GetSecretValue(ctx, sec.ValueRef)
	if err != nil {
		t.Fatalf("GetSecretValue: %v", err)
	}
	if bytes.Contains(ct, want) {
		t.Fatal("stored blob contains plaintext — not encrypted at rest")
	}

	// Inject decrypts it back into a driver mount.
	mounts, err := v.Inject(ctx, []domain.SecretRef{ref})
	if err != nil {
		t.Fatalf("Inject: %v", err)
	}
	if len(mounts) != 1 {
		t.Fatalf("got %d mounts, want 1", len(mounts))
	}
	if mounts[0].MountPath != "/run/secrets/DATABASE_URL" {
		t.Fatalf("mount path = %q", mounts[0].MountPath)
	}
	if !bytes.Equal(mounts[0].Value, want) {
		t.Fatalf("injected value = %q, want %q", mounts[0].Value, want)
	}
}

func TestSetRewriteBumpsVersionAndGCsOldBlob(t *testing.T) {
	ctx := context.Background()
	v, st, wc := newVault(t)
	ref := domain.SecretRef{BeamhallID: wc, BeamID: "beam-1", Key: "API_KEY"}

	first, err := v.Set(ctx, ref, []byte("v1-value"), store.NewID())
	if err != nil {
		t.Fatalf("Set v1: %v", err)
	}
	second, err := v.Set(ctx, ref, []byte("v2-value-rotated"), store.NewID())
	if err != nil {
		t.Fatalf("Set v2: %v", err)
	}
	if second.Version != 2 {
		t.Fatalf("rewrite version = %d, want 2", second.Version)
	}
	if second.ValueRef == first.ValueRef {
		t.Fatal("rewrite reused the ciphertext ref; want a fresh blob")
	}

	// The superseded ciphertext is gone.
	if _, err := st.GetSecretValue(ctx, first.ValueRef); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("old blob lookup err = %v, want ErrNotFound (GC failed)", err)
	}
	// Inject returns the rotated value.
	mounts, err := v.Inject(ctx, []domain.SecretRef{ref})
	if err != nil {
		t.Fatalf("Inject: %v", err)
	}
	if got := string(mounts[0].Value); got != "v2-value-rotated" {
		t.Fatalf("injected value = %q, want rotated", got)
	}
}

func TestInjectMissingRefFails(t *testing.T) {
	ctx := context.Background()
	v, _, wc := newVault(t)
	_, err := v.Inject(ctx, []domain.SecretRef{{BeamhallID: wc, BeamID: "beam-1", Key: "NOPE"}})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Inject(missing) err = %v, want ErrNotFound", err)
	}
}

func TestDeleteRemovesMetadataAndBlob(t *testing.T) {
	ctx := context.Background()
	v, st, wc := newVault(t)
	ref := domain.SecretRef{BeamhallID: wc, BeamID: "beam-1", Key: "TOKEN"}

	sec, err := v.Set(ctx, ref, []byte("secret-token"), store.NewID())
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := v.Delete(ctx, ref); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := st.GetSecret(ctx, ref.BeamhallID, ref.BeamID, ref.Key, ref.Channel); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("metadata after delete err = %v, want ErrNotFound", err)
	}
	if _, err := st.GetSecretValue(ctx, sec.ValueRef); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("blob after delete err = %v, want ErrNotFound", err)
	}
	// Delete is idempotent.
	if err := v.Delete(ctx, ref); err != nil {
		t.Fatalf("Delete (second) = %v, want nil", err)
	}
}

func TestValueSealedToKey(t *testing.T) {
	ctx := context.Background()
	v, st, wc := newVault(t)
	ref := domain.SecretRef{BeamhallID: wc, BeamID: "beam-1", Key: "K"}
	if _, err := v.Set(ctx, ref, []byte("confidential"), store.NewID()); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// A different key cannot read the value: Inject through a vault sealed by a
	// foreign identity (same store) must fail to decrypt.
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity: %v", err)
	}
	foreign := NewVault(other, st)
	if _, err := foreign.Inject(ctx, []domain.SecretRef{ref}); err == nil {
		t.Fatal("foreign-key vault decrypted the value; want failure")
	}
}

func TestLoadOrCreateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")

	id1, generated, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("LoadOrCreateKey (create): %v", err)
	}
	if !generated {
		t.Fatal("first call generated=false, want true")
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat key: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key perm = %o, want 600", perm)
	}

	id2, generated, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("LoadOrCreateKey (load): %v", err)
	}
	if generated {
		t.Fatal("second call generated=true, want false (key existed)")
	}
	if id1.Recipient().String() != id2.Recipient().String() {
		t.Fatal("reloaded identity differs from the persisted one")
	}

	// A malformed key is a hard error, never silently regenerated.
	bad := filepath.Join(t.TempDir(), "bad.key")
	if err := os.WriteFile(bad, []byte("not-an-age-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreateKey(bad); err == nil {
		t.Fatal("malformed key returned no error")
	}
}

func TestScrubber(t *testing.T) {
	s := NewScrubber([][]byte{
		[]byte("supersecretpassword"),
		[]byte("tok"),                 // too short — skipped
		[]byte("supersecret"),         // substring of the first
		[]byte("supersecretpassword"), // duplicate
	})
	in := "log line: pw=supersecretpassword token=tok other=supersecret end"
	out := s.ScrubString(in)

	if strings.Contains(out, "supersecretpassword") || strings.Contains(out, "supersecret") {
		t.Fatalf("value leaked through scrubber: %q", out)
	}
	if !strings.Contains(out, "tok") {
		t.Fatalf("short value should not be redacted: %q", out)
	}
	if !strings.Contains(out, Mask) {
		t.Fatalf("nothing was masked: %q", out)
	}
	// Empty scrubber is a no-op.
	if got := NewScrubber(nil).ScrubString(in); got != in {
		t.Fatalf("empty scrubber changed input: %q", got)
	}
}

func TestScrubberForScopesToBeam(t *testing.T) {
	ctx := context.Background()
	v, _, wc := newVault(t)

	const beam = domain.ID("beam-1")
	mustSet(t, v, domain.SecretRef{BeamhallID: wc, BeamID: beam, Key: "APP_SECRET"}, "beam-scoped-value")
	mustSet(t, v, domain.SecretRef{BeamhallID: wc, BeamID: "", Key: "SHARED"}, "beamhall-wide-value")
	mustSet(t, v, domain.SecretRef{BeamhallID: wc, BeamID: "beam-2", Key: "OTHER"}, "other-beam-value")

	sc, err := v.ScrubberFor(ctx, wc, beam)
	if err != nil {
		t.Fatalf("ScrubberFor: %v", err)
	}
	out := sc.ScrubString("a=beam-scoped-value b=beamhall-wide-value c=other-beam-value")

	if strings.Contains(out, "beam-scoped-value") {
		t.Fatalf("beam-scoped value not redacted: %q", out)
	}
	if strings.Contains(out, "beamhall-wide-value") {
		t.Fatalf("beamhall-wide value not redacted: %q", out)
	}
	if !strings.Contains(out, "other-beam-value") {
		t.Fatalf("another beam's value was redacted (over-broad scope): %q", out)
	}
}

func mustSet(t *testing.T, v *Vault, ref domain.SecretRef, value string) {
	t.Helper()
	if _, err := v.Set(context.Background(), ref, []byte(value), store.NewID()); err != nil {
		t.Fatalf("Set %q: %v", ref.Key, err)
	}
}

func TestLoadKeyIsLoadOnly(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "secret.key")

	// Load-only: a missing key is a hard error and nothing is created.
	if _, err := LoadKey(missing); err == nil {
		t.Fatal("LoadKey on a missing file should fail (production must supply the key)")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("LoadKey created a key — it must never generate")
	}

	// A real key loads to the same identity LoadOrCreateKey persisted.
	want, _, err := LoadOrCreateKey(missing)
	if err != nil {
		t.Fatal(err)
	}
	got, err := LoadKey(missing)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	if got.Recipient().String() != want.Recipient().String() {
		t.Fatal("LoadKey returned a different identity")
	}

	// A malformed key is a hard error.
	bad := filepath.Join(dir, "bad.key")
	os.WriteFile(bad, []byte("nope"), 0o600)
	if _, err := LoadKey(bad); err == nil {
		t.Fatal("LoadKey accepted a malformed key")
	}
}
