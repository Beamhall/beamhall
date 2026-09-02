package store

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/Beamhall/beamhall/internal/domain"
)

func TestControlKeyRoundTrip(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()

	if _, ok, err := s.GetControlKey(ctx, "app_assertion_es256"); err != nil || ok {
		t.Fatalf("empty store: ok=%v err=%v", ok, err)
	}
	sealed := []byte{0x00, 0x01, 0xfe, 0xff, 'k'}
	if err := s.PutControlKey(ctx, "app_assertion_es256", sealed); err != nil {
		t.Fatalf("PutControlKey: %v", err)
	}
	got, ok, err := s.GetControlKey(ctx, "app_assertion_es256")
	if err != nil || !ok {
		t.Fatalf("GetControlKey: ok=%v err=%v", ok, err)
	}
	if !bytes.Equal(got, sealed) {
		t.Fatalf("round trip mismatch: %x != %x", got, sealed)
	}
	// A key that workloads verify against must never be silently replaced.
	if err := s.PutControlKey(ctx, "app_assertion_es256", []byte("other")); !errors.Is(err, ErrConflict) {
		t.Fatalf("second Put: want ErrConflict, got %v", err)
	}
}

func TestSetReleaseAgentTools(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	w := mustCreateBeamhall(t, s, "hall")
	a := mustCreateBeam(t, s, w.ID, "app")
	b := &domain.Build{BeamID: a.ID, SourceRef: "sha", Status: domain.BuildSucceeded}
	if err := s.CreateBuild(ctx, b); err != nil {
		t.Fatalf("CreateBuild: %v", err)
	}
	_, sc := newBeamhall("ignored")
	r := &domain.Release{
		BeamID: a.ID, BuildID: b.ID,
		ConfigSnapshot:      map[string]string{"PORT": "8080"},
		SecurityProfileSnap: *sc,
		Status:              domain.ReleasePending,
	}
	if err := s.CreateRelease(ctx, r); err != nil {
		t.Fatalf("CreateRelease: %v", err)
	}

	if err := s.SetReleaseAgentTools(ctx, r.ID, true); err != nil {
		t.Fatalf("SetReleaseAgentTools(true): %v", err)
	}
	got, err := s.GetRelease(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ConfigSnapshot["agent_tools"] != "true" {
		t.Fatalf("flag not persisted: %+v", got.ConfigSnapshot)
	}
	if got.ConfigSnapshot["PORT"] != "8080" {
		t.Fatalf("existing snapshot keys must survive: %+v", got.ConfigSnapshot)
	}

	if err := s.SetReleaseAgentTools(ctx, r.ID, false); err != nil {
		t.Fatalf("SetReleaseAgentTools(false): %v", err)
	}
	got, err = s.GetRelease(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := got.ConfigSnapshot["agent_tools"]; present {
		t.Fatalf("flag not cleared: %+v", got.ConfigSnapshot)
	}

	if err := s.SetReleaseAgentTools(ctx, "missing-id", true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing release: want ErrNotFound, got %v", err)
	}
}
