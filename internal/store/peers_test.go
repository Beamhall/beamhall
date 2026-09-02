package store

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/Beamhall/beamhall/internal/domain"
)

func TestBeamPeersRoundTrip(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	w := mustCreateBeamhall(t, s, "wc")
	a := mustCreateBeam(t, s, w.ID, "caller")
	b := mustCreateBeam(t, s, w.ID, "target")

	grant := domain.BeamPeers{
		SourceBeamID: a.ID,
		BeamhallID:   w.ID,
		Peers:        domain.PeerSet{Beams: []domain.ID{b.ID}, External: []string{"api.corp.internal"}},
		UpdatedBy:    "it-admin",
	}
	if err := s.PutBeamPeers(ctx, grant); err != nil {
		t.Fatalf("PutBeamPeers: %v", err)
	}
	got, err := s.GetBeamPeers(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetBeamPeers: %v", err)
	}
	if !reflect.DeepEqual(got.Peers, grant.Peers) || got.BeamhallID != w.ID || got.UpdatedBy != "it-admin" {
		t.Errorf("grant mismatch: %+v", got)
	}
	if !got.Peers.AllowsBeam(b.ID) || got.Peers.AllowsBeam("other") {
		t.Error("AllowsBeam wrong")
	}

	// Set-replace: the new set fully supersedes the old (revocation is an
	// upsert with the entry gone).
	grant.Peers = domain.PeerSet{External: []string{"10.20.0.0/16"}}
	if err := s.PutBeamPeers(ctx, grant); err != nil {
		t.Fatalf("PutBeamPeers (replace): %v", err)
	}
	got, err = s.GetBeamPeers(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Peers.AllowsBeam(b.ID) || len(got.Peers.External) != 1 {
		t.Errorf("replace did not supersede: %+v", got.Peers)
	}

	list, err := s.ListBeamPeers(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListBeamPeers: %v (len %d)", err, len(list))
	}
	if err := s.DeleteBeamPeers(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetBeamPeers(ctx, a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete want ErrNotFound, got %v", err)
	}
	if err := s.DeleteBeamPeers(ctx, a.ID); err != nil {
		t.Fatalf("delete must be idempotent: %v", err)
	}
}

func TestC2CKeyMintMutexAndLookup(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	w := mustCreateBeamhall(t, s, "wc")
	a := mustCreateBeam(t, s, w.ID, "caller")

	created, err := s.InsertC2CKey(ctx, a.ID, "hash-1")
	if err != nil || !created {
		t.Fatalf("first insert: created=%v err=%v", created, err)
	}
	// The ON CONFLICT DO NOTHING insert is the mint mutex: the loser must see
	// created=false and NOT overwrite the winner's hash.
	created, err = s.InsertC2CKey(ctx, a.ID, "hash-2")
	if err != nil || created {
		t.Fatalf("second insert: created=%v err=%v", created, err)
	}
	beamID, err := s.GetC2CKeyBeam(ctx, "hash-1")
	if err != nil || beamID != a.ID {
		t.Fatalf("lookup by winning hash: %v %v", beamID, err)
	}
	if _, err := s.GetC2CKeyBeam(ctx, "hash-2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("losing hash must not resolve, got %v", err)
	}
	has, err := s.HasC2CKey(ctx, a.ID)
	if err != nil || !has {
		t.Fatalf("HasC2CKey: %v %v", has, err)
	}
	if err := s.DeleteC2CKey(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	has, err = s.HasC2CKey(ctx, a.ID)
	if err != nil || has {
		t.Fatalf("after delete HasC2CKey: %v %v", has, err)
	}
	if err := s.DeleteC2CKey(ctx, a.ID); err != nil {
		t.Fatalf("delete must be idempotent: %v", err)
	}
}
