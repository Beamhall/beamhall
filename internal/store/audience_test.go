package store

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/Beamhall/beamhall/internal/domain"
)

func TestBeamAudienceRoundTrip(t *testing.T) {
	s, clock := openTestStore(t)
	ctx := context.Background()
	w := mustCreateBeamhall(t, s, "wc")
	a := mustCreateBeam(t, s, w.ID, "tracker")

	pub := domain.BeamAudience{
		BeamID:     a.ID,
		BeamhallID: w.ID,
		Audience: domain.Audience{
			Everyone:   false,
			Groups:     []string{"finance", "hr"},
			Identities: []domain.ID{"id-1"},
		},
		PublishedBy: "it-admin",
	}
	if err := s.PutBeamAudience(ctx, pub); err != nil {
		t.Fatalf("PutBeamAudience: %v", err)
	}
	got, err := s.GetBeamAudience(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetBeamAudience: %v", err)
	}
	if !reflect.DeepEqual(got.Audience, pub.Audience) || got.PublishedBy != "it-admin" || got.BeamhallID != w.ID {
		t.Errorf("audience mismatch: %+v", got)
	}
	if !got.PublishedAt.Equal(clock.Now()) {
		t.Errorf("PublishedAt = %v, want %v", got.PublishedAt, clock.Now())
	}

	list, err := s.ListBeamAudiences(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListBeamAudiences: %v (len %d)", err, len(list))
	}
	byHall, err := s.ListBeamAudiencesByBeamhall(ctx, w.ID)
	if err != nil || len(byHall) != 1 {
		t.Fatalf("ListBeamAudiencesByBeamhall: %v (len %d)", err, len(byHall))
	}
}

// A re-publish replaces the audience but must keep the original publisher and
// publication time — they answer "who first exposed this app, and when".
func TestBeamAudienceRepublishKeepsFirstPublication(t *testing.T) {
	s, clock := openTestStore(t)
	ctx := context.Background()
	w := mustCreateBeamhall(t, s, "wc")
	a := mustCreateBeam(t, s, w.ID, "tracker")

	first := clock.Now()
	if err := s.PutBeamAudience(ctx, domain.BeamAudience{
		BeamID: a.ID, BeamhallID: w.ID,
		Audience: domain.Audience{Everyone: true}, PublishedBy: "alice",
	}); err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Hour)
	if err := s.PutBeamAudience(ctx, domain.BeamAudience{
		BeamID: a.ID, BeamhallID: w.ID,
		Audience: domain.Audience{Groups: []string{"hr"}}, PublishedBy: "bob",
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetBeamAudience(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Audience, domain.Audience{Groups: []string{"hr"}}) {
		t.Errorf("audience not replaced: %+v", got.Audience)
	}
	if got.PublishedBy != "alice" || !got.PublishedAt.Equal(first) {
		t.Errorf("first publication not preserved: by=%s at=%v", got.PublishedBy, got.PublishedAt)
	}
	if !got.UpdatedAt.Equal(clock.Now()) {
		t.Errorf("UpdatedAt = %v, want %v", got.UpdatedAt, clock.Now())
	}
}

func TestBeamAudienceNotFoundAndIdempotentDelete(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	if _, err := s.GetBeamAudience(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetBeamAudience on unpublished beam: got %v, want ErrNotFound", err)
	}
	if err := s.DeleteBeamAudience(ctx, "missing"); err != nil {
		t.Errorf("DeleteBeamAudience on unpublished beam: %v", err)
	}

	w := mustCreateBeamhall(t, s, "wc")
	a := mustCreateBeam(t, s, w.ID, "tracker")
	if err := s.PutBeamAudience(ctx, domain.BeamAudience{
		BeamID: a.ID, BeamhallID: w.ID, Audience: domain.Audience{Everyone: true},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteBeamAudience(ctx, a.ID); err != nil {
		t.Fatalf("DeleteBeamAudience: %v", err)
	}
	if _, err := s.GetBeamAudience(ctx, a.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("publication survived delete: %v", err)
	}
}
