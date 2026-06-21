package store

import (
	"context"
	"errors"
	"testing"

	"github.com/Beamhall/beamhall/internal/domain"
)

// TestMutateMissingRowIsNotFound asserts that every single-row mutation wrapper
// reports ErrNotFound when its target id does not exist, instead of silently
// succeeding as a zero-row no-op. Without this, a typoed/stale id (e.g. a
// promote pointed at the wrong release) would report success and leave the
// orchestrator's persisted state inconsistent — see the promote scenario below.
func TestMutateMissingRowIsNotFound(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()

	const missing = domain.ID("does-not-exist")

	cases := []struct {
		name string
		op   func() error
	}{
		{"UpdateBeam", func() error {
			return s.UpdateBeam(ctx, &domain.Beam{ID: missing, Slug: "x"})
		}},
		{"UpdateBuild", func() error {
			return s.UpdateBuild(ctx, domain.Build{ID: missing, Status: domain.BuildSucceeded})
		}},
		{"UpdateIdentity", func() error {
			return s.UpdateIdentity(ctx, domain.Identity{ID: missing, Email: "e@x", Status: "active"})
		}},
		{"ActivateRelease", func() error {
			return s.ActivateRelease(ctx, missing)
		}},
		{"UpdateReleaseStatus", func() error {
			return s.UpdateReleaseStatus(ctx, missing, domain.ReleaseSuperseded)
		}},
		{"SetReleaseRoute", func() error {
			return s.SetReleaseRoute(ctx, missing, "some-route")
		}},
		{"UpdateResource", func() error {
			return s.UpdateResource(ctx, &domain.Resource{ID: missing, Status: domain.ResourceReady})
		}},
		{"RetireRoute", func() error {
			return s.RetireRoute(ctx, missing)
		}},
		{"UpdateBeamhall", func() error {
			return s.UpdateBeamhall(ctx, &domain.Beamhall{ID: missing, Slug: "x"})
		}},
		{"UpdateSecurityContext", func() error {
			return s.UpdateSecurityContext(ctx, domain.SecurityContext{ID: missing})
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.op(); !errors.Is(err, ErrNotFound) {
				t.Fatalf("%s(missing id): got err=%v, want ErrNotFound", tc.name, err)
			}
		})
	}
}

// TestUpdateExistingRowSucceeds anchors the positive side: a mutation against a
// real id still returns nil. In particular RetireRoute stays idempotent — its
// WHERE clause matches a retired row, so re-retiring is a 1-row update, not a
// not-found.
func TestUpdateExistingRowSucceeds(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()

	wc := mustCreateBeamhall(t, s, "eng")
	beam := mustCreateBeam(t, s, wc.ID, "foo")

	beam.State = domain.StateBuilding
	if err := s.UpdateBeam(ctx, beam); err != nil {
		t.Fatalf("UpdateBeam(existing): %v", err)
	}

	rt := &domain.Route{
		BeamID:      beam.ID,
		Kind:        domain.RoutePreview,
		Hostname:    "foo.preview.example",
		BackendAddr: "10.0.0.2:8080",
		Status:      domain.RouteActive,
	}
	if err := s.CreateRoute(ctx, rt); err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}
	if err := s.RetireRoute(ctx, rt.ID); err != nil {
		t.Fatalf("RetireRoute(active): %v", err)
	}
	if err := s.RetireRoute(ctx, rt.ID); err != nil {
		t.Fatalf("RetireRoute(already retired) must stay idempotent, got: %v", err)
	}
}

// TestPromoteToStaleReleaseIsCaught is the concrete hazard the not-found guard
// closes: activating a release id that does not exist (a typo or a stale
// pointer) used to succeed silently. Now it surfaces, so the orchestrator never
// flips a Beam's CurrentReleaseID to a dangling id believing it persisted.
func TestPromoteToStaleReleaseIsCaught(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()

	wc := mustCreateBeamhall(t, s, "eng")
	beam := mustCreateBeam(t, s, wc.ID, "foo")
	b := &domain.Build{BeamID: beam.ID, Status: domain.BuildSucceeded, TriggeredBy: NewID()}
	if err := s.CreateBuild(ctx, b); err != nil {
		t.Fatalf("CreateBuild: %v", err)
	}
	rel := &domain.Release{BeamID: beam.ID, BuildID: b.ID, Status: domain.ReleasePending}
	if err := s.CreateRelease(ctx, rel); err != nil {
		t.Fatalf("CreateRelease: %v", err)
	}

	stale := rel.ID + "X"
	if err := s.ActivateRelease(ctx, stale); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ActivateRelease(stale id): got err=%v, want ErrNotFound", err)
	}
}
