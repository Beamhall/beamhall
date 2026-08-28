package orch

import (
	"context"
	"strings"
	"testing"

	"github.com/Beamhall/beamhall/internal/upgrade"
)

type fakeStager struct {
	enabled        bool
	staged         string
	stagedExpected string // the expectedSHA256 Stage was called with
}

func (f *fakeStager) Enabled() bool          { return f.enabled }
func (f *fakeStager) CurrentVersion() string { return "v0.1.10" }
func (f *fakeStager) Stage(_ context.Context, version, expectedSHA256 string) (upgrade.Result, error) {
	f.staged = version
	f.stagedExpected = expectedSHA256
	return upgrade.Result{
		Version: version, SHA256: strings.Repeat("a", 64), StagedPath: "/tmp/staged",
		ApplyCmd: "APPLY-CMD", RollbackCmd: "ROLLBACK-CMD",
	}, nil
}

// aDigest is a well-formed (but arbitrary) 64-char hex SHA-256 stand-in for
// the approver's independently-obtained expected digest.
var aDigest = strings.Repeat("ab", 32)

func TestRequestUpgradeGates(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	// Self-upgrade disabled by default → refused even for it_admin.
	if _, err := w.o.RequestUpgrade(ctx, itActor(w), "v0.1.11", aDigest); err == nil {
		t.Fatal("must refuse when self-upgrade is disabled")
	}
	// Enabled but sensitive tier off → still refused.
	w.o.upgrader = &fakeStager{enabled: true}
	if _, err := w.o.RequestUpgrade(ctx, itActor(w), "v0.1.11", aDigest); err == nil {
		t.Fatal("must refuse when the sensitive tier is off")
	}
}

// TestRequestUpgradeRequiresExpectedDigest is part of the regression
// coverage:
// a malformed or missing expected_sha256 is refused at request time, before
// a sensitive four-eyes request is even filed.
func TestRequestUpgradeRequiresExpectedDigest(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.o.upgrader = &fakeStager{enabled: true}
	w.o.idpSensitive = true
	for _, bad := range []string{"", "not-a-digest", aDigest[:63]} {
		if _, err := w.o.RequestUpgrade(ctx, itActor(w), "v0.1.11", bad); err == nil {
			t.Errorf("expected_sha256 %q should have been refused", bad)
		}
	}
}

func TestFourEyesSelfUpgradeStagesOnApproval(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	fs := &fakeStager{enabled: true}
	w.o.upgrader = fs
	w.o.idpSensitive = true

	req, err := w.o.RequestUpgrade(ctx, itActor(w), "v0.1.11", aDigest)
	if err != nil {
		t.Fatalf("RequestUpgrade: %v", err)
	}
	// Requester cannot approve their own; nothing staged yet.
	if _, err := w.o.ApproveAdminAction(ctx, itActor(w), req.ID); err == nil {
		t.Fatal("four-eyes: requester approved their own upgrade")
	}
	if fs.staged != "" {
		t.Fatal("upgrade staged before approval")
	}
	// A different IT operator approves → the upgrade stages and the runbook
	// comes back in the result.
	out, err := w.o.ApproveAdminAction(ctx, secondIT(w), req.ID)
	if err != nil {
		t.Fatalf("ApproveAdminAction: %v", err)
	}
	if fs.staged != "v0.1.11" {
		t.Fatalf("not staged on approval: %q", fs.staged)
	}
	if fs.stagedExpected != aDigest {
		t.Fatalf("the approver's expected digest did not flow through to Stage: got %q, want %q", fs.stagedExpected, aDigest)
	}
	if !strings.Contains(out.Result, "APPLY-CMD") || !strings.Contains(out.Result, "ROLLBACK-CMD") {
		t.Errorf("result missing the apply/rollback runbook: %q", out.Result)
	}
}

func TestAdminDeleteUserAndGroup(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	fp := &fakeProvider{}
	w.o.idp = fp
	if err := w.o.AdminDeleteUser(ctx, itActor(w), "u-9"); err != nil {
		t.Fatalf("AdminDeleteUser: %v", err)
	}
	if fp.deletedUser != "u-9" {
		t.Fatalf("deletedUser = %q", fp.deletedUser)
	}
	if err := w.o.AdminDeleteGroup(ctx, itActor(w), "g-9"); err != nil {
		t.Fatalf("AdminDeleteGroup: %v", err)
	}
	if fp.deletedGroup != "g-9" {
		t.Fatalf("deletedGroup = %q", fp.deletedGroup)
	}
	// Non-IT refused.
	if err := w.o.AdminDeleteUser(ctx, w.build, "u-9"); err == nil {
		t.Fatal("non-IT must be refused")
	}
}
