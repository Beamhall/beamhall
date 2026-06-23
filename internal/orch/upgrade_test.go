package orch

import (
	"context"
	"strings"
	"testing"

	"github.com/Beamhall/beamhall/internal/upgrade"
)

type fakeStager struct {
	enabled bool
	staged  string
}

func (f *fakeStager) Enabled() bool          { return f.enabled }
func (f *fakeStager) CurrentVersion() string { return "v0.1.10" }
func (f *fakeStager) Stage(_ context.Context, version string) (upgrade.Result, error) {
	f.staged = version
	return upgrade.Result{
		Version: version, SHA256: strings.Repeat("a", 64), StagedPath: "/tmp/staged",
		ApplyCmd: "APPLY-CMD", RollbackCmd: "ROLLBACK-CMD",
	}, nil
}

func TestRequestUpgradeGates(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	// Self-upgrade disabled by default → refused even for it_admin.
	if _, err := w.o.RequestUpgrade(ctx, itActor(w), "v0.1.11"); err == nil {
		t.Fatal("must refuse when self-upgrade is disabled")
	}
	// Enabled but sensitive tier off → still refused.
	w.o.upgrader = &fakeStager{enabled: true}
	if _, err := w.o.RequestUpgrade(ctx, itActor(w), "v0.1.11"); err == nil {
		t.Fatal("must refuse when the sensitive tier is off")
	}
}

func TestFourEyesSelfUpgradeStagesOnApproval(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	fs := &fakeStager{enabled: true}
	w.o.upgrader = fs
	w.o.idpSensitive = true

	req, err := w.o.RequestUpgrade(ctx, itActor(w), "v0.1.11")
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
