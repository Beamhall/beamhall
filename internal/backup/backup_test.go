package backup

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Beamhall/beamhall/internal/audit"
	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/secret"
	"github.com/Beamhall/beamhall/internal/store"
)

// seedDataDir builds a populated data dir: a store with a beamhall + an audit
// event, a secret root key, and a managed git repo file.
func seedDataDir(t *testing.T) (dir string, keyBytes []byte, beamhallID domain.ID) {
	t.Helper()
	dir = t.TempDir()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(dir, dbName))
	if err != nil {
		t.Fatal(err)
	}
	bh := &domain.Beamhall{Slug: "ops", DisplayName: "Ops", Status: domain.BeamhallActive,
		Quota: domain.ResourceQuota{MaxBeams: 3}, LiveSlotLimit: 1}
	sc := &domain.SecurityContext{RuntimeClass: domain.RuntimeRunc, Template: domain.TemplateWebApp}
	if err := st.CreateBeamhall(ctx, bh, sc); err != nil {
		t.Fatal(err)
	}
	if _, err := audit.New(st).Append(ctx, &domain.AuditEvent{
		BeamhallID: bh.ID, Action: "admin_create_beamhall", Decision: domain.DecisionAllow, ResultStatus: "ok",
	}); err != nil {
		t.Fatal(err)
	}
	st.Close()

	keyBytes = []byte("AGE-SECRET-KEY-1TESTTESTTESTTESTTESTTESTTESTTESTTESTTEST")
	if err := os.WriteFile(filepath.Join(dir, keyName), keyBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	repoFile := filepath.Join(dir, reposDir, "ops", "tracker.git", "HEAD")
	os.MkdirAll(filepath.Dir(repoFile), 0o700)
	os.WriteFile(repoFile, []byte("ref: refs/heads/main\n"), 0o644)
	return dir, keyBytes, bh.ID
}

func TestBackupRestoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	src, key, bhID := seedDataDir(t)
	archive := filepath.Join(t.TempDir(), "backup.tar.gz")

	if err := Create(ctx, src, "", archive, time.Unix(1700000000, 0)); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Archive is operator-secret: must be 0600.
	fi, _ := os.Stat(archive)
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("archive mode = %o, want 600", fi.Mode().Perm())
	}

	man, err := Verify(archive)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !man.HasKey || !man.HasRepos || man.Format != formatV1 {
		t.Errorf("manifest = %+v", man)
	}

	// Restore into a fresh, empty data dir.
	dst := t.TempDir()
	if err := Restore(archive, dst); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	// Secret key survives byte-for-byte.
	gotKey, _ := os.ReadFile(filepath.Join(dst, keyName))
	if !bytes.Equal(gotKey, key) {
		t.Errorf("secret key changed across backup/restore")
	}
	// Repo file survives.
	if _, err := os.Stat(filepath.Join(dst, reposDir, "ops", "tracker.git", "HEAD")); err != nil {
		t.Errorf("repo not restored: %v", err)
	}
	// The store reopens with its data and a clean audit chain.
	st, err := store.Open(ctx, filepath.Join(dst, dbName))
	if err != nil {
		t.Fatalf("reopen restored store: %v", err)
	}
	defer st.Close()
	bh, err := st.GetBeamhall(ctx, bhID)
	if err != nil || bh.Slug != "ops" {
		t.Fatalf("beamhall lost: %v %+v", err, bh)
	}
	issues, err := audit.New(st).Verify(ctx)
	if err != nil || len(issues) > 0 {
		t.Fatalf("restored audit chain not clean: %v %+v", err, issues)
	}
}

func TestRestorePreservesExisting(t *testing.T) {
	ctx := context.Background()
	src, _, _ := seedDataDir(t)
	archive := filepath.Join(t.TempDir(), "b.tar.gz")
	if err := Create(ctx, src, "", archive, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Restore over a dir that already has a db + key — they move to .pre-restore.
	dst, _, _ := seedDataDir(t)
	if err := Restore(archive, dst); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dst, dbName+".pre-restore")); err != nil {
		t.Errorf("prior database not preserved: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, keyName+".pre-restore")); err != nil {
		t.Errorf("prior secret key not preserved: %v", err)
	}
}

func TestCreateRefusesWithoutKey(t *testing.T) {
	ctx := context.Background()
	src, _, _ := seedDataDir(t)
	os.Remove(filepath.Join(src, keyName))
	err := Create(ctx, src, "", filepath.Join(t.TempDir(), "b.tar.gz"), time.Now())
	if err == nil {
		t.Fatal("backup without the secret key should be refused")
	}
}

// TestCreateOutOfBandKey covers the production layout: the secret key lives
// OUTSIDE the data dir (delivered out-of-band), passed explicitly as keyPath.
func TestCreateOutOfBandKey(t *testing.T) {
	ctx := context.Background()
	src, _, _ := seedDataDir(t)
	// Move the key out of the data dir to mimic /etc/beamhall/secret.key.
	oob := filepath.Join(t.TempDir(), "secret.key")
	if err := os.Rename(filepath.Join(src, keyName), oob); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "b.tar.gz")
	// Default (in-data-dir) lookup must now fail — the key isn't there.
	if err := Create(ctx, src, "", archive, time.Now()); err == nil {
		t.Fatal("expected refusal: key is not in the data dir")
	}
	// Explicit out-of-band path must succeed and embed the key.
	if err := Create(ctx, src, oob, archive, time.Now()); err != nil {
		t.Fatalf("out-of-band key backup: %v", err)
	}
	man, err := Verify(archive)
	if err != nil || !man.HasKey {
		t.Fatalf("archive should carry the secret key: man=%+v err=%v", man, err)
	}
}

func TestVerifyRejectsNonBackup(t *testing.T) {
	junk := filepath.Join(t.TempDir(), "junk.tar.gz")
	os.WriteFile(junk, []byte("not a gzip"), 0o600)
	if _, err := Verify(junk); err == nil {
		t.Fatal("garbage accepted as a backup")
	}
}

func TestSnapshotIsConsistentAndStandalone(t *testing.T) {
	ctx := context.Background()
	src, _, _ := seedDataDir(t)
	st, err := store.Open(ctx, filepath.Join(src, dbName))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	snap := filepath.Join(t.TempDir(), "snap.db")
	if err := st.Snapshot(ctx, snap); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	// A second snapshot to the same path is refused (no clobber).
	if err := st.Snapshot(ctx, snap); err == nil {
		t.Error("snapshot clobbered an existing file")
	}
	// The snapshot opens on its own with no WAL sidecar present.
	st2, err := store.Open(ctx, snap)
	if err != nil {
		t.Fatalf("open snapshot: %v", err)
	}
	st2.Close()
}

func TestSecretRecoverableFromBackup(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	// Write a real age key, then seal a secret through the vault into a LIVE
	// (still-open) store — the appliance is running when we back it up.
	id, _, err := secret.LoadOrCreateKey(filepath.Join(dir, keyName))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, filepath.Join(dir, dbName))
	if err != nil {
		t.Fatal(err)
	}
	bh := &domain.Beamhall{Slug: "ops", DisplayName: "Ops", Status: domain.BeamhallActive}
	if err := st.CreateBeamhall(ctx, bh, &domain.SecurityContext{RuntimeClass: domain.RuntimeRunc, Template: domain.TemplateWebApp}); err != nil {
		t.Fatal(err)
	}
	beam := &domain.Beam{BeamhallID: bh.ID, Slug: "tracker", Mode: domain.ModePreview, State: domain.StateCreated, SecurityTemplate: domain.TemplateWebApp}
	if err := st.CreateBeam(ctx, beam); err != nil {
		t.Fatal(err)
	}
	vault := secret.NewVault(id, st)
	ref := domain.SecretRef{BeamhallID: bh.ID, BeamID: beam.ID, Key: "API_TOKEN"}
	const plaintext = "super-secret-recoverable-token"
	if _, err := vault.Set(ctx, ref, []byte(plaintext), "actor"); err != nil {
		t.Fatal(err)
	}

	// Back up the running appliance (store still open), then close it.
	archive := filepath.Join(t.TempDir(), "b.tar.gz")
	if err := Create(ctx, dir, "", archive, time.Now()); err != nil {
		t.Fatalf("Create (live): %v", err)
	}
	st.Close()

	// Restore to a brand-new dir and recover the secret with the restored key.
	dst := t.TempDir()
	if err := Restore(archive, dst); err != nil {
		t.Fatal(err)
	}
	id2, _, err := secret.LoadOrCreateKey(filepath.Join(dst, keyName)) // loads the restored key, does NOT regenerate
	if err != nil {
		t.Fatal(err)
	}
	st2, err := store.Open(ctx, filepath.Join(dst, dbName))
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	mounts, err := secret.NewVault(id2, st2).Inject(ctx, []domain.SecretRef{ref})
	if err != nil {
		t.Fatalf("inject from restored store: %v", err)
	}
	if len(mounts) != 1 || string(mounts[0].Value) != plaintext {
		t.Fatalf("secret not recovered: %+v", mounts)
	}
}
