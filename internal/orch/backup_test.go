package orch

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Beamhall/beamhall/internal/store"
)

func TestAdminBackupRoundTrip(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	dataDir := t.TempDir()
	// A real (empty) control-plane DB + a stand-in secret key for the archive.
	st, err := store.Open(ctx, filepath.Join(dataDir, "beamhall.db"))
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	keyPath := filepath.Join(dataDir, "secret.key")
	if err := os.WriteFile(keyPath, []byte("AGE-SECRET-KEY-TEST"), 0o600); err != nil {
		t.Fatal(err)
	}
	backupDir := filepath.Join(t.TempDir(), "backups")

	w.o.backupDataDir = dataDir
	w.o.backupKeyPath = keyPath
	w.o.backupDir = backupDir
	if !w.o.BackupEnabled() {
		t.Fatal("BackupEnabled should be true after configuring")
	}

	when := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	info, err := w.o.AdminBackupNow(ctx, itActor(w), when)
	if err != nil {
		t.Fatalf("AdminBackupNow: %v", err)
	}
	if !info.Valid || !info.HasKey {
		t.Fatalf("backup info not valid/keyed: %+v", info)
	}

	list, err := w.o.AdminListBackups(ctx, itActor(w))
	if err != nil {
		t.Fatalf("AdminListBackups: %v", err)
	}
	if len(list) != 1 || list[0].Name != info.Name || !list[0].Valid {
		t.Fatalf("list mismatch: %+v", list)
	}

	// Non-IT is refused.
	if _, err := w.o.AdminBackupNow(ctx, w.build, when); err == nil {
		t.Fatal("non-IT actor must be refused")
	}
}

func TestBackupNotConfigured(t *testing.T) {
	w := newWorld(t) // no backup configured
	ctx := context.Background()
	if w.o.BackupEnabled() {
		t.Fatal("backup should be disabled by default")
	}
	if _, err := w.o.AdminBackupNow(ctx, itActor(w), time.Now()); err == nil {
		t.Fatal("AdminBackupNow must fail when backups are unconfigured")
	}
	if _, err := w.o.AdminListBackups(ctx, itActor(w)); err == nil {
		t.Fatal("AdminListBackups must fail when unconfigured")
	}
}

func TestRequestRestoreGatesSensitiveAndVerifiable(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.o.backupDir = t.TempDir()
	// Sensitive tier off → refused even with a backup dir configured.
	if _, err := w.o.RequestRestoreBackup(ctx, itActor(w), "missing.tar.gz"); err == nil {
		t.Fatal("restore must be refused when the sensitive tier is off")
	}
	// Tier on but the named backup does not exist/verify → refused.
	w.o.idpSensitive = true
	if _, err := w.o.RequestRestoreBackup(ctx, itActor(w), "missing.tar.gz"); err == nil {
		t.Fatal("restore must refuse a non-verifiable backup")
	}
}
