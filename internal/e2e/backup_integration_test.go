package e2e

// Lab test for backup/restore (Phase 4): back up a LIVE appliance (online
// snapshot while the daemon holds the WAL database), restore into a fresh data
// dir, and prove a secret sealed through the running appliance is recoverable
// with the restored key. Exercises the concurrent-open online backup that the
// unit tests can't (a second process reading the live DB).
//
//	BEAMHALL_DOCKER_IT=1 /tmp/e2e.test -test.v -test.run TestBackupRestoreLive

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Beamhall/beamhall/internal/backup"
	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/secret"
	"github.com/Beamhall/beamhall/internal/store"
)

func TestBackupRestoreLive(t *testing.T) {
	if os.Getenv("BEAMHALL_DOCKER_IT") != "1" {
		t.Skip("set BEAMHALL_DOCKER_IT=1 to run the backup suite")
	}
	binary := os.Getenv("BEAMHALL_E2E_BINARY")
	if binary == "" {
		binary = "/tmp/beamhalld"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	a := launchAppliance(t, ctx)
	cs := a.connect("e2e-builder", "beams:write beams:deploy secrets:write", nil)

	// Real running-appliance state: a beam with a secret sealed in the live DB.
	const secretValue = "backup-recoverable-secret-9f3a"
	callTool(ctx, t, cs, "create_beam", map[string]any{"beamhall": "e2e", "slug": "bkbeam"}, false)
	callTool(ctx, t, cs, "set_secret", map[string]any{
		"beamhall": "e2e", "beam": "bkbeam", "key": "API_TOKEN", "value": secretValue}, false)

	// Back up the LIVE appliance (daemon still running, holding the DB).
	archive := filepath.Join(t.TempDir(), "live-backup.tar.gz")
	bk := exec.CommandContext(ctx, binary, "backup", archive)
	bk.Env = append(os.Environ(), "BEAMHALL_DATA_DIR="+a.dataDir)
	if out, err := bk.CombinedOutput(); err != nil {
		t.Fatalf("backup of live appliance failed: %v\n%s", err, out)
	} else {
		t.Logf("backup: %s", out)
	}

	man, err := backup.Verify(archive)
	if err != nil || !man.HasKey {
		t.Fatalf("verify backup: %v %+v", err, man)
	}

	// Restore into a fresh data dir via the restore subcommand.
	restoreDir := t.TempDir()
	rs := exec.CommandContext(ctx, binary, "restore", archive)
	rs.Env = append(os.Environ(), "BEAMHALL_DATA_DIR="+restoreDir)
	if out, err := rs.CombinedOutput(); err != nil {
		t.Fatalf("restore failed: %v\n%s", err, out)
	} else {
		t.Logf("restore: %s", out)
	}

	// Recover the secret from the restored dir: load the restored key + store,
	// resolve the beam, and inject — the plaintext must come back.
	st, err := store.Open(ctx, filepath.Join(restoreDir, "beamhall.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	bh, err := st.GetBeamhallBySlug(ctx, "e2e")
	if err != nil {
		t.Fatalf("beamhall lost in restore: %v", err)
	}
	beam, err := st.GetBeamBySlug(ctx, bh.ID, "bkbeam")
	if err != nil {
		t.Fatalf("beam lost in restore: %v", err)
	}
	id, _, err := secret.LoadOrCreateKey(filepath.Join(restoreDir, "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	mounts, err := secret.NewVault(id, st).Inject(ctx, []domain.SecretRef{
		{BeamhallID: bh.ID, BeamID: beam.ID, Key: "API_TOKEN"}})
	if err != nil {
		t.Fatalf("inject from restored store: %v", err)
	}
	if len(mounts) != 1 || string(mounts[0].Value) != secretValue {
		t.Fatalf("secret not recovered from live backup: %+v", mounts)
	}
	t.Logf("recovered secret from a live-appliance backup after restore")
}
