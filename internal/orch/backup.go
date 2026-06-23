package orch

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Beamhall/beamhall/internal/backup"
	"github.com/Beamhall/beamhall/internal/domain"
)

// Appliance backup over MCP (it_admin). admin_backup_now writes an online
// snapshot (DB via VACUUM INTO + sealed secret key + git repos); admin_list_backups
// reads the directory; restore is four-eyes and operator-applied (a stop-the-world
// data-dir overwrite is never run live in-process — the dispatcher verifies the
// archive and hands back the exact stop→restore→start command).

// ErrBackupNotConfigured is returned when the appliance was started without
// WithBackup (no backup directory).
var ErrBackupNotConfigured = fmt.Errorf("appliance backups are not configured on this deployment")

// BackupEnabled reports whether the admin backup tools are available.
func (o *Orchestrator) BackupEnabled() bool { return o.backupDir != "" }

// BackupInfo describes one appliance backup archive.
type BackupInfo struct {
	Name      string
	CreatedAt string // RFC3339 from the manifest, "" if unverifiable
	SizeBytes int64
	HasKey    bool
	HasRepos  bool
	Valid     bool
	Error     string // verification error when Valid is false
}

// AdminBackupNow writes a new appliance backup to the backup directory and
// returns its verified manifest. it_admin only; audited.
func (o *Orchestrator) AdminBackupNow(ctx context.Context, actor Actor, now time.Time) (BackupInfo, error) {
	if err := o.requireIT(actor); err != nil {
		return BackupInfo{}, o.itAudit(ctx, actor, "admin_backup_now", "", err)
	}
	if o.backupDir == "" {
		return BackupInfo{}, o.itAudit(ctx, actor, "admin_backup_now", "", ErrBackupNotConfigured)
	}
	var info BackupInfo
	op := func() error {
		if err := os.MkdirAll(o.backupDir, 0o700); err != nil {
			return err
		}
		name := "beamhall-" + now.UTC().Format("20060102T150405Z") + ".tar.gz"
		if err := backup.Create(ctx, o.backupDataDir, o.backupKeyPath, filepath.Join(o.backupDir, name), now); err != nil {
			return err
		}
		info = o.describeBackup(name)
		return nil
	}
	return info, o.itAudit(ctx, actor, "admin_backup_now", "", op())
}

// AdminListBackups lists the backup archives in the backup directory, newest
// first, each with its manifest + verification status. it_admin only; a read.
func (o *Orchestrator) AdminListBackups(ctx context.Context, actor Actor) ([]BackupInfo, error) {
	if err := o.requireIT(actor); err != nil {
		return nil, err
	}
	if o.backupDir == "" {
		return nil, ErrBackupNotConfigured
	}
	entries, err := os.ReadDir(o.backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []BackupInfo
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".tar.gz") {
			continue
		}
		out = append(out, o.describeBackup(e.Name()))
	}
	// Timestamp-named, so lexical-descending is newest-first.
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out, nil
}

func (o *Orchestrator) describeBackup(name string) BackupInfo {
	info := BackupInfo{Name: name}
	path := filepath.Join(o.backupDir, name)
	if fi, err := os.Stat(path); err == nil {
		info.SizeBytes = fi.Size()
	}
	man, err := backup.Verify(path)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	info.Valid = true
	info.CreatedAt = man.CreatedAt
	info.HasKey = man.HasKey
	info.HasRepos = man.HasRepos
	return info
}

type restoreBackupPayload struct{ Name string }

// RequestRestoreBackup files a four-eyes request to restore from a named backup.
// Restore overwrites the whole control plane, so it is SENSITIVE and never
// applied live in-process: on approval the dispatcher verifies the archive and
// returns the exact stop→restore→start command the operator runs. it_admin +
// sensitive tier.
func (o *Orchestrator) RequestRestoreBackup(ctx context.Context, actor Actor, name string) (domain.AdminActionRequest, error) {
	const action = "admin_request_restore_backup"
	if err := o.requireIT(actor); err != nil {
		return domain.AdminActionRequest{}, o.itAudit(ctx, actor, action, "", err)
	}
	if o.backupDir == "" {
		return domain.AdminActionRequest{}, o.itAudit(ctx, actor, action, "", ErrBackupNotConfigured)
	}
	if err := o.requireSensitiveTier(); err != nil {
		return domain.AdminActionRequest{}, o.itAudit(ctx, actor, action, "", err)
	}
	info := o.describeBackup(name)
	if !info.Valid {
		return domain.AdminActionRequest{}, o.itAudit(ctx, actor, action, "",
			fmt.Errorf("backup %q not found or not verifiable: %s", name, info.Error))
	}
	summary := fmt.Sprintf("RESTORE appliance from backup %q (created %s) — overwrites the whole control plane", name, info.CreatedAt)
	req, err := o.requestSensitive(ctx, actor, domain.AdminActionRestoreBackup, summary, restoreBackupPayload{Name: name})
	return req, o.itAudit(ctx, actor, action, "", err)
}

// executeRestoreBackup runs on four-eyes approval. It does NOT overwrite the
// live data dir (the store is open); it verifies the archive and returns the
// operator runbook to apply it under a stopped daemon.
func (o *Orchestrator) executeRestoreBackup(payload []byte) (string, error) {
	var p restoreBackupPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return "", fmt.Errorf("decode restore payload: %w", err)
	}
	path := filepath.Join(o.backupDir, p.Name)
	man, err := backup.Verify(path)
	if err != nil {
		return "", fmt.Errorf("verify backup %q: %w", p.Name, err)
	}
	return fmt.Sprintf("backup %q verified (created %s). Restore overwrites the whole control plane, so apply it on the appliance host under a stopped daemon:\n  systemctl stop beamhalld && beamhalld restore %s && systemctl start beamhalld",
		p.Name, man.CreatedAt, path), nil
}
