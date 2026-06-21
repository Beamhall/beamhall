package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/Beamhall/beamhall/internal/audit"
	"github.com/Beamhall/beamhall/internal/domain"
)

// startAuditRetention bounds the audit log when BEAMHALL_AUDIT_RETENTION_DAYS is
// set: it prunes events older than the window once on boot and then daily,
// recording an integrity checkpoint each time so the surviving chain still
// verifies. Pruning is best-effort and never blocks the daemon.
func startAuditRetention(ctx context.Context, log *audit.Logger, days int, logger *slog.Logger) {
	policy := audit.RetentionPolicy{MaxAge: time.Duration(days) * 24 * time.Hour}
	prune := func() {
		n, err := log.Prune(ctx, policy, domain.ID("system"), time.Now())
		if err != nil {
			logger.Error("audit retention prune failed", "err", err)
			return
		}
		if n > 0 {
			logger.Info("audit retention pruned old events", "pruned", n, "keep_days", days)
		}
	}
	prune() // catch up on boot
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				prune()
			}
		}
	}()
}
