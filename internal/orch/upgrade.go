package orch

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Beamhall/beamhall/internal/domain"
)

// Self-upgrade over MCP — the control plane replacing the binary that enforces
// policy. It is the most-guarded action: fail-closed unless explicitly enabled
// (WithUpgrader), behind the four-eyes sensitive tier, and never a live
// self-replacing restart. On approval the orchestrator stages a checksum-verified
// release and returns the operator's atomic apply/rollback runbook; the
// irreversible swap+restart is a deliberate operator step.

type selfUpgradePayload struct{ Version string }

// RequestUpgrade files a four-eyes request to upgrade the appliance to a target
// release version. it_admin + sensitive tier + self-upgrade enabled.
func (o *Orchestrator) RequestUpgrade(ctx context.Context, actor Actor, version string) (domain.AdminActionRequest, error) {
	const action = "admin_request_upgrade"
	if err := o.requireIT(actor); err != nil {
		return domain.AdminActionRequest{}, o.itAudit(ctx, actor, action, "", err)
	}
	if !o.UpgradeEnabled() {
		return domain.AdminActionRequest{}, o.itAudit(ctx, actor, action, "",
			fmt.Errorf("self-upgrade is not enabled on this appliance (set BEAMHALL_SELF_UPGRADE=on)"))
	}
	if err := o.requireSensitiveTier(); err != nil {
		return domain.AdminActionRequest{}, o.itAudit(ctx, actor, action, "", err)
	}
	if version == "" {
		return domain.AdminActionRequest{}, o.itAudit(ctx, actor, action, "", fmt.Errorf("target version is required (e.g. v0.1.11)"))
	}
	summary := fmt.Sprintf("SELF-UPGRADE %s → %s (replaces the policy-enforcing binary; staged + verified, applied by an operator)",
		o.upgrader.CurrentVersion(), version)
	req, err := o.requestSensitive(ctx, actor, domain.AdminActionSelfUpgrade, summary, selfUpgradePayload{Version: version})
	return req, o.itAudit(ctx, actor, action, "", err)
}

// executeSelfUpgrade runs on four-eyes approval: it stages the verified release
// and returns the operator apply/rollback runbook. It does NOT swap the live
// binary or restart.
func (o *Orchestrator) executeSelfUpgrade(ctx context.Context, payload []byte) (string, error) {
	var p selfUpgradePayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return "", fmt.Errorf("decode upgrade payload: %w", err)
	}
	if !o.UpgradeEnabled() {
		return "", fmt.Errorf("self-upgrade is not enabled on this appliance")
	}
	res, err := o.upgrader.Stage(ctx, p.Version)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s staged + checksum-verified (sha256 %s…) at %s. It is NOT live yet — apply on the appliance host (atomic swap + restart):\n  %s\nRoll back with:\n  %s",
		res.Version, res.SHA256[:12], res.StagedPath, res.ApplyCmd, res.RollbackCmd), nil
}
