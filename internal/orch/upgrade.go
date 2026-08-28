package orch

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"strings"

	"github.com/Beamhall/beamhall/internal/domain"
)

// expectedSHA256Re matches a bare hex-encoded SHA-256 digest, case-insensitive
// (mirrors internal/upgrade's own check — validated again here so a malformed
// digest is rejected at request time, not only when the request is executed).
var expectedSHA256Re = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// Self-upgrade over MCP — the control plane replacing the binary that enforces
// policy. It is the most-guarded action: fail-closed unless explicitly enabled
// (WithUpgrader), behind the four-eyes sensitive tier, and never a live
// self-replacing restart. On approval the orchestrator stages a checksum-verified
// release and returns the operator's atomic apply/rollback runbook; the
// irreversible swap+restart is a deliberate operator step.

type selfUpgradePayload struct {
	Version        string
	ExpectedSHA256 string
}

// RequestUpgrade files a four-eyes request to upgrade the appliance to a target
// release version. it_admin + sensitive tier + self-upgrade enabled.
// expectedSHA256 must be the requester's OWN independently-obtained digest for
// the target release asset (e.g. read off the GitHub release page's
// checksums.txt) — required, not derived from anything the appliance itself
// downloads, because a compromised or MITM'd release channel can otherwise
// serve a malicious binary alongside a matching same-channel checksums.txt.
func (o *Orchestrator) RequestUpgrade(ctx context.Context, actor Actor, version, expectedSHA256 string) (domain.AdminActionRequest, error) {
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
	if !expectedSHA256Re.MatchString(expectedSHA256) {
		return domain.AdminActionRequest{}, o.itAudit(ctx, actor, action, "", fmt.Errorf(
			"expected_sha256 is required: a 64-character hex SHA-256 digest for the target release's %s_%s asset, read off the GitHub release page — not derived from anything this appliance downloads itself",
			runtime.GOOS, runtime.GOARCH))
	}
	summary := fmt.Sprintf("SELF-UPGRADE %s → %s (replaces the policy-enforcing binary; staged + verified against the approver's own digest, applied by an operator)",
		o.upgrader.CurrentVersion(), version)
	req, err := o.requestSensitive(ctx, actor, domain.AdminActionSelfUpgrade, summary,
		selfUpgradePayload{Version: version, ExpectedSHA256: strings.ToLower(expectedSHA256)})
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
	res, err := o.upgrader.Stage(ctx, p.Version, p.ExpectedSHA256)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s staged + checksum-verified (sha256 %s…, matched the approver's expected digest) at %s. It is NOT live yet — apply on the appliance host (atomic swap + restart):\n  %s\nRoll back with:\n  %s",
		res.Version, res.SHA256[:12], res.StagedPath, res.ApplyCmd, res.RollbackCmd), nil
}
