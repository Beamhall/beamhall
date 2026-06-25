// Package orch is the backplane orchestrator: the only layer that turns
// authorized intents (create_beam, deploy_beam, pause/resume, promote) into
// effects across the runtime driver, gateway, pause scheduler, secret vault,
// and control-plane store. Every operation passes the policy PEP first (which
// audits the decision) and appends an outcome event when it finishes, so the
// audit chain shows decision and result for each call (PLAN §5.7, §6).
//
// Stage 2 scope: deployments start from a pinned image digest supplied by the
// caller; the managed-git + pack build pipeline (PLAN §5.5) replaces that
// input in a later stage without changing the lifecycle below.
package orch

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/Beamhall/beamhall/internal/audit"
	"github.com/Beamhall/beamhall/internal/build"
	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/driver"
	"github.com/Beamhall/beamhall/internal/gateway"
	"github.com/Beamhall/beamhall/internal/identityadmin"
	"github.com/Beamhall/beamhall/internal/policy"
	"github.com/Beamhall/beamhall/internal/secret"
	"github.com/Beamhall/beamhall/internal/store"
	"github.com/Beamhall/beamhall/internal/upgrade"
)

// GatewayAPI is the slice of the Caddy gateway the orchestrator drives.
// *gateway.Gateway satisfies it.
type GatewayAPI interface {
	Upsert(ctx context.Context, r gateway.Route) error
	Retire(ctx context.Context, hostname string) error
	// Apply pushes the full rendered config (including static routes such as the
	// bundled IdP) to Caddy. Boot calls it so static routes are materialized even
	// when there are zero beam routes to restore.
	Apply(ctx context.Context) error
}

// PauseScheduler arms and disarms the durable preview-pause timer.
// *scheduler.Scheduler satisfies it.
type PauseScheduler interface {
	Arm(ctx context.Context, beamID string, deadline time.Time) error
	Disarm(ctx context.Context, beamID string) error
}

// Builder is the source→pinned-image pipeline seam (*build.Pipeline
// satisfies it). Optional: a backplane without one only deploys pinned
// images.
type Builder interface {
	BuildFromDir(ctx context.Context, beamhallSlug, beamSlug, srcDir string) (build.Result, error)
	BuildFromCommit(ctx context.Context, beamhallSlug, beamSlug, sha string) (build.Result, error)
}

// Actor identifies the authenticated caller of an operation; the auth layer
// (MCP) fills it from the validated token.
type Actor struct {
	ID       domain.ID
	TokenJTI string
	ITAdmin  bool
	SourceIP string
}

// Orchestrator wires the backplane services behind the PEP.
type Orchestrator struct {
	st         *store.Store
	drv        driver.RuntimeDriver
	gw         GatewayAPI
	sched      PauseScheduler
	vault      *secret.Vault
	pep        *policy.PEP
	alog       *audit.Logger
	builder    Builder
	dbProv     DatabaseProvisioner
	emailProv  EmailProvisioner
	repoRetire func(beamhallSlug, beamSlug, id string) error
	log        *slog.Logger

	baseDomain        string
	defaultPauseAfter time.Duration
	beamPort          int
	startupGrace      time.Duration
	egressSync        func(ctx context.Context) error
	buildSem          chan struct{} // bounds concurrent pack builds (build-bomb defense)
	promoteApproval   bool          // explicit IT-approval gate for promote_to_live (PLAN §10)

	// idp administers the IdP Beamhall owns (the bundled Keycloak). Defaults to
	// identityadmin.Disabled for BYO-IdP deployments. idpSensitive is the
	// operator opt-in that unlocks the SENSITIVE auth-config tier (directory
	// federation); off by default, those ops fail closed (human-in-the-loop).
	idp          identityadmin.Provider
	idpSensitive bool

	// Provisioned auth (PLAN §5.10): the OIDC issuer injected into a beam's app
	// (the discovery base) and the Beamhall resource URI that app clients must NOT
	// carry in `aud` (the audience-isolation invariant: an app token must not be
	// replayable against the MCP backplane). Both come from the appliance OAuth
	// config; set via WithProvisionedAuth.
	authIssuer   string
	authAudience string

	// Email delivery facility (PLAN §5.12): emailProv is the bh-mail broker
	// control-channel client (nil = no broker wired by the installer). emailCfg
	// holds the broker beam-host/port beams dial + default per-beam limits.
	// emailEnabled is RUNTIME state — true once an IT admin configures the provider
	// (admin_set_email_provider); the broker owns + persists the provider config,
	// and beamhalld learns "enabled" from the broker on boot/reconcile.
	emailCfg     EmailConfig
	emailEnabled atomic.Bool

	// Backup config (WithBackup): the data dir + key to archive and where
	// admin_backup_now writes. Empty backupDir = backups disabled.
	backupDataDir string
	backupKeyPath string
	backupDir     string

	// upgrader stages self-upgrades (WithUpgrader). Defaults to upgrade.Disabled
	// (fail-closed): self-upgrade is unavailable unless explicitly enabled.
	upgrader upgrade.Stager
}

// startupPolls divides the startup grace into status checks.
const startupPolls = 8

// Option configures the Orchestrator.
type Option func(*Orchestrator)

// WithLogger sets the slog logger.
func WithLogger(l *slog.Logger) Option { return func(o *Orchestrator) { o.log = l } }

// WithDefaultPauseAfter sets Y, the preview auto-pause window used when a
// Beam does not set its own (PLAN §10 open question; default 4h).
func WithDefaultPauseAfter(d time.Duration) Option {
	return func(o *Orchestrator) { o.defaultPauseAfter = d }
}

// WithBuilder enables source-driven deploys through the build pipeline.
func WithBuilder(b Builder) Option { return func(o *Orchestrator) { o.builder = b } }

// WithRepoRetirer wires the managed-git repo teardown: on beam destroy/archive
// the repo is retired aside so a reused slug starts from a fresh, empty repo.
func WithRepoRetirer(f func(beamhallSlug, beamSlug, id string) error) Option {
	return func(o *Orchestrator) { o.repoRetire = f }
}

// WithStartupGrace sets how long a workload must survive after Start before a
// deploy is declared successful (crash-on-boot detection; default 2s).
func WithStartupGrace(d time.Duration) Option {
	return func(o *Orchestrator) { o.startupGrace = d }
}

// WithMaxConcurrentBuilds caps how many pack builds run at once (build-bomb
// defense, PLAN §6). At capacity, a source deploy is refused with an
// actionable error rather than queued. Default 2; a value < 1 disables the
// cap.
func WithMaxConcurrentBuilds(n int) Option {
	return func(o *Orchestrator) {
		if n < 1 {
			o.buildSem = nil
			return
		}
		o.buildSem = make(chan struct{}, n)
	}
}

// WithEgressSync registers the egress re-assertion hook, run after every
// workload deployment. Per-beamhall bridges are created lazily at deploy
// time, so boot-only reconciliation would leave a new beamhall's first
// workloads on an unprotected bridge until the next restart. Fail-closed: a
// sync error fails the deploy — a beam must not run without its egress
// policy.
func WithEgressSync(sync func(ctx context.Context) error) Option {
	return func(o *Orchestrator) { o.egressSync = sync }
}

// WithPromoteApproval enables the explicit IT-approval gate: promote_to_live
// records a pending request that a different IT operator must approve before the
// beam goes live (PLAN §10).
func WithPromoteApproval(on bool) Option {
	return func(o *Orchestrator) { o.promoteApproval = on }
}

// PromoteApprovalEnabled reports whether the IT-approval gate is on, so the MCP
// layer routes promote_to_live to a request instead of an immediate promote.
func (o *Orchestrator) PromoteApprovalEnabled() bool { return o.promoteApproval }

// WithIdentityAdmin wires the owned-IdP administration provider (PLAN §5.9).
// sensitive unlocks the SENSITIVE auth-config tier (directory federation); with
// it off those operations fail closed, requiring a human-in-the-loop step.
func WithIdentityAdmin(p identityadmin.Provider, sensitive bool) Option {
	return func(o *Orchestrator) {
		if p != nil {
			o.idp = p
		}
		o.idpSensitive = sensitive
	}
}

// WithProvisionedAuth supplies the values provision_auth needs (PLAN §5.10): the
// OIDC issuer injected into beams (the discovery base their app points at) and the
// Beamhall resource URI (cfg.OAuthAudience) that app clients must never carry as
// `aud`. Both flow from the appliance OAuth config.
func WithProvisionedAuth(issuer, audience string) Option {
	return func(o *Orchestrator) {
		o.authIssuer = issuer
		o.authAudience = audience
	}
}

// WithBackup enables the admin backup tools: dataDir is the appliance data
// directory to snapshot, keyPath the secret root key to embed (its real
// out-of-band location), backupDir where archives are written and listed. With
// no backupDir the backup tools report unconfigured and stay off the menu.
func WithBackup(dataDir, keyPath, backupDir string) Option {
	return func(o *Orchestrator) {
		o.backupDataDir = dataDir
		o.backupKeyPath = keyPath
		o.backupDir = backupDir
	}
}

// WithUpgrader enables self-upgrade staging behind the four-eyes sensitive tier.
// A nil stager keeps the fail-closed default (self-upgrade unavailable).
func WithUpgrader(u upgrade.Stager) Option {
	return func(o *Orchestrator) {
		if u != nil {
			o.upgrader = u
		}
	}
}

// UpgradeEnabled reports whether self-upgrade staging is available.
func (o *Orchestrator) UpgradeEnabled() bool { return o.upgrader != nil && o.upgrader.Enabled() }

// IdentityAdminEnabled reports whether this appliance administers its IdP (the
// bundled Keycloak) — false for a bring-your-own-IdP deployment.
func (o *Orchestrator) IdentityAdminEnabled() bool { return o.idp.Enabled() }

// SensitiveAdminEnabled reports whether the SENSITIVE auth-config tier (the
// four-eyes directory-federation request flow) is unlocked. Off by default;
// the MCP layer uses it to keep the federate tool off the menu when the tier
// is fail-closed, so an agent isn't offered an action it can't file.
func (o *Orchestrator) SensitiveAdminEnabled() bool { return o.idpSensitive }

// New assembles the orchestrator. baseDomain anchors preview and live
// hostnames (PLAN §5.6).
func New(st *store.Store, drv driver.RuntimeDriver, gw GatewayAPI, sched PauseScheduler,
	vault *secret.Vault, pep *policy.PEP, alog *audit.Logger, baseDomain string, opts ...Option) *Orchestrator {
	o := &Orchestrator{
		st: st, drv: drv, gw: gw, sched: sched, vault: vault, pep: pep, alog: alog,
		log:               slog.Default(),
		baseDomain:        baseDomain,
		defaultPauseAfter: 4 * time.Hour,
		beamPort:          8080,
		startupGrace:      2 * time.Second,
		buildSem:          make(chan struct{}, 2),
		idp:               identityadmin.Disabled{},
		upgrader:          upgrade.Disabled{},
	}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

// acquireBuildSlot bounds concurrent pack builds (build-bomb defense, PLAN
// §6). It never blocks: at capacity it returns an actionable error so the
// agent retries rather than the appliance queueing unbounded expensive work.
func (o *Orchestrator) acquireBuildSlot() (release func(), err error) {
	if o.buildSem == nil {
		return func() {}, nil
	}
	select {
	case o.buildSem <- struct{}{}:
		return func() { <-o.buildSem }, nil
	default:
		return nil, fmt.Errorf("the appliance is already running its maximum of %d concurrent builds; retry in a moment", cap(o.buildSem))
	}
}

// operableBeam loads a beam and refuses if it is archived (destroy_beam is
// terminal) or in the wrong beamhall. Archival is a Status, not an FSM state
// — a destroyed beam still reads as "running" to the FSM — so every operation
// that mutates a beam guards on it here.
func (o *Orchestrator) operableBeam(ctx context.Context, beamhallID, beamID domain.ID) (domain.Beam, error) {
	beam, err := o.st.GetBeam(ctx, beamID)
	if err != nil {
		return domain.Beam{}, err
	}
	if beam.BeamhallID != beamhallID {
		return domain.Beam{}, fmt.Errorf("beam %s is not in beamhall %s", beamID, beamhallID)
	}
	if beam.Status == domain.BeamArchived {
		return domain.Beam{}, fmt.Errorf("beam %s has been destroyed", beamID)
	}
	return beam, nil
}

// authorize runs the PEP for an operation (the PEP audits the decision).
func (o *Orchestrator) authorize(ctx context.Context, actor Actor, action policy.Action, beamhallID, beamID domain.ID) error {
	return o.pep.Authorize(ctx, policy.Request{
		Actor:         actor.ID,
		ActorTokenJTI: actor.TokenJTI,
		ITAdmin:       actor.ITAdmin,
		BeamhallID:    beamhallID,
		BeamID:        beamID,
		Action:        action,
		SourceIP:      actor.SourceIP,
	})
}

// outcome appends the operation-result event that pairs with the PEP's
// decision event. The operation's effects stand even if this append fails —
// the error is returned so the caller surfaces it, and the gap is visible in
// the chain's absence of an outcome for the decision.
func (o *Orchestrator) outcome(ctx context.Context, actor Actor, action policy.Action,
	beamhallID, beamID domain.ID, opErr error) error {
	status, reason := "ok", ""
	if opErr != nil {
		status, reason = "failed", opErr.Error()
	}
	ev := domain.AuditEvent{
		ActorID:       actor.ID,
		ActorTokenJTI: actor.TokenJTI,
		BeamhallID:    beamhallID,
		BeamID:        beamID,
		Action:        string(action),
		Decision:      domain.DecisionAllow,
		Reason:        reason,
		ResultStatus:  status,
		SourceIP:      actor.SourceIP,
	}
	if _, err := o.alog.Append(ctx, &ev); err != nil {
		o.log.Error("audit outcome append failed", "action", action, "err", err)
		if opErr == nil {
			return fmt.Errorf("operation succeeded but its audit record failed: %w", err)
		}
	}
	return opErr
}

var slugRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)

// previewHost mints a fresh random preview hostname (re-minted on every
// resume so paused URLs go stale, PLAN §5.6).
func (o *Orchestrator) previewHost() string {
	host, _ := gateway.RandomPreviewHost(o.baseDomain)
	return host
}

// liveHost is the stable production hostname for a promoted beam.
func (o *Orchestrator) liveHost(beamSlug, beamhallSlug string) string {
	return fmt.Sprintf("%s.%s.%s", beamSlug, beamhallSlug, o.baseDomain)
}

// handleOf maps the persisted workload handle back to the driver's type.
func handleOf(rel domain.Release) driver.Handle {
	return driver.Handle{DriverName: rel.Workload.Driver, Ref: rel.Workload.Ref}
}

// networkName is the per-Beamhall bridge network (PLAN §6: one bridge per
// Beamhall, nothing crosses it by default).
func networkName(beamhallID domain.ID) string { return "bh-" + string(beamhallID) }

// profileOf resolves the Beamhall's immutable SecurityContext into the
// driver's hardening profile.
func profileOf(sc domain.SecurityContext) driver.SecurityProfile {
	return driver.SecurityProfile{
		RuntimeClass:    driver.RuntimeClass(sc.RuntimeClass),
		UsernsRemap:     sc.UsernsRemap,
		CapDrop:         sc.CapDrop,
		CapAdd:          sc.CapAdd,
		SeccompProfile:  sc.SeccompProfile,
		AppArmorProfile: sc.AppArmorProfile,
		NoNewPrivileges: sc.NoNewPrivileges,
		ReadOnlyRootfs:  sc.ReadOnlyRootfs,
		Tmpfs:           sc.Tmpfs,
	}
}

func limitsOf(sc domain.SecurityContext) driver.ResourceLimits {
	return driver.ResourceLimits{
		CPUQuota: sc.CgroupLimits.CPUQuota,
		MemBytes: sc.CgroupLimits.MemBytes,
		PidsMax:  sc.CgroupLimits.PidsMax,
	}
}
