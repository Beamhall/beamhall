package main

import (
	"context"
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/Beamhall/beamhall/internal/audit"
	"github.com/Beamhall/beamhall/internal/config"
	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/orch"
	"github.com/Beamhall/beamhall/internal/store"
)

// runAdmin provides scriptable IT provisioning — the operations the Admin
// console exposes interactively, runnable from a shell for onboarding,
// automation, and the canonical demo. It writes directly to the appliance
// store (safe alongside a running beamhalld; new rows are seen on the next
// request), so the daemon need not be stopped.
//
//	beamhalld admin bootstrap -beamhall demo -issuer <iss> -subject <sub> -email <e> [flags]
func runAdmin(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: beamhalld admin <bootstrap> [flags]")
	}
	switch args[0] {
	case "bootstrap":
		return runAdminBootstrap(args[1:])
	case "register-identity":
		return runAdminRegisterIdentity(args[1:])
	case "prune-audit":
		return runAdminPruneAudit(args[1:])
	default:
		return fmt.Errorf("unknown admin subcommand %q (have: bootstrap, register-identity, prune-audit)", args[0])
	}
}

// runAdminPruneAudit trims the append-only audit log to a retention window,
// recording an integrity checkpoint so the surviving chain still verifies.
// Pruned events are deleted for good (no SIEM export in this build).
//
//	beamhalld admin prune-audit -keep-days 90   (remove events older than 90 days)
//	beamhalld admin prune-audit -keep 50000     (keep only the newest 50k events)
//	beamhalld admin prune-audit -keep-days 90 -dry-run
func runAdminPruneAudit(args []string) error {
	fs := flag.NewFlagSet("admin prune-audit", flag.ContinueOnError)
	var (
		keepDays = fs.Int("keep-days", 0, "remove audit events older than N days")
		keepLast = fs.Int64("keep", 0, "keep at most the newest N audit events")
		dryRun   = fs.Bool("dry-run", false, "report what would be pruned without deleting")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keepDays <= 0 && *keepLast <= 0 {
		return fmt.Errorf("set -keep-days and/or -keep (nothing to do otherwise)")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	st, err := store.Open(context.Background(), filepath.Join(cfg.DataDir, "beamhall.db"))
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	log := audit.New(st)
	ctx := context.Background()
	policy := audit.RetentionPolicy{KeepLast: *keepLast}
	if *keepDays > 0 {
		policy.MaxAge = time.Duration(*keepDays) * 24 * time.Hour
	}
	// Present count = high-water seq minus what an earlier prune already cut.
	present, _ := st.MaxAuditSeq(ctx)
	if cp, ok, _ := st.LatestAuditCheckpoint(ctx); ok {
		present -= cp.ThroughSeq
	}

	if *dryRun {
		would, err := log.WouldPrune(ctx, policy, time.Now())
		if err != nil {
			return err
		}
		fmt.Printf("dry-run: would prune %d of %d audit events (retention: %s)\n", would, present, policy.Describe())
		return nil
	}
	pruned, err := log.Prune(ctx, policy, domain.ID("admin-cli"), time.Now())
	if err != nil {
		return err
	}
	issues, err := log.Verify(ctx)
	if err != nil {
		return err
	}
	chain := "verified ✓"
	if len(issues) != 0 {
		chain = fmt.Sprintf("INTEGRITY VIOLATION (%d issues)", len(issues))
	}
	fmt.Printf("pruned %d of %d audit events; %d remain; surviving chain %s\n", pruned, present, present-pruned, chain)
	return nil
}

// runAdminRegisterIdentity records an external identity so its token resolves
// to a known actor. IT-admin operators need this too: an admin:it token must
// still map to a registered identity (every action is audited against one), but
// it needs no membership — the scope is the bypass.
//
//	beamhalld admin register-identity -issuer <iss> -subject <sub> -email <e>
func runAdminRegisterIdentity(args []string) error {
	fs := flag.NewFlagSet("admin register-identity", flag.ContinueOnError)
	var (
		issuer  = fs.String("issuer", "", "IdP issuer (required)")
		subject = fs.String("subject", "", "subject (required)")
		email   = fs.String("email", "", "email")
		display = fs.String("display", "", "display name (defaults to email)")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *issuer == "" || *subject == "" {
		return fmt.Errorf("-issuer and -subject are required")
	}
	o, st, err := adminOrch()
	if err != nil {
		return err
	}
	defer st.Close()
	name := *display
	if name == "" {
		name = *email
	}
	ident, err := o.RegisterIdentity(context.Background(), itActor(), *issuer, *subject, *email, name)
	if err != nil {
		return err
	}
	fmt.Printf("identity %s (%s) registered as %s\n", *subject, *email, ident.ID)
	return nil
}

// adminOrch opens the appliance store and returns an admin-only orchestrator
// (IT methods touch only the store + audit log; runtime deps stay nil).
func adminOrch() (*orch.Orchestrator, *store.Store, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, err
	}
	st, err := store.Open(context.Background(), filepath.Join(cfg.DataDir, "beamhall.db"))
	if err != nil {
		return nil, nil, fmt.Errorf("open store: %w", err)
	}
	return orch.New(st, nil, nil, nil, nil, nil, audit.New(st), cfg.BaseDomain), st, nil
}

func itActor() orch.Actor {
	return orch.Actor{ID: domain.ID("admin-cli"), ITAdmin: true, SourceIP: "cli"}
}

// runAdminBootstrap creates a beamhall, registers an external identity, and
// grants it a role — the minimum IT setup before an agent can deploy. All
// steps are idempotent enough to re-run for a demo: a pre-existing identity is
// reused, and an existing beamhall/membership is reported, not fatal.
func runAdminBootstrap(args []string) error {
	fs := flag.NewFlagSet("admin bootstrap", flag.ContinueOnError)
	var (
		slug     = fs.String("beamhall", "", "beamhall slug (DNS-safe; required)")
		display  = fs.String("display", "", "beamhall display name")
		dept     = fs.String("department", "", "owning department")
		issuer   = fs.String("issuer", "", "IdP issuer of the owner identity (must match the token's iss; required)")
		subject  = fs.String("subject", "", "owner subject (must match the token's sub; required)")
		email    = fs.String("email", "", "owner email")
		roleStr  = fs.String("role", "builder", "membership role: viewer|builder|beamhall_admin")
		runtime  = fs.String("runtime", "runc", "runtime class: runc (hardened Docker) | runsc (gVisor)")
		egress   = fs.String("egress", "deny_all", "egress mode: deny_all | allow_set")
		allowCSV = fs.String("allow", "", "egress allowlist (FQDN/CIDR:port, comma-separated) when -egress=allow_set")
		maxBeams = fs.Int("max-beams", 10, "beamhall quota: max active beams")
		liveSlot = fs.Int("live-slots", 2, "beamhall quota: max live (promoted) beams")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *slug == "" || *issuer == "" || *subject == "" {
		return fmt.Errorf("-beamhall, -issuer and -subject are required")
	}
	role := domain.MembershipRole(*roleStr)
	switch role {
	case domain.RoleViewer, domain.RoleBuilder, domain.RoleBeamhallAdmin:
	default:
		return fmt.Errorf("invalid -role %q", *roleStr)
	}
	egMode := domain.EgressMode(*egress)
	if egMode != domain.EgressDenyAll && egMode != domain.EgressAllowSet {
		return fmt.Errorf("invalid -egress %q", *egress)
	}
	var allow []string
	if s := strings.TrimSpace(*allowCSV); s != "" {
		allow = strings.Split(s, ",")
	}

	o, st, err := adminOrch()
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	actor := itActor()

	// 1. beamhall (idempotent: reuse if the slug already exists)
	bh, err := o.CreateBeamhall(ctx, actor, orch.NewBeamhallSpec{
		Slug: *slug, DisplayName: *display, Department: *dept,
		RuntimeClass: domain.RuntimeClass(*runtime), Template: domain.TemplateWebApp,
		EgressMode: egMode, Allowlist: allow,
		Quota:     domain.ResourceQuota{MaxBeams: *maxBeams, MaxLiveSlots: *liveSlot, MaxDBCount: 5},
		LiveSlots: *liveSlot,
	})
	if err != nil {
		if existing, gerr := st.GetBeamhallBySlug(ctx, *slug); gerr == nil {
			bh = &existing
			fmt.Printf("beamhall %q already exists — reusing\n", *slug)
		} else {
			return fmt.Errorf("create beamhall: %w", err)
		}
	} else {
		fmt.Printf("beamhall %q created (runtime=%s, egress=%s)\n", bh.Slug, *runtime, egMode)
	}

	// 2. identity (idempotent by issuer+subject)
	ident, err := o.RegisterIdentity(ctx, actor, *issuer, *subject, *email, *email)
	if err != nil {
		return fmt.Errorf("register identity: %w", err)
	}
	fmt.Printf("identity %s (%s) registered\n", *subject, *email)

	// 3. membership
	if err := o.GrantMembership(ctx, actor, ident.ID, bh.ID, role); err != nil {
		// A duplicate grant is fine for a re-run.
		fmt.Printf("grant membership: %v (continuing)\n", err)
	} else {
		fmt.Printf("granted %s %q in %q\n", *subject, role, bh.Slug)
	}

	fmt.Printf("\nbootstrap complete: agent %q can now deploy beams in %q (role %s).\n", *subject, bh.Slug, role)
	return nil
}
