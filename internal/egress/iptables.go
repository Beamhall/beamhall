// Package egress programs default-deny outbound network policy for Beamhall
// bridges using iptables. It owns a single chain, BEAMHALL-EGRESS, jumped from
// Docker's DOCKER-USER chain, and rebuilds it idempotently from the desired
// state on every Reconcile — so drift (and a host reboot) self-heals. This is
// the enforcement half of the per-Beamhall egress policy; the metadata/host/
// management always-deny set is applied regardless of any allowlist
// (SSRF/metadata defense). See docs/PLAN.md §6 and hardest-problem #2.
//
// iptables (not nftables) per the 2026 hardening findings. Rules match on the
// inbound bridge interface (-i br...), i.e. packets leaving a container, so
// host SSH (INPUT) is never affected.
package egress

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

const (
	chain     = "BEAMHALL-EGRESS"
	hookChain = "DOCKER-USER"
)

// AlwaysDeny is the default set of destinations denied for every Beamhall
// bridge, independent of any allowlist: link-local + cloud metadata. Callers
// should append the host's own IP and the backplane/management subnet.
var AlwaysDeny = []string{
	"169.254.0.0/16", // link-local incl. 169.254.169.254 cloud metadata
}

// Policy is the egress desired-state for one Beamhall bridge.
type Policy struct {
	Bridge string   // host bridge interface, e.g. "br-0a1b2c3d4e5f" or "wcbr-ops"
	Allow  []string // permitted destination CIDRs (e.g. "10.20.0.0/16", "1.1.1.1/32")
}

// Reconciler programs the BEAMHALL-EGRESS chain. The zero value is not usable;
// use New.
type Reconciler struct {
	bin        string   // iptables binary
	alwaysDeny []string // applied to every bridge before the allowlist
}

// New returns a Reconciler. Pass any extra always-deny CIDRs (host IP,
// management subnet) to merge with the built-in link-local/metadata set.
func New(extraAlwaysDeny ...string) *Reconciler {
	return &Reconciler{
		bin:        "iptables",
		alwaysDeny: append(append([]string{}, AlwaysDeny...), extraAlwaysDeny...),
	}
}

// Reconcile makes the live ruleset match policies exactly: it ensures the chain
// exists and is hooked from DOCKER-USER, then flushes and rebuilds the chain.
// Safe to call repeatedly and on boot.
func (r *Reconciler) Reconcile(ctx context.Context, policies []Policy) error {
	if err := r.ensureChain(ctx); err != nil {
		return err
	}
	if err := r.ensureHook(ctx); err != nil {
		return err
	}
	if err := r.run(ctx, "-F", chain); err != nil {
		return fmt.Errorf("flush %s: %w", chain, err)
	}

	// Note: we deliberately do NOT add a conntrack ESTABLISHED,RELATED RETURN
	// rule. Every rule below matches on the inbound bridge (-i bridge), i.e. only
	// ORIGINAL-direction packets *leaving* a container. Reply traffic ingresses
	// on the host's external interface (-i ethX), matches none of these rules,
	// and is allowed by falling through to DOCKER-USER. An established-RETURN at
	// the top would instead let an outbound packet bypass the deny whenever
	// conntrack still holds a (reused) tuple from an earlier allowed flow — a
	// real egress-policy bypass. Filtering strictly by origin direction also
	// means a policy change cuts existing outbound flows immediately.

	for _, p := range policies {
		if p.Bridge == "" {
			continue
		}
		// Always-deny first: metadata/link-local/host/mgmt — beats any allow.
		for _, cidr := range r.alwaysDeny {
			if err := r.run(ctx, "-A", chain, "-i", p.Bridge, "-d", cidr, "-j", "DROP"); err != nil {
				return err
			}
		}
		// Allowlist: permitted destinations RETURN to DOCKER-USER (accepted).
		for _, cidr := range p.Allow {
			if err := r.run(ctx, "-A", chain, "-i", p.Bridge, "-d", cidr, "-j", "RETURN"); err != nil {
				return err
			}
		}
		// Default-deny everything else leaving this bridge.
		if err := r.run(ctx, "-A", chain, "-i", p.Bridge, "-j", "DROP"); err != nil {
			return err
		}
	}
	return nil
}

// Teardown removes the DOCKER-USER hook and deletes the chain. Best-effort:
// returns the first hard error encountered.
func (r *Reconciler) Teardown(ctx context.Context) error {
	// Remove the hook if present (ignore "not found").
	if r.exists(ctx, hookChain, "-j", chain) {
		if err := r.run(ctx, "-D", hookChain, "-j", chain); err != nil {
			return err
		}
	}
	_ = r.run(ctx, "-F", chain)
	_ = r.run(ctx, "-X", chain)
	return nil
}

func (r *Reconciler) ensureChain(ctx context.Context) error {
	if r.run(ctx, "-n", "-L", chain) == nil {
		return nil
	}
	if err := r.run(ctx, "-N", chain); err != nil {
		return fmt.Errorf("create chain %s: %w", chain, err)
	}
	return nil
}

// ensureHook inserts a jump from DOCKER-USER to our chain at the top, exactly
// once. DOCKER-USER is created by Docker; if it is missing we create it so the
// reconciler also works before any container network exists.
func (r *Reconciler) ensureHook(ctx context.Context) error {
	if r.run(ctx, "-n", "-L", hookChain) != nil {
		_ = r.run(ctx, "-N", hookChain)
	}
	if r.exists(ctx, hookChain, "-j", chain) {
		return nil
	}
	if err := r.run(ctx, "-I", hookChain, "1", "-j", chain); err != nil {
		return fmt.Errorf("hook %s -> %s: %w", hookChain, chain, err)
	}
	return nil
}

// exists reports whether a rule is present (iptables -C).
func (r *Reconciler) exists(ctx context.Context, chainName string, rule ...string) bool {
	args := append([]string{"-C", chainName}, rule...)
	return r.run(ctx, args...) == nil
}

func (r *Reconciler) run(ctx context.Context, args ...string) error {
	// -w: block on the xtables lock instead of failing under concurrency.
	full := append([]string{"-w"}, args...)
	cmd := exec.CommandContext(ctx, r.bin, full...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		return fmt.Errorf("%s %s: %w: %s", r.bin, strings.Join(full, " "), err, msg)
	}
	return nil
}
