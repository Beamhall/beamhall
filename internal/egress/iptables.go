// Package egress programs default-deny outbound network policy for Beamhall
// bridges using iptables. It owns a single chain, BEAMHALL-EGRESS, jumped from
// Docker's DOCKER-USER chain, and rebuilds it idempotently from the desired
// state on every Reconcile — so drift (and a host reboot) self-heals. This is
// the enforcement half of the per-Beamhall egress policy; the metadata/host/
// management always-deny set is applied regardless of any allowlist
// (SSRF/metadata defense). See PLAN §6 and hardest-problem #2.
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
	restoreBin string   // iptables-restore binary (atomic chain replace)
	alwaysDeny []string // applied to every bridge before the allowlist
}

// New returns a Reconciler. Pass any extra always-deny CIDRs (host IP,
// management subnet) to merge with the built-in link-local/metadata set.
func New(extraAlwaysDeny ...string) *Reconciler {
	return &Reconciler{
		bin:        "iptables",
		restoreBin: "iptables-restore",
		alwaysDeny: append(append([]string{}, AlwaysDeny...), extraAlwaysDeny...),
	}
}

// Reconcile makes the live ruleset match policies exactly: it ensures the chain
// exists and is hooked from DOCKER-USER, then atomically replaces the chain's
// entire rule set in one iptables-restore transaction. A flush-then-rebuild
// approach (one exec per rule) leaves a real window where the chain is empty —
// every bridge's egress falls through DOCKER-USER to Docker's default-ACCEPT
// during that window, including to the cloud metadata address — and this runs
// on every deploy (bridges are lazy-created), not just at boot. Safe to call
// repeatedly and on boot.
func (r *Reconciler) Reconcile(ctx context.Context, policies []Policy) error {
	if err := r.ensureChain(ctx); err != nil {
		return err
	}
	if err := r.ensureHook(ctx); err != nil {
		return err
	}

	script, err := r.buildScript(policies)
	if err != nil {
		return err
	}
	if err := r.restore(ctx, script); err != nil {
		return fmt.Errorf("atomically replace %s: %w", chain, err)
	}
	return nil
}

// buildScript renders policies as an iptables-restore script that fully
// replaces the BEAMHALL-EGRESS chain's contents in one transaction. Pure and
// side-effect-free (no exec), so the ruleset it would apply — including the
// injection guard — can be checked without root or a real iptables.
func (r *Reconciler) buildScript(policies []Policy) ([]byte, error) {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "*filter\n:%s -\n", chain)

	// Permanent, bridge-independent backstop: metadata/link-local is denied
	// for EVERY bridge — including one omitted from this Reconcile call
	// entirely (a stale/orphaned bridge, or a race where a container starts
	// on a bridge before its policy is registered). The per-bridge loop
	// below only ever covered bridges actually present in policies, leaving
	// any other bridge's containers free to reach the metadata endpoint with
	// no rule matching them at all — the steady-state cousin of the
	// reconcile flush-window gap. DROP is terminal, so this
	// also makes the per-bridge always-deny rules below redundant for the
	// same CIDRs; they're dropped in favor of this single unconditional set.
	for _, cidr := range r.alwaysDeny {
		if !restoreSafe(cidr) {
			return nil, fmt.Errorf("egress: unsafe always-deny entry %q", cidr)
		}
		fmt.Fprintf(&buf, "-A %s -d %s -j DROP\n", chain, cidr)
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
		if !restoreSafe(p.Bridge) {
			return nil, fmt.Errorf("egress: unsafe bridge name %q", p.Bridge)
		}
		// (Always-deny is the bridge-independent block above, ahead of this
		// loop — it already covers this bridge, so no per-bridge repeat here.)
		// Same-bridge traffic (container↔container and container↔broker inside
		// one hall) is not egress. Whether it traverses FORWARD/DOCKER-USER at
		// all depends on br_netfilter — a module Beamhall does not own and
		// Docker may load at any time — and without this exemption the terminal
		// DROP below would then sever every intra-hall connection, including
		// the beams' own Postgres/SMTP broker links. The always-deny set above
		// still precedes it.
		fmt.Fprintf(&buf, "-A %s -i %s -o %s -j RETURN\n", chain, p.Bridge, p.Bridge)
		// Allowlist: permitted destinations RETURN to DOCKER-USER (accepted).
		for _, cidr := range p.Allow {
			if !restoreSafe(cidr) {
				return nil, fmt.Errorf("egress: unsafe allowlist entry %q for bridge %s", cidr, p.Bridge)
			}
			fmt.Fprintf(&buf, "-A %s -i %s -d %s -j RETURN\n", chain, p.Bridge, cidr)
		}
		// Default-deny everything else leaving this bridge.
		fmt.Fprintf(&buf, "-A %s -i %s -j DROP\n", chain, p.Bridge)
	}
	buf.WriteString("COMMIT\n")
	return buf.Bytes(), nil
}

// restoreSafe reports whether s is safe to embed as a single field in an
// iptables-restore script line. An embedded newline (unlike an exec.Command
// argv element, which iptables-restore never sees split) would start a new
// line the restore parser executes as its own command against the live
// ruleset — so this is not a formatting nicety, it is what keeps a malformed
// or malicious CIDR/bridge value from injecting arbitrary firewall rules.
func restoreSafe(s string) bool {
	return s != "" && !strings.ContainsAny(s, "\n\r\x00")
}

// restore applies an iptables-restore script atomically. --noflush means only
// chains the script declares (here, just BEAMHALL-EGRESS) are replaced; every
// other chain in the table (DOCKER-USER, DOCKER's own chains, …) is untouched.
func (r *Reconciler) restore(ctx context.Context, rules []byte) error {
	cmd := exec.CommandContext(ctx, r.restoreBin, "-w", "--noflush")
	cmd.Stdin = bytes.NewReader(rules)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		return fmt.Errorf("%s: %w: %s", r.restoreBin, err, msg)
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
