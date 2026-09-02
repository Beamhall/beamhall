// Package egress programs default-deny outbound network policy for Beamhall
// bridges using iptables. It owns two chains, rebuilt idempotently from the
// desired state on every Reconcile — so drift (and a host reboot) self-heals:
//
//   - BEAMHALL-EGRESS, jumped from Docker's DOCKER-USER chain (FORWARD path):
//     the enforcement half of the per-Beamhall egress policy; the metadata/
//     host/management always-deny set is applied regardless of any allowlist
//     (SSRF/metadata defense). See PLAN §6 and hardest-problem #2.
//   - BEAMHALL-INPUT, jumped from INPUT: DOCKER-USER never sees traffic a
//     container addresses to the host itself (its bridge gateway IP, or any
//     host-owned address) — that is delivered locally through INPUT. Without
//     this chain a workload can open TCP to every host listener bound to a
//     wildcard address: the backplane HTTP port, and the gateway — and via
//     the gateway, any other beam's public URL, cross-hall. The guard drops
//     everything bridge-originated except the gateway ports; what those ports
//     serve to workloads is then decided at L7 by the gateway's own guard.
//
// iptables (not nftables) per the 2026 hardening findings. Egress rules match
// on the inbound bridge interface (-i br...), i.e. packets leaving a
// container, so host SSH (INPUT from operator networks) is never affected —
// the INPUT guard matches bridge interfaces only.
package egress

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

const (
	chain          = "BEAMHALL-EGRESS"
	hookChain      = "DOCKER-USER"
	inputChain     = "BEAMHALL-INPUT"
	inputHookChain = "INPUT"

	// bridgeWildcard matches every Docker-managed bridge interface (br-<id12>),
	// Beamhall's and otherwise. The guard is deliberately not scoped to known
	// Beamhall bridges: the bridge set is dynamic (halls are lazy-created) and a
	// container can start on a fresh or orphaned bridge before any per-bridge
	// rule exists — the same reasoning that made the metadata always-deny
	// bridge-independent. On the dedicated appliance every br-* interface
	// carries workload-adjacent traffic; none of it belongs on host listeners.
	bridgeWildcard = "br-+"
)

// AlwaysDeny is the default set of destinations denied for every Beamhall
// bridge, independent of any allowlist: link-local + cloud metadata. Callers
// should append the host's own IP and the backplane/management subnet.
var AlwaysDeny = []string{
	"169.254.0.0/16", // link-local incl. 169.254.169.254 cloud metadata
}

// SourceRule permits ONE workload (by its current container IP) to reach one
// destination — the per-beam external grants. Re-derived from live network
// state on every reconcile; a stale IP matches nothing (fail-closed).
type SourceRule struct {
	SourceIP string
	Dest     string
}

// Policy is the egress desired-state for one Beamhall bridge.
type Policy struct {
	Bridge string   // host bridge interface, e.g. "br-0a1b2c3d4e5f" or "wcbr-ops"
	Allow  []string // permitted destination CIDRs (e.g. "10.20.0.0/16", "1.1.1.1/32")
	// SameBridgeAllow are the broker container IPs (managed Postgres, mail,
	// object store) exempted from the intra-bridge deny — in BOTH directions.
	// Everything else on the bridge, sibling workloads included, is denied:
	// beam-to-beam rides the backplane relay, never the bridge.
	SameBridgeAllow []string
	// PerSource are the per-beam external grants for workloads on this bridge.
	PerSource []SourceRule
}

// Reconciler programs the BEAMHALL-EGRESS and BEAMHALL-INPUT chains. The zero
// value is not usable; use New.
type Reconciler struct {
	bin        string   // iptables binary
	restoreBin string   // iptables-restore binary (atomic chain replace)
	alwaysDeny []string // applied to every bridge before the allowlist
	hostPorts  []int    // host TCP ports workloads may reach (the gateway); everything else is dropped
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

// AllowHostPorts sets the host TCP ports the BEAMHALL-INPUT guard leaves open
// to bridge-originated traffic — the gateway's listen ports, so workloads can
// still reach gateway-fronted infrastructure the gateway chooses to serve
// them. Every other bridge→host packet is dropped. With no ports set the
// guard drops all bridge→host traffic (fail-closed).
func (r *Reconciler) AllowHostPorts(ports ...int) {
	r.hostPorts = ports
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
	// The intra-bridge posture (broker-only exemptions; sibling workloads
	// denied) is enforceable ONLY while bridged traffic traverses the filter
	// — a kernel setting, not a rule. Assert it here, fail-closed: without it
	// the per-bridge rules silently see nothing and sibling isolation does
	// not exist.
	if err := r.ensureBridgeNetfilter(ctx); err != nil {
		return err
	}
	if err := r.ensureChain(ctx, chain); err != nil {
		return err
	}
	if err := r.ensureChain(ctx, inputChain); err != nil {
		return err
	}
	if err := r.ensureHook(ctx, hookChain, chain, true); err != nil {
		return err
	}
	if err := r.ensureHook(ctx, inputHookChain, inputChain, false); err != nil {
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
	fmt.Fprintf(&buf, "*filter\n:%s -\n:%s -\n", chain, inputChain)

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
		// Same-bridge traffic may or may not traverse FORWARD/DOCKER-USER at
		// all, depending on br_netfilter — a module Beamhall does not own and
		// Docker may load at any time — so these rules must be correct under
		// BOTH states. Only the hall's broker containers (managed Postgres,
		// mail, object store) are exempt from the intra-bridge deny, and in
		// both directions: rules here match origin-direction packets only (no
		// conntrack, see above), so without the -s twin every broker REPLY
		// would die at the per-bridge DROP under br_netfilter. Sibling
		// workloads get no exemption — beam-to-beam rides the backplane
		// relay, never the bridge.
		for _, ip := range p.SameBridgeAllow {
			if !restoreSafe(ip) {
				return nil, fmt.Errorf("egress: unsafe broker address %q for bridge %s", ip, p.Bridge)
			}
			fmt.Fprintf(&buf, "-A %s -i %s -o %s -d %s -j RETURN\n", chain, p.Bridge, p.Bridge, ip)
			fmt.Fprintf(&buf, "-A %s -i %s -o %s -s %s -j RETURN\n", chain, p.Bridge, p.Bridge, ip)
		}
		// Per-workload external grants: one source, one destination. Ahead of
		// the hall allowlist only for readability — both RETURN.
		for _, r := range p.PerSource {
			if !restoreSafe(r.SourceIP) || !restoreSafe(r.Dest) {
				return nil, fmt.Errorf("egress: unsafe per-source rule %q -> %q for bridge %s", r.SourceIP, r.Dest, p.Bridge)
			}
			fmt.Fprintf(&buf, "-A %s -i %s -s %s -d %s -j RETURN\n", chain, p.Bridge, r.SourceIP, r.Dest)
		}
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

	// Host-listener guard (INPUT path). Container→host traffic never traverses
	// FORWARD/DOCKER-USER — it is delivered locally — so the egress chain above
	// cannot see it. Only the gateway ports pass; the gateway then decides at
	// L7 what a workload-originated request may reach.
	//
	// Unlike the egress chain, this one NEEDS the conntrack RETURN: replies to
	// host-originated dials (the backplane brokering a tool call into a
	// workload, health checks) ingress on the very bridge interface the guard
	// matches, addressed to the host's ephemeral source port — the terminal
	// DROP would sever every such connection mid-handshake. It is also not the
	// bypass it would be on the egress chain: a tuple's reply direction targets
	// the ephemeral port the host dialed from, never a listening service port,
	// so a container cannot ride an existing tuple to reach a host listener —
	// new connections still start with an unmatched SYN and fall through to
	// the port rules below.
	fmt.Fprintf(&buf, "-A %s -i %s -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN\n", inputChain, bridgeWildcard)
	for _, port := range r.hostPorts {
		if port <= 0 || port > 65535 {
			return nil, fmt.Errorf("egress: invalid host guard port %d", port)
		}
		fmt.Fprintf(&buf, "-A %s -i %s -p tcp --dport %d -j RETURN\n", inputChain, bridgeWildcard, port)
	}
	fmt.Fprintf(&buf, "-A %s -i %s -j DROP\n", inputChain, bridgeWildcard)

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

// Teardown removes both hooks and deletes both chains. Best-effort: returns
// the first hard error encountered.
func (r *Reconciler) Teardown(ctx context.Context) error {
	for _, pair := range [][2]string{{hookChain, chain}, {inputHookChain, inputChain}} {
		// Remove the hook if present (ignore "not found").
		if r.exists(ctx, pair[0], "-j", pair[1]) {
			if err := r.run(ctx, "-D", pair[0], "-j", pair[1]); err != nil {
				return err
			}
		}
		_ = r.run(ctx, "-F", pair[1])
		_ = r.run(ctx, "-X", pair[1])
	}
	return nil
}

// bridgeNFSysctl is the switch that sends bridged (same-L2) traffic through
// the iptables filter path. Docker may or may not have it on; the appliance
// REQUIRES it — the whole intra-bridge policy (broker exemptions, the sibling
// deny, per-source grants) hangs off it — so the reconciler asserts it on
// every run rather than hoping.
const bridgeNFSysctl = "/proc/sys/net/bridge/bridge-nf-call-iptables"

func (r *Reconciler) ensureBridgeNetfilter(ctx context.Context) error {
	if b, err := os.ReadFile(bridgeNFSysctl); err == nil && strings.TrimSpace(string(b)) == "1" {
		return nil
	}
	// The sysctl file appears only once the module is loaded; modprobe is
	// idempotent.
	if err := exec.CommandContext(ctx, "modprobe", "br_netfilter").Run(); err != nil {
		return fmt.Errorf("egress: load br_netfilter (required for intra-bridge policy): %w", err)
	}
	if err := os.WriteFile(bridgeNFSysctl, []byte("1\n"), 0); err != nil {
		return fmt.Errorf("egress: enable bridge-nf-call-iptables (required for intra-bridge policy): %w", err)
	}
	return nil
}

func (r *Reconciler) ensureChain(ctx context.Context, name string) error {
	if r.run(ctx, "-n", "-L", name) == nil {
		return nil
	}
	if err := r.run(ctx, "-N", name); err != nil {
		return fmt.Errorf("create chain %s: %w", name, err)
	}
	return nil
}

// ensureHook inserts a jump from a hook chain to ours at the top, exactly
// once. DOCKER-USER is created by Docker; if it is missing we create it so the
// reconciler also works before any container network exists (INPUT is a
// built-in and always exists).
func (r *Reconciler) ensureHook(ctx context.Context, from, to string, createFrom bool) error {
	if createFrom && r.run(ctx, "-n", "-L", from) != nil {
		_ = r.run(ctx, "-N", from)
	}
	if r.exists(ctx, from, "-j", to) {
		return nil
	}
	if err := r.run(ctx, "-I", from, "1", "-j", to); err != nil {
		return fmt.Errorf("hook %s -> %s: %w", from, to, err)
	}
	return nil
}

// exists reports whether a rule is present (iptables -C).
func (r *Reconciler) exists(ctx context.Context, chainName string, rule ...string) bool {
	args := append([]string{"-C", chainName}, rule...)
	return r.run(ctx, args...) == nil
}

// hostnameRe matches an RFC 1123 hostname (labels of letters/digits/hyphens,
// dot-separated). Deliberately narrow: anything it rejects would either fail
// or surprise inside an iptables-restore -d field.
var hostnameRe = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// ValidateAllowEntry reports whether one allowlist entry is a destination
// iptables-restore can actually load: an IPv4 address, an IPv4 CIDR, or a
// bare hostname. Callers MUST run this at write time: the reconciler renders
// entries verbatim into one appliance-wide restore transaction, so a single
// malformed entry in any beamhall — a "host:port" suffix, an IPv6 literal —
// would fail the whole transaction and with it every subsequent deploy on the
// appliance, not just the beamhall that stored it.
func ValidateAllowEntry(entry string) error {
	s := strings.TrimSpace(entry)
	if s == "" {
		return fmt.Errorf("empty allowlist entry")
	}
	if !restoreSafe(s) || strings.ContainsAny(s, " \t") {
		return fmt.Errorf("allowlist entry %q contains unsafe characters", s)
	}
	if strings.Contains(s, ":") {
		return fmt.Errorf("allowlist entry %q: port suffixes and IPv6 literals are not supported — egress rules match the destination address only (use a bare IPv4 address, IPv4 CIDR, or hostname)", s)
	}
	if strings.Contains(s, "/") {
		ip, _, err := net.ParseCIDR(s)
		if err != nil || ip.To4() == nil {
			return fmt.Errorf("allowlist entry %q is not a valid IPv4 CIDR", s)
		}
		return nil
	}
	if ip := net.ParseIP(s); ip != nil {
		if ip.To4() == nil {
			return fmt.Errorf("allowlist entry %q: IPv6 is not supported", s)
		}
		return nil
	}
	// All-numeric dotted entries are malformed IPs, not hostnames ("300.1.1.1"
	// would pass the hostname shape but fail resolution at restore time).
	if strings.Trim(s, "0123456789.") == "" {
		return fmt.Errorf("allowlist entry %q is not a valid IPv4 address", s)
	}
	if !hostnameRe.MatchString(s) || len(s) > 253 {
		return fmt.Errorf("allowlist entry %q is not a valid IPv4 address, IPv4 CIDR, or hostname", s)
	}
	return nil
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
