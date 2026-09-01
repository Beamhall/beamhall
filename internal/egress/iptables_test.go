package egress

import (
	"strings"
	"testing"
)

// TestBuildScriptAtomicAndOrdered is a regression test:
// Reconcile must
// replace the chain's entire ruleset in one iptables-restore transaction
// scoped to BEAMHALL-EGRESS alone (never a flush-then-rebuild that leaves the
// chain briefly empty), and always-deny must still precede the allowlist,
// which must still precede the bridge's default-deny.
func TestBuildScriptAtomicAndOrdered(t *testing.T) {
	r := New("10.0.0.5/32") // extra always-deny (host IP)
	script, err := r.buildScript([]Policy{
		{Bridge: "br-abc123", Allow: []string{"1.1.1.1/32"}},
	})
	if err != nil {
		t.Fatalf("buildScript: %v", err)
	}
	s := string(script)

	if !strings.HasPrefix(s, "*filter\n:"+chain+" -\n") {
		t.Fatalf("script does not open with an isolated chain declaration (would touch other chains under --noflush):\n%s", s)
	}
	if !strings.HasSuffix(s, "COMMIT\n") {
		t.Fatalf("script does not end with COMMIT:\n%s", s)
	}
	if strings.Count(s, "*filter") != 1 || strings.Count(s, "COMMIT") != 1 {
		t.Fatalf("script must be exactly one atomic transaction:\n%s", s)
	}

	metadataIdx := strings.Index(s, "-d 169.254.0.0/16 -j DROP")
	hostIdx := strings.Index(s, "-d 10.0.0.5/32 -j DROP")
	sameBridgeIdx := strings.Index(s, "-A "+chain+" -i br-abc123 -o br-abc123 -j RETURN")
	allowIdx := strings.Index(s, "-d 1.1.1.1/32 -j RETURN")
	defaultDenyIdx := strings.Index(s, "-A "+chain+" -i br-abc123 -j DROP")
	if metadataIdx < 0 || hostIdx < 0 || sameBridgeIdx < 0 || allowIdx < 0 || defaultDenyIdx < 0 {
		t.Fatalf("missing expected rule(s):\n%s", s)
	}
	if !(metadataIdx < sameBridgeIdx && hostIdx < sameBridgeIdx && sameBridgeIdx < allowIdx && allowIdx < defaultDenyIdx) {
		t.Fatalf("rule ordering wrong (always-deny < same-bridge exemption < allow < default-deny):\n%s", s)
	}
}

// TestSameBridgeTrafficIsExempt guards the br_netfilter failure mode: with the
// bridge-nf-call-iptables sysctl on (Docker can load the module at any time),
// same-bridge container traffic traverses DOCKER-USER and, without an explicit
// -i br -o br RETURN ahead of the terminal DROP, every intra-hall connection —
// beam↔beam and beam↔broker (Postgres, SMTP) — is silently severed.
func TestSameBridgeTrafficIsExempt(t *testing.T) {
	r := New()
	script, err := r.buildScript([]Policy{
		{Bridge: "br-abc123"},
		{Bridge: "br-def456", Allow: []string{"1.1.1.1/32"}},
	})
	if err != nil {
		t.Fatalf("buildScript: %v", err)
	}
	s := string(script)
	for _, br := range []string{"br-abc123", "br-def456"} {
		ret := "-A " + chain + " -i " + br + " -o " + br + " -j RETURN"
		drop := "-A " + chain + " -i " + br + " -j DROP"
		if !strings.Contains(s, ret) {
			t.Fatalf("bridge %s has no same-bridge exemption:\n%s", br, s)
		}
		if strings.Index(s, ret) > strings.Index(s, drop) {
			t.Fatalf("bridge %s: same-bridge RETURN must precede the terminal DROP:\n%s", br, s)
		}
	}
	// The exemption must stay bridge-pinned on both sides: cross-bridge
	// traffic (-i br-a -o br-b) must fall through to the terminal DROP.
	if strings.Contains(s, "-i br-abc123 -o br-def456") {
		t.Fatalf("cross-bridge exemption must not exist:\n%s", s)
	}
	// And it must not outrank the metadata always-deny.
	if strings.Index(s, "-d 169.254.0.0/16 -j DROP") > strings.Index(s, "-o br-abc123 -j RETURN") {
		t.Fatalf("always-deny must precede the same-bridge exemption:\n%s", s)
	}
}

// TestAlwaysDenyIsBridgeIndependent proves the fix: the metadata/
// link-local always-deny must apply to every bridge, including one that
// isn't in this Reconcile call's policy list at all (a stale/orphaned
// bridge, or a race where a container starts on a bridge before its policy
// is registered) — not just bridges explicitly listed.
func TestAlwaysDenyIsBridgeIndependent(t *testing.T) {
	r := New()
	// A policy list that never mentions "br-unlisted" at all.
	script, err := r.buildScript([]Policy{
		{Bridge: "br-abc123", Allow: []string{"1.1.1.1/32"}},
	})
	if err != nil {
		t.Fatalf("buildScript: %v", err)
	}
	s := string(script)

	// The always-deny rule must have no -i (bridge) filter at all, so it
	// matches traffic from ANY bridge, not just the ones this call listed.
	if !strings.Contains(s, "-A "+chain+" -d 169.254.0.0/16 -j DROP") {
		t.Fatalf("no bridge-independent metadata-deny rule present:\n%s", s)
	}
	if strings.Contains(s, "-i br-unlisted") {
		t.Fatalf("script references the unlisted bridge, which should never appear:\n%s", s)
	}
}

// TestBuildScriptRejectsNewlineInjection guards the new attack surface the
// text-based iptables-restore script introduces: an embedded newline in a
// bridge name or CIDR would start a new line the restore parser executes as
// its own command against the live ruleset (a risk the old one-exec-per-rule
// approach never had, since each argv element was never script-parsed).
func TestBuildScriptRejectsNewlineInjection(t *testing.T) {
	cases := []struct {
		name     string
		reconcer *Reconciler
		policies []Policy
	}{
		{
			name:     "bridge name",
			reconcer: New(),
			policies: []Policy{{Bridge: "br-x\n-A DOCKER-USER -j ACCEPT"}},
		},
		{
			name:     "allowlist entry",
			reconcer: New(),
			policies: []Policy{{Bridge: "br-x", Allow: []string{"1.1.1.1/32\n-A DOCKER-USER -j ACCEPT"}}},
		},
		{
			name:     "always-deny entry",
			reconcer: New("10.0.0.5/32\n-A DOCKER-USER -j ACCEPT"),
			policies: []Policy{{Bridge: "br-x"}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := c.reconcer.buildScript(c.policies); err == nil {
				t.Fatal("expected an error rejecting the newline-embedded value, got nil")
			}
		})
	}
}
