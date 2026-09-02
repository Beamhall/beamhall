package driver

import "testing"

// TestUsernsRemapConfigured is a regression test:
// NewDockerDriver's startup check
// must correctly recognize the daemon's own signal for whether userns-remap
// is active, so a daemon that silently isn't remapping fails closed instead
// of a deploy proceeding under a false sense of isolation.
func TestUsernsRemapConfigured(t *testing.T) {
	cases := []struct {
		name string
		opts []string
		want bool
	}{
		{"remap configured", []string{"name=seccomp", "name=userns", "name=cgroupns"}, true},
		{"remap not configured", []string{"name=seccomp", "name=apparmor", "name=cgroupns"}, false},
		{"no security options at all", nil, false},
		{"empty slice", []string{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := usernsRemapConfigured(c.opts); got != c.want {
				t.Errorf("usernsRemapConfigured(%v) = %v, want %v", c.opts, got, c.want)
			}
		})
	}
}

// TestBeamIDFromContainerName pins the name→beam derivation the relay's
// caller-address check and the egress per-source rules depend on: workload
// names are "bh_"+sanitize(beamID)+"-"+hex4, beam IDs are hyphen-free ULIDs,
// broker/infra containers must not parse.
func TestBeamIDFromContainerName(t *testing.T) {
	name := "bh_" + instanceID("01M1DEYCQZWA0QA7B4G72CXVF6")
	id, ok := BeamIDFromContainerName(name)
	if !ok || id != "01M1DEYCQZWA0QA7B4G72CXVF6" {
		t.Fatalf("BeamIDFromContainerName(%q) = %q %v", name, id, ok)
	}
	for _, n := range []string{"bh-postgres", "bh-mail", "beamhall-keycloak", "bh_", "bh_-abcd", "random"} {
		if _, ok := BeamIDFromContainerName(n); ok {
			t.Errorf("%q must not parse as a workload", n)
		}
	}
}
