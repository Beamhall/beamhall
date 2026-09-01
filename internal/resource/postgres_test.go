package resource

import (
	"strings"
	"testing"
)

func TestDeriveIdentifiersDistinguishesCollidingTuples(t *testing.T) {
	// Hyphen flattening plus the underscore join is lossy: these two distinct
	// tenant tuples flatten to the same readable prefix, and without the digest
	// suffix the second tenant's create would collide with (and squat) the
	// first's backing database on the shared server.
	a, aRole, err := deriveIdentifiers("team-blue", "api", "main")
	if err != nil {
		t.Fatalf("derive a: %v", err)
	}
	b, _, err := deriveIdentifiers("team", "blue-api", "main")
	if err != nil {
		t.Fatalf("derive b: %v", err)
	}
	if a == b {
		t.Fatalf("distinct tuples must derive distinct identifiers, both got %q", a)
	}
	if !strings.HasPrefix(a, "bh_team_blue_api_main_") || !strings.HasPrefix(b, "bh_team_blue_api_main_") {
		t.Fatalf("readable prefix lost: %q / %q", a, b)
	}
	if aRole != a+"_rw" {
		t.Fatalf("role should be db name + _rw, got %q for %q", aRole, a)
	}

	// Same tuple, same names — reconcile paths depend on determinism.
	a2, _, err := deriveIdentifiers("team-blue", "api", "main")
	if err != nil {
		t.Fatalf("derive a2: %v", err)
	}
	if a2 != a {
		t.Fatalf("derivation must be deterministic: %q vs %q", a2, a)
	}
}

func TestDeriveIdentifiersRejectsBadParts(t *testing.T) {
	if _, _, err := deriveIdentifiers("ok", "api;drop", "main"); err == nil {
		t.Fatal("invalid characters must be rejected")
	}
	if _, _, err := deriveIdentifiers("", "api", "main"); err == nil {
		t.Fatal("empty part must be rejected")
	}
	long := strings.Repeat("a", 32)
	if _, _, err := deriveIdentifiers(long, long, "extra-"+long[:8]); err == nil {
		t.Fatal("identifiers over Postgres's 63-byte limit must be rejected with guidance, not truncated")
	}
}
