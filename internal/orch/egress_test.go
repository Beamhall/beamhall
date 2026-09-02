package orch

import (
	"context"
	"strings"
	"testing"

	"github.com/Beamhall/beamhall/internal/domain"
)

// TestSetEgressRejectsUnloadableEntries: allowlist entries are rendered into
// ONE appliance-wide iptables-restore transaction, so a single stored
// malformed entry (a host:port suffix, an IPv6 literal) would fail that
// transaction — and with it every subsequent deploy on the appliance. The
// write path must refuse them with a teaching error, and the refusal must
// not persist anything.
func TestSetEgressRejectsUnloadableEntries(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	it := Actor{ITAdmin: true}

	for _, bad := range []string{"api.corp.internal:443", "2001:db8::1", "10.0.0.0/33"} {
		err := w.o.SetEgress(ctx, it, w.bh.ID, domain.EgressAllowSet, []string{bad})
		if err == nil {
			t.Fatalf("SetEgress accepted unloadable entry %q", bad)
		}
	}
	if err := w.o.SetEgress(ctx, it, w.bh.ID, domain.EgressAllowSet, []string{"api.corp.internal", "10.20.0.0/16", "1.1.1.1"}); err != nil {
		t.Fatalf("SetEgress rejected valid entries: %v", err)
	}
	bh, err := w.st.GetBeamhall(ctx, w.bh.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(bh.NetworkPolicy.EgressAllowlist) != 3 {
		t.Fatalf("allowlist = %v", bh.NetworkPolicy.EgressAllowlist)
	}

	// The port-suffix refusal must teach, not just refuse — the docs
	// advertised ":port" for two releases, so IT will type it.
	err = w.o.SetEgress(ctx, it, w.bh.ID, domain.EgressAllowSet, []string{"api.corp.internal:443"})
	if err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("port-suffix refusal should explain itself, got: %v", err)
	}
}

// TestCreateBeamhallRejectsUnloadableAllowlist: the bootstrap path stores the
// same field and must hold the same line.
func TestCreateBeamhallRejectsUnloadableAllowlist(t *testing.T) {
	w := newWorld(t)
	it := Actor{ITAdmin: true}
	_, err := w.o.CreateBeamhall(context.Background(), it, NewBeamhallSpec{
		Slug: "fresh", EgressMode: domain.EgressAllowSet, Allowlist: []string{"1.2.3.4:80"},
	})
	if err == nil {
		t.Fatal("CreateBeamhall accepted an unloadable allowlist entry")
	}
}
