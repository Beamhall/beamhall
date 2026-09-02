package orch

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Beamhall/beamhall/internal/apptools"
	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/driver"
)

// c2cWorld wires app tools + the relay, with a controllable facts map: tests
// decide which container names/IPs live on the hall bridge.
type c2cWorld struct {
	*world
	beamSrv *beamToolServer
	signer  *apptools.Signer
	facts   *driver.NetworkFacts
}

func newC2CWorld(t *testing.T, cfg C2CConfig) *c2cWorld {
	t.Helper()
	key, err := apptools.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := apptools.NewSigner(key, "https://bh.example/mcp")
	if err != nil {
		t.Fatal(err)
	}
	beamSrv := newBeamToolServer(t)
	facts := &driver.NetworkFacts{
		Bridge:       "br-test00000",
		Subnets:      []string{"172.18.0.0/16"},
		Gateway:      "172.18.0.1",
		ContainerIPs: map[string]string{},
	}
	w := newWorldOpts(t,
		WithAppTools(signer, apptools.NewClient(2*time.Second, 2*time.Second), AppToolsConfig{}),
		WithC2C(cfg, func(ctx context.Context, netName string) (driver.NetworkFacts, error) {
			return *facts, nil
		}),
	)
	w.drv.backendAddr = beamSrv.addr()
	return &c2cWorld{world: w, beamSrv: beamSrv, signer: signer, facts: facts}
}

// grantedPair deploys a source and a promoted live target, grants source →
// target, and registers the source's container on the fake bridge. Returns
// the source's plaintext relay key (read back through the vault, as the
// injected file would carry it).
func (w *c2cWorld) grantedPair(t *testing.T) (source, target *domain.Beam, key string) {
	t.Helper()
	ctx := context.Background()
	source = w.deployed(t, "caller")
	target = w.deployed(t, "handbook")
	if _, err := w.o.PromoteToLive(ctx, w.admin, w.bh.ID, target.ID); err != nil {
		t.Fatalf("PromoteToLive: %v", err)
	}
	it := Actor{ITAdmin: true, ID: "it-1"}
	res, err := w.o.SetBeamPeers(ctx, it, w.bh.ID, source.ID, PeerSpec{Peers: []string{"ops/handbook"}})
	if err != nil {
		t.Fatalf("SetBeamPeers: %v", err)
	}
	if !res.KeyCreated {
		t.Fatal("first grant must mint the relay key")
	}
	mounts, err := w.vault.Inject(ctx, []domain.SecretRef{{
		BeamhallID: w.bh.ID, BeamID: source.ID, Key: apptools.C2CKeyName, Channel: domain.ChannelPreview,
	}})
	if err != nil || len(mounts) != 1 {
		t.Fatalf("read back relay key: %v (%d mounts)", err, len(mounts))
	}
	w.facts.ContainerIPs["bh_"+string(source.ID)+"-ab12"] = "172.18.0.7"
	return source, target, string(mounts[0].Value)
}

func TestSetBeamPeersGrantWriteAndValidation(t *testing.T) {
	w := newC2CWorld(t, C2CConfig{Port: 8444})
	ctx := context.Background()
	source := w.deployed(t, "caller")
	w.deployed(t, "handbook")
	it := Actor{ITAdmin: true, ID: "it-1"}

	// Non-IT is refused and the refusal is on the chain.
	if _, err := w.o.SetBeamPeers(ctx, w.build, w.bh.ID, source.ID, PeerSpec{Peers: []string{"ops/handbook"}}); err == nil {
		t.Fatal("builder must not write grants")
	}

	for _, bad := range []PeerSpec{
		{},                                  // nothing to grant
		{Peers: []string{"handbook"}},       // missing workspace
		{Peers: []string{"ops/caller"}},     // self-reference
		{Peers: []string{"ops/nope"}},       // unknown app
		{Peers: []string{"nope/handbook"}},  // unknown workspace
		{External: []string{"1.2.3.4:443"}}, // port suffix
		{External: []string{"2001:db8::1"}}, // IPv6
	} {
		if _, err := w.o.SetBeamPeers(ctx, it, w.bh.ID, source.ID, bad); err == nil {
			t.Errorf("spec %+v must be refused", bad)
		}
	}

	res, err := w.o.SetBeamPeers(ctx, it, w.bh.ID, source.ID, PeerSpec{
		Peers: []string{"ops/handbook", "ops/handbook"}, External: []string{"api.corp.internal"},
	})
	if err != nil {
		t.Fatalf("SetBeamPeers: %v", err)
	}
	if len(res.Grant.Peers.Beams) != 1 || len(res.Targets) != 1 || !res.KeyCreated {
		t.Fatalf("result = %+v", res)
	}
	// A second write reuses the key (no rotation surprise for the workload).
	res2, err := w.o.SetBeamPeers(ctx, it, w.bh.ID, source.ID, PeerSpec{Peers: []string{"ops/handbook"}})
	if err != nil || res2.KeyCreated {
		t.Fatalf("re-grant: KeyCreated=%v err=%v", res2.KeyCreated, err)
	}

	// Clear drops the grant but keeps the key: a later re-grant must not
	// force another redeploy.
	if _, err := w.o.SetBeamPeers(ctx, it, w.bh.ID, source.ID, PeerSpec{Clear: true}); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if has, _ := w.st.HasC2CKey(ctx, source.ID); !has {
		t.Fatal("clear must keep the relay key")
	}
	peers, err := w.o.C2CPeers(ctx, source.ID)
	if err != nil || len(peers) != 0 {
		t.Fatalf("after clear: peers=%v err=%v", peers, err)
	}
}

func TestC2CRelayMenuInvokeAndClaims(t *testing.T) {
	w := newC2CWorld(t, C2CConfig{Port: 8444})
	ctx := context.Background()
	source, target, key := w.grantedPair(t)

	// Authentication: hash + the caller's live container address.
	if _, err := w.o.C2CAuthenticate(ctx, key, "172.18.0.99"); !errors.Is(err, ErrPeerAuth) {
		t.Fatalf("foreign address must be the uniform refusal, got %v", err)
	}
	if _, err := w.o.C2CAuthenticate(ctx, "not-a-key", "172.18.0.7"); !errors.Is(err, ErrPeerAuth) {
		t.Fatalf("bad key must be the uniform refusal, got %v", err)
	}
	got, err := w.o.C2CAuthenticate(ctx, key, "172.18.0.7")
	if err != nil || got != source.ID {
		t.Fatalf("C2CAuthenticate = %v, %v", got, err)
	}

	// The peers list resolves grants live.
	peers, err := w.o.C2CPeers(ctx, source.ID)
	if err != nil || len(peers) != 1 || peers[0].App != "handbook" || !peers[0].Live {
		t.Fatalf("C2CPeers = %+v, %v", peers, err)
	}

	// Menu, then invoke — and the assertion the target saw carries the beam
	// caller identity.
	res, err := w.o.C2CCall(ctx, source.ID, "ops", "handbook", "", nil)
	if err != nil || res.Menu == nil || len(res.Menu.Tools) != 2 {
		t.Fatalf("menu: %+v err=%v", res, err)
	}
	res, err = w.o.C2CCall(ctx, source.ID, "ops", "handbook", "whoami", []byte(`{}`))
	if err != nil || len(res.Result) == 0 {
		t.Fatalf("invoke: %v", err)
	}
	claims := parseAssertion(t, w.signer, w.beamSrv.lastAssertion(t))
	for k, want := range map[string]string{
		"sub": string(source.ID), "caller_type": apptools.CallerBeam,
		"aud": string(target.ID), "channel": "live", "tool": "whoami", "email": "",
	} {
		if fmt.Sprint(claims[k]) != want && !(k == "aud" && audMatches(claims[k], want)) {
			t.Errorf("claim %s = %v, want %q", k, claims[k], want)
		}
	}

	// Audit shape: use_peer_tool events under the beam actor.
	recs, _ := w.st.ListAuditEvents(ctx, 0, 100)
	var calls int
	for _, r := range recs {
		if r.Event.Action == "use_peer_tool" {
			calls++
			if r.Event.ActorID != domain.ID("beam:"+string(source.ID)) || r.Event.Decision != domain.DecisionAllow {
				t.Errorf("audit event wrong: %+v", r.Event)
			}
			if r.Event.BeamID != target.ID {
				t.Errorf("audit beam = %v, want target", r.Event.BeamID)
			}
		}
	}
	if calls != 2 {
		t.Fatalf("want 2 use_peer_tool events, got %d", calls)
	}
}

func audMatches(claim any, want string) bool {
	if s, ok := claim.(string); ok {
		return s == want
	}
	if arr, ok := claim.([]any); ok && len(arr) == 1 {
		return fmt.Sprint(arr[0]) == want
	}
	return false
}

func TestC2CUniformRefusalAndRevocation(t *testing.T) {
	w := newC2CWorld(t, C2CConfig{Port: 8444})
	ctx := context.Background()
	source, _, _ := w.grantedPair(t)
	it := Actor{ITAdmin: true, ID: "it-1"}

	// An existing-but-ungranted app and a nonexistent app read byte-identical
	// — existence must not leak to a beam any more than to a user.
	w.deployed(t, "vault-ui")
	_, errUngranted := w.o.C2CCall(ctx, source.ID, "ops", "vault-ui", "", nil)
	_, errMissing := w.o.C2CCall(ctx, source.ID, "ops", "ghost", "", nil)
	if errUngranted == nil || errMissing == nil || errUngranted.Error() != errMissing.Error() {
		t.Fatalf("refusals differ:\n  ungranted: %v\n  missing:   %v", errUngranted, errMissing)
	}
	if !errors.Is(errUngranted, ErrPeerNotGranted) {
		t.Fatalf("want ErrPeerNotGranted, got %v", errUngranted)
	}

	// Revocation bites on the very next call — the grant check is per request.
	if _, err := w.o.C2CCall(ctx, source.ID, "ops", "handbook", "", nil); err != nil {
		t.Fatalf("granted call: %v", err)
	}
	if _, err := w.o.SetBeamPeers(ctx, it, w.bh.ID, source.ID, PeerSpec{Clear: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.o.C2CCall(ctx, source.ID, "ops", "handbook", "", nil); !errors.Is(err, ErrPeerNotGranted) {
		t.Fatalf("revoked call must refuse uniformly, got %v", err)
	}

	// The denials are on the chain.
	recs, _ := w.st.ListAuditEvents(ctx, 0, 100)
	denies := 0
	for _, r := range recs {
		if r.Event.Action == "use_peer_tool" && r.Event.Decision == domain.DecisionDeny {
			denies++
		}
	}
	if denies < 3 {
		t.Fatalf("want >=3 use_peer_tool denials on the chain, got %d", denies)
	}
}

func TestC2CNotLiveTeaches(t *testing.T) {
	w := newC2CWorld(t, C2CConfig{Port: 8444})
	ctx := context.Background()
	source := w.deployed(t, "caller")
	w.deployed(t, "handbook") // never promoted
	it := Actor{ITAdmin: true, ID: "it-1"}
	if _, err := w.o.SetBeamPeers(ctx, it, w.bh.ID, source.ID, PeerSpec{Peers: []string{"ops/handbook"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.o.C2CCall(ctx, source.ID, "ops", "handbook", "", nil); !errors.Is(err, ErrPeerNotLive) {
		t.Fatalf("want ErrPeerNotLive, got %v", err)
	}
}

func TestC2CRateAndInflightBoundsUnaudited(t *testing.T) {
	w := newC2CWorld(t, C2CConfig{Port: 8444, RatePerMinute: 60, Burst: 1, MaxInflight: 1})
	ctx := context.Background()
	source, _, _ := w.grantedPair(t)

	if _, err := w.o.C2CCall(ctx, source.ID, "ops", "handbook", "", nil); err != nil {
		t.Fatalf("first call: %v", err)
	}
	before, _ := w.st.ListAuditEvents(ctx, 0, 200)
	if _, err := w.o.C2CCall(ctx, source.ID, "ops", "handbook", "", nil); err == nil ||
		!strings.Contains(err.Error(), "faster than the appliance allows") {
		t.Fatalf("second immediate call must hit the limiter, got %v", err)
	}
	after, _ := w.st.ListAuditEvents(ctx, 0, 200)
	if len(after) != len(before) {
		t.Fatal("limiter refusals must NOT be audited (the limiter bounds chain growth)")
	}

	// The in-flight cap is the enforceable recursion bound.
	release, ok := w.o.c2cAcquire(source.ID)
	if !ok {
		t.Fatal("first acquire must pass")
	}
	if _, ok := w.o.c2cAcquire(source.ID); ok {
		t.Fatal("second concurrent acquire must refuse at MaxInflight=1")
	}
	release()
	release2, ok := w.o.c2cAcquire(source.ID)
	if !ok {
		t.Fatal("acquire after release must pass")
	}
	release2()
}

func TestC2CBindingIsRefsGated(t *testing.T) {
	w := newC2CWorld(t, C2CConfig{Port: 8444})
	ctx := context.Background()

	withKey := []domain.SecretRef{{BeamhallID: w.bh.ID, BeamID: "b1", Key: apptools.C2CKeyName, Channel: domain.ChannelPreview}}
	b := w.o.c2cBinding(ctx, w.bh.ID, withKey)
	if len(b) != 1 || b[0].MountPath != apptools.C2CMountPath {
		t.Fatalf("binding = %+v", b)
	}
	want := `{"version":1,"endpoint":"http://172.18.0.1:8444","key_file":"/run/secrets/BEAMHALL_C2C_KEY"}`
	if string(b[0].Value) != want {
		t.Fatalf("binding value = %s, want %s", b[0].Value, want)
	}
	// A release whose refs lack the key (a rollback to a pre-grant release)
	// must NOT mount c2c.json — the file's presence promises the key file.
	without := []domain.SecretRef{{BeamhallID: w.bh.ID, BeamID: "b1", Key: "OTHER", Channel: domain.ChannelPreview}}
	if b := w.o.c2cBinding(ctx, w.bh.ID, without); b != nil {
		t.Fatalf("pre-grant refs must yield no binding, got %+v", b)
	}
}

func TestC2CDestroySweepsGrantsAndKey(t *testing.T) {
	w := newC2CWorld(t, C2CConfig{Port: 8444})
	ctx := context.Background()
	source, _, _ := w.grantedPair(t)

	if err := w.o.DestroyBeam(ctx, w.admin, w.bh.ID, source.ID); err != nil {
		t.Fatalf("DestroyBeam: %v", err)
	}
	if _, err := w.st.GetBeamPeers(ctx, source.ID); !isNotFound(err) {
		t.Fatalf("grant row must be swept, got %v", err)
	}
	if has, _ := w.st.HasC2CKey(ctx, source.ID); has {
		t.Fatal("relay key row must be swept")
	}
}

func TestReservedSecretPrefixRefused(t *testing.T) {
	w := newC2CWorld(t, C2CConfig{Port: 8444})
	ctx := context.Background()
	beam := w.deployed(t, "caller")
	err := w.o.SetSecret(ctx, w.build, w.bh.ID, beam.ID, "BEAMHALL_C2C_KEY", []byte("squat"))
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("reserved-prefix write must refuse with a teaching error, got %v", err)
	}
	if err := w.o.SetSecret(ctx, w.build, w.bh.ID, beam.ID, "MY_API_KEY", []byte("v")); err != nil {
		t.Fatalf("ordinary key must still work: %v", err)
	}
}

func TestShowBeamPeersView(t *testing.T) {
	w := newC2CWorld(t, C2CConfig{Port: 8444})
	ctx := context.Background()
	source, _, _ := w.grantedPair(t)

	// Viewer-tier read through the PEP; the key exists but the deployed
	// release predates it (grant came after deploy).
	v, err := w.o.ShowBeamPeers(ctx, w.build, w.bh.ID, source.ID)
	if err != nil {
		t.Fatalf("ShowBeamPeers: %v", err)
	}
	if len(v.Targets) != 1 || v.Targets[0].App != "handbook" || !v.Targets[0].Live {
		t.Fatalf("targets = %+v", v.Targets)
	}
	if !v.KeyMinted || v.PreviewHas {
		t.Fatalf("key state wrong: minted=%v previewHas=%v (release predates the key)", v.KeyMinted, v.PreviewHas)
	}
}
