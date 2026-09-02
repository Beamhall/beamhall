// Beam-to-beam via the backplane relay (PLAN §5.15, stage 3): one beam calls
// another beam's app tools THROUGH the backplane, never over the network
// directly — sibling bridges stay closed, the relay authenticates the calling
// workload by its injected key plus its live container address, checks the
// IT grant per request, mints the same signed assertion apps already verify
// (caller_type=beam), and audits every call. External destinations are the
// other half of a grant: per-workload egress rules, not relayed.
package orch

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/time/rate"

	"github.com/Beamhall/beamhall/internal/apptools"
	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/driver"
	"github.com/Beamhall/beamhall/internal/egress"
	"github.com/Beamhall/beamhall/internal/policy"
	"github.com/Beamhall/beamhall/internal/store"
)

// ErrPeerAuth is the uniform relay authentication refusal: a bad key, an
// unknown key, and a caller address that does not belong to the key's beam
// all read identically, so probing teaches nothing.
var ErrPeerAuth = errors.New("relay credentials were not accepted")

// ErrPeerNotGranted is the uniform target refusal: an app outside the
// caller's grant set is indistinguishable from one that does not exist.
var ErrPeerNotGranted = errors.New("no app by that name is reachable from this beam — ask IT to grant it (admin_set_beam_peers)")

// ErrPeerNotLive reports a granted target whose live channel is not up.
var ErrPeerNotLive = errors.New("the granted app is not live right now — its team must promote_to_live first")

// C2CConfig bounds the relay. RatePerMinute <= 0 disables the limiter;
// MaxInflight <= 0 disables the concurrency cap. Port is where the relay
// listener answers (advertised to workloads in c2c.json).
type C2CConfig struct {
	RatePerMinute int
	Burst         int
	MaxInflight   int
	Port          int
}

// NetworkFactsFn resolves one hall network's live facts (bridge, subnets,
// gateway, container addresses). Injected from main so the stable
// RuntimeDriver seam stays untouched; nil leaves the whole relay inert.
type NetworkFactsFn func(ctx context.Context, netName string) (driver.NetworkFacts, error)

// WithC2C wires the beam-to-beam relay. Without it SetBeamPeers still stores
// grants (IT can prepare), but the relay, the key mint, and the c2c binding
// are inert — unit-test worlds construct the orchestrator bare.
func WithC2C(cfg C2CConfig, facts NetworkFactsFn) Option {
	return func(o *Orchestrator) {
		o.c2cCfg = cfg
		o.netFacts = facts
	}
}

// PeerSpec is the IT grant write: peer targets as "<workspace>/<app>" slugs,
// external destinations in the hall-allowlist grammar. Set-replace; Clear
// drops the grant row entirely.
type PeerSpec struct {
	Peers    []string
	External []string
	Clear    bool
}

// SetBeamPeersResult tells the granting operator what to relay to the team.
type SetBeamPeersResult struct {
	Grant      domain.BeamPeers
	Targets    []PeerTargetView
	KeyCreated bool // first grant: the source beam picks its key up on its NEXT deploy
}

// SetBeamPeers replaces what one beam may reach. it_admin only — builders can
// see grants (show_beam_peers) but never widen them.
func (o *Orchestrator) SetBeamPeers(ctx context.Context, actor Actor, beamhallID, beamID domain.ID, spec PeerSpec) (SetBeamPeersResult, error) {
	if err := o.requireIT(actor); err != nil {
		return SetBeamPeersResult{}, o.itAuditBeam(ctx, actor, "admin_set_beam_peers", beamhallID, beamID, err)
	}
	res, err := o.setBeamPeers(ctx, actor, beamhallID, beamID, spec)
	return res, o.itAuditBeam(ctx, actor, "admin_set_beam_peers", beamhallID, beamID, err)
}

func (o *Orchestrator) setBeamPeers(ctx context.Context, actor Actor, beamhallID, beamID domain.ID, spec PeerSpec) (SetBeamPeersResult, error) {
	// Control-plane write: serialize against deploys and (critically) against
	// DestroyBeam, whose secret sweep a concurrent key mint would undo.
	unlock := o.beamLocks.lock(beamID)
	defer unlock()

	beam, err := o.operableBeam(ctx, beamhallID, beamID)
	if err != nil {
		return SetBeamPeersResult{}, err
	}
	if spec.Clear {
		if err := o.st.DeleteBeamPeers(ctx, beamID); err != nil {
			return SetBeamPeersResult{}, err
		}
		// The key stays: it grants nothing by itself, and keeping it means a
		// future re-grant works without another redeploy.
		return SetBeamPeersResult{}, o.syncEgress(ctx)
	}
	if len(spec.Peers) == 0 && len(spec.External) == 0 {
		return SetBeamPeersResult{}, fmt.Errorf("nothing to grant — pass peers and/or external, or clear:true to revoke everything")
	}

	set := domain.PeerSet{}
	var targets []PeerTargetView
	seen := map[domain.ID]bool{}
	for _, ref := range spec.Peers {
		hallSlug, appSlug, ok := strings.Cut(strings.TrimSpace(ref), "/")
		if !ok || hallSlug == "" || appSlug == "" {
			return SetBeamPeersResult{}, fmt.Errorf("peer %q: use \"<workspace>/<app>\"", ref)
		}
		hall, err := o.st.GetBeamhallBySlug(ctx, hallSlug)
		if err != nil {
			return SetBeamPeersResult{}, fmt.Errorf("peer %q: no workspace %q", ref, hallSlug)
		}
		target, err := o.st.GetBeamBySlug(ctx, hall.ID, appSlug)
		if err != nil {
			return SetBeamPeersResult{}, fmt.Errorf("peer %q: no app %q in workspace %q", ref, appSlug, hallSlug)
		}
		if target.ID == beam.ID {
			return SetBeamPeersResult{}, fmt.Errorf("peer %q is the beam itself — an app never needs a grant to reach its own tools", ref)
		}
		if seen[target.ID] {
			continue
		}
		seen[target.ID] = true
		set.Beams = append(set.Beams, target.ID)
		targets = append(targets, PeerTargetView{Workspace: hall.Slug, App: target.Slug, Live: target.LiveReleaseID != ""})
	}
	for _, e := range spec.External {
		if err := egress.ValidateAllowEntry(e); err != nil {
			return SetBeamPeersResult{}, err
		}
		set.External = append(set.External, strings.TrimSpace(e))
	}

	if err := o.st.PutBeamPeers(ctx, domain.BeamPeers{
		SourceBeamID: beam.ID, BeamhallID: beamhallID, Peers: set, UpdatedBy: actor.ID,
	}); err != nil {
		return SetBeamPeersResult{}, err
	}
	keyCreated, err := o.ensureC2CKey(ctx, beamhallID, beam.ID, actor.ID)
	if err != nil {
		return SetBeamPeersResult{}, err
	}
	// External entries change iptables now, not on the next deploy.
	if err := o.syncEgress(ctx); err != nil {
		return SetBeamPeersResult{}, err
	}
	return SetBeamPeersResult{
		Grant:      domain.BeamPeers{SourceBeamID: beam.ID, BeamhallID: beamhallID, Peers: set},
		Targets:    targets,
		KeyCreated: keyCreated,
	}, nil
}

func (o *Orchestrator) syncEgress(ctx context.Context) error {
	if o.egressSync == nil {
		return nil
	}
	return o.egressSync(ctx)
}

// ensureC2CKey mints the beam's relay credential exactly once. The c2c_keys
// insert is the mint mutex: the loser of a race sees created=false and never
// touches the winner's sealed rows. Inert without the relay wired.
func (o *Orchestrator) ensureC2CKey(ctx context.Context, beamhallID, beamID, by domain.ID) (bool, error) {
	if o.netFacts == nil {
		return false, nil
	}
	if has, err := o.st.HasC2CKey(ctx, beamID); err != nil || has {
		return false, err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return false, err
	}
	key := hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(key))
	created, err := o.st.InsertC2CKey(ctx, beamID, hex.EncodeToString(sum[:]))
	if err != nil || !created {
		return false, err
	}
	// Per-channel rows: channel-specific wins the injection dedupe, so a
	// builder's set_secret (shared channel) can never squat the mounted file.
	for _, ch := range []domain.Channel{domain.ChannelPreview, domain.ChannelLive} {
		ref := domain.SecretRef{BeamhallID: beamhallID, BeamID: beamID, Key: apptools.C2CKeyName, Channel: ch}
		if _, err := o.vault.Set(ctx, ref, []byte(key), by); err != nil {
			return false, fmt.Errorf("seal relay key: %w", err)
		}
	}
	return true, nil
}

// PeerTargetView is one granted target as shown to builders and callers.
type PeerTargetView struct {
	Workspace  string `json:"workspace"`
	App        string `json:"app"`
	Live       bool   `json:"live"`
	AgentTools bool   `json:"agent_tools"`
}

// BeamPeersView is the builder read: what IT granted this beam, and whether
// the relay key has reached its workloads yet.
type BeamPeersView struct {
	Targets  []PeerTargetView
	External []string
	// KeyMinted: the credential exists. Each channel picks it up when its
	// release is next created: preview on deploy_beam, live on promote (which
	// re-snapshots secrets — no preview redeploy required first).
	KeyMinted   bool
	PreviewHas  bool
	LiveHas     bool
	HasLiveChan bool
}

// ShowBeamPeers is the builder-side read of a beam's grants (PEP viewer+).
func (o *Orchestrator) ShowBeamPeers(ctx context.Context, actor Actor, beamhallID, beamID domain.ID) (BeamPeersView, error) {
	if err := o.authorize(ctx, actor, policy.ActionShowBeamPeers, beamhallID, beamID); err != nil {
		return BeamPeersView{}, err
	}
	v, err := o.showBeamPeers(ctx, beamhallID, beamID)
	return v, o.outcome(ctx, actor, policy.ActionShowBeamPeers, beamhallID, beamID, err)
}

func (o *Orchestrator) showBeamPeers(ctx context.Context, beamhallID, beamID domain.ID) (BeamPeersView, error) {
	beam, err := o.operableBeam(ctx, beamhallID, beamID)
	if err != nil {
		return BeamPeersView{}, err
	}
	var v BeamPeersView
	v.HasLiveChan = beam.LiveReleaseID != ""
	grant, err := o.st.GetBeamPeers(ctx, beamID)
	if err != nil && !isNotFound(err) {
		return BeamPeersView{}, err
	}
	v.External = grant.Peers.External
	v.Targets = o.resolvePeerTargets(ctx, grant.Peers.Beams)
	if v.KeyMinted, err = o.st.HasC2CKey(ctx, beamID); err != nil {
		return BeamPeersView{}, err
	}
	v.PreviewHas = o.releaseHasKey(ctx, beam.CurrentReleaseID)
	v.LiveHas = o.releaseHasKey(ctx, beam.LiveReleaseID)
	return v, nil
}

func (o *Orchestrator) releaseHasKey(ctx context.Context, releaseID domain.ID) bool {
	if releaseID == "" {
		return false
	}
	rel, err := o.st.GetRelease(ctx, releaseID)
	if err != nil {
		return false
	}
	for _, r := range rel.SecretRefs {
		if r.Key == apptools.C2CKeyName {
			return true
		}
	}
	return false
}

// resolvePeerTargets read-time-filters grant targets: archived or vanished
// beams drop silently (a stale grant is inert, never a hole), the rest carry
// their live + agent-tools state.
func (o *Orchestrator) resolvePeerTargets(ctx context.Context, ids []domain.ID) []PeerTargetView {
	var out []PeerTargetView
	for _, id := range ids {
		target, err := o.st.GetBeam(ctx, id)
		if err != nil || target.Status != domain.BeamActive {
			continue
		}
		hall, err := o.st.GetBeamhall(ctx, target.BeamhallID)
		if err != nil || hall.Status != domain.BeamhallActive {
			continue
		}
		pt := PeerTargetView{Workspace: hall.Slug, App: target.Slug, Live: target.LiveReleaseID != ""}
		if target.LiveReleaseID != "" {
			if rel, err := o.st.GetRelease(ctx, target.LiveReleaseID); err == nil {
				pt.AgentTools = rel.ConfigSnapshot["agent_tools"] == "true"
			}
		}
		out = append(out, pt)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Workspace != out[j].Workspace {
			return out[i].Workspace < out[j].Workspace
		}
		return out[i].App < out[j].App
	})
	return out
}

// C2CAuthenticate resolves a relay request to its calling beam: key hash
// lookup, then the caller's remote address must belong to a CURRENT container
// of that beam on its hall bridge (looked up live — release pointers and
// route rows are stale exactly during bring-up, when apps dial peers). Every
// failure is the uniform ErrPeerAuth. Lock-free by construction.
func (o *Orchestrator) C2CAuthenticate(ctx context.Context, key, remoteIP string) (domain.ID, error) {
	if o.netFacts == nil || o.appSigner == nil || o.appClient == nil {
		return "", errors.New("beam-to-beam is not enabled on this appliance")
	}
	if key == "" || remoteIP == "" {
		return "", ErrPeerAuth
	}
	sum := sha256.Sum256([]byte(key))
	beamID, err := o.st.GetC2CKeyBeam(ctx, hex.EncodeToString(sum[:]))
	if err != nil {
		return "", ErrPeerAuth
	}
	beam, err := o.st.GetBeam(ctx, beamID)
	if err != nil || beam.Status != domain.BeamActive {
		return "", ErrPeerAuth
	}
	facts, err := o.netFacts(ctx, networkName(beam.BeamhallID))
	if err != nil {
		return "", ErrPeerAuth
	}
	for name, ip := range facts.ContainerIPs {
		if ip != remoteIP {
			continue
		}
		if owner, ok := driver.BeamIDFromContainerName(name); ok && owner == string(beamID) {
			return beamID, nil
		}
	}
	return "", ErrPeerAuth
}

// C2CPeers lists the caller's reachable targets, live-fresh.
func (o *Orchestrator) C2CPeers(ctx context.Context, sourceBeamID domain.ID) ([]PeerTargetView, error) {
	if !o.c2cAllow(sourceBeamID) {
		return nil, o.c2cRateErr()
	}
	grant, err := o.st.GetBeamPeers(ctx, sourceBeamID)
	if err != nil {
		if isNotFound(err) {
			return []PeerTargetView{}, nil
		}
		return nil, err
	}
	return o.resolvePeerTargets(ctx, grant.Peers.Beams), nil
}

// C2CCall relays one call (menu when tool is empty) from a beam into a
// granted, live target. Audited per call on the use_app template; limiter and
// in-flight refusals are deliberately not audited (they exist to bound audit
// growth and pinned goroutines — an event per rejection hands a flood
// exactly that).
func (o *Orchestrator) C2CCall(ctx context.Context, sourceBeamID domain.ID, targetWorkspace, targetApp, tool string, args []byte) (UseAppResult, error) {
	release, ok := o.c2cAcquire(sourceBeamID)
	if !ok {
		return UseAppResult{}, fmt.Errorf("too many relay calls in flight for this beam (max %d) — a peer call must finish before another starts", o.c2cCfg.MaxInflight)
	}
	defer release()
	if !o.c2cAllow(sourceBeamID) {
		return UseAppResult{}, o.c2cRateErr()
	}

	res, hallID, beamID, opErr := o.c2cCall(ctx, sourceBeamID, targetWorkspace, targetApp, tool, args)

	ev := domain.AuditEvent{
		ActorID:       domain.ID("beam:" + string(sourceBeamID)),
		BeamhallID:    hallID,
		BeamID:        beamID,
		Action:        "use_peer_tool",
		Decision:      domain.DecisionAllow,
		RequestDigest: c2cDigest(targetWorkspace, targetApp, tool, args),
		ResultStatus:  "ok",
	}
	if opErr != nil {
		ev.Reason = opErr.Error()
		var ate *AppToolError
		switch {
		case errors.Is(opErr, ErrPeerNotGranted), errors.Is(opErr, ErrPeerNotLive), errors.Is(opErr, ErrAppNoTools):
			ev.Decision = domain.DecisionDeny
			ev.ResultStatus = "denied"
		case errors.As(opErr, &ate):
			ev.ResultStatus = "failed" // the target answered — the relayed call happened
		default:
			ev.ResultStatus = "failed"
		}
	}
	if _, err := o.alog.Append(ctx, &ev); err != nil {
		o.log.Error("audit use_peer_tool append failed", "source", sourceBeamID, "err", err)
		if opErr == nil {
			return res, fmt.Errorf("the call succeeded but could NOT be recorded on the audit chain: %w — investigate the audit store before continuing", err)
		}
	}
	return res, opErr
}

func c2cDigest(ws, app, tool string, args []byte) string {
	if tool == "" {
		return fmt.Sprintf("peer=%s/%s menu", ws, app)
	}
	return fmt.Sprintf("peer=%s/%s tool=%s args_sha256=%x", ws, app, tool, sha256.Sum256(args))
}

func (o *Orchestrator) c2cCall(ctx context.Context, sourceBeamID domain.ID, targetWorkspace, targetApp, tool string, args []byte) (UseAppResult, domain.ID, domain.ID, error) {
	grant, err := o.st.GetBeamPeers(ctx, sourceBeamID)
	if err != nil {
		if isNotFound(err) {
			return UseAppResult{}, "", "", ErrPeerNotGranted
		}
		return UseAppResult{}, "", "", err
	}
	// Resolve the target FIRST but refuse identically whether it is missing
	// or merely ungranted — existence must not leak through wording.
	hall, err := o.st.GetBeamhallBySlug(ctx, targetWorkspace)
	if err != nil {
		return UseAppResult{}, "", "", ErrPeerNotGranted
	}
	target, err := o.st.GetBeamBySlug(ctx, hall.ID, targetApp)
	if err != nil || target.Status != domain.BeamActive || !grant.Peers.AllowsBeam(target.ID) {
		return UseAppResult{}, "", "", ErrPeerNotGranted
	}
	if target.LiveReleaseID == "" {
		return UseAppResult{}, hall.ID, target.ID, ErrPeerNotLive
	}
	addr, err := o.resolveLiveBackend(ctx, target, hall.Slug)
	if err != nil {
		return UseAppResult{}, hall.ID, target.ID, err
	}
	caller := Actor{ID: sourceBeamID}
	res, err := o.callAppTool(ctx, caller, apptools.CallerBeam, hall.ID, target.ID, addr, "live", tool, args)
	return res, hall.ID, target.ID, err
}

func (o *Orchestrator) c2cAllow(id domain.ID) bool {
	if o.c2cCfg.RatePerMinute <= 0 {
		return true
	}
	o.c2cLimMu.Lock()
	defer o.c2cLimMu.Unlock()
	if o.c2cLimiters == nil {
		o.c2cLimiters = make(map[domain.ID]*rate.Limiter)
	}
	lim, ok := o.c2cLimiters[id]
	if !ok {
		burst := o.c2cCfg.Burst
		if burst <= 0 {
			burst = 1
		}
		lim = rate.NewLimiter(rate.Limit(float64(o.c2cCfg.RatePerMinute)/60.0), burst)
		o.c2cLimiters[id] = lim
	}
	return lim.Allow()
}

func (o *Orchestrator) c2cRateErr() error {
	return fmt.Errorf("this beam is calling peers faster than the appliance allows (max %d calls per minute) — retry in a moment", o.c2cCfg.RatePerMinute)
}

// c2cAcquire bounds concurrently pinned relay calls per source beam — the
// enforceable form of a recursion limit: mutually-granted beams cannot chain
// A→B→A amplification past beams × MaxInflight, cooperation or not.
func (o *Orchestrator) c2cAcquire(id domain.ID) (func(), bool) {
	if o.c2cCfg.MaxInflight <= 0 {
		return func() {}, true
	}
	o.c2cLimMu.Lock()
	defer o.c2cLimMu.Unlock()
	if o.c2cInflight == nil {
		o.c2cInflight = make(map[domain.ID]int)
	}
	if o.c2cInflight[id] >= o.c2cCfg.MaxInflight {
		return nil, false
	}
	o.c2cInflight[id]++
	return func() {
		o.c2cLimMu.Lock()
		o.c2cInflight[id]--
		o.c2cLimMu.Unlock()
	}, true
}

// c2cBinding mounts a beam's relay instructions. Gated on the RELEASE's
// secret refs, not the fresh key row: a rollback to a pre-grant release must
// not mount a c2c.json whose key file does not exist. Never fails a deploy.
func (o *Orchestrator) c2cBinding(ctx context.Context, beamhallID domain.ID, refs []domain.SecretRef) []driver.ResourceBinding {
	if o.netFacts == nil || o.c2cCfg.Port == 0 {
		return nil
	}
	hasKey := false
	for _, r := range refs {
		if r.Key == apptools.C2CKeyName {
			hasKey = true
			break
		}
	}
	if !hasKey {
		return nil
	}
	facts, err := o.netFacts(ctx, networkName(beamhallID))
	if err != nil || facts.Gateway == "" {
		o.log.Warn("c2c binding skipped: no gateway address", "beamhall", beamhallID, "err", err)
		return nil
	}
	val := fmt.Sprintf(`{"version":1,"endpoint":"http://%s:%d","key_file":"/run/secrets/%s"}`,
		facts.Gateway, o.c2cCfg.Port, apptools.C2CKeyName)
	return []driver.ResourceBinding{{
		Alias:     "c2c.json",
		MountPath: apptools.C2CMountPath,
		Value:     []byte(val),
	}}
}

// reclaimPeerGrants sweeps a destroyed beam's grant row and relay key.
// Best-effort like its siblings; the sealed secret rows are swept by
// reclaimUserSecrets. Grants NAMING this beam as a target need no sweep —
// they are read-time-filtered into nothing.
func (o *Orchestrator) reclaimPeerGrants(ctx context.Context, beamID domain.ID) {
	if err := o.st.DeleteBeamPeers(ctx, beamID); err != nil {
		o.log.Warn("reclaim peer grants", "beam", beamID, "err", err)
	}
	if err := o.st.DeleteC2CKey(ctx, beamID); err != nil {
		o.log.Warn("reclaim relay key", "beam", beamID, "err", err)
	}
}

func isNotFound(err error) bool { return errors.Is(err, store.ErrNotFound) }
