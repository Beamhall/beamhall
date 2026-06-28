package orch

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/facility/s3"
	"github.com/Beamhall/beamhall/internal/policy"
)

// Object-storage facility (PLAN §5.11 facility brokers; §5.13 object storage). A
// beam inherits S3-compatible object storage the way it inherits a database:
// provision_object_store mints per-beam S3 credentials and seals
// S3_ENDPOINT/REGION/FORCE_PATH_STYLE (shared) + S3_BUCKET/ACCESS_KEY/SECRET_KEY
// (per-channel) so the app reads them from /run/secrets and speaks stock S3 to
// the shared bh-objstore broker container. The broker stores the bytes locally
// (batteries-included) or forwards to an admin-configured external S3; the
// external credential lives only in the broker, never in the beam.
//
// Three deliberate divergences from the email facility:
//   - PER-CHANNEL (like the database): preview and live each get their own bucket
//     + credentials, so preview iteration can't read or delete production data.
//     provision_object_store provisions PREVIEW; promote reconciles LIVE
//     (reconcileLiveResources → reconcileLiveObjectStore).
//   - RECONCILE READS THE PLAINTEXT SECRET FROM THE VAULT, not the resource Spec:
//     SigV4 needs the broker to hold the plaintext key (it can't verify from a
//     hash), and a plaintext secret must never sit in Spec (which show_ surfaces).
//   - ENABLED BY DEFAULT: the broker boots in local mode, so the facility is on as
//     soon as the installer wires it; admin_set_object_store_provider only switches
//     the backend (local↔external), it does not gate availability.

const (
	s3EndpointKey  = "S3_ENDPOINT"          // shared
	s3RegionKey    = "S3_REGION"            // shared
	s3PathStyleKey = "S3_FORCE_PATH_STYLE"  // shared
	s3BucketKey    = "S3_BUCKET"            // per-channel
	s3AccessKeyKey = "S3_ACCESS_KEY"        // per-channel
	s3SecretKeyKey = "S3_SECRET_KEY"        // per-channel (the SigV4 secret)
)

func objStoreSharedKeys() []string  { return []string{s3EndpointKey, s3RegionKey, s3PathStyleKey} }
func objStoreChannelKeys() []string { return []string{s3BucketKey, s3AccessKeyKey, s3SecretKeyKey} }

func objStoreAllKeys() []string {
	return append(objStoreSharedKeys(), objStoreChannelKeys()...)
}

// ObjectStoreProvisioner is the object-store facility seam — the broker control
// channel. *s3.Client satisfies it. A backplane without one has no object store.
type ObjectStoreProvisioner interface {
	Provision(ctx context.Context, req s3.ProvisionRequest) (s3.Credentials, error)
	RegisterKey(ctx context.Context, reg s3.Registration) error
	Deregister(ctx context.Context, beamID, channel string, purge bool) error
	SetProvider(ctx context.Context, cfg s3.ProviderConfig) error
	SetQuota(ctx context.Context, beamID, channel string, maxBytes int64) error
	PullEvents(ctx context.Context, after int64) ([]s3.SeqEvent, int64, error)
	Status(ctx context.Context) (enabled bool, next int64, err error)
}

// ObjectStoreConfig carries the non-per-beam settings: the broker's in-bridge
// address beams dial (S3_ENDPOINT), the injected region, and the default per-beam
// storage quota. The backend (local vs external) is owned + persisted by the
// broker; an IT admin switches it at runtime (admin_set_object_store_provider).
type ObjectStoreConfig struct {
	BeamHost     string
	BeamPort     int
	Region       string
	DefaultQuota int64 // bytes; 0 = unlimited
	// Attach connects the shared bh-objstore broker container to a beamhall bridge
	// so the beam reaches it as <BeamHost>:<BeamPort> (the bh-postgres precedent).
	Attach func(ctx context.Context, network string) error
}

// WithObjectStore wires the bh-objstore broker (the installer stands it up). The
// facility is enabled as soon as it's wired (local default); objStoreEnabled is
// learned from the broker at boot (ReconcileObjectStore).
func WithObjectStore(p ObjectStoreProvisioner, cfg ObjectStoreConfig) Option {
	return func(o *Orchestrator) {
		o.objStoreProv = p
		if cfg.BeamHost == "" {
			cfg.BeamHost = "bh-objstore"
		}
		if cfg.BeamPort == 0 {
			cfg.BeamPort = 9000
		}
		if cfg.Region == "" {
			cfg.Region = "us-east-1"
		}
		o.objStoreCfg = cfg
	}
}

// ObjectStoreBrokerWired reports whether a bh-objstore broker is wired.
func (o *Orchestrator) ObjectStoreBrokerWired() bool { return o.objStoreProv != nil }

// ObjectStoreEnabled reports whether object storage is usable (a broker is wired
// and reports a backend — true by default once wired, since the broker boots in
// local mode). Gates provision_object_store / show_object_store.
func (o *Orchestrator) ObjectStoreEnabled() bool {
	return o.objStoreProv != nil && o.objStoreEnabled.Load()
}

func (o *Orchestrator) objStoreEndpointURL() string {
	return fmt.Sprintf("http://%s:%d", o.objStoreCfg.BeamHost, o.objStoreCfg.BeamPort)
}

// objStoreBucket is the per-beam, per-channel bucket name (globally unique on the
// appliance, since the local backend shares one store across beams). DNS-safe.
func objStoreBucket(beamID domain.ID, ch domain.Channel) string {
	return "bh-" + sanitizeBucket(string(beamID)) + "-" + string(ch)
}

func sanitizeBucket(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-':
			b.WriteByte('-')
		}
	}
	out := b.String()
	if len(out) > 40 {
		out = out[:40]
	}
	if out == "" {
		out = "beam"
	}
	return out
}

// ProvisionObjectStore gives a beam object storage: mints per-beam S3 credentials
// for the PREVIEW channel at the broker and seals the shared + per-channel
// secrets. Idempotent (re-returns the keys). The agent never sees a value. Promote
// reconciles a separate live bucket so production data is isolated from preview.
// Returns s3.ErrNotEnabled when no broker is wired so the MCP layer can hand back
// the set_secret fallback recipe.
func (o *Orchestrator) ProvisionObjectStore(ctx context.Context, actor Actor, beamhallID, beamID domain.ID) (keys []string, err error) {
	if err := o.authorize(ctx, actor, policy.ActionProvisionObjectStore, beamhallID, beamID); err != nil {
		return nil, err
	}
	keys, err = o.provisionObjectStore(ctx, actor, beamhallID, beamID)
	return keys, o.outcome(ctx, actor, policy.ActionProvisionObjectStore, beamhallID, beamID, err)
}

func (o *Orchestrator) provisionObjectStore(ctx context.Context, actor Actor, beamhallID, beamID domain.ID) ([]string, error) {
	if !o.ObjectStoreEnabled() {
		return nil, s3.ErrNotEnabled
	}
	if _, err := o.operableBeam(ctx, beamhallID, beamID); err != nil {
		return nil, err
	}
	// Idempotent: an already-provisioned beam re-returns the same keys.
	existing, err := o.st.ListResourcesByBeamAndChannel(ctx, beamID, domain.ChannelPreview)
	if err != nil {
		return nil, err
	}
	for _, r := range existing {
		if r.Type == domain.ResourceObjectStore {
			o.log.Info("object store already provisioned; returning existing keys", "beam", beamID)
			return objStoreAllKeys(), nil
		}
	}

	bucket := objStoreBucket(beamID, domain.ChannelPreview)
	creds, err := o.objStoreProv.Provision(ctx, s3.ProvisionRequest{
		BeamID:  string(beamID),
		Channel: string(domain.ChannelPreview),
		Bucket:  bucket,
		Limits:  s3.Limits{MaxBytes: o.objStoreCfg.DefaultQuota},
	})
	if err != nil {
		return nil, err
	}

	// Make the broker reachable from this beam's bridge (bh-postgres precedent).
	if o.objStoreCfg.Attach != nil {
		if err := o.objStoreCfg.Attach(ctx, networkName(beamhallID)); err != nil {
			o.deregisterObjStore(ctx, beamID, domain.ChannelPreview, true)
			return nil, fmt.Errorf("attach object-store broker to beam network: %w", err)
		}
	}

	// Shared (channel-agnostic) connection secrets: same endpoint for both channels.
	shared := map[string]string{
		s3EndpointKey:  o.objStoreEndpointURL(),
		s3RegionKey:    o.objStoreCfg.Region,
		s3PathStyleKey: "true",
	}
	for _, key := range objStoreSharedKeys() {
		ref := domain.SecretRef{BeamhallID: beamhallID, BeamID: beamID, Key: key, Channel: domain.ChannelShared}
		if _, err := o.vault.Set(ctx, ref, []byte(shared[key]), actor.ID); err != nil {
			o.deregisterObjStore(ctx, beamID, domain.ChannelPreview, true)
			return nil, fmt.Errorf("seal %s: %w", key, err)
		}
	}
	// Per-channel secrets (preview).
	if err := o.sealObjStoreChannel(ctx, beamhallID, beamID, domain.ChannelPreview, bucket, creds, actor.ID); err != nil {
		o.deregisterObjStore(ctx, beamID, domain.ChannelPreview, true)
		return nil, err
	}

	res := &domain.Resource{
		BeamhallID:          beamhallID,
		BeamID:              beamID,
		Channel:             domain.ChannelPreview,
		Type:                domain.ResourceObjectStore,
		Status:              domain.ResourceReady,
		ConnectionSecretRef: domain.SecretRef{BeamhallID: beamhallID, BeamID: beamID, Key: s3SecretKeyKey, Channel: domain.ChannelPreview},
		Spec: map[string]string{
			"access_key":  creds.AccessKey,
			"bucket":      bucket,
			"quota_bytes": strconv.FormatInt(o.objStoreCfg.DefaultQuota, 10),
		},
		BackingHandle: creds.AccessKey,
	}
	if err := o.st.CreateResource(ctx, res); err != nil {
		return nil, err
	}
	o.log.Info("object store provisioned", "beam", beamID, "bucket", bucket)
	return objStoreAllKeys(), nil
}

// sealObjStoreChannel seals the per-channel bucket/access/secret for a channel.
func (o *Orchestrator) sealObjStoreChannel(ctx context.Context, beamhallID, beamID domain.ID, ch domain.Channel, bucket string, creds s3.Credentials, by domain.ID) error {
	vals := map[string]string{
		s3BucketKey:    bucket,
		s3AccessKeyKey: creds.AccessKey,
		s3SecretKeyKey: creds.SecretKey,
	}
	for _, key := range objStoreChannelKeys() {
		ref := domain.SecretRef{BeamhallID: beamhallID, BeamID: beamID, Key: key, Channel: ch}
		if _, err := o.vault.Set(ctx, ref, []byte(vals[key]), by); err != nil {
			return fmt.Errorf("seal %s (%s): %w", key, ch, err)
		}
	}
	return nil
}

func (o *Orchestrator) deregisterObjStore(ctx context.Context, beamID domain.ID, ch domain.Channel, purge bool) {
	if o.objStoreProv == nil {
		return
	}
	if err := o.objStoreProv.Deregister(ctx, string(beamID), string(ch), purge); err != nil {
		o.log.Error("rollback of object-store registration failed", "beam", beamID, "channel", ch, "err", err)
	}
}

// reconcileLiveObjectStore gives the live channel its own bucket + credentials for
// each preview object store the beam has — production data isolated from preview.
// Idempotent: a live object store that already exists is left as-is (re-promote
// preserves production data). Called from reconcileLiveResources.
func (o *Orchestrator) reconcileLiveObjectStore(ctx context.Context, actor Actor, bh domain.Beamhall, beamID domain.ID) error {
	if o.objStoreProv == nil {
		return nil
	}
	previewRes, err := o.st.ListResourcesByBeamAndChannel(ctx, beamID, domain.ChannelPreview)
	if err != nil {
		return err
	}
	liveRes, err := o.st.ListResourcesByBeamAndChannel(ctx, beamID, domain.ChannelLive)
	if err != nil {
		return err
	}
	haveLive := false
	for _, r := range liveRes {
		if r.Type == domain.ResourceObjectStore {
			haveLive = true
		}
	}
	for _, pr := range previewRes {
		if pr.Type != domain.ResourceObjectStore || haveLive {
			continue
		}
		bucket := objStoreBucket(beamID, domain.ChannelLive)
		quota, _ := strconv.ParseInt(pr.Spec["quota_bytes"], 10, 64)
		creds, err := o.objStoreProv.Provision(ctx, s3.ProvisionRequest{
			BeamID:  string(beamID),
			Channel: string(domain.ChannelLive),
			Bucket:  bucket,
			Limits:  s3.Limits{MaxBytes: quota},
		})
		if err != nil {
			return fmt.Errorf("provision live object store: %w", err)
		}
		if err := o.sealObjStoreChannel(ctx, bh.ID, beamID, domain.ChannelLive, bucket, creds, actor.ID); err != nil {
			o.deregisterObjStore(ctx, beamID, domain.ChannelLive, true)
			return err
		}
		res := &domain.Resource{
			BeamhallID:          bh.ID,
			BeamID:              beamID,
			Channel:             domain.ChannelLive,
			Type:                domain.ResourceObjectStore,
			Status:              domain.ResourceReady,
			ConnectionSecretRef: domain.SecretRef{BeamhallID: bh.ID, BeamID: beamID, Key: s3SecretKeyKey, Channel: domain.ChannelLive},
			Spec:                map[string]string{"access_key": creds.AccessKey, "bucket": bucket, "quota_bytes": strconv.FormatInt(quota, 10)},
			BackingHandle:       creds.AccessKey,
		}
		if err := o.st.CreateResource(ctx, res); err != nil {
			return err
		}
		o.log.Info("live object store provisioned", "beam", beamID, "bucket", bucket)
	}
	return nil
}

// ObjectStoreInfo is the non-secret view of a beam's object storage.
type ObjectStoreInfo struct {
	Provisioned bool                     `json:"provisioned"`
	Endpoint    string                   `json:"endpoint,omitempty"`
	Region      string                   `json:"region,omitempty"`
	Channels    []ObjectStoreChannelInfo `json:"channels,omitempty"`
}

// ObjectStoreChannelInfo is one channel's bucket (no secret values).
type ObjectStoreChannelInfo struct {
	Channel    string `json:"channel"`
	Bucket     string `json:"bucket"`
	QuotaBytes int64  `json:"quota_bytes"`
}

// ShowObjectStore reports a beam's object storage without exposing credentials.
func (o *Orchestrator) ShowObjectStore(ctx context.Context, actor Actor, beamhallID, beamID domain.ID) (ObjectStoreInfo, error) {
	if err := o.authorize(ctx, actor, policy.ActionShowObjectStore, beamhallID, beamID); err != nil {
		return ObjectStoreInfo{}, err
	}
	info, err := o.showObjectStore(ctx, beamID)
	return info, o.outcome(ctx, actor, policy.ActionShowObjectStore, beamhallID, beamID, err)
}

func (o *Orchestrator) showObjectStore(ctx context.Context, beamID domain.ID) (ObjectStoreInfo, error) {
	resources, err := o.st.ListResourcesByBeam(ctx, beamID)
	if err != nil {
		return ObjectStoreInfo{}, err
	}
	info := ObjectStoreInfo{Endpoint: o.objStoreEndpointURL(), Region: o.objStoreCfg.Region}
	for _, r := range resources {
		if r.Type != domain.ResourceObjectStore {
			continue
		}
		info.Provisioned = true
		quota, _ := strconv.ParseInt(r.Spec["quota_bytes"], 10, 64)
		info.Channels = append(info.Channels, ObjectStoreChannelInfo{
			Channel:    string(r.Channel),
			Bucket:     r.Spec["bucket"],
			QuotaBytes: quota,
		})
	}
	if !info.Provisioned {
		return ObjectStoreInfo{Provisioned: false}, nil
	}
	return info, nil
}

// SetObjectStoreProvider switches the appliance's object-store backend at runtime
// (admin_set_object_store_provider): an empty endpoint restores the batteries-
// included local backend; an endpoint+credential forwards to an external S3. The
// broker holds + persists the external credential (never the vault, never a beam).
// IT-only, audited, routine (backend plumbing, not appliance-wide auth topology).
// Primitive args (not s3.ProviderConfig) keep the MCP layer decoupled from the
// facility package, mirroring SetEmailProvider.
func (o *Orchestrator) SetObjectStoreProvider(ctx context.Context, actor Actor, endpoint, region, bucket, accessKey, secretKey string, forcePathStyle, useSSL bool) error {
	if err := o.requireIT(actor); err != nil {
		return o.itAudit(ctx, actor, "admin_set_object_store_provider", "", err)
	}
	cfg := s3.ProviderConfig{
		Endpoint: strings.TrimSpace(endpoint), Region: region, Bucket: bucket,
		AccessKey: accessKey, SecretKey: secretKey,
		ForcePathStyle: forcePathStyle, UseSSL: useSSL,
	}
	return o.itAudit(ctx, actor, "admin_set_object_store_provider", "", o.setObjectStoreProvider(ctx, cfg))
}

func (o *Orchestrator) setObjectStoreProvider(ctx context.Context, cfg s3.ProviderConfig) error {
	if o.objStoreProv == nil {
		return fmt.Errorf("no object-store broker is configured on this appliance")
	}
	if err := o.objStoreProv.SetProvider(ctx, cfg); err != nil {
		return err
	}
	// Re-push registrations so existing beams' buckets exist on the new backend.
	return o.ReconcileObjectStore(ctx)
}

// SetObjectStoreQuota sets a beam's storage cap on every channel (IT-only).
func (o *Orchestrator) SetObjectStoreQuota(ctx context.Context, actor Actor, beamhallID, beamID domain.ID, maxBytes int64) error {
	if err := o.requireIT(actor); err != nil {
		return o.itAudit(ctx, actor, "admin_set_object_store_quota", beamhallID, err)
	}
	return o.itAudit(ctx, actor, "admin_set_object_store_quota", beamhallID, o.setObjectStoreQuota(ctx, beamID, maxBytes))
}

func (o *Orchestrator) setObjectStoreQuota(ctx context.Context, beamID domain.ID, maxBytes int64) error {
	if !o.ObjectStoreEnabled() {
		return s3.ErrNotEnabled
	}
	resources, err := o.st.ListResourcesByBeam(ctx, beamID)
	if err != nil {
		return err
	}
	found := false
	for i := range resources {
		r := resources[i]
		if r.Type != domain.ResourceObjectStore {
			continue
		}
		found = true
		if err := o.objStoreProv.SetQuota(ctx, string(beamID), string(r.Channel), maxBytes); err != nil {
			return fmt.Errorf("set quota at broker: %w", err)
		}
		if r.Spec == nil {
			r.Spec = map[string]string{}
		}
		r.Spec["quota_bytes"] = strconv.FormatInt(maxBytes, 10)
		if err := o.st.UpdateResource(ctx, &r); err != nil {
			return err
		}
	}
	if !found {
		return fmt.Errorf("beam has no provisioned object store — call provision_object_store first")
	}
	return nil
}

// reclaimObjectStore deregisters a beam+channel at the broker (purging its bucket
// data) and deletes its sealed secrets on destroy. Called per object_store
// resource from reclaimResources.
func (o *Orchestrator) reclaimObjectStore(ctx context.Context, r domain.Resource) {
	o.deregisterObjStore(ctx, r.BeamID, r.Channel, true)
	keys := objStoreChannelKeys()
	for _, key := range keys {
		ref := domain.SecretRef{BeamhallID: r.BeamhallID, BeamID: r.BeamID, Key: key, Channel: r.Channel}
		if err := o.vault.Delete(ctx, ref); err != nil {
			o.log.Warn("deleting sealed object-store secret on destroy", "beam", r.BeamID, "channel", r.Channel, "key", key, "err", err)
		}
	}
	// Shared secrets are channel-agnostic; deleting them per channel is idempotent.
	for _, key := range objStoreSharedKeys() {
		ref := domain.SecretRef{BeamhallID: r.BeamhallID, BeamID: r.BeamID, Key: key, Channel: domain.ChannelShared}
		_ = o.vault.Delete(ctx, ref)
	}
}

// ReconcileObjectStore learns whether the broker has a backend (always true once
// wired, since it defaults to local) and re-pushes every beam's per-channel
// registration so a restarted broker is rebuilt from the authoritative resource
// rows. The plaintext SigV4 secret is read back from the VAULT (it can't live in
// Spec). Idempotent + self-healing; run at boot and on a tick.
func (o *Orchestrator) ReconcileObjectStore(ctx context.Context) error {
	if !o.ObjectStoreBrokerWired() {
		return nil
	}
	enabled, _, err := o.objStoreProv.Status(ctx)
	if err != nil {
		return fmt.Errorf("object-store broker status: %w", err)
	}
	o.objStoreEnabled.Store(enabled)
	if !enabled {
		return nil
	}
	halls, err := o.st.ListBeamhalls(ctx)
	if err != nil {
		return err
	}
	for _, h := range halls {
		resources, err := o.st.ListResourcesByBeamhall(ctx, h.ID)
		if err != nil {
			o.log.Warn("object-store reconcile: list resources", "beamhall", h.ID, "err", err)
			continue
		}
		for _, r := range resources {
			if r.Type != domain.ResourceObjectStore {
				continue
			}
			secret, err := o.vault.Reveal(ctx, domain.SecretRef{BeamhallID: r.BeamhallID, BeamID: r.BeamID, Key: s3SecretKeyKey, Channel: r.Channel})
			if err != nil {
				o.log.Warn("object-store reconcile: reveal secret", "beam", r.BeamID, "channel", r.Channel, "err", err)
				continue
			}
			quota, _ := strconv.ParseInt(r.Spec["quota_bytes"], 10, 64)
			if err := o.objStoreProv.RegisterKey(ctx, s3.Registration{
				BeamID:    string(r.BeamID),
				Channel:   string(r.Channel),
				AccessKey: r.Spec["access_key"],
				SecretKey: string(secret),
				Bucket:    r.Spec["bucket"],
				Limits:    s3.Limits{MaxBytes: quota},
			}); err != nil {
				o.log.Warn("object-store reconcile: register beam", "beam", r.BeamID, "channel", r.Channel, "err", err)
			}
		}
	}
	return nil
}

// ObjectStoreAuditCursor returns the broker's current high-water audit seq, used
// to initialise the pull cursor at boot.
func (o *Orchestrator) ObjectStoreAuditCursor(ctx context.Context) (int64, error) {
	if !o.ObjectStoreBrokerWired() {
		return 0, nil
	}
	_, next, err := o.objStoreProv.Status(ctx)
	return next, err
}

// DrainObjectStoreAudit pulls per-request events newer than after from the broker
// and appends each to the hash chain, returning the new cursor. Run on a ticker.
func (o *Orchestrator) DrainObjectStoreAudit(ctx context.Context, after int64) (int64, error) {
	if !o.ObjectStoreBrokerWired() {
		return after, nil
	}
	events, next, err := o.objStoreProv.PullEvents(ctx, after)
	if err != nil {
		return after, err
	}
	for _, se := range events {
		o.appendObjectStoreAudit(ctx, se)
	}
	if next < after {
		next = after // broker ring reset (restart)
	}
	return next, nil
}

func (o *Orchestrator) appendObjectStoreAudit(ctx context.Context, se s3.SeqEvent) {
	beamID := domain.ID(se.BeamID)
	var beamhallID domain.ID
	if b, err := o.st.GetBeam(ctx, beamID); err == nil {
		beamhallID = b.BeamhallID
	}
	decision := domain.DecisionAllow
	if se.Result != "ok" {
		decision = domain.DecisionDeny
	}
	ev := domain.AuditEvent{
		BeamhallID:    beamhallID,
		BeamID:        beamID,
		Action:        "object_store_op",
		Decision:      decision,
		Reason:        se.Err,
		ResultStatus:  se.Result,
		RequestDigest: objStoreDigest(se.Event),
	}
	if _, err := o.alog.Append(ctx, &ev); err != nil {
		o.log.Error("append object-store audit event failed", "beam", beamID, "err", err)
	}
}

func objStoreDigest(ev s3.Event) string {
	return fmt.Sprintf("op=%s channel=%s bucket=%s key=%q size=%d", ev.Op, ev.Channel, ev.Bucket, ev.Key, ev.Size)
}
