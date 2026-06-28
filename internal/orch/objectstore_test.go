package orch

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/facility/s3"
)

// fakeObjectStoreProv satisfies ObjectStoreProvisioner, recording control-channel
// calls without a real bh-objstore broker. Status reports enabled (the broker
// defaults to the local backend), so the facility is on by default once wired.
type fakeObjectStoreProv struct {
	provisioned  []string // "beamID:channel"
	registered   []string
	deregistered []string
	quota        map[string]int64
	provider     *s3.ProviderConfig
}

func (f *fakeObjectStoreProv) Provision(_ context.Context, req s3.ProvisionRequest) (s3.Credentials, error) {
	f.provisioned = append(f.provisioned, req.BeamID+":"+req.Channel)
	return s3.Credentials{
		AccessKey: "AK-" + req.BeamID + "-" + req.Channel,
		SecretKey: "SK-" + req.BeamID + "-" + req.Channel,
	}, nil
}
func (f *fakeObjectStoreProv) RegisterKey(_ context.Context, reg s3.Registration) error {
	f.registered = append(f.registered, reg.BeamID+":"+reg.Channel)
	return nil
}
func (f *fakeObjectStoreProv) Deregister(_ context.Context, beamID, channel string, _ bool) error {
	f.deregistered = append(f.deregistered, beamID+":"+channel)
	return nil
}
func (f *fakeObjectStoreProv) SetProvider(_ context.Context, cfg s3.ProviderConfig) error {
	f.provider = &cfg
	return nil
}
func (f *fakeObjectStoreProv) SetQuota(_ context.Context, beamID, channel string, max int64) error {
	if f.quota == nil {
		f.quota = map[string]int64{}
	}
	f.quota[beamID+":"+channel] = max
	return nil
}
func (f *fakeObjectStoreProv) PullEvents(_ context.Context, after int64) ([]s3.SeqEvent, int64, error) {
	return nil, after, nil
}
func (f *fakeObjectStoreProv) Status(_ context.Context) (bool, int64, error) { return true, 0, nil }

func enableObjectStore(w *world, fp *fakeObjectStoreProv) {
	WithObjectStore(fp, ObjectStoreConfig{
		BeamHost: "bh-objstore", BeamPort: 9000, Region: "us-east-1",
		DefaultQuota: 5 << 30,
		Attach:       func(_ context.Context, _ string) error { return nil },
	})(w.o)
	if err := w.o.ReconcileObjectStore(context.Background()); err != nil {
		panic(err)
	}
}

func TestProvisionObjectStoreSealsAndInjects(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	fp := &fakeObjectStoreProv{}
	enableObjectStore(w, fp)

	if !w.o.ObjectStoreEnabled() {
		t.Fatal("object store should be enabled by default once wired")
	}
	beam, err := w.o.CreateBeam(ctx, w.build, w.bh.ID, "store", "Store", "node")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := w.o.ProvisionObjectStore(ctx, w.build, w.bh.ID, beam.ID)
	if err != nil {
		t.Fatalf("ProvisionObjectStore: %v", err)
	}
	if len(keys) != 6 {
		t.Fatalf("keys = %v", keys)
	}
	if len(fp.provisioned) != 1 || fp.provisioned[0] != string(beam.ID)+":preview" {
		t.Fatalf("broker provisioned = %v", fp.provisioned)
	}

	// Idempotent.
	if _, err := w.o.ProvisionObjectStore(ctx, w.build, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("re-provision: %v", err)
	}
	if len(fp.provisioned) != 1 {
		t.Fatalf("idempotency broke: %v", fp.provisioned)
	}

	resources, err := w.st.ListResourcesByBeamAndChannel(ctx, beam.ID, domain.ChannelPreview)
	if err != nil || len(resources) != 1 {
		t.Fatalf("resources = %v err %v", resources, err)
	}
	r := resources[0]
	if r.Type != domain.ResourceObjectStore || r.Channel != domain.ChannelPreview {
		t.Fatalf("resource row = %+v", r)
	}
	wantBucket := objStoreBucket(beam.ID, domain.ChannelPreview)
	if r.Spec["bucket"] != wantBucket || r.Spec["access_key"] != "AK-"+string(beam.ID)+"-preview" {
		t.Fatalf("resource spec = %+v", r.Spec)
	}

	// Deploy injects the 6 S3_* secrets as file mounts.
	if _, err := w.o.DeployBeam(ctx, w.build, w.bh.ID, beam.ID, DeployRequest{ImageDigest: "sha256:x"}); err != nil {
		t.Fatal(err)
	}
	spec := w.drv.deploys[len(w.drv.deploys)-1]
	mounts := map[string]string{}
	for _, m := range spec.Secrets {
		mounts[m.MountPath] = string(m.Value)
	}
	if mounts["/run/secrets/S3_ENDPOINT"] != "http://bh-objstore:9000" || mounts["/run/secrets/S3_REGION"] != "us-east-1" {
		t.Fatalf("endpoint mounts = %+v", mounts)
	}
	if mounts["/run/secrets/S3_FORCE_PATH_STYLE"] != "true" {
		t.Fatalf("path style mount = %q", mounts["/run/secrets/S3_FORCE_PATH_STYLE"])
	}
	if mounts["/run/secrets/S3_BUCKET"] != wantBucket {
		t.Fatalf("bucket mount = %q want %q", mounts["/run/secrets/S3_BUCKET"], wantBucket)
	}
	if mounts["/run/secrets/S3_ACCESS_KEY"] != "AK-"+string(beam.ID)+"-preview" ||
		mounts["/run/secrets/S3_SECRET_KEY"] != "SK-"+string(beam.ID)+"-preview" {
		t.Fatalf("cred mounts = %+v", mounts)
	}

	// The secret key never appears in the audit chain.
	recs, _ := w.st.ListAuditEvents(ctx, 0, 50)
	for _, rec := range recs {
		if strings.Contains(rec.Event.Reason, "SK-"+string(beam.ID)) {
			t.Fatalf("secret leaked into audit: %+v", rec.Event)
		}
	}
}

func TestPromoteMirrorsLiveObjectStore(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	fp := &fakeObjectStoreProv{}
	enableObjectStore(w, fp)

	beam := w.deployed(t, "store")
	if _, err := w.o.ProvisionObjectStore(ctx, w.build, w.bh.ID, beam.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.o.PromoteToLive(ctx, w.admin, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("PromoteToLive: %v", err)
	}

	live, err := w.st.ListResourcesByBeamAndChannel(ctx, beam.ID, domain.ChannelLive)
	if err != nil {
		t.Fatal(err)
	}
	var liveOS *domain.Resource
	for i := range live {
		if live[i].Type == domain.ResourceObjectStore {
			liveOS = &live[i]
		}
	}
	if liveOS == nil {
		t.Fatal("promote did not mirror a live object store")
	}
	if liveOS.Spec["bucket"] != objStoreBucket(beam.ID, domain.ChannelLive) {
		t.Fatalf("live bucket = %q", liveOS.Spec["bucket"])
	}
	// Preview and live buckets differ — production data is isolated.
	prev, _ := w.st.ListResourcesByBeamAndChannel(ctx, beam.ID, domain.ChannelPreview)
	if prev[0].Spec["bucket"] == liveOS.Spec["bucket"] {
		t.Fatal("live bucket must differ from preview bucket")
	}
}

func TestSetObjectStoreQuotaRequiresIT(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	fp := &fakeObjectStoreProv{}
	enableObjectStore(w, fp)
	beam, _ := w.o.CreateBeam(ctx, w.build, w.bh.ID, "store", "Store", "node")
	if _, err := w.o.ProvisionObjectStore(ctx, w.build, w.bh.ID, beam.ID); err != nil {
		t.Fatal(err)
	}
	// Builder denied.
	if err := w.o.SetObjectStoreQuota(ctx, w.build, w.bh.ID, beam.ID, 1<<20); err == nil {
		t.Fatal("builder must not set object-store quota")
	}
	// IT allowed; broker updated + persisted.
	if err := w.o.SetObjectStoreQuota(ctx, Actor{ITAdmin: true}, w.bh.ID, beam.ID, 1<<20); err != nil {
		t.Fatalf("IT SetObjectStoreQuota: %v", err)
	}
	if fp.quota[string(beam.ID)+":preview"] != 1<<20 {
		t.Fatalf("broker quota = %v", fp.quota)
	}
	resources, _ := w.st.ListResourcesByBeamAndChannel(ctx, beam.ID, domain.ChannelPreview)
	if resources[0].Spec["quota_bytes"] != "1048576" {
		t.Fatalf("persisted quota = %q", resources[0].Spec["quota_bytes"])
	}
}

func TestSetObjectStoreProviderRequiresIT(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	fp := &fakeObjectStoreProv{}
	enableObjectStore(w, fp)
	// Builder denied.
	if err := w.o.SetObjectStoreProvider(ctx, w.build, "s3.x:9000", "us-east-1", "co", "k", "s", true, true); err == nil {
		t.Fatal("builder must not set the object-store provider")
	}
	// IT switches to an external backend.
	if err := w.o.SetObjectStoreProvider(ctx, Actor{ITAdmin: true}, "s3.x:9000", "us-east-1", "co", "k", "s", true, true); err != nil {
		t.Fatalf("IT SetObjectStoreProvider: %v", err)
	}
	if fp.provider == nil || fp.provider.Endpoint != "s3.x:9000" {
		t.Fatalf("broker provider = %+v", fp.provider)
	}
}

func TestDestroyReclaimsObjectStore(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	fp := &fakeObjectStoreProv{}
	enableObjectStore(w, fp)
	beam := w.deployed(t, "store")
	if _, err := w.o.ProvisionObjectStore(ctx, w.build, w.bh.ID, beam.ID); err != nil {
		t.Fatal(err)
	}
	if err := w.o.DestroyBeam(ctx, w.admin, w.bh.ID, beam.ID); err != nil {
		t.Fatalf("DestroyBeam: %v", err)
	}
	found := false
	for _, d := range fp.deregistered {
		if d == string(beam.ID)+":preview" {
			found = true
		}
	}
	if !found {
		t.Fatalf("broker deregister = %v", fp.deregistered)
	}
}

func TestObjectStoreBrokerWiredEnabledByDefault(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	// Wire the broker but do NOT reconcile yet.
	WithObjectStore(&fakeObjectStoreProv{}, ObjectStoreConfig{})(w.o)
	if !w.o.ObjectStoreBrokerWired() {
		t.Fatal("broker should be wired")
	}
	if w.o.ObjectStoreEnabled() {
		t.Fatal("enabled flag is learned at reconcile, not at wire time")
	}
	if err := w.o.ReconcileObjectStore(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !w.o.ObjectStoreEnabled() {
		t.Fatal("object store should be enabled after reconcile (local default)")
	}
}

func TestObjectStoreProvisionDisabledWithoutBroker(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	beam, _ := w.o.CreateBeam(ctx, w.build, w.bh.ID, "store", "Store", "node")
	if _, err := w.o.ProvisionObjectStore(ctx, w.build, w.bh.ID, beam.ID); !errors.Is(err, s3.ErrNotEnabled) {
		t.Fatalf("want s3.ErrNotEnabled with no broker, got %v", err)
	}
}
