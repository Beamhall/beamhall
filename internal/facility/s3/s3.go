// Package s3 is the object-storage facility broker (PLAN §5.11 facility brokers;
// §5.13 object storage). A beam inherits S3-compatible object storage the way it
// inherits a database: one provision call mints per-beam S3 credentials, the app
// speaks stock S3 (boto3/aws-sdk/minio) to an in-hall endpoint, and the broker
// stores the bytes — either on a LOCAL disk-backed store (batteries-included, no
// external account) or by FORWARDING to an admin-configured external S3
// (AWS/MinIO/Wasabi). The external credential lives only in the broker — never in
// the beam — and the app never learns which backend stores its data.
//
// Unlike the email facility (where the broker keeps only a password HASH and the
// client transmits the plaintext over the wire), S3 clients authenticate with
// AWS SigV4 HMAC signatures: the secret key is NEVER sent on the wire, so the
// broker must hold the per-beam secret in PLAINTEXT to derive the signing key and
// verify each request. It is one shared container on every beam bridge, so it
// cannot distinguish beams by source IP — per-request SigV4 verification is the
// only thing that isolates beams. The plaintext per-beam secrets live only in the
// broker's memory (repopulated by beamhalld's reconcile on restart) and are
// sealed in the vault for injection; they never reach the agent/builder. See
// sigv4.go for the verifier, forward.go for the external-S3 backend.
//
// This file holds the Provisioner (the registration/lifecycle seam, the backend
// swap, and provider persistence) and its helpers.
package s3

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3afero"
)

// Errors returned by the facility.
var (
	// ErrNotEnabled means the broker has no backend yet (should not happen once
	// wired: the broker defaults to the local backend).
	ErrNotEnabled = errors.New("s3: object store not available")
	// ErrUnknownBeam means the beam has no object-store registration.
	ErrUnknownBeam = errors.New("s3: beam not registered for object storage")
)

// ProviderConfig is the south-side backend the broker stores through. An empty
// Endpoint selects the LOCAL disk backend (the default); a non-empty Endpoint
// forwards to an external S3, namespacing every beam under a key prefix inside
// the single admin-supplied Bucket.
type ProviderConfig struct {
	// Endpoint is the external S3 endpoint as "host:port" (e.g. "s3.amazonaws.com"
	// or "minio.corp:9000"). Empty = local disk backend.
	Endpoint string
	// Region is the external S3 region (default "us-east-1").
	Region string
	// Bucket is the single real bucket in the external S3 that holds every beam's
	// objects under a per-beam key prefix.
	Bucket string
	// AccessKey/SecretKey authenticate to the external S3. Held only here, never
	// injected into a beam.
	AccessKey string
	SecretKey string
	// ForcePathStyle uses path-style addressing against the external S3 (required
	// by MinIO and most non-AWS endpoints).
	ForcePathStyle bool
	// UseSSL dials the external S3 over HTTPS (default true for a real provider).
	UseSSL bool
}

// Credentials are the per-beam S3 credentials minted at provision time. The
// orchestrator seals these into the vault (S3_ACCESS_KEY/S3_SECRET_KEY) for
// file-injection into the beam; they are valid only against the in-hall endpoint.
type Credentials struct {
	AccessKey string
	SecretKey string
}

// Limits bounds a beam's stored data. MaxBytes == 0 means unlimited.
type Limits struct {
	MaxBytes int64
}

// ProvisionRequest asks for object storage for one beam+channel. The orchestrator
// supplies the bucket name (derived from beam+channel slugs); the broker mints
// the credentials.
type ProvisionRequest struct {
	BeamID  string
	Channel string
	Bucket  string
	Limits  Limits
}

// Registration is one beam+channel's object-store binding. Pushed over the
// control channel (with the PLAINTEXT secret — SigV4 requires it) and held in
// broker memory; repopulated by beamhalld's reconcile on broker restart.
type Registration struct {
	BeamID    string
	Channel   string
	AccessKey string
	SecretKey string
	Bucket    string
	Limits    Limits
}

// Event is the per-request audit record the broker emits for mutations and
// denials (never object contents). Result is "ok" | "denied" | "failed".
type Event struct {
	BeamID  string
	Channel string
	Op      string // PutObject | DeleteObject | DeleteObjects | CompleteMultipartUpload | ...
	Bucket  string
	Key     string
	Size    int64
	Result  string
	Err     string
}

// registration is one beam+channel's live binding. The secret is plaintext —
// SigV4 verification derives the signing key from it.
type registration struct {
	beamID    string
	channel   string
	accessKey string
	secret    string
	bucket    string
	maxBytes  int64
}

// Provisioner is the object-store facility's registration/lifecycle seam and the
// holder of the current backend. It keeps the in-memory registry of per-beam
// bindings (by access key, for SigV4 lookup; by beam+channel, for reconcile) and
// the swappable gofakes3 engine (local disk or forward-to-external).
type Provisioner struct {
	mu       sync.RWMutex
	byKey    map[string]*registration // accessKey -> binding (SigV4 lookup + scope)
	byBeam   map[string]*registration // beam+channel -> binding (reconcile/dereg)
	backend  gofakes3.Backend
	faker    *gofakes3.GoFakeS3
	provider *ProviderConfig

	audit    func(Event)
	defaults Limits
	stateDir string // holds provider.json (root-only) + the local backend's data dir
}

// Option configures a Provisioner.
type Option func(*Provisioner)

// WithAuditSink wires the per-request audit callback (the orchestrator points it
// at the hash-chained audit log).
func WithAuditSink(fn func(Event)) Option { return func(p *Provisioner) { p.audit = fn } }

// WithDefaultLimits sets the default per-beam quota applied when a provision
// request leaves it unset.
func WithDefaultLimits(l Limits) Option {
	return func(p *Provisioner) {
		if l.MaxBytes > 0 {
			p.defaults.MaxBytes = l.MaxBytes
		}
	}
}

// WithStateDir sets the broker's state directory: provider.json (the persisted
// south-side config, root-only) lives here, and the local backend stores objects
// under <dir>/data. New() builds the local backend immediately if this is set.
func WithStateDir(dir string) Option { return func(p *Provisioner) { p.stateDir = dir } }

// WithBackend pins a backend (tests), bypassing local/forward construction.
func WithBackend(be gofakes3.Backend) Option {
	return func(p *Provisioner) { p.setBackend(be) }
}

// New builds a Provisioner. If a state dir is set (and no backend was pinned),
// the broker comes up in LOCAL mode immediately — object storage is available by
// default, switched to an external backend only when an admin sets a provider.
func New(opts ...Option) *Provisioner {
	p := &Provisioner{
		byKey:    map[string]*registration{},
		byBeam:   map[string]*registration{},
		defaults: Limits{},
	}
	for _, o := range opts {
		o(p)
	}
	if p.backend == nil && p.stateDir != "" {
		if be, err := p.buildLocalBackend(); err == nil {
			p.setBackend(be)
		}
	}
	return p
}

func beamKey(beamID, channel string) string { return beamID + "\x00" + channel }

func (p *Provisioner) buildLocalBackend() (gofakes3.Backend, error) {
	dataDir := filepath.Join(p.stateDir, "data")
	fs, err := s3afero.FsPath(dataDir, s3afero.FsPathCreate)
	if err != nil {
		return nil, fmt.Errorf("s3: local data dir: %w", err)
	}
	be, err := s3afero.MultiBucket(fs)
	if err != nil {
		return nil, fmt.Errorf("s3: local backend: %w", err)
	}
	return be, nil
}

// setBackend swaps the backend + its gofakes3 engine under lock. WithAutoBucket
// is off: buckets are created explicitly at registration so a typo'd bucket can't
// be conjured by a request.
func (p *Provisioner) setBackend(be gofakes3.Backend) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.backend = be
	p.faker = gofakes3.New(be, gofakes3.WithoutVersioning(), gofakes3.WithLogger(gofakes3.DiscardLog()))
}

// Enabled reports whether the broker has a backend. The local default means this
// is true as soon as the broker is wired (object storage is on by default).
func (p *Provisioner) Enabled() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.backend != nil
}

// SetProvider switches the south-side backend (admin_set_object_store_provider).
// An empty Endpoint restores the LOCAL disk backend; a non-empty Endpoint builds
// a forward-to-external backend. The config is persisted (root-only) so it
// survives a broker restart. Switching does not migrate existing data; beamhalld
// re-ensures buckets on the new backend via reconcile.
func (p *Provisioner) SetProvider(cfg ProviderConfig) error {
	var (
		be  gofakes3.Backend
		err error
	)
	if strings.TrimSpace(cfg.Endpoint) == "" {
		be, err = p.buildLocalBackend()
	} else {
		be, err = newForwardBackend(cfg)
	}
	if err != nil {
		return err
	}
	p.setBackend(be)
	p.mu.Lock()
	c := cfg
	p.provider = &c
	dir := p.stateDir
	p.mu.Unlock()
	if dir != "" {
		p.persistProvider(dir, cfg)
	}
	return nil
}

func providerStorePath(dir string) string { return filepath.Join(dir, "provider.json") }

func (p *Provisioner) persistProvider(dir string, cfg ProviderConfig) {
	path := providerStorePath(dir)
	if strings.TrimSpace(cfg.Endpoint) == "" {
		_ = os.Remove(path) // local mode is the default; nothing to persist
		return
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		return
	}
	_ = os.WriteFile(path, b, 0o600)
}

// LoadProvider restores a persisted provider config (broker startup). No-op if no
// store is configured or none has been persisted (stays in local mode).
func (p *Provisioner) LoadProvider() error {
	p.mu.RLock()
	dir := p.stateDir
	p.mu.RUnlock()
	if dir == "" {
		return nil
	}
	b, err := os.ReadFile(providerStorePath(dir))
	if err != nil {
		return nil // none persisted yet → local mode
	}
	var cfg ProviderConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return fmt.Errorf("s3: parse persisted provider: %w", err)
	}
	return p.SetProvider(cfg)
}

// RegisterKey (re)registers a beam+channel's binding from the control channel:
// the access key, the PLAINTEXT secret (for SigV4), the bucket, and the quota.
// It ensures the bucket exists on the current backend. This is both the provision
// path and the reconcile path (beamhalld re-pushes from the vault on restart).
func (p *Provisioner) RegisterKey(reg Registration) error {
	if reg.BeamID == "" || reg.AccessKey == "" || reg.SecretKey == "" || reg.Bucket == "" {
		return errors.New("s3: incomplete registration")
	}
	maxBytes := reg.Limits.MaxBytes
	if maxBytes == 0 {
		maxBytes = p.defaults.MaxBytes
	}
	r := &registration{
		beamID:    reg.BeamID,
		channel:   reg.Channel,
		accessKey: reg.AccessKey,
		secret:    reg.SecretKey,
		bucket:    reg.Bucket,
		maxBytes:  maxBytes,
	}
	if err := p.ensureBucket(reg.Bucket); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if old, ok := p.byBeam[beamKey(reg.BeamID, reg.Channel)]; ok && old.accessKey != reg.AccessKey {
		delete(p.byKey, old.accessKey) // key rotated
	}
	p.byKey[reg.AccessKey] = r
	p.byBeam[beamKey(reg.BeamID, reg.Channel)] = r
	return nil
}

// ensureBucket creates the beam's bucket on the current backend if absent. On the
// forward backend this is a no-op (the prefix lives inside the admin bucket).
func (p *Provisioner) ensureBucket(bucket string) error {
	p.mu.RLock()
	be := p.backend
	p.mu.RUnlock()
	if be == nil {
		return ErrNotEnabled
	}
	exists, err := be.BucketExists(bucket)
	if err != nil {
		return fmt.Errorf("s3: bucket exists check: %w", err)
	}
	if exists {
		return nil
	}
	if err := be.CreateBucket(bucket); err != nil && !gofakes3.IsAlreadyExists(err) {
		return fmt.Errorf("s3: create bucket: %w", err)
	}
	return nil
}

// SetQuota updates a beam+channel's storage cap (admin_set_object_store_quota).
func (p *Provisioner) SetQuota(beamID, channel string, maxBytes int64) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	r, ok := p.byBeam[beamKey(beamID, channel)]
	if !ok {
		return ErrUnknownBeam
	}
	r.maxBytes = maxBytes
	return nil
}

// Deregister removes a beam+channel's binding (reclaim on destroy). If purge is
// true, the bucket and all its objects are deleted to free the quota.
func (p *Provisioner) Deregister(beamID, channel string, purge bool) {
	p.mu.Lock()
	r, ok := p.byBeam[beamKey(beamID, channel)]
	if ok {
		delete(p.byKey, r.accessKey)
		delete(p.byBeam, beamKey(beamID, channel))
	}
	be := p.backend
	p.mu.Unlock()
	if ok && purge && be != nil {
		_ = be.ForceDeleteBucket(r.bucket)
	}
}

func (p *Provisioner) lookup(accessKey string) (*registration, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	r, ok := p.byKey[accessKey]
	return r, ok
}

func (p *Provisioner) currentBackend() gofakes3.Backend {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.backend
}

func (p *Provisioner) currentFaker() *gofakes3.GoFakeS3 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.faker
}

func (p *Provisioner) emit(ev Event) {
	if p.audit != nil {
		p.audit(ev)
	}
}

// MintCredentials returns fresh per-beam S3 credentials. beamhalld calls this (or
// the control-channel client does) to mint then RegisterKey + seal into the vault.
func MintCredentials() (Credentials, error) {
	ak, err := randomToken(10) // 20 hex chars
	if err != nil {
		return Credentials{}, err
	}
	sk, err := randomToken(24) // 48 hex chars
	if err != nil {
		return Credentials{}, err
	}
	return Credentials{AccessKey: "BH" + strings.ToUpper(ak), SecretKey: sk}, nil
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
