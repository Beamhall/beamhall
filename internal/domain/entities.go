// Package domain holds Beamhall's core entities and the Beam lifecycle state
// machine. It is pure: no I/O, no Docker, no MCP, no database. Everything here
// is the vocabulary the backplane, MCP layer, and Admin UI share.
//
// Two invariants drive the model (see docs/PLAN.md §5.2):
//
//   - SecurityContext is data, not code paths. It is set by IT when a Beamhall
//     is created, snapshotted into every Release, and is immutable to the agent.
//   - A Release is a frozen (image digest + config + security profile + secret
//     refs) tuple, so rollback is a pointer flip with no rebuild.
package domain

import "time"

// ID is an opaque identifier (ULID in practice). Kept as a string alias so the
// domain package stays dependency-free; generation lives in the store layer.
type ID string

// ---------------------------------------------------------------------------
// Identity & membership
// ---------------------------------------------------------------------------

// Identity statuses. Disabled identities keep their rows (audit references
// them) but fail every authorization.
const (
	IdentityActive   = "active"
	IdentityDisabled = "disabled"
)

// Identity is a principal authenticated by an external OIDC IdP. Beamhall never
// stores passwords; auth is delegated (Keycloak/Auth0/Okta/Entra).
type Identity struct {
	ID              ID
	ExternalSubject string // IdP `sub`
	Email           string
	DisplayName     string
	IdPIssuer       string
	Status          string
	CreatedAt       time.Time
}

// MembershipRole scopes what an Identity may do within a single Beamhall.
type MembershipRole string

const (
	RoleViewer        MembershipRole = "viewer"
	RoleBuilder       MembershipRole = "builder"
	RoleBeamhallAdmin MembershipRole = "beamhall_admin"
)

// GlobalRole is cross-Beamhall. Only it_admin may create Beamhalls, edit
// security contexts/quotas/egress, and allocate live slots.
type GlobalRole string

const (
	RoleITAdmin GlobalRole = "it_admin"
)

// Membership maps an Identity to a Beamhall with a role.
type Membership struct {
	ID         ID
	IdentityID ID
	BeamhallID ID
	Role       MembershipRole
	GrantedBy  ID
	GrantedAt  time.Time
}

// ---------------------------------------------------------------------------
// Beamhall (aggregate root, IT-owned boundary)
// ---------------------------------------------------------------------------

type BeamhallStatus string

const (
	BeamhallActive    BeamhallStatus = "active"
	BeamhallSuspended BeamhallStatus = "suspended"
	BeamhallArchived  BeamhallStatus = "archived"
)

// Beamhall is the isolation/policy boundary for a department/team/project.
type Beamhall struct {
	ID                ID
	Slug              string // DNS-safe; appears in subdomains
	DisplayName       string
	Department        string
	Status            BeamhallStatus
	SecurityContextID ID // immutable after create; weakening requires IT
	NetworkPolicy     NetworkPolicy
	Quota             ResourceQuota
	LiveSlotLimit     int // commercial unit; gates promote_to_live
	CreatedBy         ID
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// RuntimeClass selects the OCI runtime / isolation tier for a Beamhall's
// workloads. runc is the hardened-Docker default; runsc is gVisor (the
// regulated tier). Firecracker is a future driver behind RuntimeDriver and is
// intentionally absent here (docs/PLAN.md §3).
type RuntimeClass string

const (
	RuntimeRunc  RuntimeClass = "runc"  // hardened Docker (default)
	RuntimeRunsc RuntimeClass = "runsc" // gVisor (regulated tier)
)

// SecurityTemplate narrows the capability set for a workload type. It can only
// narrow, never exceed, the Beamhall's SecurityContext ceiling.
type SecurityTemplate string

const (
	TemplateWebApp        SecurityTemplate = "web-app"        // cap-drop ALL + NET_BIND_SERVICE
	TemplateDataProcessor SecurityTemplate = "data-processor" // + CHOWN
	TemplateDatabaseInit  SecurityTemplate = "database-init"  // + DAC_OVERRIDE
)

// SecurityContext is the immutable hardening baseline for a Beamhall. Agents may
// never weaken it; only it_admin can change it, and any change is audited.
type SecurityContext struct {
	ID              ID
	BeamhallID      ID
	RuntimeClass    RuntimeClass // runc | runsc
	UsernsRemap     bool         // dockermap:dockermap
	CapDrop         []string     // typically ["ALL"]
	CapAdd          []string     // template-driven, e.g. ["NET_BIND_SERVICE"]
	SeccompProfile  string       // "default" | named ref
	AppArmorProfile string
	NoNewPrivileges bool
	ReadOnlyRootfs  bool
	Tmpfs           []string // e.g. ["/tmp"]
	CgroupLimits    ResourceLimits
	Template        SecurityTemplate
}

// NetworkPolicy is the per-Beamhall egress posture. Default is deny-all; IT adds
// an explicit allowlist. Always-deny destinations (metadata/link-local/host/
// management subnet) are enforced by the egress reconciler regardless of this.
type NetworkPolicy struct {
	EgressMode      EgressMode
	EgressAllowlist []string // FQDN/CIDR:port entries (IT-managed)
}

type EgressMode string

const (
	EgressDenyAll  EgressMode = "deny_all"
	EgressAllowSet EgressMode = "allow_set"
)

// ResourceLimits are cgroup v2 ceilings applied per container.
type ResourceLimits struct {
	CPUQuota int64 // microseconds per cpu period; 0 = unset
	MemBytes int64
	PidsMax  int64
}

// ResourceQuota caps a Beamhall's footprint. Immutable to agents (IT-set).
type ResourceQuota struct {
	MaxBeams        int
	MaxLiveSlots    int
	MaxDBCount      int
	MaxStorageBytes int64
	CPUCeiling      int64
	MemCeiling      int64
}

// ---------------------------------------------------------------------------
// Beam, Build, Release, Route
// ---------------------------------------------------------------------------

// BeamMode records whether a beam has a live channel. A beam always runs a
// preview channel; promote_to_live adds a pinned live channel and flips Mode to
// ModeLive (the preview channel keeps running and iterating). Mode is no longer
// exclusive — ModeLive means "has production", not "is no longer previewable".
type BeamMode string

const (
	ModePreview BeamMode = "preview" // preview channel only (never promoted)
	ModeLive    BeamMode = "live"    // has a pinned live channel alongside preview
)

// Channel selects which of a beam's two deployments a resource or secret binds
// to. The preview and live channels each get their own data, so iterating in
// preview can never read or corrupt production. ChannelShared secrets (user- or
// beamhall-set) inject into both channels; database connection secrets are
// channel-specific so the same app key (e.g. MAIN_URL) resolves to a different
// DSN in each channel.
type Channel string

const (
	ChannelShared  Channel = ""        // injected into both channels
	ChannelPreview Channel = "preview" // the builder's iterating workload
	ChannelLive    Channel = "live"    // the pinned production workload
)

// Beam is a deployable unit inside a Beamhall.
type Beam struct {
	ID                ID
	BeamhallID        ID
	Slug              string
	DisplayName       string
	RuntimeHint       string // auto|node|python|go|static
	Mode              BeamMode
	State             BeamState // the PREVIEW channel's lifecycle state
	CurrentReleaseID  ID        // active preview release; empty until first deploy
	DesiredReleaseID  ID        // preview target during a deploy; reconciled by orchestrator
	LiveReleaseID     ID        // active live release; empty until first promote
	LiveState         BeamState // live channel state: "" (none) | StateLive | StateFailed
	SecurityTemplate  SecurityTemplate
	PreviewPauseAfter time.Duration // Y; default inherited from Beamhall
	ResumedAt         time.Time     // wall-clock anchor for the continuous-runtime pause timer
	PreviewHost       string        // stable preview URL across redeploys; rotated only on pause->resume
	GitRemoteURL      string
	RepoID            ID
	Status            BeamStatus // active until destroy_beam archives it
	CreatedBy         ID
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// BeamStatus is the lifecycle disposition of a Beam, distinct from its runtime
// BeamState. destroy_beam archives a Beam (terminal); quota and slug
// uniqueness count only active Beams.
type BeamStatus string

const (
	BeamActive   BeamStatus = "active"
	BeamArchived BeamStatus = "archived"
)

type BuildStatus string

const (
	BuildQueued    BuildStatus = "queued"
	BuildBuilding  BuildStatus = "building"
	BuildSucceeded BuildStatus = "succeeded"
	BuildFailed    BuildStatus = "failed"
)

// SourceKind is how the source for a Build arrived.
type SourceKind string

const (
	SourceManagedGit SourceKind = "managed_git"
	SourceMCPTarball SourceKind = "mcp_tarball"
	SourceImageRef   SourceKind = "image_ref"
)

// Build is an immutable artifact record. image_digest is the pin carried into a
// Release.
type Build struct {
	ID            ID
	BeamID        ID
	SourceRef     string // git commit sha | tarball sha256
	SourceKind    SourceKind
	Builder       string // paketo builder image tag
	Status        BuildStatus
	ImageRef      string
	ImageDigest   string // sha256:...  -> the immutable pin
	SBOMRef       string
	CVEScanStatus string // pass | warn | fail
	LogStreamID   ID
	TriggeredBy   ID
	StartedAt     time.Time
	FinishedAt    time.Time
}

type ReleaseStatus string

const (
	ReleasePending    ReleaseStatus = "pending"
	ReleaseActive     ReleaseStatus = "active"
	ReleaseSuperseded ReleaseStatus = "superseded"
	ReleaseRolledBack ReleaseStatus = "rolled_back"
)

// Release is the deployable, frozen tuple. Rollback = activate an older Release.
// PromotionStatus is the state of a pending IT-approval-gated promotion.
type PromotionStatus string

const (
	PromotionPending  PromotionStatus = "pending"
	PromotionApproved PromotionStatus = "approved"
	PromotionRejected PromotionStatus = "rejected"
)

// AdminActionStatus is the state of a four-eyes-gated sensitive admin action.
type AdminActionStatus string

const (
	AdminActionPending  AdminActionStatus = "pending"
	AdminActionApproved AdminActionStatus = "approved"
	AdminActionRejected AdminActionStatus = "rejected"
)

// AdminActionType discriminates the sensitive admin actions that go through the
// four-eyes approval flow (PLAN §5.9). New sensitive actions (restore, upgrade)
// add a constant + a dispatcher case.
type AdminActionType string

const (
	AdminActionFederateDirectory   AdminActionType = "federate_directory"
	AdminActionUnfederateDirectory AdminActionType = "unfederate_directory"
	AdminActionSetSecurityContext  AdminActionType = "set_security_context"
	AdminActionPruneAudit          AdminActionType = "prune_audit"
	AdminActionRestoreBackup       AdminActionType = "restore_backup"
)

// AdminActionRequest records a SENSITIVE admin action awaiting a second IT
// operator's approval (separation of duties). The requesting operator cannot
// approve their own request; on approval the backplane executes the stored
// intent. The payload may carry secrets (e.g. an LDAP bind credential) and is
// stored vault-sealed; only Summary is non-secret and safe to display.
type AdminActionRequest struct {
	ID            ID
	ActionType    AdminActionType
	Summary       string
	PayloadCipher []byte // vault-sealed JSON intent
	RequestedBy   ID
	Status        AdminActionStatus
	Reason        string
	Result        string
	CreatedAt     time.Time
	DecidedBy     ID
	DecidedAt     time.Time
}

// PromotionRequest records a builder's request to promote a beam to live when
// the explicit IT-approval gate is enabled (PLAN §10). A different IT operator
// approves it (four-eyes), at which point the promotion executes.
type PromotionRequest struct {
	ID          ID
	BeamhallID  ID
	BeamID      ID
	ReleaseID   ID
	RequestedBy ID
	Status      PromotionStatus
	Reason      string
	CreatedAt   time.Time
	DecidedBy   ID
	DecidedAt   time.Time
}

type Release struct {
	ID                  ID
	BeamID              ID
	BuildID             ID
	Version             int               // monotonic per beam
	Channel             Channel           // which channel this release served: preview | live
	ConfigSnapshot      map[string]string // env KEYS (not values) + port/bindings metadata
	SecretRefs          []SecretRef       // keys only; values injected at runtime
	SecurityProfileSnap SecurityContext   // resolved hardening at deploy time
	RouteID             ID
	Workload            WorkloadHandle // runtime handle of this release's workload (stale once destroyed)
	Status              ReleaseStatus
	CreatedAt           time.Time
	ActivatedAt         time.Time
}

// WorkloadHandle mirrors driver.Handle without importing the driver package
// (domain stays pure); the orchestrator maps between them.
type WorkloadHandle struct {
	Driver string // "docker" | ...
	Ref    string // container id / pod name / vm id
}

type RouteKind string

const (
	RoutePreview RouteKind = "preview"
	RouteLive    RouteKind = "live"
)

type RouteStatus string

const (
	RouteActive  RouteStatus = "active"
	RouteRetired RouteStatus = "retired"
)

// Route maps a hostname to a running backend. Preview hosts are random and
// regenerated on every resume; live hosts are stable.
type Route struct {
	ID          ID
	BeamID      ID
	ReleaseID   ID
	Kind        RouteKind
	Hostname    string // <random>.preview.<base> | <beam>.<beamhall>.<base>
	RandomToken string // preview only; regenerated each resume
	BackendAddr string // container addr:port on the per-Beamhall bridge
	TLSCertRef  string
	Status      RouteStatus
	CreatedAt   time.Time
	RetiredAt   time.Time
}

// ---------------------------------------------------------------------------
// Resources, Secrets, Jobs, Logs
// ---------------------------------------------------------------------------

type ResourceType string

const (
	ResourceDatabase    ResourceType = "database"     // Postgres (MVP)
	ResourceObjectStore ResourceType = "object_store" // MinIO (fast-follow)
	ResourceQueue       ResourceType = "queue"        // fast-follow
)

type ResourceStatus string

const (
	ResourceProvisioning ResourceStatus = "provisioning"
	ResourceReady        ResourceStatus = "ready"
	ResourceFailed       ResourceStatus = "failed"
	ResourceDeleting     ResourceStatus = "deleting"
)

// Resource is a beam- or beamhall-scoped managed primitive. Connection
// credentials live in the secret service and are never returned to the agent.
type Resource struct {
	ID                  ID
	BeamhallID          ID
	BeamID              ID      // empty if beamhall-scoped
	Channel             Channel // preview | live (beam-scoped resources only)
	Type                ResourceType
	Status              ResourceStatus
	ConnectionSecretRef SecretRef
	Spec                map[string]string // db_name/version | bucket/quota | queue/backend
	BackingHandle       string            // driver handle (container id, etc.)
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// SecretRef points at a secret without carrying its value. Channel disambiguates
// per-channel secrets (e.g. a database DSN) that share a Key across channels;
// ChannelShared secrets are visible to both channels.
type SecretRef struct {
	BeamhallID ID
	BeamID     ID
	Key        string
	Channel    Channel
}

// Secret is backplane-controlled and write-only from the agent's perspective:
// there is no get_secret tool. Values are age-encrypted at rest and injected as
// files under /run/secrets/<key> at container create — never as env vars, never
// returned via MCP.
type Secret struct {
	ID         ID
	BeamhallID ID
	BeamID     ID      // empty if beamhall-scoped
	Channel    Channel // "" shared | preview | live
	Key        string
	ValueRef   string // pointer into the encrypted store; never plaintext here
	Version    int
	CreatedBy  ID
	CreatedAt  time.Time
}

// ScheduledJob is a cron-driven run of a beam image (fast-follow).
type ScheduledJob struct {
	ID         ID
	BeamID     ID
	Name       string
	Schedule   string // cron expr
	ReleaseID  ID
	Command    []string
	Enabled    bool
	LastRunAt  time.Time
	LastStatus string
	NextRunAt  time.Time
}

type LogStreamKind string

const (
	LogStdout LogStreamKind = "stdout"
	LogStderr LogStreamKind = "stderr"
	LogBuild  LogStreamKind = "build"
	LogAudit  LogStreamKind = "audit"
)

type LogStream struct {
	ID         ID
	OwnerKind  string // beam | build | job
	OwnerID    ID
	BeamhallID ID
	Kind       LogStreamKind
	Retention  time.Duration
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

type AuditDecision string

const (
	DecisionAllow AuditDecision = "allow"
	DecisionDeny  AuditDecision = "deny"
)

// AuditEvent is append-only and hash-chained (PrevHash + Hash). Every auth
// decision and state-changing operation writes one. This is the IT/Security
// buyer's core purchase reason.
type AuditEvent struct {
	ID            ID
	At            time.Time
	ActorID       ID
	ActorTokenJTI string
	BeamhallID    ID
	BeamID        ID
	Action        string // MCP tool or backplane op
	Decision      AuditDecision
	Reason        string
	RequestDigest string
	ResultStatus  string
	SourceIP      string
	PrevHash      string // hash of the previous row (tamper-evidence)
	Hash          string // hash of this row incl. PrevHash
}
