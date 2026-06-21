// Package driver defines the RuntimeDriver interface — the abstraction the
// orchestrator depends on to build, run, and observe workloads. Docker is the
// only MVP implementation; Kubernetes (and, if a regulated partner's security
// review demands it, Firecracker) can be added later WITHOUT changing the MCP
// tool contract or the backplane services. See docs/PLAN.md §5.3.
//
// Deliberately, nothing here mentions MCP, OAuth, or the backplane. The contract
// is decoupled so the seam stays stable. The Docker driver applies the hardening
// profile (userns-remap, cap-drop, seccomp/AppArmor, read-only rootfs, cgroup v2
// limits) and selects the runtime class (runc | runsc/gVisor) from the
// SecurityProfile.
package driver

import (
	"context"
	"io"
	"time"
)

// Handle is an opaque, driver-specific reference to a workload.
type Handle struct {
	DriverName string // "docker" | "kubernetes" | ...
	Ref        string // container id / pod name / vm id
}

// RuntimeClass mirrors domain.RuntimeClass but is kept local so the driver layer
// does not import the domain package (avoids a cycle; the orchestrator maps
// between them).
type RuntimeClass string

const (
	RuntimeRunc  RuntimeClass = "runc"
	RuntimeRunsc RuntimeClass = "runsc"
)

// SecurityProfile is the resolved, immutable hardening applied to a workload.
type SecurityProfile struct {
	RuntimeClass    RuntimeClass
	UsernsRemap     bool
	CapDrop         []string
	CapAdd          []string
	SeccompProfile  string
	AppArmorProfile string
	NoNewPrivileges bool
	ReadOnlyRootfs  bool
	Tmpfs           []string
}

// ResourceLimits are cgroup v2 ceilings.
type ResourceLimits struct {
	CPUQuota int64
	MemBytes int64
	PidsMax  int64
}

// NetworkPolicy is the per-Beamhall network + egress posture the driver must
// realize (a per-Beamhall bridge under Docker; the egress allowlist is enforced
// out-of-band by the egress reconciler, but the driver places the workload on
// the right network).
type NetworkPolicy struct {
	BeamhallNetwork string // e.g. "bh-<id>"
	EgressDenyAll   bool
	EgressAllowlist []string // FQDN/CIDR:port (informational to the driver)
}

// SecretMount injects a secret as a file at MountPath (tmpfs), never as an env
// var. The driver receives already-decrypted material from the secret service.
type SecretMount struct {
	Key       string
	MountPath string // e.g. /run/secrets/<key>
	Value     []byte
}

// ResourceBinding wires a provisioned resource (db/object-store/queue) into the
// workload via a connection secret ref. The driver mounts it like a secret.
type ResourceBinding struct {
	Alias     string // logical name the beam reads, e.g. "db.primary"
	MountPath string
	Value     []byte
}

// SourceRef points the builder at unpacked source on disk.
type SourceRef struct {
	Dir       string // checkout/unpack directory
	CommitSHA string
}

// BuildRequest drives a Cloud Native Buildpacks build. The agent never supplies
// a Dockerfile; the builder detects the language. Builds run non-root.
type BuildRequest struct {
	BeamID   string
	Source   SourceRef
	Builder  string // paketo builder image tag
	Env      map[string]string
	Security SecurityProfile // the build container is hardened too
}

// BuildResult carries the immutable image pin.
type BuildResult struct {
	ImageRef    string
	ImageDigest string // sha256:...
	SBOMRef     string
}

// DeploySpec is everything needed to create (not start) a workload.
type DeploySpec struct {
	BeamID      string
	BeamhallID  string
	ImageDigest string   // immutable pin from a Build
	Command     []string // optional entrypoint/cmd override (empty = image default)
	Network     NetworkPolicy
	Security    SecurityProfile
	Resources   ResourceLimits
	Secrets     []SecretMount
	Bindings    []ResourceBinding
	Port        int
}

// LogOptions controls a Logs read.
type LogOptions struct {
	Follow  bool
	Since   time.Time
	TailN   int
	Streams []string // "stdout","stderr"
}

// Stats is a point-in-time resource sample.
type Stats struct {
	CPUPct     float64
	MemBytes   uint64
	MemLimit   uint64
	NetRxBytes uint64
	NetTxBytes uint64
	SampledAt  time.Time
}

// WorkloadState is the runtime status of a workload.
type WorkloadState string

const (
	WorkloadRunning WorkloadState = "running"
	WorkloadPaused  WorkloadState = "paused"
	WorkloadExited  WorkloadState = "exited"
	WorkloadFailed  WorkloadState = "failed"
	WorkloadUnknown WorkloadState = "unknown"
)

// Status reports a workload's state and the address the gateway should route to.
type Status struct {
	State       WorkloadState
	ExitCode    *int
	StartedAt   time.Time
	Health      string // healthy | unhealthy | starting | none
	BackendAddr string // addr:port for gateway registration
}

// Capabilities advertises optional behaviors so the orchestrator can adapt
// (e.g. emulate pause as scale-to-zero on a driver that cannot freeze).
type Capabilities struct {
	SupportsPause bool
	SupportsExec  bool
	SupportsBuild bool
}

// Event is a progress event streamed during a long operation (build/deploy),
// relayed to the AI client over MCP SSE.
type Event struct {
	At      time.Time
	Phase   string // clone | detect | build | export | start | ...
	Message string
	Percent int // 0..100; -1 if indeterminate
}

// ExecStreams carries the I/O for an Exec call.
type ExecStreams struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	TTY    bool
}

// RuntimeDriver is the single abstraction the orchestrator depends on. Long
// operations accept a progress channel and honor context cancellation so an MCP
// CancelledNotification can abort an in-flight build/deploy.
type RuntimeDriver interface {
	Name() string
	Capabilities() Capabilities

	// Build turns untrusted source into a pinned image via Cloud Native
	// Buildpacks (no Dockerfile). Progress events are emitted on progress, which
	// the caller owns and must drain; Build closes nothing.
	Build(ctx context.Context, req BuildRequest, progress chan<- Event) (BuildResult, error)

	// Deploy creates (does not start) a workload from a pinned image digest,
	// applying the security profile, network, limits, and secret/file mounts.
	Deploy(ctx context.Context, spec DeploySpec) (Handle, error)

	Start(ctx context.Context, h Handle) error

	// Pause freezes a workload (preview auto-pause / pause_preview); Resume
	// thaws it. On drivers without freeze support the orchestrator emulates this
	// via Stop/Deploy+Start (see Capabilities.SupportsPause).
	Pause(ctx context.Context, h Handle) error
	Resume(ctx context.Context, h Handle) error

	// Stop terminates the workload process with a grace period.
	Stop(ctx context.Context, h Handle, grace time.Duration) error

	// Destroy removes the workload and its ephemeral resources.
	Destroy(ctx context.Context, h Handle) error

	Logs(ctx context.Context, h Handle, opts LogOptions) (io.ReadCloser, error)
	Stats(ctx context.Context, h Handle) (Stats, error)
	Status(ctx context.Context, h Handle) (Status, error)

	// Exec is capability-gated, IT-controllable, audited, and off by default.
	Exec(ctx context.Context, h Handle, cmd []string, io ExecStreams) (int, error)
}
