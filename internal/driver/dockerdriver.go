package driver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

// ErrBuildUnsupported signals that the Docker runtime driver does not build
// images. Buildpack builds must run in a separate, non-userns-remapped context
// and publish the pinned image to the internal registry; the runtime daemon
// only pulls and runs it. This is a lab-verified constraint — see
// docs/lab-phase0-validation.md and docs/PLAN.md §4/§8.
var ErrBuildUnsupported = errors.New("docker driver does not build images; builds run in a separate non-remapped context")

const (
	labelManaged = "beamhall.managed"
	labelBeam    = "beamhall.beam"
	labelPort    = "beamhall.port"
	labelStaging = "beamhall.staging" // per-instance secrets staging dir name
)

// DockerDriver implements RuntimeDriver against a hardened, userns-remapped
// Docker daemon. It applies the SecurityContext (runc/runsc, cap-drop, seccomp/
// AppArmor, read-only rootfs, tmpfs, cgroup v2 limits) and places each workload
// on its per-Beamhall bridge network. It does not publish host ports — the
// gateway routes to the container's address on the bridge (see Status).
type DockerDriver struct {
	cli *client.Client
	// secretsRoot is a root-owned, 0700 host directory under which per-instance
	// secret files are staged and bind-mounted read-only into /run/secrets.
	secretsRoot string
}

// NewDockerDriver connects to the daemon from the environment (DOCKER_HOST etc.)
// with API-version negotiation, so a v28 client talks to a v29 daemon.
func NewDockerDriver(secretsRoot string) (*DockerDriver, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("docker client: %w", err)
	}
	if secretsRoot == "" {
		secretsRoot = "/var/lib/beamhall/secrets"
	}
	if err := os.MkdirAll(secretsRoot, 0o700); err != nil {
		return nil, fmt.Errorf("secrets root: %w", err)
	}
	return &DockerDriver{cli: cli, secretsRoot: secretsRoot}, nil
}

func (d *DockerDriver) Name() string { return "docker" }

func (d *DockerDriver) Capabilities() Capabilities {
	return Capabilities{SupportsPause: true, SupportsExec: true, SupportsBuild: false}
}

// Build is unsupported on the runtime daemon (see ErrBuildUnsupported).
func (d *DockerDriver) Build(ctx context.Context, req BuildRequest, progress chan<- Event) (BuildResult, error) {
	return BuildResult{}, ErrBuildUnsupported
}

// EnsureNetwork creates the per-Beamhall bridge network if it is absent. Egress
// policy (default-deny + allowlist) is enforced out-of-band by the iptables
// DOCKER-USER reconciler; here we only guarantee the isolated bridge exists.
func (d *DockerDriver) EnsureNetwork(ctx context.Context, name string) error {
	if name == "" {
		return nil
	}
	list, err := d.cli.NetworkList(ctx, network.ListOptions{
		Filters: filters.NewArgs(filters.Arg("name", name)),
	})
	if err != nil {
		return fmt.Errorf("network list: %w", err)
	}
	for _, n := range list {
		if n.Name == name {
			return nil
		}
	}
	_, err = d.cli.NetworkCreate(ctx, name, network.CreateOptions{
		Driver:   "bridge",
		Internal: false, // egress is governed by DOCKER-USER, not network internality
		Labels:   map[string]string{labelManaged: "true"},
	})
	if err != nil {
		return fmt.Errorf("network create %q: %w", name, err)
	}
	return nil
}

// RemoveNetwork deletes a Beamhall network (used on teardown).
func (d *DockerDriver) RemoveNetwork(ctx context.Context, name string) error {
	return d.cli.NetworkRemove(ctx, name)
}

// ConnectContainerToNetwork attaches an existing container (e.g. the
// appliance Postgres) to a network, so beams on that bridge reach it by DNS
// name without any egress exception. Idempotent.
func (d *DockerDriver) ConnectContainerToNetwork(ctx context.Context, containerRef, netName string) error {
	if err := d.EnsureNetwork(ctx, netName); err != nil {
		return err
	}
	err := d.cli.NetworkConnect(ctx, netName, containerRef, nil)
	if err != nil && strings.Contains(err.Error(), "already exists in network") {
		return nil
	}
	return err
}

// NetworkBridge returns the host bridge interface name for a Beamhall network,
// which the egress reconciler needs to scope its rules. Docker uses the
// com.docker.network.bridge.name option if set, else "br-"+networkID[:12].
func (d *DockerDriver) NetworkBridge(ctx context.Context, name string) (string, error) {
	n, err := d.cli.NetworkInspect(ctx, name, network.InspectOptions{})
	if err != nil {
		return "", fmt.Errorf("network inspect %q: %w", name, err)
	}
	if br := n.Options["com.docker.network.bridge.name"]; br != "" {
		return br, nil
	}
	if len(n.ID) >= 12 {
		return "br-" + n.ID[:12], nil
	}
	return "", fmt.Errorf("network %q has no resolvable bridge", name)
}

// Deploy creates (does not start) a container from the pinned image with the
// full hardening profile applied. An image that is not present locally is
// pulled by digest from the internal registry — the runtime daemon never
// builds, it only pulls and runs (PLAN §4, lab finding on userns vs pack).
func (d *DockerDriver) Deploy(ctx context.Context, spec DeploySpec) (Handle, error) {
	if err := d.ensureImage(ctx, spec.ImageDigest); err != nil {
		return Handle{}, err
	}
	if err := d.EnsureNetwork(ctx, spec.Network.BeamhallNetwork); err != nil {
		return Handle{}, err
	}

	inst := instanceID(spec.BeamID)
	mounts, err := d.stageSecrets(spec, inst)
	if err != nil {
		return Handle{}, err
	}

	env := make([]string, 0, len(spec.Bindings)+1)
	if spec.Port > 0 {
		env = append(env, "PORT="+strconv.Itoa(spec.Port))
	}

	cfg := &container.Config{
		Image:  spec.ImageDigest, // a locally-resolvable reference (name:tag | name@sha256 | id)
		Cmd:    spec.Command,     // nil => image default
		Env:    env,
		Labels: map[string]string{labelManaged: "true", labelBeam: spec.BeamID, labelPort: strconv.Itoa(spec.Port), labelStaging: inst},
	}

	host := &container.HostConfig{
		Runtime:        runtimeName(spec.Security.RuntimeClass),
		NetworkMode:    container.NetworkMode(spec.Network.BeamhallNetwork),
		ExtraHosts:     d.peerHosts(ctx, spec.Network.BeamhallNetwork),
		CapDrop:        spec.Security.CapDrop,
		CapAdd:         spec.Security.CapAdd,
		SecurityOpt:    securityOpts(spec.Security),
		ReadonlyRootfs: spec.Security.ReadOnlyRootfs,
		Tmpfs:          tmpfsMap(spec.Security.Tmpfs),
		Mounts:         mounts,
		Resources:      resourceConfig(spec.Resources),
		RestartPolicy:  container.RestartPolicy{Name: container.RestartPolicyDisabled},
	}

	var netCfg *network.NetworkingConfig
	if spec.Network.BeamhallNetwork != "" {
		netCfg = &network.NetworkingConfig{
			EndpointsConfig: map[string]*network.EndpointSettings{spec.Network.BeamhallNetwork: {}},
		}
	}

	resp, err := d.cli.ContainerCreate(ctx, cfg, host, netCfg, nil, "bh_"+inst)
	if err != nil {
		return Handle{}, fmt.Errorf("container create: %w", err)
	}
	return Handle{DriverName: d.Name(), Ref: resp.ID}, nil
}

// peerHosts returns --add-host entries (name:ip) for the containers already
// attached to netName, so a beam resolves same-network peers — notably the
// managed Postgres — via /etc/hosts instead of Docker's embedded DNS
// (127.0.0.11), which gVisor (runsc) cannot reach. The beam being deployed is
// not yet on the network, so it never lists itself. Best-effort: any inspect
// failure yields no entries (the beam still deploys).
func (d *DockerDriver) peerHosts(ctx context.Context, netName string) []string {
	if netName == "" {
		return nil
	}
	info, err := d.cli.NetworkInspect(ctx, netName, network.InspectOptions{})
	if err != nil {
		return nil
	}
	hosts := make([]string, 0, len(info.Containers))
	for _, c := range info.Containers {
		ip := c.IPv4Address
		if i := strings.IndexByte(ip, '/'); i >= 0 {
			ip = ip[:i] // strip the CIDR mask
		}
		if c.Name == "" || ip == "" {
			continue
		}
		hosts = append(hosts, c.Name+":"+ip)
	}
	return hosts
}

// ensureImage pulls ref if it is not already in the local store. Pulling by
// pinned digest is idempotent and immutable; failures surface the registry
// error verbatim.
func (d *DockerDriver) ensureImage(ctx context.Context, ref string) error {
	if _, err := d.cli.ImageInspect(ctx, ref); err == nil {
		return nil
	}
	rc, err := d.cli.ImagePull(ctx, ref, image.PullOptions{})
	if err != nil {
		return fmt.Errorf("pull %s: %w", ref, err)
	}
	defer rc.Close()
	// The pull stream must be drained for the operation to complete.
	if _, err := io.Copy(io.Discard, rc); err != nil {
		return fmt.Errorf("pull %s: %w", ref, err)
	}
	return nil
}

func (d *DockerDriver) Start(ctx context.Context, h Handle) error {
	if err := d.cli.ContainerStart(ctx, h.Ref, container.StartOptions{}); err != nil {
		return fmt.Errorf("start %s: %w", short(h.Ref), err)
	}
	return nil
}

func (d *DockerDriver) Pause(ctx context.Context, h Handle) error {
	return d.cli.ContainerPause(ctx, h.Ref)
}

func (d *DockerDriver) Resume(ctx context.Context, h Handle) error {
	return d.cli.ContainerUnpause(ctx, h.Ref)
}

func (d *DockerDriver) Stop(ctx context.Context, h Handle, grace time.Duration) error {
	secs := int(grace.Seconds())
	return d.cli.ContainerStop(ctx, h.Ref, container.StopOptions{Timeout: &secs})
}

func (d *DockerDriver) Destroy(ctx context.Context, h Handle) error {
	// Resolve this instance's staging dir BEFORE removal — the container is
	// not inspectable afterwards. Cleanup is best-effort; never fail Destroy.
	var staging string
	if info, ierr := d.cli.ContainerInspect(ctx, h.Ref); ierr == nil {
		staging = sanitize(info.Config.Labels[labelStaging])
	}
	err := d.cli.ContainerRemove(ctx, h.Ref, container.RemoveOptions{Force: true, RemoveVolumes: true})
	if staging != "" {
		_ = os.RemoveAll(filepath.Join(d.secretsRoot, staging))
	}
	if err != nil {
		return fmt.Errorf("remove %s: %w", short(h.Ref), err)
	}
	return nil
}

func (d *DockerDriver) Logs(ctx context.Context, h Handle, opts LogOptions) (io.ReadCloser, error) {
	o := container.LogsOptions{ShowStdout: true, ShowStderr: true, Follow: opts.Follow}
	if len(opts.Streams) > 0 {
		o.ShowStdout, o.ShowStderr = false, false
		for _, s := range opts.Streams {
			switch s {
			case "stdout":
				o.ShowStdout = true
			case "stderr":
				o.ShowStderr = true
			}
		}
	}
	if !opts.Since.IsZero() {
		o.Since = opts.Since.Format(time.RFC3339Nano)
	}
	if opts.TailN > 0 {
		o.Tail = strconv.Itoa(opts.TailN)
	}
	raw, err := d.cli.ContainerLogs(ctx, h.Ref, o)
	if err != nil {
		return nil, err
	}
	// Workloads run without a TTY, so the daemon multiplexes stdout/stderr
	// with 8-byte frame headers. Demux here — callers get plain text, not
	// frame garbage interleaved into every line.
	pr, pw := io.Pipe()
	go func() {
		_, err := stdcopy.StdCopy(pw, pw, raw)
		raw.Close()
		pw.CloseWithError(err)
	}()
	return pr, nil
}

func (d *DockerDriver) Stats(ctx context.Context, h Handle) (Stats, error) {
	resp, err := d.cli.ContainerStats(ctx, h.Ref, false)
	if err != nil {
		return Stats{}, fmt.Errorf("stats %s: %w", short(h.Ref), err)
	}
	defer resp.Body.Close()

	var s dockerStats
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return Stats{}, fmt.Errorf("decode stats: %w", err)
	}
	out := Stats{
		CPUPct:    cpuPercent(s),
		MemBytes:  s.MemoryStats.Usage,
		MemLimit:  s.MemoryStats.Limit,
		SampledAt: time.Now(),
	}
	for _, n := range s.Networks {
		out.NetRxBytes += n.RxBytes
		out.NetTxBytes += n.TxBytes
	}
	return out, nil
}

func (d *DockerDriver) Status(ctx context.Context, h Handle) (Status, error) {
	info, err := d.cli.ContainerInspect(ctx, h.Ref)
	if err != nil {
		return Status{}, fmt.Errorf("inspect %s: %w", short(h.Ref), err)
	}
	st := Status{State: mapState(info.State.Status)}
	if started, perr := time.Parse(time.RFC3339Nano, info.State.StartedAt); perr == nil {
		st.StartedAt = started
	}
	if info.State.ExitCode != 0 || info.State.Status == "exited" {
		ec := info.State.ExitCode
		st.ExitCode = &ec
	}
	if info.State.Health != nil {
		st.Health = info.State.Health.Status
	} else {
		st.Health = "none"
	}
	// BackendAddr = container IP on its (per-Beamhall) network + the beam port.
	// The gateway proxies here; we never publish a host port.
	port := info.Config.Labels[labelPort]
	for _, ep := range info.NetworkSettings.Networks {
		if ep.IPAddress != "" && port != "" {
			st.BackendAddr = ep.IPAddress + ":" + port
			break
		}
	}
	return st, nil
}

func (d *DockerDriver) Exec(ctx context.Context, h Handle, cmd []string, streams ExecStreams) (int, error) {
	// Always attach stdout/stderr so the attached stream stays open until the
	// process exits — draining it is how we know the command finished. (If we
	// only attached when the caller wants output, a no-output command would let
	// us inspect the exit code before it actually exited, returning a stale 0.)
	ec, err := d.cli.ContainerExecCreate(ctx, h.Ref, container.ExecOptions{
		Cmd:          cmd,
		AttachStdin:  streams.Stdin != nil,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          streams.TTY,
	})
	if err != nil {
		return -1, fmt.Errorf("exec create: %w", err)
	}
	att, err := d.cli.ContainerExecAttach(ctx, ec.ID, container.ExecAttachOptions{Tty: streams.TTY})
	if err != nil {
		return -1, fmt.Errorf("exec attach: %w", err)
	}
	defer att.Close()
	out, errw := streams.Stdout, streams.Stderr
	if out == nil {
		out = io.Discard
	}
	if errw == nil {
		errw = io.Discard
	}
	if streams.TTY {
		_, _ = io.Copy(out, att.Reader) // TTY: single un-multiplexed stream
	} else {
		_, _ = stdcopy.StdCopy(out, errw, att.Reader)
	}
	// Stream EOF means the process exited; poll inspect to read the final code
	// (and guard the brief window where it may still report Running).
	for {
		insp, err := d.cli.ContainerExecInspect(ctx, ec.ID)
		if err != nil {
			return -1, fmt.Errorf("exec inspect: %w", err)
		}
		if !insp.Running {
			return insp.ExitCode, nil
		}
		select {
		case <-ctx.Done():
			return -1, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// --- helpers ----------------------------------------------------------------

func runtimeName(rc RuntimeClass) string {
	if rc == RuntimeRunsc {
		return "runsc"
	}
	return "" // empty => daemon default (runc)
}

func securityOpts(p SecurityProfile) []string {
	var opts []string
	if p.NoNewPrivileges {
		opts = append(opts, "no-new-privileges:true")
	}
	if p.SeccompProfile != "" && p.SeccompProfile != "default" {
		opts = append(opts, "seccomp="+p.SeccompProfile)
	}
	if p.AppArmorProfile != "" && p.AppArmorProfile != "default" {
		opts = append(opts, "apparmor="+p.AppArmorProfile)
	}
	return opts
}

func tmpfsMap(paths []string) map[string]string {
	if len(paths) == 0 {
		return nil
	}
	m := make(map[string]string, len(paths))
	for _, p := range paths {
		m[p] = "rw,nosuid,nodev"
	}
	return m
}

func resourceConfig(r ResourceLimits) container.Resources {
	res := container.Resources{}
	if r.MemBytes > 0 {
		res.Memory = r.MemBytes
	}
	if r.PidsMax > 0 {
		pm := r.PidsMax
		res.PidsLimit = &pm
	}
	if r.CPUQuota > 0 {
		res.CPUQuota = r.CPUQuota
		res.CPUPeriod = 100000
	}
	return res
}

// stageSecrets writes each secret/binding to a per-beam, root-owned file and
// returns read-only bind mounts into the container. Files are 0444 so the
// userns-remapped container user can read them through the bind mount; the
// parent directory is 0700 so they are not reachable on the host otherwise.
func (d *DockerDriver) stageSecrets(spec DeploySpec, inst string) ([]mount.Mount, error) {
	if len(spec.Secrets) == 0 && len(spec.Bindings) == 0 {
		return nil, nil
	}
	// Staging is per-INSTANCE, not per-beam: during a redeploy the old and
	// new workloads coexist (new up before old retired), and destroying the
	// old must not unstage the new one's secrets.
	dir := filepath.Join(d.secretsRoot, inst)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("stage secrets dir: %w", err)
	}
	var mounts []mount.Mount
	write := func(name, target string, val []byte) error {
		host := filepath.Join(dir, sanitize(name))
		if err := os.WriteFile(host, val, 0o444); err != nil {
			return fmt.Errorf("write secret %q: %w", name, err)
		}
		mounts = append(mounts, mount.Mount{Type: mount.TypeBind, Source: host, Target: target, ReadOnly: true})
		return nil
	}
	for _, s := range spec.Secrets {
		if err := write(s.Key, s.MountPath, s.Value); err != nil {
			return nil, err
		}
	}
	for _, b := range spec.Bindings {
		if err := write(b.Alias, b.MountPath, b.Value); err != nil {
			return nil, err
		}
	}
	return mounts, nil
}

func (d *DockerDriver) beamOf(ctx context.Context, h Handle) string {
	info, err := d.cli.ContainerInspect(ctx, h.Ref)
	if err != nil {
		return ""
	}
	return sanitize(info.Config.Labels[labelBeam])
}

var nameSanitizer = regexp.MustCompile(`[^a-zA-Z0-9_.-]`)

func sanitize(s string) string { return nameSanitizer.ReplaceAllString(s, "_") }

// instanceID names one workload instance uniquely: redeploys briefly run the
// old and new containers side by side (new up before old retired), so a
// fixed per-beam name would collide at create time.
func instanceID(beamID string) string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return sanitize(beamID) + "-" + hex.EncodeToString(b[:])
}

func short(ref string) string {
	if len(ref) > 12 {
		return ref[:12]
	}
	return ref
}

func mapState(s string) WorkloadState {
	switch s {
	case "running":
		return WorkloadRunning
	case "paused":
		return WorkloadPaused
	case "exited", "dead":
		return WorkloadExited
	case "created", "restarting", "removing":
		return WorkloadUnknown
	default:
		return WorkloadUnknown
	}
}

// dockerStats is a minimal subset of the daemon's stats JSON, decoded directly
// so we don't depend on churn-prone SDK stats types.
type dockerStats struct {
	CPUStats struct {
		CPUUsage struct {
			TotalUsage uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
		SystemUsage uint64 `json:"system_cpu_usage"`
		OnlineCPUs  uint32 `json:"online_cpus"`
	} `json:"cpu_stats"`
	PreCPUStats struct {
		CPUUsage struct {
			TotalUsage uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
		SystemUsage uint64 `json:"system_cpu_usage"`
	} `json:"precpu_stats"`
	MemoryStats struct {
		Usage uint64 `json:"usage"`
		Limit uint64 `json:"limit"`
	} `json:"memory_stats"`
	Networks map[string]struct {
		RxBytes uint64 `json:"rx_bytes"`
		TxBytes uint64 `json:"tx_bytes"`
	} `json:"networks"`
}

func cpuPercent(s dockerStats) float64 {
	cpuDelta := float64(s.CPUStats.CPUUsage.TotalUsage) - float64(s.PreCPUStats.CPUUsage.TotalUsage)
	sysDelta := float64(s.CPUStats.SystemUsage) - float64(s.PreCPUStats.SystemUsage)
	if cpuDelta <= 0 || sysDelta <= 0 {
		return 0
	}
	cpus := float64(s.CPUStats.OnlineCPUs)
	if cpus == 0 {
		cpus = 1
	}
	return (cpuDelta / sysDelta) * cpus * 100.0
}
