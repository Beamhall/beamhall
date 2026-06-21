package build

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Packer runs Cloud Native Buildpacks builds via the `pack` CLI against the
// appliance's separate build context and publishes the result to the internal
// registry. It must NEVER point at the hardened runtime daemon: the buildpack
// lifecycle cannot run there (userns-remap; lab finding), and build isolation
// stays decoupled from runtime isolation. --network host lets the lifecycle
// reach the loopback registry, which is safe precisely because this is the
// non-remapped build daemon, not the runtime one.
type Packer struct {
	// PackBin is the pack CLI path (default "pack").
	PackBin string
	// DockerHost is the build daemon socket, e.g.
	// unix:///run/docker-build.sock. Empty means the environment's default —
	// only acceptable when that already IS a dedicated build daemon.
	DockerHost string
	// Builder is the trusted CNB builder image (PLAN: Paketo).
	Builder string
	// Registry is the internal registry host:port the build publishes to and
	// the runtime daemon pulls from, e.g. "127.0.0.1:5000".
	Registry string
	// PullPolicy is pack's image pull policy: "always" (default), "if-not-present"
	// (air-gapped: use the pre-mirrored builder/run images), or "never".
	PullPolicy string
	// RunImage overrides the builder's default run image (air-gapped: a mirror in
	// the internal registry). Empty uses the builder's metadata default.
	RunImage string
	// Timeout bounds one build (runaway-build defense; default 10m).
	Timeout time.Duration
}

// Build runs `pack build` on srcDir, publishing registry/<imageRepo>:<tag>,
// and returns the registry-resolved content digest ("sha256:..."). Build logs
// stream to logs (the future SSE progress source).
func (p *Packer) Build(ctx context.Context, imageRepo, tag, srcDir string, logs io.Writer) (string, error) {
	if p.Registry == "" || p.Builder == "" {
		return "", fmt.Errorf("packer needs Registry and Builder configured")
	}
	bin := p.PackBin
	if bin == "" {
		bin = "pack"
	}
	timeout := p.Timeout
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	image := fmt.Sprintf("%s/%s:%s", p.Registry, imageRepo, tag)
	args := []string{"build", image,
		"--path", srcDir,
		"--builder", p.Builder,
		"--publish",
		"--network", "host",
		"--trust-builder",
	}
	// Air-gapped: "if-not-present"/"never" makes pack use the pre-mirrored
	// builder + run images instead of pulling from the internet on every build.
	if p.PullPolicy != "" {
		args = append(args, "--pull-policy", p.PullPolicy)
	}
	if p.RunImage != "" {
		args = append(args, "--run-image", p.RunImage)
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = os.Environ()
	if p.DockerHost != "" {
		cmd.Env = append(cmd.Env, "DOCKER_HOST="+p.DockerHost)
	}
	cmd.Stdout = logs
	cmd.Stderr = logs
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("pack build %s: %w", image, err)
	}
	digest, err := p.resolveDigest(ctx, imageRepo, tag)
	if err != nil {
		return "", fmt.Errorf("build published but digest resolution failed: %w", err)
	}
	return digest, nil
}

// resolveDigest asks the registry for the manifest digest of repo:tag — the
// immutable pin the runtime daemon pulls. Plain HTTP: the internal registry
// listens on loopback only (TLS arrives if/when the registry moves off-box).
func (p *Packer) resolveDigest(ctx context.Context, imageRepo, tag string) (string, error) {
	url := fmt.Sprintf("http://%s/v2/%s/manifests/%s", p.Registry, imageRepo, tag)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.docker.distribution.manifest.v2+json",
	}, ", "))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registry %s: HTTP %d for %s:%s", p.Registry, resp.StatusCode, imageRepo, tag)
	}
	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		return "", fmt.Errorf("registry returned no Docker-Content-Digest for %s:%s", imageRepo, tag)
	}
	return digest, nil
}
