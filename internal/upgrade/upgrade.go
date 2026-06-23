// Package upgrade is the self-upgrade seam: replacing the binary that enforces
// policy is the most sensitive thing the control plane can do, so it is
// fail-closed by default (Disabled), gated behind the four-eyes sensitive tier,
// and never performs a live self-replacing restart. The Stager downloads a
// pinned release, verifies its checksum, stages the new binary, and hands back
// an operator runbook for the atomic apply (+ rollback) — the irreversible
// swap+restart is a deliberate operator step, not an autonomous one.
package upgrade

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// ErrNotEnabled is returned when self-upgrade is not configured on this appliance.
var ErrNotEnabled = errors.New("self-upgrade is not enabled on this appliance (set BEAMHALL_SELF_UPGRADE=on)")

// Result describes a staged upgrade awaiting the operator's atomic apply.
type Result struct {
	Version        string // the target version (normalized, e.g. v0.1.11)
	CurrentVersion string
	StagedPath     string // the verified new binary on disk, not yet live
	SHA256         string // verified checksum of the downloaded release asset
	ApplyCmd       string // operator command: back up current + swap + restart
	RollbackCmd    string // operator command to revert
}

// Stager stages a verified upgrade. The orchestrator calls it only after
// four-eyes approval.
type Stager interface {
	Enabled() bool
	CurrentVersion() string
	// Stage downloads, checksum-verifies, and stages the target version, returning
	// the operator apply/rollback runbook. It does NOT touch the live binary.
	Stage(ctx context.Context, version string) (Result, error)
}

// Disabled is the fail-closed default: self-upgrade is unavailable.
type Disabled struct{ Version string }

func (Disabled) Enabled() bool            { return false }
func (d Disabled) CurrentVersion() string { return d.Version }
func (Disabled) Stage(context.Context, string) (Result, error) {
	return Result{}, ErrNotEnabled
}

var _ Stager = Disabled{}

// versionRe constrains a target version to a release-tag shape, so it can never
// inject into the download URL or a staged file path.
var versionRe = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.+-]+)?$`)

// Release stages from a GoReleaser-style release: <BaseURL>/v<ver>/beamhall_<ver>_<os>_<arch>.tar.gz
// plus a checksums.txt alongside it.
type Release struct {
	BaseURL     string // e.g. https://github.com/Beamhall/beamhall/releases/download
	InstallPath string // the live binary to replace, e.g. /usr/local/bin/beamhalld
	StagingDir  string // where the verified new binary is written
	GOOS        string
	GOARCH      string
	Current     string // current running version
	HTTP        *http.Client
	// SkipSelfCheck disables running "<staged> version" after staging (the
	// post-stage sanity check). Left false in production.
	SkipSelfCheck bool
}

func (r Release) Enabled() bool          { return true }
func (r Release) CurrentVersion() string { return r.Current }

func (r Release) client() *http.Client {
	if r.HTTP != nil {
		return r.HTTP
	}
	return http.DefaultClient
}

func (r Release) Stage(ctx context.Context, version string) (Result, error) {
	if !versionRe.MatchString(version) {
		return Result{}, fmt.Errorf("invalid target version %q (want e.g. v0.1.11)", version)
	}
	bare := strings.TrimPrefix(version, "v")
	tag := "v" + bare
	if tag == "v"+strings.TrimPrefix(r.Current, "v") {
		return Result{}, fmt.Errorf("already running %s", r.Current)
	}
	asset := fmt.Sprintf("beamhall_%s_%s_%s.tar.gz", bare, r.GOOS, r.GOARCH)
	base := strings.TrimRight(r.BaseURL, "/") + "/" + tag

	// 1. Expected checksum from checksums.txt.
	want, err := r.fetchChecksum(ctx, base+"/checksums.txt", asset)
	if err != nil {
		return Result{}, err
	}
	// 2. Download the asset and verify its checksum.
	blob, err := r.fetch(ctx, base+"/"+asset)
	if err != nil {
		return Result{}, err
	}
	sum := sha256.Sum256(blob)
	got := hex.EncodeToString(sum[:])
	if got != want {
		return Result{}, fmt.Errorf("checksum mismatch for %s: got %s, release lists %s", asset, got, want)
	}
	// 3. Extract beamhalld and stage it.
	bin, err := extractBeamhalld(blob)
	if err != nil {
		return Result{}, err
	}
	if err := os.MkdirAll(r.StagingDir, 0o700); err != nil {
		return Result{}, err
	}
	stagedPath := filepath.Join(r.StagingDir, "beamhalld-"+tag)
	if err := os.WriteFile(stagedPath, bin, 0o755); err != nil {
		return Result{}, err
	}
	// 4. Sanity-check: the staged binary runs and reports the target version.
	if !r.SkipSelfCheck {
		out, err := exec.CommandContext(ctx, stagedPath, "version").CombinedOutput()
		if err != nil {
			return Result{}, fmt.Errorf("staged binary failed its version self-check: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		if !strings.Contains(string(out), bare) {
			return Result{}, fmt.Errorf("staged binary reports %q, expected version %s", strings.TrimSpace(string(out)), bare)
		}
	}
	rollback := r.InstallPath + ".rollback"
	return Result{
		Version: tag, CurrentVersion: r.Current, StagedPath: stagedPath, SHA256: got,
		ApplyCmd:    fmt.Sprintf("cp %s %s && mv %s %s && systemctl restart beamhalld", r.InstallPath, rollback, stagedPath, r.InstallPath),
		RollbackCmd: fmt.Sprintf("mv %s %s && systemctl restart beamhalld", rollback, r.InstallPath),
	}, nil
}

func (r Release) fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 256<<20))
}

func (r Release) fetchChecksum(ctx context.Context, url, asset string) (string, error) {
	body, err := r.fetch(ctx, url)
	if err != nil {
		return "", fmt.Errorf("fetch checksums: %w", err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[1] == asset {
			return f[0], nil
		}
	}
	return "", fmt.Errorf("no checksum for %s in checksums.txt", asset)
}

// extractBeamhalld pulls the beamhalld entry out of a gzip'd tar release asset.
func extractBeamhalld(blob []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(blob))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if filepath.Base(h.Name) == "beamhalld" && h.Typeflag == tar.TypeReg {
			return io.ReadAll(io.LimitReader(tr, 256<<20))
		}
	}
	return nil, errors.New("release asset does not contain a beamhalld binary")
}
