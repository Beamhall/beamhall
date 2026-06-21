package build

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Beamhall/beamhall/internal/diagnose"
)

// Result is one finished build: the source pin, the human image ref, the
// content digest, and the exact reference the runtime daemon pulls.
type Result struct {
	SourceSHA   string // commit on the beam's managed repo (Build.source_ref)
	Builder     string // CNB builder image used
	ImageRef    string // registry/<hall>/<beam>:<sha12>
	ImageDigest string // sha256:...
	PullRef     string // registry/<hall>/<beam>@sha256:... (what Deploy uses)
}

// Pipeline composes the managed repos and the packer into the full
// source→pinned-image path: snapshot → commit SHA → checkout → pack build
// --publish → registry digest.
type Pipeline struct {
	Repos  *Repos
	Packer *Packer
	// Logs receives build output (nil = discard). A per-call writer attached
	// with WithProgress is written to as well — that is how the MCP layer
	// streams pack output to the agent as progress notifications.
	Logs io.Writer
}

// tailBuffer keeps the last max bytes written (build-failure evidence).
type tailBuffer struct {
	max int
	buf []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.max {
		t.buf = t.buf[len(t.buf)-t.max:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string { return string(t.buf) }

type progressKey struct{}

// WithProgress attaches a per-call build log writer to the context. Build
// output is tee'd to it in addition to Pipeline.Logs; the writer must remain
// usable until the build call returns.
func WithProgress(ctx context.Context, w io.Writer) context.Context {
	return context.WithValue(ctx, progressKey{}, w)
}

// ProgressWriter returns the per-call writer attached with WithProgress, or
// nil. Exposed so other build-adjacent emitters can reuse the same channel.
func ProgressWriter(ctx context.Context) io.Writer {
	w, _ := ctx.Value(progressKey{}).(io.Writer)
	return w
}

// BuildFromDir converges srcDir into the beam's managed repo and builds the
// resulting commit. Both the git-push path and the MCP tarball path end up
// here once their transports land — they only differ in how srcDir arrives.
func (pl *Pipeline) BuildFromDir(ctx context.Context, beamhallSlug, beamSlug, srcDir string) (Result, error) {
	logs := pl.Logs
	if logs == nil {
		logs = io.Discard
	}
	if w := ProgressWriter(ctx); w != nil {
		logs = io.MultiWriter(logs, w)
	}
	repoPath, err := pl.Repos.Ensure(beamhallSlug, beamSlug)
	if err != nil {
		return Result{}, fmt.Errorf("ensure repo: %w", err)
	}
	sha, err := pl.Repos.ImportSnapshot(ctx, repoPath, srcDir, "deploy snapshot")
	if err != nil {
		return Result{}, fmt.Errorf("import snapshot: %w", err)
	}
	workDir, err := os.MkdirTemp("", "beamhall-build-*")
	if err != nil {
		return Result{}, err
	}
	defer os.RemoveAll(workDir)
	if err := pl.Repos.CheckoutTo(ctx, repoPath, sha, workDir); err != nil {
		return Result{}, fmt.Errorf("checkout %s: %w", sha, err)
	}

	return pl.buildCommit(ctx, beamhallSlug, beamSlug, repoPath, sha, logs)
}

// BuildFromCommit builds a commit that is ALREADY in the beam's managed repo
// (the git-push transport: the agent pushed the commit, this builds it). No
// snapshot import — the pushed SHA is the immutable Build.source_ref.
func (pl *Pipeline) BuildFromCommit(ctx context.Context, beamhallSlug, beamSlug, sha string) (Result, error) {
	logs := pl.Logs
	if logs == nil {
		logs = io.Discard
	}
	if w := ProgressWriter(ctx); w != nil {
		logs = io.MultiWriter(logs, w)
	}
	repoPath, err := pl.Repos.Ensure(beamhallSlug, beamSlug)
	if err != nil {
		return Result{}, fmt.Errorf("ensure repo: %w", err)
	}
	return pl.buildCommit(ctx, beamhallSlug, beamSlug, repoPath, sha, logs)
}

// buildCommit checks an existing commit out of repoPath and packs it.
func (pl *Pipeline) buildCommit(ctx context.Context, beamhallSlug, beamSlug, repoPath, sha string, logs io.Writer) (Result, error) {
	workDir, err := os.MkdirTemp("", "beamhall-build-*")
	if err != nil {
		return Result{}, err
	}
	defer os.RemoveAll(workDir)
	if err := pl.Repos.CheckoutTo(ctx, repoPath, sha, workDir); err != nil {
		return Result{}, fmt.Errorf("checkout %s: %w", sha, err)
	}

	imageRepo := beamhallSlug + "/" + beamSlug
	tag := sha[:12]
	// Keep the tail of the build output so a failure is self-contained: the
	// agent gets the evidence and a classified hint in the error itself, not
	// just in the (possibly unrequested) progress stream.
	tail := &tailBuffer{max: 4096}
	digest, err := pl.Packer.Build(ctx, imageRepo, tag, workDir, io.MultiWriter(logs, tail))
	if err != nil {
		return Result{}, errors.New(diagnose.BuildFailure(err, tail.String()))
	}
	return Result{
		SourceSHA:   sha,
		Builder:     pl.Packer.Builder,
		ImageRef:    fmt.Sprintf("%s/%s:%s", pl.Packer.Registry, imageRepo, tag),
		ImageDigest: digest,
		PullRef:     fmt.Sprintf("%s/%s@%s", pl.Packer.Registry, imageRepo, digest),
	}, nil
}
