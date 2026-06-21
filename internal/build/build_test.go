package build

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5"
)

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReposSnapshotAndCheckout(t *testing.T) {
	ctx := context.Background()
	repos := NewRepos(filepath.Join(t.TempDir(), "repos"))

	p1, err := repos.Ensure("ops", "tracker")
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	p2, err := repos.Ensure("ops", "tracker")
	if err != nil || p2 != p1 {
		t.Fatalf("Ensure not idempotent: %q vs %q (%v)", p1, p2, err)
	}

	src := t.TempDir()
	writeTree(t, src, map[string]string{
		"app.js":           "console.log('v1')",
		"package.json":     `{"name":"tracker"}`,
		"lib/util.js":      "module.exports = 1",
		"scripts/start.sh": "#!/bin/sh\necho hi\n",
	})
	if err := os.Chmod(filepath.Join(src, "scripts/start.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("app.js", filepath.Join(src, "main.js")); err != nil {
		t.Fatal(err)
	}

	sha1, err := repos.ImportSnapshot(ctx, p1, src, "first")
	if err != nil {
		t.Fatalf("ImportSnapshot: %v", err)
	}
	if len(sha1) != 40 {
		t.Fatalf("sha = %q", sha1)
	}

	// Same content again: new commit (parented), still importable.
	sha2, err := repos.ImportSnapshot(ctx, p1, src, "second")
	if err != nil {
		t.Fatalf("ImportSnapshot again: %v", err)
	}
	if sha2 == sha1 {
		t.Fatal("second snapshot reused the first commit")
	}

	// Changed content → checkout of each SHA yields its own version.
	writeTree(t, src, map[string]string{"app.js": "console.log('v2')"})
	sha3, err := repos.ImportSnapshot(ctx, p1, src, "third")
	if err != nil {
		t.Fatal(err)
	}

	for sha, want := range map[string]string{sha1: "console.log('v1')", sha3: "console.log('v2')"} {
		dst := t.TempDir()
		if err := repos.CheckoutTo(ctx, p1, sha, dst); err != nil {
			t.Fatalf("CheckoutTo(%s): %v", sha, err)
		}
		got, err := os.ReadFile(filepath.Join(dst, "app.js"))
		if err != nil || string(got) != want {
			t.Fatalf("app.js @%s = %q (err %v), want %q", sha[:8], got, err, want)
		}
		if _, err := os.Stat(filepath.Join(dst, "lib/util.js")); err != nil {
			t.Fatalf("nested file missing: %v", err)
		}
		info, err := os.Stat(filepath.Join(dst, "scripts/start.sh"))
		if err != nil || info.Mode()&0o111 == 0 {
			t.Fatalf("executable bit lost: %v %v", info, err)
		}
		link, err := os.Readlink(filepath.Join(dst, "main.js"))
		if err != nil || link != "app.js" {
			t.Fatalf("symlink = %q (err %v)", link, err)
		}
	}
}

func TestRetireFreesSlugForFreshRepo(t *testing.T) {
	ctx := context.Background()
	repos := NewRepos(filepath.Join(t.TempDir(), "repos"))

	// A beam with committed history, then retired.
	p, err := repos.Ensure("ops", "tracker")
	if err != nil {
		t.Fatal(err)
	}
	src := t.TempDir()
	writeTree(t, src, map[string]string{"app.js": "v1"})
	sha, err := repos.ImportSnapshot(ctx, p, src, "v1")
	if err != nil {
		t.Fatal(err)
	}
	if err := repos.Retire("ops", "tracker", "beam-1"); err != nil {
		t.Fatalf("Retire: %v", err)
	}

	// Reusing the slug yields a FRESH, empty repo (no inherited history).
	p2, err := repos.Ensure("ops", "tracker")
	if err != nil {
		t.Fatal(err)
	}
	r, err := git.PlainOpen(p2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reference("refs/heads/main", false); err == nil {
		t.Fatal("reused slug inherited a main ref; expected a fresh empty repo")
	}
	// The retired source is preserved (not deleted).
	if _, err := os.Stat(filepath.Join(repos.root, "ops", ".retired", "tracker-beam-1.git")); err != nil {
		t.Fatalf("retired repo not preserved: %v", err)
	}
	_ = sha

	// Retiring an absent repo is a no-op.
	if err := repos.Retire("ops", "nope", "x"); err != nil {
		t.Fatalf("Retire(absent) = %v, want nil", err)
	}
}

func TestImportSnapshotEmptyDirFails(t *testing.T) {
	repos := NewRepos(t.TempDir())
	p, err := repos.Ensure("ops", "empty")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repos.ImportSnapshot(context.Background(), p, t.TempDir(), "x"); err == nil {
		t.Fatal("empty source dir must fail")
	}
}

// fakePack writes a script that records its argv and env, standing in for the
// pack CLI.
func fakePack(t *testing.T, capture string) string {
	t.Helper()
	script := filepath.Join(t.TempDir(), "pack")
	body := fmt.Sprintf("#!/bin/sh\n{ echo \"args:$@\"; echo \"dockerhost:$DOCKER_HOST\"; } > %s\n", capture)
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return script
}

func fakeRegistry(t *testing.T, digest string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/manifests/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Docker-Content-Digest", digest)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return u.Host
}

func TestPackerInvocationAndDigest(t *testing.T) {
	const digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	capture := filepath.Join(t.TempDir(), "capture")
	registry := fakeRegistry(t, digest)

	p := &Packer{
		PackBin:    fakePack(t, capture),
		DockerHost: "unix:///run/docker-build.sock",
		Builder:    "paketobuildpacks/builder-jammy-base",
		Registry:   registry,
	}
	var logs bytes.Buffer
	got, err := p.Build(context.Background(), "ops/tracker", "abc123def456", t.TempDir(), &logs)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got != digest {
		t.Fatalf("digest = %q", got)
	}

	rec, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	s := string(rec)
	for _, want := range []string{
		"build " + registry + "/ops/tracker:abc123def456",
		"--publish",
		"--network host",
		"--trust-builder",
		"--builder paketobuildpacks/builder-jammy-base",
		"dockerhost:unix:///run/docker-build.sock",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("pack invocation missing %q:\n%s", want, s)
		}
	}
}

func TestPipelineBuildFromDir(t *testing.T) {
	const digest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	registry := fakeRegistry(t, digest)
	pl := &Pipeline{
		Repos: NewRepos(filepath.Join(t.TempDir(), "repos")),
		Packer: &Packer{
			PackBin:  fakePack(t, filepath.Join(t.TempDir(), "capture")),
			Builder:  "paketobuildpacks/builder-jammy-base",
			Registry: registry,
		},
	}
	src := t.TempDir()
	writeTree(t, src, map[string]string{"app.js": "x", "package.json": "{}"})

	res, err := pl.BuildFromDir(context.Background(), "ops", "tracker", src)
	if err != nil {
		t.Fatalf("BuildFromDir: %v", err)
	}
	if len(res.SourceSHA) != 40 {
		t.Fatalf("SourceSHA = %q", res.SourceSHA)
	}
	wantRef := registry + "/ops/tracker:" + res.SourceSHA[:12]
	if res.ImageRef != wantRef {
		t.Fatalf("ImageRef = %q, want %q", res.ImageRef, wantRef)
	}
	if res.ImageDigest != digest || res.PullRef != registry+"/ops/tracker@"+digest {
		t.Fatalf("digest/pullref = %q / %q", res.ImageDigest, res.PullRef)
	}
}

// TestPackerAirgapArgs: an air-gapped Packer passes --pull-policy and
// --run-image so pack uses the pre-mirrored builder/run images.
func TestPackerAirgapArgs(t *testing.T) {
	const digest = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	capture := filepath.Join(t.TempDir(), "capture")
	registry := fakeRegistry(t, digest)
	p := &Packer{
		PackBin:    fakePack(t, capture),
		DockerHost: "unix:///run/docker-build.sock",
		Builder:    registry + "/paketo/builder-jammy-base:1",
		Registry:   registry,
		PullPolicy: "if-not-present",
		RunImage:   registry + "/paketo/run-jammy-base:1",
	}
	var logs bytes.Buffer
	if _, err := p.Build(context.Background(), "ops/tracker", "abc", t.TempDir(), &logs); err != nil {
		t.Fatalf("Build: %v", err)
	}
	rec, _ := os.ReadFile(capture)
	for _, want := range []string{"--pull-policy if-not-present", "--run-image " + registry + "/paketo/run-jammy-base:1"} {
		if !strings.Contains(string(rec), want) {
			t.Fatalf("pack invocation missing %q:\n%s", want, rec)
		}
	}
}

// Default (non-air-gap) Packer must NOT add pull-policy/run-image flags.
func TestPackerDefaultNoAirgapArgs(t *testing.T) {
	const digest = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
	capture := filepath.Join(t.TempDir(), "capture")
	registry := fakeRegistry(t, digest)
	p := &Packer{PackBin: fakePack(t, capture), Builder: "b", Registry: registry}
	var logs bytes.Buffer
	p.Build(context.Background(), "ops/tracker", "abc", t.TempDir(), &logs)
	rec, _ := os.ReadFile(capture)
	if strings.Contains(string(rec), "--pull-policy") || strings.Contains(string(rec), "--run-image") {
		t.Fatalf("default build should not add air-gap flags:\n%s", rec)
	}
}
