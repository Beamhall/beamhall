package gitserver

import (
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/storage/memory"

	"github.com/Beamhall/beamhall/internal/build"
	"github.com/Beamhall/beamhall/internal/domain"
)

type fakeDir struct{}

func (fakeDir) GetBeamhallBySlug(ctx context.Context, slug string) (domain.Beamhall, error) {
	if slug != "ops" {
		return domain.Beamhall{}, errNotFound
	}
	return domain.Beamhall{ID: "hall-1", Slug: "ops"}, nil
}
func (fakeDir) GetBeamBySlug(ctx context.Context, bh domain.ID, slug string) (domain.Beam, error) {
	if slug != "tracker" {
		return domain.Beam{}, errNotFound
	}
	return domain.Beam{ID: "beam-1", BeamhallID: bh, Slug: slug}, nil
}

var errNotFound = errNF{}

type errNF struct{}

func (errNF) Error() string { return "not found" }

// pushSource makes a tiny repo and pushes its main branch to remoteURL with
// the given basic-auth password (the deploy token).
func pushSource(t *testing.T, remoteURL, token string, files map[string]string) (sha string, err error) {
	return pushSourceProgress(t, remoteURL, token, files, io.Discard)
}

// pushSourceProgress is pushSource with the sideband progress writer exposed.
func pushSourceProgress(t *testing.T, remoteURL, token string, files map[string]string, progress io.Writer) (string, error) {
	t.Helper()
	repo, err := git.Init(memory.NewStorage(), memfs.New())
	if err != nil {
		t.Fatal(err)
	}
	wt, _ := repo.Worktree()
	for name, content := range files {
		f, _ := wt.Filesystem.Create(name)
		f.Write([]byte(content))
		f.Close()
		wt.Add(name)
	}
	h, err := wt.Commit("snapshot", &git.CommitOptions{Author: &object.Signature{Name: "a", Email: "a@x", When: time.Unix(1700000000, 0)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateRemote(&config.RemoteConfig{Name: "origin", URLs: []string{remoteURL}}); err != nil {
		t.Fatal(err)
	}
	err = repo.Push(&git.PushOptions{
		RemoteName: "origin",
		RefSpecs:   []config.RefSpec{"refs/heads/master:refs/heads/main"},
		Auth:       &http.BasicAuth{Username: "x-access-token", Password: token},
		Progress:   progress,
	})
	return h.String(), err
}

func TestPushTriggersDeploy(t *testing.T) {
	tokens := NewTokenStore(time.Minute)
	var (
		mu        sync.Mutex
		gotSHA    string
		gotPrinc  Principal
		gotSource string
	)
	deploy := func(ctx context.Context, p Principal, sha string, progress io.Writer) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		gotSHA, gotPrinc = sha, p
		// Read back what was pushed by checking out via build.Repos.
		io.WriteString(progress, "===> BUILDING\n")
		return "https://tracker.preview.test", nil
	}
	root := t.TempDir()
	// Pre-create the bare repo so the loader finds it.
	repos := build.NewRepos(root)
	if _, err := repos.Ensure("ops", "tracker"); err != nil {
		t.Fatal(err)
	}
	svc := New(root, fakeDir{}, tokens, deploy, nil, nil)
	ts := httptest.NewServer(svc.Handler())
	defer ts.Close()

	tok, _ := tokens.Mint("hall-1", "beam-1", "actor-1")
	remote := ts.URL + "/git/ops/tracker.git"
	var prog strings.Builder
	sha, err := pushSourceProgress(t, remote, tok, map[string]string{"app.js": "console.log(1)", "package.json": "{}"}, &prog)
	if err != nil {
		t.Fatalf("push: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotSHA != sha {
		t.Errorf("deploy SHA = %q, pushed %q", gotSHA, sha)
	}
	if gotPrinc.Beam != "beam-1" || gotPrinc.Actor != "actor-1" {
		t.Errorf("principal = %+v", gotPrinc)
	}
	if !strings.Contains(prog.String(), "BUILDING") {
		t.Errorf("sideband progress not delivered to client: %q", prog.String())
	}
	_ = gotSource

	// Token is one-time: a second push with the same token is refused.
	if _, err := pushSource(t, remote, tok, map[string]string{"app.js": "x"}); err == nil {
		t.Error("reused deploy token accepted")
	}
}

// A FAILED build must NOT consume the one-time push token: the user fixes
// their code and re-pushes the same command (the commit is already on main).
// Consuming it on failure is what spiralled agents into 403 → re-init →
// divergent-history (lab finding).
func TestFailedDeployKeepsTokenValid(t *testing.T) {
	tokens := NewTokenStore(time.Minute)
	root := t.TempDir()
	if _, err := build.NewRepos(root).Ensure("ops", "tracker"); err != nil {
		t.Fatal(err)
	}
	deploy := func(context.Context, Principal, string, io.Writer) (string, error) {
		return "", errors.New("build failed: incompatible node version")
	}
	svc := New(root, fakeDir{}, tokens, deploy, nil, nil)
	ts := httptest.NewServer(svc.Handler())
	defer ts.Close()

	tok, _ := tokens.Mint("hall-1", "beam-1", "actor-1")
	remote := ts.URL + "/git/ops/tracker.git"
	// The push reports failure (build failed), but the token must survive.
	_, _ = pushSource(t, remote, tok, map[string]string{"app.js": "boom"})
	if _, ok := tokens.Validate("hall-1", "beam-1", tok); !ok {
		t.Fatal("one-time token was consumed on a FAILED deploy; it must stay valid for a fix-and-retry")
	}
}

func TestPushRejectsBadToken(t *testing.T) {
	tokens := NewTokenStore(time.Minute)
	root := t.TempDir()
	build.NewRepos(root).Ensure("ops", "tracker")
	svc := New(root, fakeDir{}, tokens, func(context.Context, Principal, string, io.Writer) (string, error) {
		t.Fatal("deploy called despite bad token")
		return "", nil
	}, nil, nil)
	ts := httptest.NewServer(svc.Handler())
	defer ts.Close()

	_, err := pushSource(t, ts.URL+"/git/ops/tracker.git", "wrong-token", map[string]string{"x": "y"})
	if err == nil {
		t.Fatal("push with invalid token succeeded")
	}
}

func TestUnknownRepo404(t *testing.T) {
	tokens := NewTokenStore(time.Minute)
	root := t.TempDir()
	svc := New(root, fakeDir{}, tokens, nil, nil, nil)
	ts := httptest.NewServer(svc.Handler())
	defer ts.Close()
	tok, _ := tokens.Mint("hall-1", "ghost", "a")
	if _, err := pushSource(t, ts.URL+"/git/ops/ghost.git", tok, map[string]string{"x": "y"}); err == nil {
		t.Fatal("push to unknown beam succeeded")
	}
}

func TestTokenStoreLifecycle(t *testing.T) {
	s := NewTokenStore(time.Minute)
	tok, _ := s.Mint("h", "b", "actor")
	if _, ok := s.Validate("h", "b", "nope"); ok {
		t.Error("wrong token validated")
	}
	if _, ok := s.Validate("h", "other", tok); ok {
		t.Error("token validated for a different beam")
	}
	p, ok := s.Validate("h", "b", tok)
	if !ok || p.Actor != "actor" {
		t.Fatalf("validate = %v %+v", ok, p)
	}
	if !s.Claim(p) {
		t.Fatal("claim failed on a freshly validated grant")
	}
	if _, ok := s.Validate("h", "b", tok); ok {
		t.Error("claimed token still valid")
	}
}

// TestConcurrentClaimOnlyOneSucceeds proves the fix directly: two
// concurrent receive-pack requests presenting the identical valid token both
// pass Validate (it has no side effects), but only one Claim call for that
// grant can ever succeed — the other must be refused before it would have
// started a second, redundant build/deploy.
func TestConcurrentClaimOnlyOneSucceeds(t *testing.T) {
	s := NewTokenStore(time.Minute)
	tok, _ := s.Mint("h", "b", "actor")

	// Both requests independently validate first, exactly as info/refs then
	// receive-pack (or two genuinely concurrent pushes) would.
	p1, ok1 := s.Validate("h", "b", tok)
	p2, ok2 := s.Validate("h", "b", tok)
	if !ok1 || !ok2 {
		t.Fatalf("both concurrent validations should succeed: %v %v", ok1, ok2)
	}

	var wg sync.WaitGroup
	results := make([]bool, 2)
	wg.Add(2)
	go func() { defer wg.Done(); results[0] = s.Claim(p1) }()
	go func() { defer wg.Done(); results[1] = s.Claim(p2) }()
	wg.Wait()

	if results[0] == results[1] {
		t.Fatalf("exactly one concurrent claim must succeed, got %v and %v", results[0], results[1])
	}
}

// TestClaimActsOnCapturedGrantNotAFreshMint proves the fix: Claim (and
// Unclaim) act on the EXACT grant Validate returned, not a fresh
// (beamhall,beam) map lookup. Pre-fix, Consume looked the grant up by key —
// so if a push's deploy took long enough that the agent re-minted a fresh
// token for the same beam before the OLD push finished, the old push's
// post-deploy consumption would find and invalidate the NEW grant instead
// (it "currently occupies the key"), killing a token before it was ever used.
func TestClaimActsOnCapturedGrantNotAFreshMint(t *testing.T) {
	s := NewTokenStore(time.Minute)
	oldTok, _ := s.Mint("h", "b", "actor-1")
	p, ok := s.Validate("h", "b", oldTok)
	if !ok {
		t.Fatal("validate on the original grant failed")
	}

	// A re-mint mid-deploy (e.g. the agent requested a fresh push command
	// while the old push's deploy was still running) replaces the
	// (beamhall,beam) slot with a brand new grant.
	newTok, _ := s.Mint("h", "b", "actor-2")

	// The original (now stale, no longer in the map) push's deploy succeeds;
	// it claims its OWN captured grant.
	if !s.Claim(p) {
		t.Fatal("claim on the original grant failed")
	}

	// The freshly minted token must be completely unaffected — still valid,
	// never touched by the old push's claim.
	if _, ok := s.Validate("h", "b", newTok); !ok {
		t.Fatal("claiming a stale grant invalidated the freshly re-minted token before it was ever used")
	}
}

func TestTokenExpiry(t *testing.T) {
	s := NewTokenStore(time.Minute)
	now := time.Unix(1700000000, 0)
	s.now = func() time.Time { return now }
	tok, _ := s.Mint("h", "b", "a")
	now = now.Add(2 * time.Minute)
	if _, ok := s.Validate("h", "b", tok); ok {
		t.Error("expired token validated")
	}
}

func TestParsePath(t *testing.T) {
	cases := map[string][3]string{
		"/git/ops/tracker.git/info/refs":        {"ops", "tracker", "info/refs"},
		"/git/ops/tracker.git/git-receive-pack": {"ops", "tracker", "git-receive-pack"},
	}
	for in, want := range cases {
		h, b, rest, ok := parsePath(in)
		if !ok || h != want[0] || b != want[1] || rest != want[2] {
			t.Errorf("parsePath(%q) = %q %q %q %v", in, h, b, rest, ok)
		}
	}
	if _, _, _, ok := parsePath("/git/bad"); ok {
		t.Error("malformed path accepted")
	}
}

func TestServeNoLog(t *testing.T) {
	// New with nil logger must not panic.
	_ = New(t.TempDir(), fakeDir{}, NewTokenStore(0), nil, nil, nil)
	_ = strings.TrimSpace("")
}

// cloneSource clones remoteURL with the given read token and returns the
// working tree's top-level files.
func cloneSource(t *testing.T, remoteURL, token string) (map[string]string, error) {
	t.Helper()
	fs := memfs.New()
	repo, err := git.Clone(memory.NewStorage(), fs, &git.CloneOptions{
		URL:  remoteURL,
		Auth: &http.BasicAuth{Username: "x-access-token", Password: token},
	})
	if err != nil {
		return nil, err
	}
	wt, err := repo.Worktree()
	if err != nil {
		return nil, err
	}
	infos, err := wt.Filesystem.ReadDir("/")
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, fi := range infos {
		if fi.IsDir() {
			continue
		}
		f, err := wt.Filesystem.Open(fi.Name())
		if err != nil {
			return nil, err
		}
		b, _ := io.ReadAll(f)
		f.Close()
		out[fi.Name()] = string(b)
	}
	return out, nil
}

func TestCloneWithReadToken(t *testing.T) {
	tokens := NewTokenStore(time.Minute)
	root := t.TempDir()
	if _, err := build.NewRepos(root).Ensure("ops", "tracker"); err != nil {
		t.Fatal(err)
	}
	deploy := func(context.Context, Principal, string, io.Writer) (string, error) {
		return "https://tracker.preview.test", nil
	}
	svc := New(root, fakeDir{}, tokens, deploy, nil, nil)
	ts := httptest.NewServer(svc.Handler())
	defer ts.Close()
	remote := ts.URL + "/git/ops/tracker.git"

	// Seed the repo with a push.
	ptok, _ := tokens.Mint("hall-1", "beam-1", "actor-1")
	files := map[string]string{"app.js": "console.log(1)", "package.json": "{}"}
	if _, err := pushSource(t, remote, ptok, files); err != nil {
		t.Fatalf("push: %v", err)
	}

	// Clone it back with a read token.
	rtok, _ := tokens.MintRead("hall-1", "beam-1", "actor-1")
	got, err := cloneSource(t, remote, rtok)
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	for name, want := range files {
		if got[name] != want {
			t.Errorf("clone[%s] = %q, want %q", name, got[name], want)
		}
	}

	// Read tokens are reusable (a sync clone later must still work).
	if _, err := cloneSource(t, remote, rtok); err != nil {
		t.Errorf("read token not reusable: %v", err)
	}

	// Kinds don't cross: a push token can't clone, a read token can't push.
	freshPush, _ := tokens.Mint("hall-1", "beam-1", "actor-1")
	if _, err := cloneSource(t, remote, freshPush); err == nil {
		t.Error("push token accepted for clone")
	}
	if _, err := pushSource(t, remote, rtok, map[string]string{"x": "y"}); err == nil {
		t.Error("read token accepted for push")
	}
}

func TestReadTokenStore(t *testing.T) {
	s := NewTokenStore(time.Minute)
	rtok, _ := s.MintRead("h", "b", "actor")
	if _, ok := s.ValidateRead("h", "b", rtok); !ok {
		t.Fatal("read token not valid")
	}
	// Reusable within TTL (clone = info/refs + upload-pack).
	if _, ok := s.ValidateRead("h", "b", rtok); !ok {
		t.Error("read token not reusable")
	}
	// A read token is not a push token, and vice-versa.
	if _, ok := s.Validate("h", "b", rtok); ok {
		t.Error("read token validated as push")
	}
	ptok, _ := s.Mint("h", "b", "actor")
	if _, ok := s.ValidateRead("h", "b", ptok); ok {
		t.Error("push token validated as read")
	}
	// Claiming the push token must not kill the read token.
	pp, ok := s.Validate("h", "b", ptok)
	if !ok || !s.Claim(pp) {
		t.Fatal("claim failed on a freshly validated push grant")
	}
	if _, ok := s.ValidateRead("h", "b", rtok); !ok {
		t.Error("read token died when push token was claimed")
	}
}
