package e2e

// Lab test for the git smart-HTTP push transport (Phase 3 item 4): the agent
// calls deploy_beam with no inline source, gets a one-time push remote, and
// `git push`es real source — the push builds and deploys the commit. Uses the
// stock git binary (proves interop beyond go-git's own client).
//
//	BEAMHALL_DOCKER_IT=1 /tmp/e2e.test -test.v -test.run TestGitPushDeploy

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGitPushDeploy(t *testing.T) {
	if os.Getenv("BEAMHALL_DOCKER_IT") != "1" {
		t.Skip("set BEAMHALL_DOCKER_IT=1 to run the git-push suite")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not available")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	a := launchAppliance(t, ctx)
	cs := a.connect("e2e-builder", "beams:write beams:deploy logs:read", nil)

	callTool(ctx, t, cs, "create_beam",
		map[string]any{"beamhall": "e2e", "slug": "gitpush", "runtime_hint": "node"}, false)

	// deploy_beam with no source → a push command carrying a one-time token.
	_, instr := callTool(ctx, t, cs, "deploy_beam",
		map[string]any{"beamhall": "e2e", "beam": "gitpush"}, false)
	pushURL := extractPushURL(t, instr)

	// Build a tiny Node app and push it with the stock git client.
	src := t.TempDir()
	writeFiles(t, src, map[string]string{
		"package.json": `{ "name": "gitpush", "version": "1.0.0", "main": "app.js", "scripts": { "start": "node app.js" } }`,
		"app.js":       `require("http").createServer((q,s)=>{s.setHeader("content-type","application/json");s.end(JSON.stringify({ok:true,via:"git-push"}))}).listen(process.env.PORT||8080);`,
	})
	runGit(t, src, "init", "-q")
	runGit(t, src, "-c", "user.email=a@b", "-c", "user.name=a", "add", ".")
	runGit(t, src, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "-m", "app")
	out, err := gitPush(t, src, pushURL)
	t.Logf("git push output:\n%s", out)
	if err != nil {
		t.Fatalf("git push failed: %v", err)
	}
	if !strings.Contains(out, "remote:") {
		t.Errorf("no sideband progress in push output")
	}
	// The build progress and the preview URL come back as "remote:" lines.
	url := extractDeployedURL(t, out)
	if body := curlHost(t, url, 200); !strings.Contains(body, `"via":"git-push"`) {
		t.Fatalf("git-pushed beam not serving: %s", body)
	}
}

// extractDeployedURL reads the "remote: deployed; reachable at <url>" sideband
// line git printed during the push.
func extractDeployedURL(t *testing.T, pushOut string) string {
	t.Helper()
	const marker = "reachable at "
	i := strings.Index(pushOut, marker)
	if i < 0 {
		t.Fatalf("push output has no deployed URL:\n%s", pushOut)
	}
	rest := pushOut[i+len(marker):]
	end := strings.IndexAny(rest, " \n\r")
	if end < 0 {
		end = len(rest)
	}
	return strings.TrimSpace(rest[:end])
}

// extractPushURL pulls the `git push https://x-access-token:...@.../...git ...`
// remote (with embedded token) out of the deploy_beam instructions.
func extractPushURL(t *testing.T, instr string) string {
	t.Helper()
	const prefix = "git push "
	i := strings.Index(instr, prefix)
	if i < 0 {
		t.Fatalf("no push command in deploy_beam output:\n%s", instr)
	}
	rest := instr[i+len(prefix):]
	if j := strings.Index(rest, " HEAD:main"); j >= 0 {
		return strings.TrimSpace(rest[:j])
	}
	t.Fatalf("malformed push command:\n%s", instr)
	return ""
}

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func gitPush(t *testing.T, dir, pushURL string) (string, error) {
	t.Helper()
	// pushURL is "https://x-access-token:TOK@host/git/h/b.git HEAD:main" — split
	// the remote from the refspec.
	parts := strings.Fields(pushURL)
	remote := parts[0]
	refspec := "HEAD:main"
	if len(parts) > 1 {
		refspec = parts[1]
	}
	cmd := exec.Command("git", "-c", "http.sslVerify=false", "push", remote, refspec)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}
