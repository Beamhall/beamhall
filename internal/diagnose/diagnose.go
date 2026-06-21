// Package diagnose turns infrastructure failures into messages an AI agent
// can act on (PLAN §8 Phase 3 — the "#1 underestimated item"). The hardening
// stack deliberately breaks naive workloads: read-only rootfs, dropped
// capabilities, default-deny egress, cgroup ceilings. A raw "exit status 1"
// teaches the agent nothing; these classifiers read the failure's own
// evidence (build output, log tail, exit code) and name the constraint that
// fired plus the concrete next step. Everything here is pure string
// classification — callers scrub log material BEFORE passing it in.
package diagnose

import (
	"fmt"
	"regexp"
	"strings"
)

// signature maps a failure's textual evidence to an actionable hint.
type signature struct {
	re   *regexp.Regexp
	hint string
}

// buildSignatures classify `pack` output. Order matters: first match wins.
var buildSignatures = []signature{
	{regexp.MustCompile(`(?i)no buildpack groups passed detection|failed to detect`),
		"no supported app was detected in the source. Buildpacks need a recognizable project root: package.json (Node.js), requirements.txt/pyproject.toml (Python), or a static site. Dockerfiles are ignored by design — do not add one; add the project manifest instead."},
	{regexp.MustCompile(`(?i)npm (ERR!|error)|npm install.*failed`),
		"npm install failed inside the build. Check that package.json is valid and every dependency exists at the pinned version; the build has no access to private registries."},
	{regexp.MustCompile(`(?i)pip (install )?error|could not find a version that satisfies`),
		"pip could not resolve the dependencies. Check requirements.txt for typos and versions that exist on PyPI; the build has no access to private indexes."},
	{regexp.MustCompile(`(?i)context deadline exceeded|signal: killed`),
		"the build exceeded its time limit. Trim heavy build steps (large dependency trees, asset compilation) or split the beam."},
	{regexp.MustCompile(`(?i)connection refused|i/o timeout|TLS handshake timeout|no such host`),
		"the build could not reach a network dependency. Builds may fetch public packages but nothing else; vendor anything unusual into the source."},
}

// runSignatures classify a workload's log tail after a startup crash or for
// log inspection. First match wins.
var runSignatures = []signature{
	{regexp.MustCompile(`(?i)EROFS|read-only file system`),
		"the workload tried to write to its filesystem, which is read-only by policy. Write only under /tmp (tmpfs), or keep state in the beam's database (create_database)."},
	{regexp.MustCompile(`(?i)(listen|bind)\w* EACCES|EACCES.*(listen|bind|port)|permission denied.*(listen|bind|port)`),
		"the workload may not bind that port. Listen on the port in the PORT environment variable (plain HTTP; TLS terminates at the gateway)."},
	{regexp.MustCompile(`(?i)EADDRINUSE`),
		"the port is already taken inside the container — the app is probably binding a hardcoded port AND $PORT. Bind only the PORT environment variable, once."},
	{regexp.MustCompile(`(?i)ENOENT.*(/run/secrets/[A-Za-z0-9_]+)`),
		"the workload reads a secret file that does not exist. Create it first (set_secret or create_database), then redeploy — secrets are mounted under /run/secrets/<KEY> at deploy time."},
	{regexp.MustCompile(`(?i)JavaScript heap out of memory|OOMKilled|Out of memory`),
		"the workload exceeded its memory ceiling (set by IT, immutable to agents). Reduce memory use; if genuinely undersized, ask IT to raise the beamhall quota."},
	{regexp.MustCompile(`(?i)ETIMEDOUT|EAI_AGAIN|getaddrinfo|ENETUNREACH|TimeoutError|UND_ERR_CONNECT_TIMEOUT|fetch failed|connect ECONNREFUSED \d+\.\d+\.\d+\.\d+:(80|443)`),
		"an outbound connection failed: egress is DENIED BY DEFAULT for every beam. Internal dependencies live on the beam's own network (e.g. its database via /run/secrets/<NAME>_URL); anything external needs an IT-approved allowlist entry."},
	{regexp.MustCompile(`(?i)EPERM|operation not permitted`),
		"the operation needs a capability this workload does not have — the hardening baseline drops all capabilities and cannot be changed from here. Restructure the app to avoid it (no raw sockets, no mounts, no setuid)."},
}

// exitHints name well-known exit codes when the logs alone say nothing.
var exitHints = map[int]string{
	125: "the container runtime refused the configuration",
	126: "the start command exists but is not executable",
	127: "the start command was not found — for Node, package.json needs a \"start\" script (or a server.js/index.js entrypoint)",
	137: "the workload was killed (SIGKILL) — usually the memory ceiling (OOM). Reduce memory use or ask IT to raise the quota",
	139: "the workload crashed with a segmentation fault",
	143: "the workload was terminated (SIGTERM) without shutting down",
}

// Build classifies pack output and returns an actionable hint ("" if the
// output matches nothing known).
func Build(output string) string {
	for _, s := range buildSignatures {
		if s.re.MatchString(output) {
			return s.hint
		}
	}
	return ""
}

// Run classifies a workload log tail ("" if nothing matches).
func Run(logTail string) string {
	for _, s := range runSignatures {
		if s.re.MatchString(logTail) {
			return s.hint
		}
	}
	return ""
}

// Exit names an exit code ("" for unremarkable codes).
func Exit(code int) string { return exitHints[code] }

// StartFailure composes the agent-facing message for a workload that died
// during startup: what happened, why (best classification), and the evidence.
// logTail must already be scrubbed.
func StartFailure(exitCode *int, logTail string) string {
	var b strings.Builder
	b.WriteString("the workload exited during startup")
	if exitCode != nil {
		fmt.Fprintf(&b, " with code %d", *exitCode)
	}
	hint := Run(logTail)
	if hint == "" && exitCode != nil {
		hint = Exit(*exitCode)
	}
	if hint != "" {
		b.WriteString(". Likely cause: ")
		b.WriteString(hint)
	}
	if tail := strings.TrimSpace(logTail); tail != "" {
		b.WriteString("\n--- last log lines (sanitized) ---\n")
		b.WriteString(tail)
	}
	return b.String()
}

// BuildFailure composes the agent-facing message for a failed build.
// outputTail is the end of the pack output (already streamed as progress;
// repeated here so the error itself is self-contained).
func BuildFailure(cause error, outputTail string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "the build failed: %v", cause)
	if hint := Build(outputTail); hint != "" {
		b.WriteString(". Likely cause: ")
		b.WriteString(hint)
	}
	if tail := strings.TrimSpace(outputTail); tail != "" {
		b.WriteString("\n--- end of build output ---\n")
		b.WriteString(tail)
	}
	return b.String()
}
