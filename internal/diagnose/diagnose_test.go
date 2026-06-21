package diagnose

import (
	"errors"
	"strings"
	"testing"
)

func TestBuildSignatures(t *testing.T) {
	cases := []struct {
		name, output, want string
	}{
		{"no detection", "===> DETECTING\nERROR: No buildpack groups passed detection.", "package.json"},
		{"npm failure", "npm ERR! code E404\nnpm ERR! 404 Not Found - GET https://registry.npmjs.org/left-pad-x", "package.json is valid"},
		{"pip failure", "ERROR: Could not find a version that satisfies the requirement flask==99", "requirements.txt"},
		{"timeout", "building...\ncontext deadline exceeded", "time limit"},
		{"network", "Get \"https://example.test\": dial tcp: i/o timeout", "network dependency"},
		{"unknown", "some novel failure", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Build(tc.output)
			if tc.want == "" && got != "" {
				t.Fatalf("unexpected hint: %s", got)
			}
			if !strings.Contains(got, tc.want) {
				t.Fatalf("hint %q does not mention %q", got, tc.want)
			}
		})
	}
}

func TestRunSignatures(t *testing.T) {
	cases := []struct {
		name, logs, want string
	}{
		{"read-only rootfs", "Error: EROFS: read-only file system, open '/app/data.json'", "/tmp"},
		{"privileged bind", "Error: listen EACCES: permission denied 0.0.0.0:80", "PORT environment variable"},
		{"double bind", "Error: listen EADDRINUSE: address already in use :::8080", "once"},
		{"missing secret", "Error: ENOENT: no such file or directory, open '/run/secrets/MAIN_URL'", "set_secret or create_database"},
		{"oom node", "FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory", "memory ceiling"},
		{"egress dns", "Error: getaddrinfo EAI_AGAIN api.stripe.com", "DENIED BY DEFAULT"},
		{"egress timeout", "Error: connect ETIMEDOUT 140.82.112.3:443", "DENIED BY DEFAULT"},
		{"egress fetch abort", "egress blocked: http://1.1.1.1/ (TimeoutError)", "DENIED BY DEFAULT"},
		{"capability", "mount: operation not permitted", "capability"},
		{"clean logs", "Server listening on 8080", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Run(tc.logs)
			if tc.want == "" && got != "" {
				t.Fatalf("unexpected hint: %s", got)
			}
			if !strings.Contains(got, tc.want) {
				t.Fatalf("hint %q does not mention %q", got, tc.want)
			}
		})
	}
}

func TestStartFailureComposition(t *testing.T) {
	code := 1
	msg := StartFailure(&code, "Error: EROFS: read-only file system, open '/app/x'")
	for _, want := range []string{"exited during startup with code 1", "Likely cause:", "/tmp", "last log lines", "EROFS"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in:\n%s", want, msg)
		}
	}

	// Exit-code fallback when logs are silent.
	oom := 137
	msg = StartFailure(&oom, "")
	if !strings.Contains(msg, "OOM") {
		t.Errorf("exit 137 not named: %s", msg)
	}
	if strings.Contains(msg, "last log lines") {
		t.Errorf("empty tail must not add a log section: %s", msg)
	}

	c127 := 127
	if msg := StartFailure(&c127, "sh: not found"); !strings.Contains(msg, `"start" script`) {
		t.Errorf("exit 127: %s", msg)
	}
}

func TestBuildFailureComposition(t *testing.T) {
	msg := BuildFailure(errors.New("pack build x: exit status 1"),
		"===> DETECTING\nERROR: No buildpack groups passed detection.")
	for _, want := range []string{"the build failed", "exit status 1", "package.json", "end of build output"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in:\n%s", want, msg)
		}
	}
}
