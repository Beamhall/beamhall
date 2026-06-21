package secret

import (
	"strings"
	"testing"
)

func TestHeuristicScrubRedacts(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"PEM private key", "config dump:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\nlines\n-----END RSA PRIVATE KEY-----\ndone"},
		{"OpenSSH key", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA==\n-----END OPENSSH PRIVATE KEY-----"},
		{"JWT", "auth header was Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6InJzYS0xIn0.eyJzdWIiOiJ1c2VyLTEiLCJleHAiOjk5OTl9.sig-bytes_here123 ok"},
		{"AWS key id", "using AKIAIOSFODNN7EXAMPLE for s3"},
		{"OpenAI-style", "key sk-proj1234567890abcdefGHIJ in env"},
		{"GitHub PAT", "cloning with ghp_abcdefghijklmnopqrst123456"},
		{"Slack token", "posted via xoxb-1234567890-abcdefghij"},
		{"age identity", "loaded AGE-SECRET-KEY-1QQPGZV9XGRPDQ5XGZ9QYR5DASHV3OMG6PJW4GZ9QYR5DASHV3OMG"},
		{"URL credentials", "dialing postgres://app_rw:supersecretpw@db:5432/app"},
		{"high-entropy base64", "token=dGhpcyBpcyBhIHNlY3JldCB0b2tlbiE+PT0/PyEh printed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := string(heuristicScrub([]byte(tc.in)))
			if !strings.Contains(out, Mask) {
				t.Fatalf("nothing redacted:\n%s", out)
			}
		})
	}
}

func TestHeuristicScrubLeavesNormalLogsAlone(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"git SHA", "built commit 0f53a0ab99271bdfc5d7e838f387c5f09c79a618 successfully"},
		{"sha256 digest", "pulled bh-registry:5000/ops/tracker@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
		{"plain prose", "Server listening on port 8080, request took 200ms, status 200 OK"},
		{"hostname", "route minted at h7k2m9x4.preview.beamhall.internal"},
		{"path", "reading /run/secrets/MAIN_URL from tmpfs mount /workspace/node_modules/.bin"},
		{"uuid", "request id 550e8400-e29b-41d4-a716-446655440000 handled"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := string(heuristicScrub([]byte(tc.in)))
			if out != tc.in {
				t.Fatalf("false positive:\n in: %s\nout: %s", tc.in, out)
			}
		})
	}
}

func TestScrubberForEnablesHeuristics(t *testing.T) {
	s := NewScrubber(nil).WithHeuristics()
	in := "leak: eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.abcdef123456"
	if out := s.ScrubString(in); !strings.Contains(out, Mask) {
		t.Fatalf("heuristics not applied through Scrubber: %s", out)
	}
	// Known-value masks must not confuse the heuristic pass.
	s2 := NewScrubber([][]byte{[]byte("supersecret")}).WithHeuristics()
	if out := s2.ScrubString("value supersecret end"); !strings.Contains(out, Mask) {
		t.Fatal("known-value pass broken")
	}
}
