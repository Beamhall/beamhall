package secret

import (
	"math"
	"regexp"
)

// Heuristic scrubbing (PLAN §6): the known-value pass catches everything the
// vault knows about, but logs can leak secrets Beamhall never stored — a token
// the beam fetched at runtime, a key pasted into app config, a credential in a
// stack trace. These patterns catch secret-shaped content by form. They run
// after the known-value pass and are deliberately conservative: a redaction
// miss leaks one secret, but an aggressive matcher shreds every build log
// (image digests and commit SHAs are high-entropy strings that are NOT
// secrets).

var heuristicPatterns = []*regexp.Regexp{
	// PEM private-key blocks (multi-line, any key type incl. OPENSSH/EC/PKCS8).
	regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----.*?-----END [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----`),
	// JWTs: three dot-separated base64url segments, header starting {"alg"/{"typ"
	// (eyJ...). The signature segment may be empty (unsecured JWT).
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*`),
	// Well-known credential prefixes (vendor-tagged, so zero false positives).
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),              // AWS access key id
	regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{16,}`),           // OpenAI/Stripe-style secret key
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`),    // GitHub tokens
	regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}`),    // Slack tokens
	regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),         // Google API key
	regexp.MustCompile(`\bAGE-SECRET-KEY-1[A-Z0-9]{40,}\b`), // age identity
	regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`),      // GitLab PAT
	// URL userinfo credentials: scheme://user:password@host.
	regexp.MustCompile(`\b[a-z][a-z0-9+.-]*://[^/\s:@]+:([^/\s@]+)@`),
}

// entropyCandidate bounds the generic high-entropy detector: a long
// base64-alphabet word. Pure-hex matches are skipped below (git SHAs and
// sha256 digests live in normal logs); real random base64 secrets of this
// length are all-hex with probability (16/64)^28 ≈ never.
var (
	entropyCandidate = regexp.MustCompile(`[A-Za-z0-9+/_=-]{28,}`)
	pureHex          = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

// entropyThreshold is bits/char of Shannon entropy above which a candidate is
// treated as secret material. Random base64 sits near its sample-size bound
// (log2(len) for short strings); English-ish identifiers sit well below 4.
const entropyThreshold = 4.2

// heuristicScrub applies the pattern + entropy passes. It runs on output that
// already had known values masked, so masks never feed the matchers.
func heuristicScrub(b []byte) []byte {
	for _, re := range heuristicPatterns {
		b = re.ReplaceAll(b, []byte(Mask))
	}
	b = entropyCandidate.ReplaceAllFunc(b, func(m []byte) []byte {
		if pureHex.Match(m) {
			return m // digest/SHA shaped — routine log content, not a secret
		}
		if shannon(m) < entropyThreshold {
			return m
		}
		return []byte(Mask)
	})
	return b
}

// shannon is bits of entropy per byte of the sample.
func shannon(b []byte) float64 {
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	n := float64(len(b))
	var h float64
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := float64(f) / n
		h -= p * math.Log2(p)
	}
	return h
}
