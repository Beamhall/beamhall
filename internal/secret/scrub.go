package secret

import (
	"bytes"
	"context"
	"fmt"
	"sort"

	"github.com/Beamhall/beamhall/internal/domain"
)

// Mask replaces a secret value wherever it appears in scrubbed output.
const Mask = "***REDACTED***"

// minScrubLen is the shortest value the scrubber will redact. Values shorter
// than this are skipped: short, low-entropy strings (e.g. "1", "true", a port)
// occur constantly in real logs and redacting them would shred the output
// without protecting anything meaningful.
const minScrubLen = 4

// Scrubber redacts known secret values from text. Matching is exact-substring:
// every occurrence of a value is replaced with Mask. It carries plaintext
// values in memory, so it is built per request, used backplane-side to sanitize
// show_logs / show_metrics output, and then dropped — values never reach the
// agent.
type Scrubber struct {
	values     [][]byte // de-duped, >= minScrubLen, longest-first
	heuristics bool
}

// WithHeuristics enables the secret-shape heuristics (PEM blocks, JWTs,
// vendor key prefixes, high-entropy tokens — see heuristics.go) on top of the
// known-value pass. ScrubberFor enables this by default: show_logs output
// must catch secrets the vault never stored (PLAN §6).
func (s *Scrubber) WithHeuristics() *Scrubber {
	s.heuristics = true
	return s
}

// NewScrubber builds a scrubber over the given plaintext values. Empty and
// sub-minScrubLen values are dropped, duplicates removed, and the rest sorted
// longest-first so that when one value contains another the longer match wins.
func NewScrubber(values [][]byte) *Scrubber {
	seen := make(map[string]bool, len(values))
	keep := make([][]byte, 0, len(values))
	for _, v := range values {
		if len(v) < minScrubLen || seen[string(v)] {
			continue
		}
		seen[string(v)] = true
		keep = append(keep, v)
	}
	sort.SliceStable(keep, func(i, j int) bool { return len(keep[i]) > len(keep[j]) })
	return &Scrubber{values: keep}
}

// Scrub returns b with every known secret value replaced by Mask. The input is
// not modified.
func (s *Scrubber) Scrub(b []byte) []byte {
	for _, v := range s.values {
		b = bytes.ReplaceAll(b, v, []byte(Mask))
	}
	if s.heuristics {
		b = heuristicScrub(b)
	}
	return b
}

// ScrubString is the string convenience form of Scrub.
func (s *Scrubber) ScrubString(str string) string {
	return string(s.Scrub([]byte(str)))
}

// ScrubberFor builds a scrubber covering every secret in scope for a beam: its
// own beam-scoped secrets plus the beamhall-wide ones (BeamID == ""). Values are
// decrypted backplane-side. Use it to sanitize a beam's logs/metrics before
// they reach the agent.
func (v *Vault) ScrubberFor(ctx context.Context, beamhallID, beamID domain.ID) (*Scrubber, error) {
	metas, err := v.store.ListSecretsByBeamhall(ctx, beamhallID)
	if err != nil {
		return nil, err
	}
	values := make([][]byte, 0, len(metas))
	for _, m := range metas {
		if m.BeamID != "" && m.BeamID != beamID {
			continue // belongs to a different beam in this beamhall
		}
		val, err := v.value(ctx, m.ValueRef)
		if err != nil {
			return nil, fmt.Errorf("scrubber secret %q: %w", m.Key, err)
		}
		values = append(values, val)
	}
	return NewScrubber(values).WithHeuristics(), nil
}
