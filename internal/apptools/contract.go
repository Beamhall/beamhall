// Package apptools implements the agent-facing app-tools contract (PLAN
// §5.15): a beam may expose tools to its users' agents by serving a small
// HTTP surface on its own origin, and the backplane brokers every call,
// delivering the caller's identity as a short-lived signed assertion. The
// beam never sees the user's IdP token; the agent never reaches the beam
// directly. This package holds the wire contract, the assertion signer, and
// the broker-side HTTP client; orchestration and policy live in internal/orch.
package apptools

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
)

const (
	// Version is the contract version both sides speak.
	Version = 1
	// PathTools is the manifest path on the beam's origin; POST
	// PathTools+"/<name>" invokes one tool.
	PathTools = "/.beamhall/tools"
	// HeaderAssertion carries the backplane-signed identity assertion on
	// every brokered request. The endpoints are reachable on the app's
	// public origin, so apps must verify it and refuse requests without it.
	HeaderAssertion = "Beamhall-Assertion"
	// MountPath is where the verification material (issuer, audience, JWKS)
	// is bound into every workload.
	MountPath = "/run/beamhall/assertion.json"
)

// Caps enforced broker-side so an app can never balloon an agent's context
// or the appliance's memory.
const (
	MaxManifestBytes = 64 << 10
	MaxTools         = 64
	MaxArgumentBytes = 64 << 10
	MaxResultBytes   = 256 << 10
	maxErrorBytes    = 4 << 10
)

// Tool is one entry of a beam's manifest — deliberately the same shape as an
// MCP tool definition so builders and agents recognize it.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
}

// Manifest is the response of GET PathTools.
type Manifest struct {
	Version int    `json:"version"`
	Tools   []Tool `json:"tools"`
}

var toolNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// ParseManifest decodes and validates a manifest body. The caller is expected
// to have already bounded the byte count (MaxManifestBytes).
func ParseManifest(b []byte) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return Manifest{}, fmt.Errorf("manifest is not valid JSON: %w", err)
	}
	if m.Version != Version {
		return Manifest{}, fmt.Errorf("manifest version %d is not supported (this appliance speaks version %d)", m.Version, Version)
	}
	if len(m.Tools) > MaxTools {
		return Manifest{}, fmt.Errorf("manifest lists %d tools; the maximum is %d", len(m.Tools), MaxTools)
	}
	seen := make(map[string]bool, len(m.Tools))
	for _, t := range m.Tools {
		if !toolNameRe.MatchString(t.Name) {
			return Manifest{}, fmt.Errorf("tool name %q is invalid (want lowercase letters, digits, - or _, max 64 chars)", t.Name)
		}
		if seen[t.Name] {
			return Manifest{}, fmt.Errorf("tool name %q appears twice", t.Name)
		}
		seen[t.Name] = true
		if len(t.InputSchema) > 0 {
			if s := bytes.TrimSpace(t.InputSchema); len(s) == 0 || s[0] != '{' {
				return Manifest{}, fmt.Errorf("tool %q input_schema must be a JSON object", t.Name)
			}
		}
	}
	return m, nil
}
