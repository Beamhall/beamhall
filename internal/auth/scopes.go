package auth

// OAuth scopes are coarse capability classes (PLAN §6): which Beamhall an
// identity may act in is data-driven in the backplane (membership → role),
// never encoded in the token. The PEP remains the single authorization point;
// scopes only gate which tool *classes* a token may invoke at all.
const (
	ScopeBeamhallsRead  = "beamhalls:read"
	ScopeBeamsWrite     = "beams:write"
	ScopeBeamsDeploy    = "beams:deploy"
	ScopeBeamsOperate   = "beams:operate"
	ScopeBeamsPromote   = "beams:promote"
	ScopeSecretsWrite   = "secrets:write"
	ScopeResourcesWrite = "resources:write"
	ScopeLogsRead       = "logs:read"
	ScopeMetricsRead    = "metrics:read"
	// ScopeBeamsUse is the using tier: discovery of apps published TO the
	// caller (list_apps / describe_app). Any employee may hold it — it grants
	// no build, deploy, or inspection capability; the audience is the gate.
	ScopeBeamsUse = "beams:use"
	ScopeAdminIT  = "admin:it"
)

// AllScopes is the scopes_supported list for the RFC 9728 metadata document —
// the scopes a normal agent client should request. ScopeAdminIT is deliberately
// excluded: it is a privileged IT-operator capability granted out-of-band (the
// Admin console / an explicitly-scoped IT token), never something the agent
// channel advertises or a self-registering (DCR) client should obtain. The IT
// MCP tools still honor admin:it when a token legitimately carries it.
// ScopeBeamsUse IS included: it is the least-privileged scope of all.
func AllScopes() []string {
	return []string{
		ScopeBeamhallsRead, ScopeBeamsWrite, ScopeBeamsDeploy, ScopeBeamsOperate,
		ScopeBeamsPromote, ScopeSecretsWrite, ScopeResourcesWrite,
		ScopeLogsRead, ScopeMetricsRead, ScopeBeamsUse,
	}
}

// HasScope reports whether the granted scope list contains want.
func HasScope(granted []string, want string) bool {
	for _, s := range granted {
		if s == want {
			return true
		}
	}
	return false
}
