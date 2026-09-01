package identityadmin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// Realm baseline: the client-scope + agent-client shape a running build of
// Beamhall needs from the bundled realm. The install-time realm import runs
// exactly once (Keycloak skips an existing realm), so an appliance upgraded in
// place would never learn a scope or client added after its install — this is
// the counterpart that additively brings an existing realm up to date at boot.
// It creates what is missing and attaches missing scopes, and never deletes,
// renames, or narrows anything an operator configured.

// RealmBaseline declares the shape EnsureRealmBaseline converges the realm to.
type RealmBaseline struct {
	ClientScopes []ClientScopeSpec
	Clients      []AgentClientSpec
}

// ClientScopeSpec is one capability client scope.
type ClientScopeSpec struct {
	Name        string
	Description string
}

// AgentClientSpec is one public PKCE+ROPC agent client.
type AgentClientSpec struct {
	ClientID       string
	Name           string
	Description    string
	RedirectURIs   []string
	DefaultScopes  []string
	OptionalScopes []string
	// GroupsClaimMapper emits the user's realm group membership as a flat
	// `groups` claim (full.path=false), the app-audience group source.
	GroupsClaimMapper bool
	// AttachOnly means the client is expected to pre-exist (it came from the
	// realm import); the baseline only attaches missing scopes and never
	// creates it — a realm missing this client is broken beyond what an
	// additive reconcile should paper over.
	AttachOnly bool
}

// RealmBaselineResult reports what a run actually changed (all empty on an
// already-current realm).
type RealmBaselineResult struct {
	CreatedScopes  []string
	CreatedClients []string
	AttachedScopes []string // "<clientId>:<scope>"
}

func (r RealmBaselineResult) Changed() bool {
	return len(r.CreatedScopes)+len(r.CreatedClients)+len(r.AttachedScopes) > 0
}

const userAgentClientID = "beamhall-user-agent"

// userAgentAllowedScopes is every scope the user-tier client may carry. A user
// token must never be able to carry a builder or admin scope; a careless
// future edit to the baseline must fail loudly here, not quietly widen it.
var userAgentAllowedScopes = map[string]bool{
	"beamhall-audience": true,
	"beams:use":         true,
	"offline_access":    true,
}

var agentRedirectURIs = []string{
	"http://localhost/*", "http://127.0.0.1/*", "http://localhost:*/*", "http://127.0.0.1:*/*",
}

// BeamhallRealmBaseline is the single source of truth for the realm shape this
// build needs. packaging/keycloak/realm-template.json must agree (asserted by
// TestRealmTemplateMatchesBaseline) so a fresh install and an upgraded
// appliance converge on the same realm.
func BeamhallRealmBaseline() RealmBaseline {
	return RealmBaseline{
		ClientScopes: []ClientScopeSpec{
			{Name: "beams:use", Description: "Use apps published to you (discovery only — no build or deploy capability)."},
		},
		Clients: []AgentClientSpec{
			{
				ClientID:          userAgentClientID,
				Name:              "Beamhall user agent (everyone)",
				Description:       "Public PKCE client for employees' own agents: discover and use the apps published to them. Carries no build, deploy, or admin capability.",
				RedirectURIs:      agentRedirectURIs,
				DefaultScopes:     []string{"beamhall-audience"},
				OptionalScopes:    []string{"beams:use", "offline_access"},
				GroupsClaimMapper: true,
			},
			{
				ClientID:       "beamhall-agent",
				OptionalScopes: []string{"beams:use"},
				AttachOnly:     true,
			},
		},
	}
}

// EnsureRealmBaseline additively converges the realm to spec. Idempotent —
// safe to run on every boot.
func (k *Keycloak) EnsureRealmBaseline(ctx context.Context, spec RealmBaseline) (RealmBaselineResult, error) {
	var res RealmBaselineResult
	for _, c := range spec.Clients {
		if c.ClientID == userAgentClientID {
			for _, s := range append(append([]string{}, c.DefaultScopes...), c.OptionalScopes...) {
				if !userAgentAllowedScopes[s] {
					return res, fmt.Errorf("realm baseline: refusing scope %q on %s — the user-tier client may carry only %v", s, userAgentClientID, []string{"beamhall-audience", "beams:use", "offline_access"})
				}
			}
		}
	}

	for _, sc := range spec.ClientScopes {
		created, err := k.ensureClientScope(ctx, sc)
		if err != nil {
			return res, err
		}
		if created {
			res.CreatedScopes = append(res.CreatedScopes, sc.Name)
		}
	}
	for _, c := range spec.Clients {
		if err := k.ensureAgentClient(ctx, c, &res); err != nil {
			return res, err
		}
	}
	return res, nil
}

// ensureClientScope creates the client scope when absent (include-in-token,
// off the consent screen — the shape every capability scope uses).
func (k *Keycloak) ensureClientScope(ctx context.Context, spec ClientScopeSpec) (created bool, err error) {
	scopes, err := k.listClientScopes(ctx)
	if err != nil {
		return false, err
	}
	if _, ok := scopes[spec.Name]; ok {
		return false, nil
	}
	body := map[string]any{
		"name":        spec.Name,
		"description": spec.Description,
		"protocol":    "openid-connect",
		"attributes":  map[string]string{"include.in.token.scope": "true", "display.on.consent.screen": "false"},
	}
	resp, err := k.do(ctx, http.MethodPost, "/client-scopes", body)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusConflict {
		return false, nil
	}
	if resp.StatusCode != http.StatusCreated {
		return false, fmt.Errorf("create client scope %q: HTTP %d (%s)", spec.Name, resp.StatusCode, snippet(resp))
	}
	return true, nil
}

func (k *Keycloak) listClientScopes(ctx context.Context) (map[string]string, error) {
	resp, err := k.do(ctx, http.MethodGet, "/client-scopes", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list client scopes: HTTP %d (%s)", resp.StatusCode, snippet(resp))
	}
	var scopes []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&scopes); err != nil {
		return nil, fmt.Errorf("decode client scopes: %w", err)
	}
	byName := make(map[string]string, len(scopes))
	for _, s := range scopes {
		byName[s.Name] = s.ID
	}
	return byName, nil
}

func (k *Keycloak) ensureAgentClient(ctx context.Context, spec AgentClientSpec, res *RealmBaselineResult) error {
	existing, err := k.findClient(ctx, spec.ClientID)
	if err != nil {
		return err
	}
	uuid := existing.ID
	if uuid == "" {
		if spec.AttachOnly {
			return fmt.Errorf("realm baseline: client %q is missing and attach-only — the realm import did not run or the client was deleted", spec.ClientID)
		}
		rep := kcClient{
			ClientID:             spec.ClientID,
			Name:                 spec.Name,
			Description:          spec.Description,
			Protocol:             "openid-connect",
			Enabled:              true,
			PublicClient:         true,
			StandardFlowEnabled:  true,
			DirectAccessGrants:   true,
			ImplicitFlowEnabled:  false,
			FullScopeAllowed:     false,
			RedirectURIs:         spec.RedirectURIs,
			Attributes:           map[string]string{"pkce.code.challenge.method": "S256"},
			DefaultClientScopes:  spec.DefaultScopes,
			OptionalClientScopes: spec.OptionalScopes,
		}
		resp, err := k.do(ctx, http.MethodPost, "/clients", rep)
		if err != nil {
			return err
		}
		loc := resp.Header.Get("Location")
		status := resp.StatusCode
		resp.Body.Close()
		if status != http.StatusCreated && status != http.StatusConflict {
			return fmt.Errorf("create client %q: HTTP %d", spec.ClientID, status)
		}
		if uuid = lastPathSegment(loc); uuid == "" {
			found, ferr := k.findClient(ctx, spec.ClientID)
			if ferr != nil || found.ID == "" {
				return fmt.Errorf("create client %q: IdP returned no client id", spec.ClientID)
			}
			uuid = found.ID
		}
		if status == http.StatusCreated {
			res.CreatedClients = append(res.CreatedClients, spec.ClientID)
		}
	}

	// Attach any declared scope the client does not carry yet. Additive only:
	// nothing already attached is ever removed, so an operator's own realm
	// changes survive every boot.
	for kind, want := range map[string][]string{
		"default-client-scopes":  spec.DefaultScopes,
		"optional-client-scopes": spec.OptionalScopes,
	} {
		if len(want) == 0 {
			continue
		}
		attached, err := k.listAttachedScopes(ctx, uuid, kind)
		if err != nil {
			return err
		}
		var realm map[string]string
		for _, name := range want {
			if attached[name] {
				continue
			}
			if realm == nil {
				if realm, err = k.listClientScopes(ctx); err != nil {
					return err
				}
			}
			scopeID, ok := realm[name]
			if !ok {
				return fmt.Errorf("realm baseline: client scope %q does not exist in the realm", name)
			}
			put, err := k.do(ctx, http.MethodPut, "/clients/"+url.PathEscape(uuid)+"/"+kind+"/"+url.PathEscape(scopeID), nil)
			if err != nil {
				return err
			}
			status := put.StatusCode
			put.Body.Close()
			if status != http.StatusNoContent && status != http.StatusOK {
				return fmt.Errorf("attach scope %q to %q: HTTP %d", name, spec.ClientID, status)
			}
			res.AttachedScopes = append(res.AttachedScopes, spec.ClientID+":"+name)
		}
	}

	if spec.GroupsClaimMapper {
		if err := k.ensureGroupMembershipMapper(ctx, uuid); err != nil {
			return err
		}
	}
	return nil
}

func (k *Keycloak) listAttachedScopes(ctx context.Context, clientUUID, kind string) (map[string]bool, error) {
	resp, err := k.do(ctx, http.MethodGet, "/clients/"+url.PathEscape(clientUUID)+"/"+kind, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list %s: HTTP %d (%s)", kind, resp.StatusCode, snippet(resp))
	}
	var scopes []struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&scopes); err != nil {
		return nil, fmt.Errorf("decode %s: %w", kind, err)
	}
	out := make(map[string]bool, len(scopes))
	for _, s := range scopes {
		out[s.Name] = true
	}
	return out, nil
}

// ensureGroupMembershipMapper emits the user's realm group membership as a
// flat `groups` claim. full.path=false so the claim value is "finance", not
// "/finance" — matching the audience values IT types.
func (k *Keycloak) ensureGroupMembershipMapper(ctx context.Context, clientUUID string) error {
	resp, err := k.do(ctx, http.MethodGet, "/clients/"+url.PathEscape(clientUUID)+"/protocol-mappers/models", nil)
	if err != nil {
		return err
	}
	var mappers []kcProtocolMapper
	_ = json.NewDecoder(resp.Body).Decode(&mappers)
	resp.Body.Close()
	for _, m := range mappers {
		if m.Name == "groups" {
			return nil
		}
	}
	mapper := kcProtocolMapper{
		Name:           "groups",
		Protocol:       "openid-connect",
		ProtocolMapper: "oidc-group-membership-mapper",
		Config: map[string]string{
			"claim.name":         "groups",
			"full.path":          "false",
			"multivalued":        "true",
			"access.token.claim": "true",
			"id.token.claim":     "false",
		},
	}
	cr, err := k.do(ctx, http.MethodPost, "/clients/"+url.PathEscape(clientUUID)+"/protocol-mappers/models", mapper)
	if err != nil {
		return err
	}
	defer cr.Body.Close()
	if cr.StatusCode != http.StatusCreated && cr.StatusCode != http.StatusConflict {
		return fmt.Errorf("create groups membership mapper: HTTP %d (%s)", cr.StatusCode, snippet(cr))
	}
	return nil
}
