package identityadmin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// OIDC relying-party (per-beam app SSO) administration over the Keycloak Admin
// REST API (PLAN §5.10). A beam reuses the bundled Keycloak for its own end-user
// sign-in via a dedicated confidential client; Beamhall holds/seals the secret,
// the agent never sees it. The load-bearing invariant is audience isolation: an
// app client's tokens carry only its OWN clientId as `aud`, never the Beamhall
// resource URI — so an app token cannot be replayed against the MCP backplane.

// kcClient is the subset of Keycloak's client representation Beamhall uses.
type kcClient struct {
	ID                     string             `json:"id,omitempty"`
	ClientID               string             `json:"clientId"`
	Protocol               string             `json:"protocol,omitempty"`
	PublicClient           bool               `json:"publicClient"`
	StandardFlowEnabled    bool               `json:"standardFlowEnabled"`
	DirectAccessGrants     bool               `json:"directAccessGrantsEnabled"`
	ImplicitFlowEnabled    bool               `json:"implicitFlowEnabled"`
	ServiceAccountsEnabled bool               `json:"serviceAccountsEnabled"`
	FullScopeAllowed       bool               `json:"fullScopeAllowed"`
	RedirectURIs           []string           `json:"redirectUris,omitempty"`
	WebOrigins             []string           `json:"webOrigins,omitempty"`
	Attributes             map[string]string  `json:"attributes,omitempty"`
	ProtocolMappers        []kcProtocolMapper `json:"protocolMappers,omitempty"`
}

type kcProtocolMapper struct {
	ID             string            `json:"id,omitempty"`
	Name           string            `json:"name"`
	Protocol       string            `json:"protocol"`
	ProtocolMapper string            `json:"protocolMapper"`
	Config         map[string]string `json:"config"`
}

type kcRole struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name"`
}

func (k *Keycloak) CreateClient(ctx context.Context, spec ClientSpec) (Client, error) {
	if spec.ClientID == "" {
		return Client{}, fmt.Errorf("clientID is required")
	}
	if err := assertNoWildcard(spec.RedirectURIs); err != nil {
		return Client{}, err
	}
	if err := assertNoWildcard(spec.WebOrigins); err != nil {
		return Client{}, err
	}
	// Idempotent on clientId: return the existing client (with its current secret).
	if existing, err := k.findClient(ctx, spec.ClientID); err == nil && existing.ID != "" {
		secret, serr := k.GetClientSecret(ctx, existing.ID)
		if serr != nil {
			return Client{}, serr
		}
		return Client{UUID: existing.ID, ClientID: spec.ClientID, Secret: secret}, nil
	}

	rep := kcClient{
		ClientID:               spec.ClientID,
		Protocol:               "openid-connect",
		PublicClient:           false,
		StandardFlowEnabled:    true,
		DirectAccessGrants:     false,
		ImplicitFlowEnabled:    false,
		ServiceAccountsEnabled: false,
		FullScopeAllowed:       false,
		RedirectURIs:           spec.RedirectURIs,
		WebOrigins:             spec.WebOrigins,
		Attributes:             map[string]string{"pkce.code.challenge.method": "S256"},
		ProtocolMappers:        []kcProtocolMapper{audienceMapper(spec.ClientID)},
	}
	if spec.AccessTokenTTLSeconds > 0 {
		rep.Attributes["access.token.lifespan"] = strconv.Itoa(spec.AccessTokenTTLSeconds)
	}
	resp, err := k.do(ctx, http.MethodPost, "/clients", rep)
	if err != nil {
		return Client{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return Client{}, fmt.Errorf("create client %q: HTTP %d (%s)", spec.ClientID, resp.StatusCode, snippet(resp))
	}
	uuid := lastPathSegment(resp.Header.Get("Location"))
	if uuid == "" {
		found, ferr := k.findClient(ctx, spec.ClientID)
		if ferr != nil || found.ID == "" {
			return Client{}, fmt.Errorf("create client %q: IdP returned no client id", spec.ClientID)
		}
		uuid = found.ID
	}

	// Defensive: detach any audience-bearing client scope (e.g. a realm-default
	// "beamhall-audience") so the app token cannot inherit the backplane aud.
	_ = k.detachAudienceScopes(ctx, uuid)

	// POST-ASSERT the audience-isolation invariant against the client's EFFECTIVE
	// mappers (own + from assigned scopes). Refuse + clean up if violated.
	if spec.ForbiddenAudience != "" {
		bad, aerr := k.clientInjectsAudience(ctx, uuid, spec.ForbiddenAudience)
		if aerr != nil {
			_ = k.DeleteClient(ctx, uuid)
			return Client{}, fmt.Errorf("create client %q: audience post-assert failed: %w", spec.ClientID, aerr)
		}
		if bad {
			_ = k.DeleteClient(ctx, uuid)
			return Client{}, fmt.Errorf("create client %q: refusing — an effective mapper/scope injects the Beamhall resource URI into the app token (would permit backplane replay)", spec.ClientID)
		}
	}

	secret, err := k.GetClientSecret(ctx, uuid)
	if err != nil {
		_ = k.DeleteClient(ctx, uuid)
		return Client{}, err
	}
	return Client{UUID: uuid, ClientID: spec.ClientID, Secret: secret}, nil
}

func (k *Keycloak) GetClientSecret(ctx context.Context, clientUUID string) (string, error) {
	if clientUUID == "" {
		return "", fmt.Errorf("clientUUID is required")
	}
	resp, err := k.do(ctx, http.MethodGet, "/clients/"+url.PathEscape(clientUUID)+"/client-secret", nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("get client secret: HTTP %d (%s)", resp.StatusCode, snippet(resp))
	}
	var cs struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cs); err != nil {
		return "", fmt.Errorf("decode client secret: %w", err)
	}
	return cs.Value, nil
}

func (k *Keycloak) RotateClientSecret(ctx context.Context, clientUUID string) (string, error) {
	if clientUUID == "" {
		return "", fmt.Errorf("clientUUID is required")
	}
	resp, err := k.do(ctx, http.MethodPost, "/clients/"+url.PathEscape(clientUUID)+"/client-secret", nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("rotate client secret: HTTP %d (%s)", resp.StatusCode, snippet(resp))
	}
	var cs struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cs); err != nil {
		return "", fmt.Errorf("decode rotated secret: %w", err)
	}
	return cs.Value, nil
}

// SyncRedirectURIs replaces the client's redirect-URI/web-origin allowlist with
// the exact given sets (set-and-replace). nil is normalized to an empty slice so
// an empty allowlist (preview paused) actually clears it rather than being a no-op.
func (k *Keycloak) SyncRedirectURIs(ctx context.Context, clientUUID string, redirectURIs, webOrigins []string) error {
	if clientUUID == "" {
		return fmt.Errorf("clientUUID is required")
	}
	if err := assertNoWildcard(redirectURIs); err != nil {
		return err
	}
	if err := assertNoWildcard(webOrigins); err != nil {
		return err
	}
	if redirectURIs == nil {
		redirectURIs = []string{}
	}
	if webOrigins == nil {
		webOrigins = []string{}
	}
	body := map[string]any{"redirectUris": redirectURIs, "webOrigins": webOrigins}
	resp, err := k.do(ctx, http.MethodPut, "/clients/"+url.PathEscape(clientUUID), body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sync redirect URIs: HTTP %d (%s)", resp.StatusCode, snippet(resp))
	}
	return nil
}

// DeleteClient removes a client. Idempotent: an absent client (404) is success.
func (k *Keycloak) DeleteClient(ctx context.Context, clientUUID string) error {
	if clientUUID == "" {
		return nil
	}
	resp, err := k.do(ctx, http.MethodDelete, "/clients/"+url.PathEscape(clientUUID), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("delete client: HTTP %d (%s)", resp.StatusCode, snippet(resp))
	}
	return nil
}

// SetClientGroupRoles curates the realm groups a client's tokens may expose, as
// the IT-set allowlist (separation of duties — PLAN §5.10). It is leak-proof by
// construction: each allowed group becomes a per-client role mapped from that
// realm group, surfaced through a single "groups" claim mapper — Keycloak only
// ever puts a client's OWN roles in that client's token, so no app can learn a
// group IT did not map to it. Set-and-replace: roles no longer in the allowlist
// are removed.
func (k *Keycloak) SetClientGroupRoles(ctx context.Context, clientUUID string, groups []string) error {
	if clientUUID == "" {
		return fmt.Errorf("clientUUID is required")
	}
	cl, err := k.getClient(ctx, clientUUID)
	if err != nil {
		return err
	}
	desired := map[string]bool{}
	for _, g := range groups {
		if g = strings.TrimSpace(g); g != "" {
			desired[g] = true
		}
	}
	existing, err := k.listClientRoles(ctx, clientUUID)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for _, r := range existing {
		have[r.Name] = true
		if !desired[r.Name] {
			// No longer allowed — delete the client role (its group mappings go with it).
			if derr := k.deleteClientRole(ctx, clientUUID, r.Name); derr != nil {
				return derr
			}
		}
	}
	for g := range desired {
		if have[g] {
			continue
		}
		if err := k.createClientRole(ctx, clientUUID, g); err != nil {
			return err
		}
		role, err := k.getClientRole(ctx, clientUUID, g)
		if err != nil {
			return err
		}
		grp, err := k.findGroupByName(ctx, g)
		if err != nil {
			return err
		}
		if grp.ID == "" {
			return fmt.Errorf("realm group %q not found (create it / add members first)", g)
		}
		if err := k.mapClientRoleToGroup(ctx, grp.ID, clientUUID, role); err != nil {
			return err
		}
	}
	// Ensure the single "groups" claim mapper exists (idempotent).
	return k.ensureGroupsClaimMapper(ctx, clientUUID, cl.ClientID, len(desired) > 0)
}

// --- helpers ---------------------------------------------------------------

func assertNoWildcard(uris []string) error {
	for _, u := range uris {
		if strings.Contains(u, "*") {
			return fmt.Errorf("wildcard URI %q not allowed — provisioned auth uses exact redirect URIs only (PLAN §5.10)", u)
		}
	}
	return nil
}

// audienceMapper makes the client's tokens carry ONLY its own clientId as `aud`.
func audienceMapper(clientID string) kcProtocolMapper {
	return kcProtocolMapper{
		Name:           "aud-" + clientID,
		Protocol:       "openid-connect",
		ProtocolMapper: "oidc-audience-mapper",
		Config: map[string]string{
			"included.client.audience": clientID,
			"access.token.claim":       "true",
			"id.token.claim":           "false",
		},
	}
}

func (k *Keycloak) findClient(ctx context.Context, clientID string) (kcClient, error) {
	resp, err := k.do(ctx, http.MethodGet, "/clients?clientId="+url.QueryEscape(clientID), nil)
	if err != nil {
		return kcClient{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return kcClient{}, fmt.Errorf("find client: HTTP %d (%s)", resp.StatusCode, snippet(resp))
	}
	var reps []kcClient
	if err := json.NewDecoder(resp.Body).Decode(&reps); err != nil {
		return kcClient{}, fmt.Errorf("decode clients: %w", err)
	}
	for _, c := range reps {
		if c.ClientID == clientID {
			return c, nil
		}
	}
	return kcClient{}, nil
}

func (k *Keycloak) getClient(ctx context.Context, clientUUID string) (kcClient, error) {
	resp, err := k.do(ctx, http.MethodGet, "/clients/"+url.PathEscape(clientUUID), nil)
	if err != nil {
		return kcClient{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return kcClient{}, fmt.Errorf("get client: HTTP %d (%s)", resp.StatusCode, snippet(resp))
	}
	var c kcClient
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		return kcClient{}, fmt.Errorf("decode client: %w", err)
	}
	return c, nil
}

// detachAudienceScopes removes any client scope named "beamhall-audience" from
// the client's default and optional scope sets (a realm-default would otherwise
// inject the backplane aud). Best-effort; clientInjectsAudience is the hard gate.
func (k *Keycloak) detachAudienceScopes(ctx context.Context, clientUUID string) error {
	for _, kind := range []string{"default-client-scopes", "optional-client-scopes"} {
		resp, err := k.do(ctx, http.MethodGet, "/clients/"+url.PathEscape(clientUUID)+"/"+kind, nil)
		if err != nil {
			return err
		}
		var scopes []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&scopes)
		resp.Body.Close()
		for _, s := range scopes {
			if s.Name == "beamhall-audience" {
				del, err := k.do(ctx, http.MethodDelete, "/clients/"+url.PathEscape(clientUUID)+"/"+kind+"/"+url.PathEscape(s.ID), nil)
				if err != nil {
					return err
				}
				del.Body.Close()
			}
		}
	}
	return nil
}

// clientInjectsAudience reports whether the client's EFFECTIVE protocol mappers
// (own + from assigned scopes, via Keycloak's evaluate-scopes endpoint) would put
// the forbidden resource URI into a token's `aud`.
func (k *Keycloak) clientInjectsAudience(ctx context.Context, clientUUID, forbidden string) (bool, error) {
	resp, err := k.do(ctx, http.MethodGet,
		"/clients/"+url.PathEscape(clientUUID)+"/evaluate-scopes/protocol-mappers?scope=openid", nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("evaluate scopes: HTTP %d (%s)", resp.StatusCode, snippet(resp))
	}
	var mappers []kcProtocolMapper
	if err := json.NewDecoder(resp.Body).Decode(&mappers); err != nil {
		return false, fmt.Errorf("decode effective mappers: %w", err)
	}
	for _, m := range mappers {
		if m.ProtocolMapper == "oidc-audience-mapper" && m.Config["included.custom.audience"] == forbidden {
			return true, nil
		}
		// A hardcoded-claim mapper writing the aud claim directly.
		if m.Config["claim.name"] == "aud" {
			for _, v := range m.Config {
				if v == forbidden {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func (k *Keycloak) listClientRoles(ctx context.Context, clientUUID string) ([]kcRole, error) {
	resp, err := k.do(ctx, http.MethodGet, "/clients/"+url.PathEscape(clientUUID)+"/roles", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list client roles: HTTP %d (%s)", resp.StatusCode, snippet(resp))
	}
	var roles []kcRole
	if err := json.NewDecoder(resp.Body).Decode(&roles); err != nil {
		return nil, fmt.Errorf("decode client roles: %w", err)
	}
	return roles, nil
}

func (k *Keycloak) createClientRole(ctx context.Context, clientUUID, name string) error {
	resp, err := k.do(ctx, http.MethodPost, "/clients/"+url.PathEscape(clientUUID)+"/roles", kcRole{Name: name})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusConflict {
		return fmt.Errorf("create client role %q: HTTP %d (%s)", name, resp.StatusCode, snippet(resp))
	}
	return nil
}

func (k *Keycloak) getClientRole(ctx context.Context, clientUUID, name string) (kcRole, error) {
	resp, err := k.do(ctx, http.MethodGet, "/clients/"+url.PathEscape(clientUUID)+"/roles/"+url.PathEscape(name), nil)
	if err != nil {
		return kcRole{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return kcRole{}, fmt.Errorf("get client role %q: HTTP %d (%s)", name, resp.StatusCode, snippet(resp))
	}
	var r kcRole
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return kcRole{}, fmt.Errorf("decode client role: %w", err)
	}
	return r, nil
}

func (k *Keycloak) deleteClientRole(ctx context.Context, clientUUID, name string) error {
	resp, err := k.do(ctx, http.MethodDelete, "/clients/"+url.PathEscape(clientUUID)+"/roles/"+url.PathEscape(name), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("delete client role %q: HTTP %d (%s)", name, resp.StatusCode, snippet(resp))
	}
	return nil
}

func (k *Keycloak) findGroupByName(ctx context.Context, name string) (Group, error) {
	resp, err := k.do(ctx, http.MethodGet, "/groups?search="+url.QueryEscape(name)+"&max=200", nil)
	if err != nil {
		return Group{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Group{}, fmt.Errorf("find group: HTTP %d (%s)", resp.StatusCode, snippet(resp))
	}
	var reps []kcGroup
	if err := json.NewDecoder(resp.Body).Decode(&reps); err != nil {
		return Group{}, fmt.Errorf("decode groups: %w", err)
	}
	for _, g := range reps {
		if strings.EqualFold(g.Name, name) {
			return Group{ID: g.ID, Name: g.Name, Path: g.Path}, nil
		}
	}
	return Group{}, nil
}

func (k *Keycloak) mapClientRoleToGroup(ctx context.Context, groupID, clientUUID string, role kcRole) error {
	resp, err := k.do(ctx, http.MethodPost,
		"/groups/"+url.PathEscape(groupID)+"/role-mappings/clients/"+url.PathEscape(clientUUID),
		[]kcRole{role})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("map client role to group: HTTP %d (%s)", resp.StatusCode, snippet(resp))
	}
	return nil
}

// ensureGroupsClaimMapper makes the client emit its (allowlisted) client roles as
// a flat "groups" claim. Idempotent; removes the mapper when no groups remain.
func (k *Keycloak) ensureGroupsClaimMapper(ctx context.Context, clientUUID, clientID string, want bool) error {
	resp, err := k.do(ctx, http.MethodGet, "/clients/"+url.PathEscape(clientUUID)+"/protocol-mappers/models", nil)
	if err != nil {
		return err
	}
	var mappers []kcProtocolMapper
	_ = json.NewDecoder(resp.Body).Decode(&mappers)
	resp.Body.Close()
	var existingID string
	for _, m := range mappers {
		if m.Name == "groups-from-client-roles" {
			existingID = m.ID
			break
		}
	}
	if !want {
		if existingID != "" {
			del, err := k.do(ctx, http.MethodDelete, "/clients/"+url.PathEscape(clientUUID)+"/protocol-mappers/models/"+url.PathEscape(existingID), nil)
			if err != nil {
				return err
			}
			del.Body.Close()
		}
		return nil
	}
	if existingID != "" {
		return nil
	}
	mapper := kcProtocolMapper{
		Name:           "groups-from-client-roles",
		Protocol:       "openid-connect",
		ProtocolMapper: "oidc-usermodel-client-role-mapper",
		Config: map[string]string{
			"usermodel.clientRoleMapping.clientId": clientID,
			"claim.name":                           "groups",
			"jsonType.label":                       "String",
			"multivalued":                          "true",
			"access.token.claim":                   "true",
			"id.token.claim":                       "false",
		},
	}
	cr, err := k.do(ctx, http.MethodPost, "/clients/"+url.PathEscape(clientUUID)+"/protocol-mappers/models", mapper)
	if err != nil {
		return err
	}
	defer cr.Body.Close()
	if cr.StatusCode != http.StatusCreated && cr.StatusCode != http.StatusConflict {
		return fmt.Errorf("create groups claim mapper: HTTP %d (%s)", cr.StatusCode, snippet(cr))
	}
	return nil
}
