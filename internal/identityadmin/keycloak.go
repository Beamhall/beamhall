package identityadmin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Keycloak administers the bundled Keycloak realm via its Admin REST API. It
// authenticates with a confidential service-account client (client_credentials)
// that carries the realm-management roles — Beamhall holds that secret; the
// agent never does. The admin token is cached until shortly before expiry.
//
// The same realm hosts both the service-account client and the users being
// managed (the bundled-IdP setup), so AdminRealm and the managed realm are one;
// the type keeps them separate for a future split.
type Keycloak struct {
	base       string // Keycloak base URL, e.g. http://127.0.0.1:8090 (no trailing slash)
	realm      string // realm whose users/groups are managed
	tokenRealm string // realm the service-account client authenticates against
	clientID   string
	clientSec  string
	hc         *http.Client

	mu     sync.Mutex
	token  string
	expiry time.Time
}

var _ Provider = (*Keycloak)(nil)

// KeycloakConfig configures a Keycloak provider.
type KeycloakConfig struct {
	BaseURL      string // e.g. http://127.0.0.1:8090
	Realm        string // managed realm (default "beamhall")
	TokenRealm   string // realm the admin client lives in (default = Realm)
	ClientID     string // confidential service-account client id
	ClientSecret string
	HTTPClient   *http.Client
}

// NewKeycloak builds a Keycloak provider. It returns a Disabled-equivalent
// (Enabled()==false) configuration only via the caller's choice; here a missing
// BaseURL/ClientID/ClientSecret is a configuration error so misconfiguration is
// loud rather than silently no-op.
func NewKeycloak(cfg KeycloakConfig) (*Keycloak, error) {
	if cfg.BaseURL == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, fmt.Errorf("identityadmin: BaseURL, ClientID and ClientSecret are all required")
	}
	realm := cfg.Realm
	if realm == "" {
		realm = "beamhall"
	}
	tokenRealm := cfg.TokenRealm
	if tokenRealm == "" {
		tokenRealm = realm
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	return &Keycloak{
		base:       strings.TrimRight(cfg.BaseURL, "/"),
		realm:      realm,
		tokenRealm: tokenRealm,
		clientID:   cfg.ClientID,
		clientSec:  cfg.ClientSecret,
		hc:         hc,
	}, nil
}

func (k *Keycloak) Enabled() bool { return true }

// adminToken returns a cached admin access token, refreshing via
// client_credentials when absent or near expiry.
func (k *Keycloak) adminToken(ctx context.Context) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.token != "" && time.Now().Before(k.expiry) {
		return k.token, nil
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {k.clientID},
		"client_secret": {k.clientSec},
	}
	endpoint := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", k.base, url.PathEscape(k.tokenRealm))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := k.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("identityadmin: token request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("identityadmin: token request: HTTP %d (%s)", resp.StatusCode, snippet(resp))
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("identityadmin: decode token: %w", err)
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("identityadmin: token response carried no access_token")
	}
	ttl := time.Duration(tr.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	// Refresh 10s before the IdP's expiry to avoid using a token mid-flight.
	k.token = tr.AccessToken
	k.expiry = time.Now().Add(ttl - 10*time.Second)
	return k.token, nil
}

// do issues an authenticated Admin REST request against the managed realm.
// path is relative to /admin/realms/<realm> (e.g. "/users"). It returns the
// response for the caller to inspect (status, Location header, body).
func (k *Keycloak) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	tok, err := k.adminToken(ctx)
	if err != nil {
		return nil, err
	}
	var rdr *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	endpoint := fmt.Sprintf("%s/admin/realms/%s%s", k.base, url.PathEscape(k.realm), path)
	req, err := http.NewRequestWithContext(ctx, method, endpoint, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	return k.hc.Do(req)
}

func (k *Keycloak) CreateUser(ctx context.Context, u NewUser) (User, error) {
	if u.Username == "" {
		return User{}, fmt.Errorf("username is required")
	}
	// Idempotent on username: return an exact-username match if it already exists.
	if existing, err := k.findByUsername(ctx, u.Username); err == nil && existing.ID != "" {
		return existing, nil
	}
	rep := kcUser{
		Username:      u.Username,
		Email:         u.Email,
		FirstName:     u.FirstName,
		LastName:      u.LastName,
		Enabled:       u.Enabled,
		EmailVerified: u.Email != "",
	}
	resp, err := k.do(ctx, http.MethodPost, "/users", rep)
	if err != nil {
		return User{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return User{}, fmt.Errorf("create user %q: HTTP %d (%s)", u.Username, resp.StatusCode, snippet(resp))
	}
	// Keycloak returns the new user's id in the Location header.
	id := lastPathSegment(resp.Header.Get("Location"))
	if id == "" {
		// Fall back to a lookup if Location was absent.
		if found, ferr := k.findByUsername(ctx, u.Username); ferr == nil {
			return found, nil
		}
	}
	return User{ID: id, Username: u.Username, Email: u.Email, Enabled: u.Enabled}, nil
}

func (k *Keycloak) findByUsername(ctx context.Context, username string) (User, error) {
	users, err := k.listUsers(ctx, "username="+url.QueryEscape(username)+"&exact=true&max=1")
	if err != nil {
		return User{}, err
	}
	for _, u := range users {
		if strings.EqualFold(u.Username, username) {
			return u, nil
		}
	}
	return User{}, nil
}

func (k *Keycloak) ListUsers(ctx context.Context, query string, max int) ([]User, error) {
	if max <= 0 || max > 200 {
		max = 100
	}
	q := "max=" + strconv.Itoa(max)
	if query != "" {
		q += "&search=" + url.QueryEscape(query)
	}
	return k.listUsers(ctx, q)
}

func (k *Keycloak) listUsers(ctx context.Context, rawQuery string) ([]User, error) {
	resp, err := k.do(ctx, http.MethodGet, "/users?"+rawQuery, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list users: HTTP %d (%s)", resp.StatusCode, snippet(resp))
	}
	var reps []kcUser
	if err := json.NewDecoder(resp.Body).Decode(&reps); err != nil {
		return nil, fmt.Errorf("decode users: %w", err)
	}
	out := make([]User, 0, len(reps))
	for _, r := range reps {
		out = append(out, User{ID: r.ID, Username: r.Username, Email: r.Email, Enabled: r.Enabled})
	}
	return out, nil
}

func (k *Keycloak) SetTemporaryPassword(ctx context.Context, userID, password string) error {
	if userID == "" || password == "" {
		return fmt.Errorf("userID and password are required")
	}
	cred := map[string]any{"type": "password", "value": password, "temporary": true}
	resp, err := k.do(ctx, http.MethodPut, "/users/"+url.PathEscape(userID)+"/reset-password", cred)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("set password: HTTP %d (%s)", resp.StatusCode, snippet(resp))
	}
	return nil
}

// SetUserEnabled toggles a user's enabled flag. Keycloak's update endpoint
// applies only the non-null fields of the representation, so a partial body
// with just "enabled" flips that flag and leaves the rest of the account intact.
func (k *Keycloak) SetUserEnabled(ctx context.Context, userID string, enabled bool) error {
	if userID == "" {
		return fmt.Errorf("userID is required")
	}
	resp, err := k.do(ctx, http.MethodPut, "/users/"+url.PathEscape(userID), map[string]any{"enabled": enabled})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("set user enabled: HTTP %d (%s)", resp.StatusCode, snippet(resp))
	}
	return nil
}

func (k *Keycloak) CreateGroup(ctx context.Context, name string) (Group, error) {
	if name == "" {
		return Group{}, fmt.Errorf("group name is required")
	}
	if existing, err := k.findGroup(ctx, name); err == nil && existing.ID != "" {
		return existing, nil
	}
	resp, err := k.do(ctx, http.MethodPost, "/groups", map[string]string{"name": name})
	if err != nil {
		return Group{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return Group{}, fmt.Errorf("create group %q: HTTP %d (%s)", name, resp.StatusCode, snippet(resp))
	}
	id := lastPathSegment(resp.Header.Get("Location"))
	return Group{ID: id, Name: name, Path: "/" + name}, nil
}

func (k *Keycloak) ListGroups(ctx context.Context) ([]Group, error) {
	resp, err := k.do(ctx, http.MethodGet, "/groups?max=200", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list groups: HTTP %d (%s)", resp.StatusCode, snippet(resp))
	}
	var reps []kcGroup
	if err := json.NewDecoder(resp.Body).Decode(&reps); err != nil {
		return nil, fmt.Errorf("decode groups: %w", err)
	}
	out := make([]Group, 0, len(reps))
	for _, r := range reps {
		out = append(out, Group{ID: r.ID, Name: r.Name, Path: r.Path})
	}
	return out, nil
}

func (k *Keycloak) findGroup(ctx context.Context, name string) (Group, error) {
	groups, err := k.ListGroups(ctx)
	if err != nil {
		return Group{}, err
	}
	for _, g := range groups {
		if strings.EqualFold(g.Name, name) {
			return g, nil
		}
	}
	return Group{}, nil
}

func (k *Keycloak) AddUserToGroup(ctx context.Context, userID, groupID string) error {
	if userID == "" || groupID == "" {
		return fmt.Errorf("userID and groupID are required")
	}
	resp, err := k.do(ctx, http.MethodPut,
		"/users/"+url.PathEscape(userID)+"/groups/"+url.PathEscape(groupID), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("add user to group: HTTP %d (%s)", resp.StatusCode, snippet(resp))
	}
	return nil
}

// FederateDirectory creates an LDAP UserStorageProvider component. The MCP layer
// only reaches this after a human confirms the sensitive auth-config change.
func (k *Keycloak) FederateDirectory(ctx context.Context, d DirectoryFederation) error {
	if d.Name == "" || d.ConnectionURL == "" || d.UsersDN == "" {
		return fmt.Errorf("federation name, connectionUrl and usersDn are required")
	}
	vendor := "other"
	if strings.EqualFold(d.Vendor, "ad") {
		vendor = "ad"
	}
	// A single-value-per-key config map, as Keycloak's component API expects.
	cfg := map[string][]string{
		"enabled":               {"true"},
		"vendor":                {vendor},
		"connectionUrl":         {d.ConnectionURL},
		"usersDn":               {d.UsersDN},
		"authType":              {"simple"},
		"bindDn":                {d.BindDN},
		"bindCredential":        {d.BindCredential},
		"editMode":              {"READ_ONLY"},
		"importEnabled":         {"true"},
		"syncRegistrations":     {"false"},
		"usernameLDAPAttribute": {ldapUsernameAttr(vendor)},
		"rdnLDAPAttribute":      {ldapUsernameAttr(vendor)},
		"uuidLDAPAttribute":     {ldapUUIDAttr(vendor)},
		"userObjectClasses":     {ldapUserObjectClasses(vendor)},
	}
	comp := map[string]any{
		"name":         d.Name,
		"providerId":   "ldap",
		"providerType": "org.keycloak.storage.UserStorageProvider",
		"config":       cfg,
	}
	resp, err := k.do(ctx, http.MethodPost, "/components", comp)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("federate directory %q: HTTP %d (%s)", d.Name, resp.StatusCode, snippet(resp))
	}
	return nil
}

func (k *Keycloak) RemoveUserFromGroup(ctx context.Context, userID, groupID string) error {
	if userID == "" || groupID == "" {
		return fmt.Errorf("userID and groupID are required")
	}
	resp, err := k.do(ctx, http.MethodDelete,
		"/users/"+url.PathEscape(userID)+"/groups/"+url.PathEscape(groupID), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("remove user from group: HTTP %d (%s)", resp.StatusCode, snippet(resp))
	}
	return nil
}

// UnfederateDirectory deletes the LDAP UserStorageProvider component created by
// FederateDirectory, looked up by its name. The MCP layer only reaches this
// after four-eyes approval (it changes who can sign in).
func (k *Keycloak) UnfederateDirectory(ctx context.Context, name string) error {
	if name == "" {
		return fmt.Errorf("federation name is required")
	}
	resp, err := k.do(ctx, http.MethodGet, "/components?type=org.keycloak.storage.UserStorageProvider", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("list federation components: HTTP %d (%s)", resp.StatusCode, snippet(resp))
	}
	var comps []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&comps); err != nil {
		return fmt.Errorf("decode federation components: %w", err)
	}
	id := ""
	for _, c := range comps {
		if strings.EqualFold(c.Name, name) {
			id = c.ID
			break
		}
	}
	if id == "" {
		return fmt.Errorf("no federation source named %q", name)
	}
	del, err := k.do(ctx, http.MethodDelete, "/components/"+url.PathEscape(id), nil)
	if err != nil {
		return err
	}
	defer del.Body.Close()
	if del.StatusCode != http.StatusNoContent && del.StatusCode != http.StatusOK {
		return fmt.Errorf("delete federation %q: HTTP %d (%s)", name, del.StatusCode, snippet(del))
	}
	return nil
}

func ldapUsernameAttr(vendor string) string {
	if vendor == "ad" {
		return "sAMAccountName"
	}
	return "uid"
}

func ldapUUIDAttr(vendor string) string {
	if vendor == "ad" {
		return "objectGUID"
	}
	return "entryUUID"
}

func ldapUserObjectClasses(vendor string) string {
	if vendor == "ad" {
		return "person, organizationalPerson, user"
	}
	return "inetOrgPerson, organizationalPerson"
}

// kcUser/kcGroup are the subset of Keycloak's representations Beamhall reads.
type kcUser struct {
	ID            string `json:"id,omitempty"`
	Username      string `json:"username"`
	Email         string `json:"email,omitempty"`
	FirstName     string `json:"firstName,omitempty"`
	LastName      string `json:"lastName,omitempty"`
	Enabled       bool   `json:"enabled"`
	EmailVerified bool   `json:"emailVerified,omitempty"`
}

type kcGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Path string `json:"path"`
}

// lastPathSegment returns the final segment of a URL/path (the id Keycloak puts
// in the Location header on create).
func lastPathSegment(loc string) string {
	loc = strings.TrimRight(loc, "/")
	if i := strings.LastIndex(loc, "/"); i >= 0 {
		return loc[i+1:]
	}
	return loc
}

// snippet returns a short, bounded copy of an error response body for messages.
func snippet(resp *http.Response) string {
	buf := make([]byte, 256)
	n, _ := resp.Body.Read(buf)
	return strings.TrimSpace(string(buf[:n]))
}
