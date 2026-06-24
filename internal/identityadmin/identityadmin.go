// Package identityadmin is Beamhall's third stable seam, alongside the
// RuntimeDriver interface and the MCP tool contract: administering the identity
// provider Beamhall *owns* (the bundled Keycloak), so the operator can manage
// users, groups, and directory federation through the same MCP channel that
// drives everything else — never a second web console, and never with raw IdP
// credentials in the agent's hands.
//
// The boundary that keeps Beamhall IdP-agnostic: *authentication* validates any
// OIDC token (internal/auth), but *administration* is offered only for the IdP
// Beamhall provisions. For a bring-your-own-IdP deployment (customer Okta/Entra)
// the Provider is Disabled — Beamhall does not administer a corporate directory
// it does not own. The seam lets a different owned-IdP implementation drop in
// later without touching the MCP admin tools, exactly as RuntimeDriver lets a
// new runtime arrive without touching the beam tools.
//
// Credential containment mirrors the rest of Beamhall (PLAN §6): the Provider
// holds the IdP admin credential; the agent only ever sees intents and handles.
package identityadmin

import (
	"context"
	"errors"
)

// ErrNotEnabled is returned by every mutating call on the Disabled provider —
// the deployment points at an IdP Beamhall does not administer (BYO-IdP), or no
// IdP-admin credential is configured.
var ErrNotEnabled = errors.New("IdP administration is not enabled on this Beamhall appliance (no owned/bundled IdP configured)")

// Provider administers the owned IdP. Implementations hold the IdP admin
// credential and translate these intents to the IdP's native admin API; the
// returned types are deliberately IdP-neutral so the MCP tool contract never
// leaks Keycloak (or any IdP) specifics.
type Provider interface {
	// Enabled reports whether IdP administration is available. False means the
	// deployment uses a BYO-IdP (or none is configured) and every mutating call
	// returns ErrNotEnabled.
	Enabled() bool

	// CreateUser provisions a local account in the owned IdP. Idempotent on
	// username: an existing user with the same username is returned unchanged.
	CreateUser(ctx context.Context, u NewUser) (User, error)
	// ListUsers returns users matching an optional free-text query (username,
	// email, name); empty query lists the first page. max bounds the result.
	ListUsers(ctx context.Context, query string, max int) ([]User, error)
	// SetTemporaryPassword sets a one-time password the user must change at next
	// login — the onboarding hand-off for a freshly created account.
	SetTemporaryPassword(ctx context.Context, userID, password string) error
	// SetUserEnabled enables or disables a local account. A disabled account
	// cannot authenticate — the offboarding control that stops short of deleting
	// the user (and the audit/history linkage that deletion would orphan).
	SetUserEnabled(ctx context.Context, userID string, enabled bool) error
	// DeleteUser permanently removes a local account. Prefer SetUserEnabled for
	// reversible offboarding; deletion is for genuine cleanup.
	DeleteUser(ctx context.Context, userID string) error

	// CreateGroup creates a group used to organize users. Idempotent on name.
	CreateGroup(ctx context.Context, name string) (Group, error)
	// ListGroups returns the realm's groups.
	ListGroups(ctx context.Context) ([]Group, error)
	// AddUserToGroup adds a user to a group (membership in the IdP, distinct
	// from Beamhall's own beamhall memberships).
	AddUserToGroup(ctx context.Context, userID, groupID string) error
	// RemoveUserFromGroup removes a user from a group (the AddUserToGroup
	// inverse).
	RemoveUserFromGroup(ctx context.Context, userID, groupID string) error
	// DeleteGroup permanently removes a group (its members are not deleted, only
	// un-grouped).
	DeleteGroup(ctx context.Context, groupID string) error

	// FederateDirectory configures an LDAP/Active Directory user-federation
	// source on the owned IdP, so the customer's existing directory users
	// authenticate without local accounts. This is a SENSITIVE auth-config
	// change (it changes who can sign in to the whole appliance): the MCP layer
	// gates it behind human confirmation.
	FederateDirectory(ctx context.Context, d DirectoryFederation) error
	// UnfederateDirectory removes a federation source by name (the
	// FederateDirectory inverse) — also SENSITIVE (it changes who can sign in).
	UnfederateDirectory(ctx context.Context, name string) error

	// --- OIDC relying-party (per-beam app SSO) administration (PLAN §5.10) ---
	// These let a beam reuse the owned IdP for its own end-user sign-in, the way
	// CreateUser/groups let an operator manage people. The agent never sees the
	// client secret; Beamhall seals it like a database DSN.

	// CreateClient provisions a per-beam OIDC relying party (a confidential
	// client) in the owned IdP and returns its handle + generated secret.
	// Idempotent on ClientID. The returned token audience is the client's OWN id;
	// implementations MUST NOT inject the Beamhall resource URI (ForbiddenAudience)
	// into the client's tokens, and MUST refuse (deleting the half-created client)
	// if any effective mapper/scope would — that audience isolation is what stops
	// an app token from being replayed against the Beamhall backplane (PLAN §5.10).
	CreateClient(ctx context.Context, spec ClientSpec) (Client, error)
	// GetClientSecret reads a client's current secret backplane-side (for sealing
	// into the vault); it is never returned to the agent.
	GetClientSecret(ctx context.Context, clientUUID string) (string, error)
	// RotateClientSecret regenerates a client's secret (incident response) and
	// returns the new value for re-sealing.
	RotateClientSecret(ctx context.Context, clientUUID string) (string, error)
	// SyncRedirectURIs replaces a client's redirect-URI / web-origin allowlist
	// with the given EXACT sets (no wildcards). Set-and-replace, so a stale rotated
	// preview host stops being a valid callback. Takes effect immediately (no
	// redeploy) — the allowlist lives in the IdP, not the injected secret.
	SyncRedirectURIs(ctx context.Context, clientUUID string, redirectURIs, webOrigins []string) error
	// SetClientGroupRoles curates which realm groups a client's tokens may expose
	// (the admin-curated allowlist, IT decision — separation of duties). It is
	// leak-proof by construction: each allowed group becomes a client role mapped
	// from that group and surfaced as a flat `groups` claim, so the client only
	// ever learns groups IT mapped to it. Set-and-replace.
	SetClientGroupRoles(ctx context.Context, clientUUID string, groups []string) error
	// DeleteClient removes a client (archive/destroy cleanup). Idempotent: an
	// already-absent client is success.
	DeleteClient(ctx context.Context, clientUUID string) error
}

// NewUser is the input to CreateUser.
type NewUser struct {
	Username  string
	Email     string
	FirstName string
	LastName  string
	// Enabled defaults to true via CreateUser when the zero value is used by a
	// caller that always wants active accounts; callers set false explicitly to
	// stage a disabled account.
	Enabled bool
}

// User is an IdP-neutral account record.
type User struct {
	ID       string
	Username string
	Email    string
	Enabled  bool
}

// Group is an IdP-neutral group record.
type Group struct {
	ID   string
	Name string
	Path string
}

// DirectoryFederation describes an LDAP/AD user-federation source.
type DirectoryFederation struct {
	// Name labels the federation source in the IdP (e.g. "corp-ad").
	Name string
	// Vendor is the directory kind: "ad" (Active Directory) or "other" (generic
	// LDAP). It selects the IdP's vendor-specific LDAP defaults.
	Vendor string
	// ConnectionURL is the LDAP endpoint, e.g. ldaps://dc1.corp.example:636.
	ConnectionURL string
	// UsersDN is the base DN to search for users, e.g.
	// OU=Beamhall,OU=Users,DC=corp,DC=example.
	UsersDN string
	// BindDN / BindCredential authenticate the IdP to the directory. The
	// credential is held by the Provider and never returned to the agent.
	BindDN         string
	BindCredential string
}

// ClientSpec is the IdP-neutral input to CreateClient — a per-beam OIDC relying
// party. RedirectURIs/WebOrigins are EXACT (no wildcards); the caller keeps them
// current via SyncRedirectURIs across the beam's URL lifecycle.
type ClientSpec struct {
	// ClientID is the stable per-beam-channel identifier, e.g.
	// "beam-<beamhall>-<beam>-preview". The client's tokens carry this as `aud`.
	ClientID string
	// RedirectURIs / WebOrigins are exact callback URLs / CORS origins.
	RedirectURIs []string
	WebOrigins   []string
	// AccessTokenTTLSeconds bounds the client's access-token lifespan (0 = realm
	// default); the regulated profile uses a short value.
	AccessTokenTTLSeconds int
	// ForbiddenAudience is the Beamhall resource URI (cfg.Audience) that must NOT
	// appear in this client's `aud`. CreateClient post-asserts its absence and
	// refuses otherwise — the audience-isolation invariant (PLAN §5.10).
	ForbiddenAudience string
}

// Client is a created relying party. Secret is the confidential client secret,
// read backplane-side for sealing and never returned to the agent.
type Client struct {
	UUID     string // the IdP's internal client id, for subsequent admin calls
	ClientID string
	Secret   string
}

// Disabled is the no-op Provider for deployments that bring their own IdP (or
// configure none): authentication still works against the customer's tokens,
// but Beamhall administers nothing.
type Disabled struct{}

var _ Provider = Disabled{}

func (Disabled) Enabled() bool { return false }

func (Disabled) CreateUser(context.Context, NewUser) (User, error) { return User{}, ErrNotEnabled }

func (Disabled) ListUsers(context.Context, string, int) ([]User, error) { return nil, ErrNotEnabled }

func (Disabled) SetTemporaryPassword(context.Context, string, string) error { return ErrNotEnabled }

func (Disabled) SetUserEnabled(context.Context, string, bool) error { return ErrNotEnabled }

func (Disabled) DeleteUser(context.Context, string) error { return ErrNotEnabled }

func (Disabled) CreateGroup(context.Context, string) (Group, error) { return Group{}, ErrNotEnabled }

func (Disabled) ListGroups(context.Context) ([]Group, error) { return nil, ErrNotEnabled }

func (Disabled) AddUserToGroup(context.Context, string, string) error { return ErrNotEnabled }

func (Disabled) RemoveUserFromGroup(context.Context, string, string) error { return ErrNotEnabled }

func (Disabled) DeleteGroup(context.Context, string) error { return ErrNotEnabled }

func (Disabled) FederateDirectory(context.Context, DirectoryFederation) error { return ErrNotEnabled }

func (Disabled) UnfederateDirectory(context.Context, string) error { return ErrNotEnabled }

func (Disabled) CreateClient(context.Context, ClientSpec) (Client, error) {
	return Client{}, ErrNotEnabled
}

func (Disabled) GetClientSecret(context.Context, string) (string, error) { return "", ErrNotEnabled }

func (Disabled) RotateClientSecret(context.Context, string) (string, error) { return "", ErrNotEnabled }

func (Disabled) SyncRedirectURIs(context.Context, string, []string, []string) error {
	return ErrNotEnabled
}

func (Disabled) SetClientGroupRoles(context.Context, string, []string) error { return ErrNotEnabled }

func (Disabled) DeleteClient(context.Context, string) error { return ErrNotEnabled }
