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

	// CreateGroup creates a group used to organize users. Idempotent on name.
	CreateGroup(ctx context.Context, name string) (Group, error)
	// ListGroups returns the realm's groups.
	ListGroups(ctx context.Context) ([]Group, error)
	// AddUserToGroup adds a user to a group (membership in the IdP, distinct
	// from Beamhall's own beamhall memberships).
	AddUserToGroup(ctx context.Context, userID, groupID string) error

	// FederateDirectory configures an LDAP/Active Directory user-federation
	// source on the owned IdP, so the customer's existing directory users
	// authenticate without local accounts. This is a SENSITIVE auth-config
	// change (it changes who can sign in to the whole appliance): the MCP layer
	// gates it behind human confirmation.
	FederateDirectory(ctx context.Context, d DirectoryFederation) error
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

// Disabled is the no-op Provider for deployments that bring their own IdP (or
// configure none): authentication still works against the customer's tokens,
// but Beamhall administers nothing.
type Disabled struct{}

var _ Provider = Disabled{}

func (Disabled) Enabled() bool { return false }

func (Disabled) CreateUser(context.Context, NewUser) (User, error) { return User{}, ErrNotEnabled }

func (Disabled) ListUsers(context.Context, string, int) ([]User, error) { return nil, ErrNotEnabled }

func (Disabled) SetTemporaryPassword(context.Context, string, string) error { return ErrNotEnabled }

func (Disabled) CreateGroup(context.Context, string) (Group, error) { return Group{}, ErrNotEnabled }

func (Disabled) ListGroups(context.Context) ([]Group, error) { return nil, ErrNotEnabled }

func (Disabled) AddUserToGroup(context.Context, string, string) error { return ErrNotEnabled }

func (Disabled) FederateDirectory(context.Context, DirectoryFederation) error { return ErrNotEnabled }
