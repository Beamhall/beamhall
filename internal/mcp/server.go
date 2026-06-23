// Package mcp is Beamhall's agent-facing surface: the remote MCP server
// (official modelcontextprotocol/go-sdk, Streamable HTTP) exposing the PLAN
// §5.7 tool contract. It runs in the same binary as the backplane; the auth
// layer (internal/auth) authenticates tokens at the HTTP boundary and this
// package maps the authenticated principal to a registered Identity, gates
// each tool on its coarse OAuth scope, and calls the orchestrator — which is
// the single authorization point (PEP) and audit writer. Tools return handles
// and intents, never credentials (PLAN §6).
package mcp

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	"github.com/Beamhall/beamhall/internal/auth"
	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/driver"
	"github.com/Beamhall/beamhall/internal/identityadmin"
	"github.com/Beamhall/beamhall/internal/orch"
	"github.com/Beamhall/beamhall/internal/store"
)

// Backplane is the slice of the orchestrator the tools call
// (*orch.Orchestrator satisfies it).
type Backplane interface {
	CreateBeam(ctx context.Context, actor orch.Actor, beamhallID domain.ID, slug, displayName, runtimeHint string) (*domain.Beam, error)
	DeployBeam(ctx context.Context, actor orch.Actor, beamhallID, beamID domain.ID, req orch.DeployRequest) (*domain.Beam, error)
	DeployBeamFromSource(ctx context.Context, actor orch.Actor, beamhallID, beamID domain.ID, srcDir string) (*domain.Beam, error)
	SetSecret(ctx context.Context, actor orch.Actor, beamhallID, beamID domain.ID, key string, value []byte) error
	CreateDatabase(ctx context.Context, actor orch.Actor, beamhallID, beamID domain.ID, name string) (string, error)
	ShowLogs(ctx context.Context, actor orch.Actor, beamhallID, beamID domain.ID, opts driver.LogOptions) ([]byte, error)
	PausePreview(ctx context.Context, actor orch.Actor, beamhallID, beamID domain.ID) error
	ResumePreview(ctx context.Context, actor orch.Actor, beamhallID, beamID domain.ID) (string, error)
	PromoteToLive(ctx context.Context, actor orch.Actor, beamhallID, beamID domain.ID) (string, error)
	PromoteApprovalEnabled() bool
	RequestPromotion(ctx context.Context, actor orch.Actor, beamhallID, beamID domain.ID) (domain.PromotionRequest, error)
	ListPendingPromotions(ctx context.Context, actor orch.Actor, beamhallID domain.ID) ([]domain.PromotionRequest, error)
	ApprovePromotion(ctx context.Context, actor orch.Actor, requestID domain.ID) (string, error)
	RejectPromotion(ctx context.Context, actor orch.Actor, requestID domain.ID, reason string) error
	RollbackBeam(ctx context.Context, actor orch.Actor, beamhallID, beamID, targetReleaseID domain.ID) (string, error)
	ArchiveBeam(ctx context.Context, actor orch.Actor, beamhallID, beamID domain.ID) error
	DestroyBeam(ctx context.Context, actor orch.Actor, beamhallID, beamID domain.ID) error
	ShowMetrics(ctx context.Context, actor orch.Actor, beamhallID, beamID domain.ID) (driver.Stats, error)

	// IT-structural + owned-IdP administration (the admin_* tool family,
	// admin:it scope). These reuse the orchestrator's PEP/audit so the MCP
	// admin surface is a thin client over the same enforcement as the Admin
	// console.
	CreateBeamhall(ctx context.Context, actor orch.Actor, spec orch.NewBeamhallSpec) (*domain.Beamhall, error)
	AdminListBeamhalls(ctx context.Context, actor orch.Actor) ([]domain.Beamhall, error)
	AdminBeamhallView(ctx context.Context, actor orch.Actor, slug string) (*orch.BeamhallView, error)
	SetEgress(ctx context.Context, actor orch.Actor, beamhallID domain.ID, mode domain.EgressMode, allowlist []string) error
	RegisterIdentity(ctx context.Context, actor orch.Actor, issuer, subject, email, displayName string) (*domain.Identity, error)
	GrantMembership(ctx context.Context, actor orch.Actor, identityID, beamhallID domain.ID, role domain.MembershipRole) error
	AdminListIdentities(ctx context.Context, actor orch.Actor) ([]domain.Identity, error)
	IdentityAdminEnabled() bool
	AdminCreateUser(ctx context.Context, actor orch.Actor, u identityadmin.NewUser) (identityadmin.User, error)
	AdminListUsers(ctx context.Context, actor orch.Actor, query string, max int) ([]identityadmin.User, error)
	AdminSetUserPassword(ctx context.Context, actor orch.Actor, userID, password string) error
	AdminCreateGroup(ctx context.Context, actor orch.Actor, name string) (identityadmin.Group, error)
	AdminListGroups(ctx context.Context, actor orch.Actor) ([]identityadmin.Group, error)
	AdminAddUserToGroup(ctx context.Context, actor orch.Actor, userID, groupID string) error
	// SENSITIVE tier (four-eyes): federation files a request a different IT
	// operator must approve before it executes (PLAN §5.9).
	RequestFederateDirectory(ctx context.Context, actor orch.Actor, d identityadmin.DirectoryFederation) (domain.AdminActionRequest, error)
	ListPendingAdminActions(ctx context.Context, actor orch.Actor) ([]domain.AdminActionRequest, error)
	ApproveAdminAction(ctx context.Context, actor orch.Actor, id domain.ID) (domain.AdminActionRequest, error)
	RejectAdminAction(ctx context.Context, actor orch.Actor, id domain.ID, reason string) error
}

// Directory is the slice of the store the MCP layer reads to resolve the
// caller and tool addressing (*store.Store satisfies it). Slugs resolve
// before the PEP runs — a denied caller learns a slug exists, which is
// acceptable: slugs are internal names, and the denial itself is audited.
type Directory interface {
	GetIdentityByIssuerSubject(ctx context.Context, issuer, subject string) (domain.Identity, error)
	GetBeamhall(ctx context.Context, id domain.ID) (domain.Beamhall, error)
	GetBeamhallBySlug(ctx context.Context, slug string) (domain.Beamhall, error)
	GetBeamBySlug(ctx context.Context, beamhallID domain.ID, slug string) (domain.Beam, error)
	ListMembershipsByIdentity(ctx context.Context, identityID domain.ID) ([]domain.Membership, error)
	ListBeamsByBeamhall(ctx context.Context, beamhallID domain.ID) ([]domain.Beam, error)
	ListRoutesByBeam(ctx context.Context, beamID domain.ID) ([]domain.Route, error)
	ListReleasesByBeam(ctx context.Context, beamID domain.ID) ([]domain.Release, error)
}

// maxTarballBytes caps the source_tarball transport (PLAN §5.5: the tarball
// fallback covers tiny/no-VCS beams; bigger sources use the git remote).
const maxTarballBytes = 8 << 20

// Compile-time checks that the real backplane satisfies the seams.
var (
	_ Backplane = (*orch.Orchestrator)(nil)
	_ Directory = (*store.Store)(nil)
)

// Server is the Beamhall MCP server.
type Server struct {
	bp         Backplane
	dir        Directory
	log        *slog.Logger
	srv        *sdkmcp.Server
	gitMinter  DeployTokenMinter
	gitBaseURL string
	adminRole  string // realm role that elevates to IT admin (in addition to the admin:it scope)
}

// DeployTokenMinter issues beam-scoped git tokens (*gitserver.TokenStore
// satisfies it): Mint = a one-time push token (deploy), MintRead = a
// clone/fetch token (read your own source back).
type DeployTokenMinter interface {
	Mint(beamhall, beam, actor domain.ID) (string, error)
	MintRead(beamhall, beam, actor domain.ID) (string, error)
}

// Option configures the Server.
type Option func(*Server)

// WithLogger sets the slog logger.
func WithLogger(l *slog.Logger) Option { return func(s *Server) { s.log = l } }

// WithGitTransport enables the deploy_beam git-push path: with no inline
// source, deploy_beam mints a token and returns a push remote. gitBaseURL is
// the externally-reachable base (e.g. https://beamhall.acme.internal).
func WithGitTransport(minter DeployTokenMinter, gitBaseURL string) Option {
	return func(s *Server) { s.gitMinter = minter; s.gitBaseURL = strings.TrimRight(gitBaseURL, "/") }
}

// WithAdminRole sets the IdP realm role that elevates a caller to IT admin even
// when the token carries no admin:it scope (the role-gated admin-agent path).
// Empty keeps the scope-only behaviour. Defaults to auth.DefaultAdminRole.
func WithAdminRole(role string) Option { return func(s *Server) { s.adminRole = role } }

// New assembles the MCP server and registers the tool contract.
func New(bp Backplane, dir Directory, version string, opts ...Option) *Server {
	s := &Server{bp: bp, dir: dir, log: slog.Default(), adminRole: auth.DefaultAdminRole}
	for _, opt := range opts {
		opt(s)
	}
	s.srv = sdkmcp.NewServer(&sdkmcp.Implementation{
		Name:    "beamhall",
		Title:   "Beamhall infrastructure backplane",
		Version: version,
	}, nil)
	s.registerTools()
	return s
}

// MCPServer exposes the underlying SDK server (tests, alternate transports).
func (s *Server) MCPServer() *sdkmcp.Server { return s.srv }

// Handler returns the authenticated Streamable HTTP stack for /mcp:
// Origin check → bearer-token validation (401 + WWW-Authenticate pointing at
// the RFC 9728 metadata) → MCP session handling. allowedOrigins lists the
// hostnames browsers may call from (the appliance's own); resourceMetadataURL
// is where MetadataHandler is mounted.
func (s *Server) Handler(verifier sdkauth.TokenVerifier, resourceMetadataURL string, allowedOrigins []string) http.Handler {
	h := sdkmcp.NewStreamableHTTPHandler(
		func(*http.Request) *sdkmcp.Server { return s.srv },
		// beamhalld runs behind the gateway, which presents the appliance's real
		// Host (e.g. beamhall.internal) while dialing beamhalld over loopback. The
		// SDK's loopback DNS-rebinding guard would 403 that legitimate proxied
		// request; auth.CheckOrigin (below) provides rebinding/CSRF protection via
		// the appliance's own Origin allowlist instead.
		&sdkmcp.StreamableHTTPOptions{Logger: s.log, DisableLocalhostProtection: true},
	)
	authed := sdkauth.RequireBearerToken(verifier, &sdkauth.RequireBearerTokenOptions{
		ResourceMetadataURL: resourceMetadataURL,
	})(h)
	return auth.CheckOrigin(allowedOrigins, authed)
}

// MetadataHandler serves the RFC 9728 Protected Resource Metadata document
// (mount at /.well-known/oauth-protected-resource). resourceURI is the
// Beamhall resource identifier (== the token audience); authServers lists the
// IdP issuer(s) clients should authorize against.
func MetadataHandler(resourceURI string, authServers []string) http.Handler {
	return sdkauth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
		Resource:               resourceURI,
		AuthorizationServers:   authServers,
		ScopesSupported:        auth.AllScopes(),
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "Beamhall",
	})
}
