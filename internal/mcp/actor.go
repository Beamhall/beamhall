package mcp

import (
	"context"
	"errors"
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Beamhall/beamhall/internal/auth"
	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/orch"
	"github.com/Beamhall/beamhall/internal/store"
)

// resolveActor maps the transport's validated token to the backplane Actor:
// the IdP (issuer, sub) pair must correspond to a registered Identity — IT
// registers identities; an unknown-but-valid token gets nothing. The
// `admin:it` scope marks the IT-admin bypass for the PEP; everything finer
// is membership-driven there.
func (s *Server) resolveActor(ctx context.Context, req *sdkmcp.CallToolRequest, requiredScope string) (orch.Actor, error) {
	if req.Extra == nil || req.Extra.TokenInfo == nil {
		return orch.Actor{}, fmt.Errorf("unauthenticated: no bearer token on this session")
	}
	info := req.Extra.TokenInfo
	// IT-admin elevation comes from the admin:it scope OR a configured realm role
	// (the role-gated admin-agent path: a public client can't request the hidden
	// admin:it scope, but IdP role assignment is naturally user-gated).
	itAdmin := auth.HasScope(info.Scopes, auth.ScopeAdminIT) || auth.HasRole(info, s.adminRole)
	if requiredScope == auth.ScopeAdminIT {
		if !itAdmin {
			return orch.Actor{}, fmt.Errorf("insufficient_scope: this tool requires IT-admin (the %q scope or the %q role)", auth.ScopeAdminIT, s.adminRole)
		}
	} else if !auth.HasScope(info.Scopes, requiredScope) {
		// The agent surfaces this verbatim; "insufficient_scope" is the cue
		// for the client's OAuth step-up flow (PLAN §6).
		return orch.Actor{}, fmt.Errorf("insufficient_scope: this tool requires the %q scope", requiredScope)
	}
	issuer, _ := info.Extra[auth.ExtraIssuer].(string)
	subject, _ := info.Extra[auth.ExtraSubject].(string)
	ident, err := s.dir.GetIdentityByIssuerSubject(ctx, issuer, subject)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return orch.Actor{}, fmt.Errorf("identity %q is not registered on this Beamhall appliance — ask IT to register it", subject)
		}
		return orch.Actor{}, fmt.Errorf("resolve identity: %w", err)
	}
	jti, _ := info.Extra[auth.ExtraJTI].(string)
	return orch.Actor{
		ID:       ident.ID,
		TokenJTI: jti,
		ITAdmin:  itAdmin,
		SourceIP: req.Extra.Header.Get("X-Forwarded-For"),
	}, nil
}

// resolveBeamhall and resolveBeam translate agent-facing slugs to IDs.
func (s *Server) resolveBeamhall(ctx context.Context, slug string) (domain.Beamhall, error) {
	bh, err := s.dir.GetBeamhallBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return domain.Beamhall{}, fmt.Errorf("no beamhall named %q", slug)
		}
		return domain.Beamhall{}, err
	}
	return bh, nil
}

func (s *Server) resolveBeam(ctx context.Context, beamhallID domain.ID, slug string) (domain.Beam, error) {
	beam, err := s.dir.GetBeamBySlug(ctx, beamhallID, slug)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return domain.Beam{}, fmt.Errorf("no beam named %q in this beamhall", slug)
		}
		return domain.Beam{}, err
	}
	return beam, nil
}

// channelURLs returns the beam's active preview and live route URLs as https
// URLs ("" for a channel with no active route — e.g. a paused preview or a beam
// that was never promoted). A dual-channel beam can have both at once.
func (s *Server) channelURLs(ctx context.Context, beamID domain.ID) (preview, live string) {
	routes, err := s.dir.ListRoutesByBeam(ctx, beamID)
	if err != nil {
		return "", ""
	}
	for _, rt := range routes {
		if rt.Status != domain.RouteActive {
			continue
		}
		// Only an explicit live route is production; any other active route is
		// the preview channel.
		if rt.Kind == domain.RouteLive {
			live = "https://" + rt.Hostname
		} else {
			preview = "https://" + rt.Hostname
		}
	}
	return preview, live
}

// activeURL returns the beam's primary active URL — the live (production) URL if
// it has one, otherwise the preview URL ("" if neither is active, e.g. paused).
func (s *Server) activeURL(ctx context.Context, beamID domain.ID) string {
	preview, live := s.channelURLs(ctx, beamID)
	if live != "" {
		return live
	}
	return preview
}
