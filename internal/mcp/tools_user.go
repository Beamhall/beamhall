package mcp

import (
	"context"
	"errors"
	"fmt"
	"strings"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Beamhall/beamhall/internal/auth"
	"github.com/Beamhall/beamhall/internal/orch"
)

// The using tier: tools for a person who builds nothing and only needs to
// find the apps their company published to them. Audience-scoped, not
// membership-scoped — these are the only tools whose caller may hold no
// membership at all.

type listAppsArgs struct{}

type describeAppArgs struct {
	App       string `json:"app" jsonschema:"the app's short name, exactly as list_apps returned it"`
	Workspace string `json:"workspace,omitempty" jsonschema:"the owning workspace (team) slug from list_apps; needed only to disambiguate when two teams publish an app with the same name"`
}

type appSummary struct {
	App         string `json:"app"`
	DisplayName string `json:"display_name,omitempty"`
	Description string `json:"description,omitempty"`
	Workspace   string `json:"workspace"`
	URL         string `json:"url,omitempty"`
	Live        bool   `json:"live"`
	SignIn      string `json:"sign_in"` // "company_sso" | "app_managed"
	PublishedAt string `json:"published_at,omitempty"`
}

type listAppsOut struct {
	Apps  []appSummary `json:"apps"`
	Count int          `json:"count"`
}

// appCapabilities is forward-compatible with the brokered tool-call stage:
// today an app is used by opening its URL; agent_tools flips to true when the
// backplane can call into the app on the user's behalf.
type appCapabilities struct {
	Browse     bool `json:"browse"`
	AgentTools bool `json:"agent_tools"`
}

type describeAppOut struct {
	appSummary
	Capabilities appCapabilities `json:"capabilities"`
}

func (s *Server) registerUserTools() {
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "list_apps",
		Description: "See which apps you're allowed to use here — the apps other people in your company have built and published to you on Beamhall (an app is a website/service/internal tool; \"beam\" is Beamhall's word for one, and a \"beamhall\" is the workspace/team that owns it). Start here whenever the user asks what internal tools exist, what they're allowed to use, where a company app lives, or names one (\"the expenses tool\", \"our leave tracker\"). Returns each app's name, what it's for, and its live URL — open that URL in a browser to use the app, signing in with the same company account the user already has. This is a PERSONAL list: it shows only apps IT published to this user (by name, or through a group they're in), never every app on the appliance and never anything still in preview. It grants nothing else — there is no tool here to change, deploy, inspect or read the data of an app someone else built; that requires being on the team that builds it (list_beams). Empty list? Ask IT to publish the app to this user with admin_set_app_audience. For one app's detail, call describe_app.",
	}, s.listApps)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "describe_app",
		Description: "Get the detail of ONE app that's published to you: what it's for, its live URL, which workspace (team) owns and maintains it, how you sign in, and since when it's been available to you. Use it after list_apps, or straight away when the user names an app, before telling them where to go. app is the short name list_apps returned; workspace is optional and only needed when two teams publish an app with the same name. Only apps published to YOU resolve — anything else gets the same \"no app named X is published to you\" answer whether it exists or not, so this is not a way to discover what else runs here. Read-only: seeing an app never lets you change, redeploy or read the internals of it. App misbehaving? That's the owning team. Can't get in, or need access? That's IT.",
	}, s.describeApp)
}

func appLine(v orch.AppView) string {
	name := v.App
	desc := v.Description
	if desc == "" {
		desc = v.DisplayName
	}
	line := fmt.Sprintf("  - %s — %s  (%s)\n", name, desc, v.Workspace)
	if v.Live {
		extra := ""
		if v.SignIn == "company_sso" {
			extra = "   sign in with your company account"
		}
		line += fmt.Sprintf("      %s%s\n", v.URL, extra)
	} else {
		line += "      (not live yet — the team that owns it hasn't put it into production)\n"
	}
	return line
}

func (s *Server) listApps(ctx context.Context, req *sdkmcp.CallToolRequest, _ listAppsArgs) (*sdkmcp.CallToolResult, listAppsOut, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeBeamsUse)
	if err != nil {
		return nil, listAppsOut{}, err
	}
	views, err := s.bp.ListApps(ctx, actor)
	if err != nil {
		return nil, listAppsOut{}, err
	}
	out := listAppsOut{Apps: make([]appSummary, 0, len(views)), Count: len(views)}
	for _, v := range views {
		out.Apps = append(out.Apps, appSummaryOf(v))
	}
	if len(views) == 0 {
		return text("No apps are published to you yet. Ask IT to publish the app you need to you — they do that with admin_set_app_audience, and they'll need your name or a group you belong to. This list only shows apps published TO YOU; it is not the list of everything that exists here, so an empty list does not mean the app is missing."), out, nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "You can use %d app(s):\n\n", len(views))
	for _, v := range views {
		b.WriteString(appLine(v))
	}
	b.WriteString("\nOpen an app's URL in a browser to use it. Call describe_app with an app's name for detail. Expected an app that isn't here? Ask IT to publish it to you — they do that with admin_set_app_audience.")
	return text(b.String()), out, nil
}

func (s *Server) describeApp(ctx context.Context, req *sdkmcp.CallToolRequest, args describeAppArgs) (*sdkmcp.CallToolResult, describeAppOut, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeBeamsUse)
	if err != nil {
		return nil, describeAppOut{}, err
	}
	v, err := s.bp.DescribeApp(ctx, actor, args.App, args.Workspace)
	if err != nil {
		var amb *orch.AmbiguousAppError
		if errors.As(err, &amb) {
			return nil, describeAppOut{}, fmt.Errorf("%d workspaces publish an app named %q: %s. Call describe_app again with workspace set to the one you mean",
				len(amb.Workspaces), amb.App, strings.Join(amb.Workspaces, ", "))
		}
		if errors.Is(err, orch.ErrAppNotPublished) {
			// Identical for a nonexistent app and an unpublished one — this
			// answer must not be an existence oracle.
			return nil, describeAppOut{}, fmt.Errorf("no app named %q is published to you. Call list_apps to see what is, or ask IT to publish it to you (admin_set_app_audience)", args.App)
		}
		return nil, describeAppOut{}, err
	}

	title := v.App
	desc := v.Description
	if desc == "" {
		desc = v.DisplayName
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s — %s\n\n", title, desc)
	if v.Live {
		fmt.Fprintf(&b, "  Open:      %s\n", v.URL)
	} else {
		b.WriteString("  Open:      (not live yet — the owning team hasn't run promote_to_live; ask them)\n")
	}
	fmt.Fprintf(&b, "  Owned by:  %s (the team that builds and maintains it)\n", v.Workspace)
	if v.SignIn == "company_sso" {
		b.WriteString("  Sign in:   your company account (single sign-on) — no separate password\n")
	} else {
		b.WriteString("  Sign in:   handled by the app itself (not company single sign-on)\n")
	}
	fmt.Fprintf(&b, "  Published to you since: %s\n", v.PublishedAt.Format("2006-01-02"))
	b.WriteString("\nOpen the URL in a browser to use it. Beamhall hosts this app and tells you where it is; it does not perform the app's actions for you. Problems with the app itself go to the owning team; access problems go to IT.")

	out := describeAppOut{
		appSummary:   appSummaryOf(v),
		Capabilities: appCapabilities{Browse: true, AgentTools: false},
	}
	return text(b.String()), out, nil
}

func appSummaryOf(v orch.AppView) appSummary {
	return appSummary{
		App:         v.App,
		DisplayName: v.DisplayName,
		Description: v.Description,
		Workspace:   v.Workspace,
		URL:         v.URL,
		Live:        v.Live,
		SignIn:      v.SignIn,
		PublishedAt: v.PublishedAt.Format("2006-01-02"),
	}
}
