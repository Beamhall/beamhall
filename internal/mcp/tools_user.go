package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Beamhall/beamhall/internal/apptools"
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
	AgentTools  bool   `json:"agent_tools"`
	PublishedAt string `json:"published_at,omitempty"`
}

type listAppsOut struct {
	Apps  []appSummary `json:"apps"`
	Count int          `json:"count"`
}

// appCapabilities: browse is every app's baseline (open the URL);
// agent_tools reports whether the app's live workload answered the app-tools
// capability probe. Advisory — use_app fetches the real menu live either way.
type appCapabilities struct {
	Browse     bool `json:"browse"`
	AgentTools bool `json:"agent_tools"`
}

type describeAppOut struct {
	appSummary
	Capabilities appCapabilities `json:"capabilities"`
}

type useAppArgs struct {
	App       string         `json:"app" jsonschema:"the app's short name, exactly as list_apps returned it"`
	Workspace string         `json:"workspace,omitempty" jsonschema:"the owning workspace (team) slug from list_apps; needed only to disambiguate when two teams publish an app with the same name"`
	Tool      string         `json:"tool,omitempty" jsonschema:"the tool to invoke, from the app's own menu; leave it out to fetch the menu first"`
	Arguments map[string]any `json:"arguments,omitempty" jsonschema:"the tool's arguments as a JSON object matching the input_schema its menu entry declared; only meaningful together with tool"`
}

type useAppToolInfo struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"input_schema,omitempty"`
}

type useAppOut struct {
	App       string           `json:"app"`
	Workspace string           `json:"workspace"`
	Tool      string           `json:"tool,omitempty"`
	Tools     []useAppToolInfo `json:"tools,omitempty"`  // menu fetch
	Result    any              `json:"result,omitempty"` // invocation (the app's own output)
}

func useAppToolInfoOf(t apptools.Tool) useAppToolInfo {
	info := useAppToolInfo{Name: t.Name, Description: t.Description}
	if len(t.InputSchema) > 0 {
		_ = json.Unmarshal(t.InputSchema, &info.InputSchema)
	}
	return info
}

// errAppNotPublished is the ONE refusal for an app the caller cannot see.
// Byte-identical across describe_app and use_app, and identical for a
// nonexistent app and an unpublished one — never an existence oracle.
func errAppNotPublished(app string) error {
	return fmt.Errorf("no app named %q is published to you. Call list_apps to see what is, or ask IT to publish it to you (admin_set_app_audience)", app)
}

func errAppAmbiguous(tool string, amb *orch.AmbiguousAppError) error {
	return fmt.Errorf("%d workspaces publish an app named %q: %s. Call %s again with workspace set to the one you mean",
		len(amb.Workspaces), amb.App, strings.Join(amb.Workspaces, ", "), tool)
}

func (s *Server) registerUserTools() {
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "list_apps",
		Description: "See which apps you're allowed to use here — the apps other people in your company have built and published to you on Beamhall (an app is a website/service/internal tool; \"beam\" is Beamhall's word for one, and a \"beamhall\" is the workspace/team that owns it). Start here whenever the user asks what internal tools exist, what they're allowed to use, where a company app lives, or names one (\"the expenses tool\", \"our leave tracker\"). Returns each app's name, what it's for, and its live URL — open that URL in a browser to use the app, signing in with the same company account the user already has. This is a PERSONAL list: it shows only apps IT published to this user (by name, or through a group they're in), never every app on the appliance and never anything still in preview. It grants nothing else — there is no tool here to change, deploy, inspect or read the data of an app someone else built; that requires being on the team that builds it (list_beams). Empty list? Ask IT to publish the app to this user with admin_set_app_audience. For one app's detail, call describe_app.",
	}, s.listApps)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "describe_app",
		Description: "Get the detail of ONE app that's published to you: what it's for, its live URL, which workspace (team) owns and maintains it, how you sign in, whether it offers agent tools (things you can do for the user via use_app instead of the browser), and since when it's been available to you. Use it after list_apps, or straight away when the user names an app, before telling them where to go. app is the short name list_apps returned; workspace is optional and only needed when two teams publish an app with the same name. Only apps published to YOU resolve — anything else gets the same \"no app named X is published to you\" answer whether it exists or not, so this is not a way to discover what else runs here. Read-only: seeing an app never lets you change, redeploy or read the internals of it. App misbehaving? That's the owning team. Can't get in, or need access? That's IT.",
	}, s.describeApp)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "use_app",
		Description: "Do things WITH an app published to you — not just open it. Apps on Beamhall can expose tools of their own (file a leave request, look up a policy, book a room); this is how you call them for the user. The tools are the APP'S OWN: its team wrote them, Beamhall only relays your call and tells the app who the user is — there is nothing to sign into, no API key, and Beamhall neither vets nor performs what the tool does. Call it with just app (from list_apps) to fetch the app's tool menu; call it again with tool and arguments (a JSON object matching the menu entry's input_schema) to act. An app with no menu is NOT broken — many apps are browser-only (describe_app shows agent_tools, and even that is advisory); an EMPTY menu is also a valid answer. Only live apps answer — \"not live yet\" means the owning team hasn't put it into production. Only apps published to YOU resolve; anything else gets the same \"no app named X is published to you\" answer whether it exists or not. Results are the app's own output — relay them to the user as the app's answer, not Beamhall's. Every call is recorded in the company audit log under the user's identity.",
	}, s.useApp)
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
		if v.AgentTools {
			line += "      offers agent tools — use_app shows its menu\n"
		}
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
			return nil, describeAppOut{}, errAppAmbiguous("describe_app", amb)
		}
		if errors.Is(err, orch.ErrAppNotPublished) {
			return nil, describeAppOut{}, errAppNotPublished(args.App)
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
	if v.AgentTools {
		b.WriteString("  Agent tools: yes — call use_app with this app's name to see what it can do for the user without the browser\n")
	}
	fmt.Fprintf(&b, "  Published to you since: %s\n", v.PublishedAt.Format("2006-01-02"))
	b.WriteString("\nOpen the URL in a browser to use it. Problems with the app itself go to the owning team; access problems go to IT.")

	out := describeAppOut{
		appSummary:   appSummaryOf(v),
		Capabilities: appCapabilities{Browse: true, AgentTools: v.AgentTools},
	}
	return text(b.String()), out, nil
}

func (s *Server) useApp(ctx context.Context, req *sdkmcp.CallToolRequest, args useAppArgs) (*sdkmcp.CallToolResult, useAppOut, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeBeamsUse)
	if err != nil {
		return nil, useAppOut{}, err
	}
	var argBytes []byte
	if len(args.Arguments) > 0 {
		if argBytes, err = json.Marshal(args.Arguments); err != nil {
			return nil, useAppOut{}, fmt.Errorf("arguments do not encode as JSON: %w", err)
		}
	}
	res, err := s.bp.UseApp(ctx, actor, orch.UseAppRequest{
		App: args.App, Workspace: args.Workspace, Tool: args.Tool, Arguments: argBytes,
	})
	if err != nil {
		var amb *orch.AmbiguousAppError
		var ate *orch.AppToolError
		switch {
		case errors.As(err, &amb):
			return nil, useAppOut{}, errAppAmbiguous("use_app", amb)
		case errors.Is(err, orch.ErrAppNotPublished):
			return nil, useAppOut{}, errAppNotPublished(args.App)
		case errors.Is(err, orch.ErrAppNotLive):
			return nil, useAppOut{}, fmt.Errorf("the app %q is not live yet — its tools answer only in production, and the owning team hasn't run promote_to_live. Ask them; describe_app shows the app's status", args.App)
		case errors.Is(err, orch.ErrAppNoTools):
			return nil, useAppOut{}, fmt.Errorf("the app %q does not offer agent tools — it is used in the browser. Call describe_app for its URL and open that instead", args.App)
		case errors.As(err, &ate):
			return nil, useAppOut{}, fmt.Errorf("the app answered HTTP %d to tool %q:\n%s\n\nThis is the app's own refusal or failure, relayed unchanged — the owning team is the right contact if it looks wrong", ate.Status, args.Tool, ate.Body)
		}
		return nil, useAppOut{}, err
	}

	out := useAppOut{App: res.View.App, Workspace: res.View.Workspace, Tool: args.Tool}
	if res.Menu != nil {
		var b strings.Builder
		if len(res.Menu.Tools) == 0 {
			fmt.Fprintf(&b, "The app %q currently lists no tools — a valid answer from the app (its menu can change with its next release), not an error. Use it in the browser instead: describe_app has the URL.", res.View.App)
		} else {
			fmt.Fprintf(&b, "The app %q offers %d tool(s):\n\n", res.View.App, len(res.Menu.Tools))
			for _, tl := range res.Menu.Tools {
				fmt.Fprintf(&b, "  - %s — %s\n", tl.Name, tl.Description)
			}
			b.WriteString("\nCall use_app again with tool set to one of these names and arguments matching its input_schema (in the structured content). These tools are the app's own — Beamhall relays your call and tells the app who the user is.")
		}
		out.Tools = make([]useAppToolInfo, 0, len(res.Menu.Tools))
		for _, tl := range res.Menu.Tools {
			out.Tools = append(out.Tools, useAppToolInfoOf(tl))
		}
		return text(b.String()), out, nil
	}

	body := strings.TrimSpace(string(res.Result))
	if json.Valid(res.Result) {
		var v any
		if json.Unmarshal(res.Result, &v) == nil {
			out.Result = v
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s answered tool %q:\n\n%s\n\nThis is the app's own output, relayed by Beamhall — present it to the user as the app's answer.", res.View.App, args.Tool, body)
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
		AgentTools:  v.AgentTools,
		PublishedAt: v.PublishedAt.Format("2006-01-02"),
	}
}
