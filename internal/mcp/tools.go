package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Beamhall/beamhall/internal/auth"
	"github.com/Beamhall/beamhall/internal/build"
	"github.com/Beamhall/beamhall/internal/diagnose"
	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/driver"
	"github.com/Beamhall/beamhall/internal/orch"
)

// The tool contract per PLAN §5.7. Argument structs carry jsonschema
// descriptions — they are the agent's documentation.

type createBeamArgs struct {
	Beamhall    string `json:"beamhall" jsonschema:"slug of the beamhall (workspace) to create the beam in"`
	Slug        string `json:"slug" jsonschema:"DNS-safe beam name: lowercase letters digits and inner hyphens; becomes the live subdomain"`
	DisplayName string `json:"display_name,omitempty" jsonschema:"human-readable beam name"`
	RuntimeHint string `json:"runtime_hint,omitempty" jsonschema:"expected runtime: auto|node|python|static (buildpacks auto-detect; this is a hint)"`
}

type beamOut struct {
	Beam     string `json:"beam"`
	Beamhall string `json:"beamhall"`
	State    string `json:"state"` // preview channel state
	Mode     string `json:"mode"`  // "live" once a live channel exists, else "preview"
	URL      string `json:"url,omitempty"`
	// Dual-channel detail: a beam runs a preview channel and, once promoted, a
	// separate pinned live channel. URL above is the primary (live if present).
	PreviewURL string `json:"preview_url,omitempty"`
	LiveURL    string `json:"live_url,omitempty"`
	LiveState  string `json:"live_state,omitempty"` // "live" when production is up
}

type deployBeamArgs struct {
	Beamhall string `json:"beamhall" jsonschema:"beamhall slug"`
	Beam     string `json:"beam" jsonschema:"beam slug (create_beam first)"`
	// Source of truth is a git push (call deploy_beam with no source to get the
	// one-time remote). source_tarball is a fallback; image_ref pins a prebuilt image.
	SourceTarball string `json:"source_tarball,omitempty" jsonschema:"FALLBACK ONLY — prefer the git push remote (call deploy_beam with no source). base64-encoded gzip tarball of the source tree (max 8 MB compressed), built with buildpacks (Dockerfile ignored). Use only when a git client is unavailable or the git push isn't working"`
	ImageRef      string `json:"image_ref,omitempty" jsonschema:"pre-built image reference (advanced; requires image_digest)"`
	ImageDigest   string `json:"image_digest,omitempty" jsonschema:"sha256:... content digest pinning image_ref"`
}

type deployOut struct {
	beamOut
	ImageDigest string `json:"image_digest,omitempty"`
	// Set on the no-source git path so the remote/command reach clients that
	// consume structured output only (not the text block).
	GitRemote   string `json:"git_remote,omitempty"`   // push URL, no credentials
	PushCommand string `json:"push_command,omitempty"` // ready-to-run git push with the one-time token
}

type beamArgs struct {
	Beamhall string `json:"beamhall" jsonschema:"beamhall slug"`
	Beam     string `json:"beam" jsonschema:"beam slug"`
}

type getRepoArgs struct {
	Beamhall string `json:"beamhall" jsonschema:"beamhall slug"`
	Beam     string `json:"beam" jsonschema:"beam slug"`
}

type listBeamsArgs struct {
	Beamhall string `json:"beamhall,omitempty" jsonschema:"optional beamhall slug to filter to a single beamhall; omit to list across all your beamhalls"`
}

type beamSummary struct {
	Beam        string `json:"beam"`
	DisplayName string `json:"display_name,omitempty"`
	Mode        string `json:"mode"`
	State       string `json:"state"`
	URL         string `json:"url,omitempty"`
	PreviewURL  string `json:"preview_url,omitempty"`
	LiveURL     string `json:"live_url,omitempty"`
	LiveState   string `json:"live_state,omitempty"`
}

type hallBeams struct {
	Beamhall string        `json:"beamhall"`
	Role     string        `json:"role"`
	Beams    []beamSummary `json:"beams"`
}

type listBeamsOut struct {
	Beamhalls []hallBeams `json:"beamhalls"`
}

type repoOut struct {
	Beam     string `json:"beam"`
	Beamhall string `json:"beamhall"`
	Remote   string `json:"remote"`
	CloneURL string `json:"clone_url"`
}

type createDatabaseArgs struct {
	Beamhall string `json:"beamhall" jsonschema:"beamhall slug"`
	Beam     string `json:"beam" jsonschema:"beam slug the database belongs to"`
	Name     string `json:"name" jsonschema:"logical database name, e.g. main; lowercase letters digits and inner hyphens"`
}

type setSecretArgs struct {
	Beamhall string `json:"beamhall" jsonschema:"beamhall slug"`
	Beam     string `json:"beam,omitempty" jsonschema:"beam slug; omit for a beamhall-wide secret visible to every beam in it"`
	Key      string `json:"key" jsonschema:"secret name, e.g. API_TOKEN; surfaces as the file /run/secrets/<key> inside the workload"`
	Value    string `json:"value" jsonschema:"secret value; write-only — no tool can read it back"`
}

type showLogsArgs struct {
	Beamhall  string `json:"beamhall" jsonschema:"beamhall slug"`
	Beam      string `json:"beam" jsonschema:"beam slug"`
	TailLines int    `json:"tail_lines,omitempty" jsonschema:"number of trailing log lines (default 200)"`
}

func text(msg string) *sdkmcp.CallToolResult {
	return &sdkmcp.CallToolResult{Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: msg}}}
}

func (s *Server) registerTools() {
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "list_beams",
		Description: "Discover what already exists: list your workspaces (beamhalls) and the apps (beams — apps/websites/services/APIs/projects) in them. Each beam shows its preview channel (the URL you iterate on) and, once promoted, its separate live/production URL. Start here whenever the user wants to deploy, host, or work on an app, and on a new machine or session before deploy_beam / get_repo. Scoped to your memberships — you only see beamhalls you're a member of. Archived beams are not listed.",
	}, s.listBeams)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "create_beam",
		Description: "Register a new beam — the user's app/website/service/API/project — in a beamhall (workspace). This is how you stand up a new app in this environment (not local hosting, not an external provider). Returns its state; this does NOT ship any code — deploy_beam does that (call deploy_beam with no source for the preferred one-time git-push remote). Shelve a beam that didn't pan out with archive_beam.",
	}, s.createBeam)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "deploy_beam",
		Description: "Build and deploy a beam (the user's app/site/service) with Cloud Native Buildpacks (no Dockerfile). This is the sanctioned way to deploy and host apps here — use it instead of external platforms (Fly.io, Vercel, Netlify, Heroku, Render, Neon, Supabase, the cloud CLIs, …) or local one-off hosting. PREFERRED: call with NO source_tarball to get a one-time `git push` remote — pushing builds and deploys, and is the right path for the edit→redeploy loop. Use source_tarball (base64 gzip, ≤8 MB) only as a fallback when no git client is available or the push isn't working; or pass image_ref+image_digest for a prebuilt image. Streams build progress. Returns the preview URL.",
	}, s.deployBeam)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "get_repo",
		Description: "Get a `git clone` command for a beam's managed source repo — Beamhall is the home of the beam's code. Use it to restore or sync a project on a new machine before editing. Returns a one-time, read-only, beam-scoped clone token (expires shortly; call again for a fresh one). The repo is the same one deploy_beam pushes to.",
	}, s.getRepo)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "create_database",
		Description: "Provision a managed PostgreSQL database for a beam. Returns the secret key whose file (/run/secrets/<key>) holds the connection string inside the workload after the next deploy — the connection string itself is never returned.",
	}, s.createDatabase)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "provision_auth",
		Description: "Give this beam COMPANY SIGN-IN using the same employee directory your Beamhall already uses — users log in with the accounts they have here, you configure NO identity-provider settings, and you NEVER see any secret (exactly like create_database hands you a database whose password you never see). SCOPE: this is for INTERNAL/employee SSO only — it is NOT a way to build public or customer self-signup. For an app where outside users create their OWN accounts (a signup form, a customer/candidate portal), build that yourself: keep those users in your own database (create_database) with your own login flow; do NOT use provision_auth for them. After the next deploy_beam your app reads three files — /run/secrets/OIDC_ISSUER, /run/secrets/OIDC_CLIENT_ID, /run/secrets/OIDC_CLIENT_SECRET — and runs a standard OpenID Connect code+PKCE flow with any off-the-shelf library. Derive your redirect URL from the incoming request Host and read the client id from its FILE (never hardcode) so one image works on every preview URL and in production. Beamhall keeps your login URLs correct automatically as the preview URL changes, and gives preview and production fully isolated credentials. Idempotent. If this Beamhall uses an external corporate IdP it does not administer, this tool is unavailable and tells you how to wire sign-in with set_secret instead. Credentials appear only AFTER the next deploy_beam (no hot reload).",
	}, s.provisionAuth)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "show_auth",
		Description: "Read-only: show whether this beam has company sign-in provisioned, in which mode, which channels (preview/production) have a login, the audience each mints, the login URLs Beamhall is keeping in sync, and which employee groups an admin has allowed into its tokens — without ever revealing a secret value. Use it to inspect the wiring or debug a callback. The group allowlist is set by IT (admin_set_auth_groups), not the builder.",
	}, s.showAuth)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "provision_email",
		Description: "Give this beam OUTBOUND EMAIL so your app can send mail (sign-up/verification links, notifications, password resets) — you configure NO mail provider and NEVER see any credential (exactly like create_database hands you a database whose password you never see). Send through Beamhall; do NOT wire Mailgun/SendGrid/SES/Postmark or raw SMTP into the app yourself — that leaks a credential and bypasses the audit trail. After the next deploy_beam your app reads five files — /run/secrets/SMTP_HOST, /run/secrets/SMTP_PORT, /run/secrets/SMTP_USER, /run/secrets/SMTP_PASS, and /run/secrets/SMTP_CA — and sends with any standard SMTP library; Beamhall relays to the company's real mail provider for you. Connect to SMTP_HOST:SMTP_PORT, issue STARTTLS verifying against SMTP_CA (the broker's certificate), then AUTH with SMTP_USER/SMTP_PASS — STARTTLS is required by strict clients like Go's net/smtp before they will authenticate. IMPORTANT: a newly provisioned beam may send from NO addresses until an IT admin allows a sender domain/address with admin_set_email_senders (separation of duties) — until then the relay rejects sends; ask IT for the From address you need. Idempotent. If this appliance has no mail provider configured, this tool is unavailable and tells you how to wire SMTP with set_secret instead. Credentials appear only AFTER the next deploy_beam (no hot reload).",
	}, s.provisionEmail)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "show_email",
		Description: "Read-only: show whether this beam has outbound email provisioned, the in-hall SMTP host/port it sends through, its sender username, which From addresses/domains IT has allowed it to send as, and its per-day rate limit — without ever revealing the SMTP password. Use it to inspect the wiring or debug a rejected send. The sender allowlist is set by IT (admin_set_email_senders), not the builder.",
	}, s.showEmail)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "set_secret",
		Description: "Store a secret (write-only). It surfaces as the file /run/secrets/<key> inside the workload on the next deploy. There is no tool to read secrets back.",
	}, s.setSecret)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "show_logs",
		Description: "Fetch recent logs from a beam's running workload (sanitized: secret values are redacted).",
	}, s.showLogs)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "pause_preview",
		Description: "Pause a preview beam: the workload freezes and its preview URL is retired. The inverse is resume_preview, which wakes it on a NEW URL (the retired one stays dead).",
	}, s.pausePreview)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "resume_preview",
		Description: "Resume a paused preview beam (the inverse of pause_preview). It gets a NEW random preview URL (the old one stays dead).",
	}, s.resumePreview)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "promote_to_live",
		Description: "Ship the beam's CURRENT PREVIEW BUILD to production. Pins a separate live channel (stable URL, no auto-pause, its own database) to exactly what the preview is running now. Your preview channel keeps running and iterating — promote again to ship the next version (repeatable, zero-downtime; a failed promote leaves production untouched). Consumes one live slot on the first promote. When the IT-approval gate is on this does NOT go live directly — it files a promotion request (the reply carries the request_id) that a DIFFERENT IT operator must approve via approve_promotion (four-eyes); the requester cannot approve their own.",
	}, s.promoteToLive)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "rollback",
		Description: "Roll PRODUCTION back to a previous live release WITHOUT rebuilding — the prior image and config come straight back up against the live database. Targets the live channel; the preview channel is unaffected (to undo a preview change, just push again). Requires a beam that has been promoted.",
	}, s.rollback)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "list_pending_promotions",
		Description: "IT only: list promotion requests awaiting approval in a beamhall (when the IT-approval gate is enabled).",
	}, s.listPendingPromotions)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "approve_promotion",
		Description: "IT only: approve a pending promotion request and take the beam live. The approver must differ from the requester (four-eyes).",
	}, s.approvePromotion)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "reject_promotion",
		Description: "IT only: reject a pending promotion request (the beam stays in preview).",
	}, s.rejectPromotion)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "show_metrics",
		Description: "Current resource usage (CPU, memory, network) of a beam's running workload.",
	}, s.showMetrics)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "archive_beam",
		Description: "Archive (shelve) a PREVIEW beam whose idea didn't pan out — e.g. the team didn't approve it. Stops the workload, retires its URL, frees its quota slot and name. Builder-accessible (your own preview beams). Terminal but non-destructive: source and history are kept; to start again, create a new beam. Live beams must be retired by IT via destroy_beam.",
	}, s.archiveBeam)
	sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
		Name:        "destroy_beam",
		Description: "Permanently retire a beam (preview or LIVE): stop and remove its workload, retire its URL, free its quota slot. Terminal and IT-gated (use it to tear down a live beam). Source and history are retained; the name becomes available for reuse. Builders shelve their own previews with archive_beam instead.",
	}, s.destroyBeam)

	// IT lifecycle over MCP (admin:it): onboarding + owned-IdP administration.
	s.registerAdminTools()

	// Contract placeholders (PLAN §5.7): present so agents get a clear answer
	// instead of an unknown-tool error; enabled in a future build.
	for _, name := range []string{"create_object_store", "create_queue"} {
		n := name
		sdkmcp.AddTool(s.srv, &sdkmcp.Tool{
			Name:        n,
			Description: "Not enabled in this build of Beamhall (fast-follow).",
		}, func(ctx context.Context, req *sdkmcp.CallToolRequest, args struct{}) (*sdkmcp.CallToolResult, any, error) {
			return nil, nil, fmt.Errorf("%s is not enabled in this build of Beamhall", n)
		})
	}
}

func (s *Server) createBeam(ctx context.Context, req *sdkmcp.CallToolRequest, args createBeamArgs) (*sdkmcp.CallToolResult, beamOut, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeBeamsWrite)
	if err != nil {
		return nil, beamOut{}, err
	}
	bh, err := s.resolveBeamhall(ctx, args.Beamhall)
	if err != nil {
		return nil, beamOut{}, err
	}
	beam, err := s.bp.CreateBeam(ctx, actor, bh.ID, args.Slug, args.DisplayName, args.RuntimeHint)
	if err != nil {
		return nil, beamOut{}, err
	}
	out := beamOut{Beam: beam.Slug, Beamhall: bh.Slug, State: string(beam.State), Mode: string(beam.Mode)}
	return text(fmt.Sprintf("beam %q created in beamhall %q (state %s). Deploy it with deploy_beam — call it with no source to get a one-time git push remote (preferred).",
		beam.Slug, bh.Slug, beam.State)), out, nil
}

func (s *Server) deployBeam(ctx context.Context, req *sdkmcp.CallToolRequest, args deployBeamArgs) (*sdkmcp.CallToolResult, deployOut, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeBeamsDeploy)
	if err != nil {
		return nil, deployOut{}, err
	}
	bh, err := s.resolveBeamhall(ctx, args.Beamhall)
	if err != nil {
		return nil, deployOut{}, err
	}
	beam, err := s.resolveBeam(ctx, bh.ID, args.Beam)
	if err != nil {
		return nil, deployOut{}, err
	}

	progress := newProgressNotifier(ctx, req)
	defer progress.Flush()

	var deployed *domain.Beam
	switch {
	case args.SourceTarball != "" && (args.ImageRef != "" || args.ImageDigest != ""):
		return nil, deployOut{}, fmt.Errorf("give either source_tarball or image_ref+image_digest, not both")

	case args.SourceTarball != "":
		raw, err := base64.StdEncoding.DecodeString(args.SourceTarball)
		if err != nil {
			return nil, deployOut{}, fmt.Errorf("source_tarball is not valid base64: %w", err)
		}
		if len(raw) > maxTarballBytes {
			return nil, deployOut{}, fmt.Errorf("source_tarball exceeds %d MB; push to the beam's managed git remote instead", maxTarballBytes>>20)
		}
		srcDir, err := os.MkdirTemp("", "beamhall-src-*")
		if err != nil {
			return nil, deployOut{}, err
		}
		defer os.RemoveAll(srcDir)
		if err := extractTarGz(bytes.NewReader(raw), srcDir); err != nil {
			return nil, deployOut{}, err
		}
		progress.Stage("source received; building with buildpacks (this can take a few minutes on a first build)")
		bctx := ctx
		if progress != nil {
			bctx = build.WithProgress(ctx, progress)
		}
		deployed, err = s.bp.DeployBeamFromSource(bctx, actor, bh.ID, beam.ID, srcDir)
		if err != nil {
			return nil, deployOut{}, err
		}

	case args.ImageDigest != "":
		progress.Stage("deploying pinned image")
		deployed, err = s.bp.DeployBeam(ctx, actor, bh.ID, beam.ID, orch.DeployRequest{
			ImageRef: args.ImageRef, ImageDigest: args.ImageDigest,
		})
		if err != nil {
			return nil, deployOut{}, err
		}

	case s.gitMinter != nil:
		// No inline source: return a one-time git push remote. The push
		// itself builds and deploys (PLAN §5.5).
		tok, err := s.gitMinter.Mint(bh.ID, beam.ID, actor.ID)
		if err != nil {
			return nil, deployOut{}, err
		}
		remote, scheme, hostPath := s.gitRemote(bh.Slug, beam.Slug)
		// pack.window=0 (+ --no-thin): send a DELTA-FREE, self-contained pack.
		// go-git's receive-pack cannot reliably resolve REF_DELTA objects
		// ("reference delta not found") — it broke incremental redeploys even
		// with --no-thin alone. Disabling delta compression sidesteps it
		// entirely; the source is tiny so the larger pack is irrelevant (lab finding).
		cmd := fmt.Sprintf("git -c pack.window=0 push --no-thin %sx-access-token:%s@%s HEAD:main", scheme, tok, hostPath)
		msg := fmt.Sprintf("Push your source to build and deploy %q. From your project directory, commit your code, then run:\n\n  %s\n\n"+
			"Build progress streams back as \"remote:\" lines and the preview URL prints on success. "+
			"If the build fails, fix your code, commit, and run the SAME command again — the token stays valid until a deploy succeeds (or it expires shortly). "+
			"For a later, separate deploy, call deploy_beam again for a fresh command. "+
			"(Fallback, only if you can't use git: call deploy_beam with source_tarball for a direct upload.)",
			beam.Slug, cmd)
		out := deployOut{beamOut: beamOut{Beam: beam.Slug, Beamhall: bh.Slug,
			State: string(beam.State), Mode: string(beam.Mode)},
			GitRemote: remote, PushCommand: cmd}
		return text(msg), out, nil

	default:
		return nil, deployOut{}, fmt.Errorf("deploy_beam needs source_tarball (preferred) or image_ref+image_digest")
	}

	previewURL, liveURL := s.channelURLs(ctx, deployed.ID)
	out := deployOut{
		beamOut:     s.beamChannels(*deployed, bh.Slug, previewURL, liveURL),
		ImageDigest: args.ImageDigest,
	}
	msg := fmt.Sprintf("beam %q deployed to its preview channel (state %s)", deployed.Slug, deployed.State)
	if previewURL != "" {
		msg += " — preview at " + previewURL
	}
	msg += ". Previews auto-pause after their idle window; resume_preview wakes them on a new URL."
	if deployed.Mode == domain.ModeLive && liveURL != "" {
		msg += fmt.Sprintf(" Production is unchanged at %s (promote_to_live again to ship this build).", liveURL)
	}
	return text(msg), out, nil
}

// beamChannels builds a beamOut describing both of a beam's channels: State and
// the preview URL track the preview channel the builder iterates on; LiveState
// and the live URL track the pinned production channel (empty until promoted).
// URL is the primary address (live if promoted, else preview).
func (s *Server) beamChannels(beam domain.Beam, hallSlug, previewURL, liveURL string) beamOut {
	primary := previewURL
	if liveURL != "" {
		primary = liveURL
	}
	return beamOut{
		Beam: beam.Slug, Beamhall: hallSlug,
		State: string(beam.State), Mode: string(beam.Mode),
		URL: primary, PreviewURL: previewURL, LiveURL: liveURL,
		LiveState: string(beam.LiveState),
	}
}

// gitRemote builds the externally-reachable remote URL for a beam's managed
// repo and splits its scheme, so a token can be embedded as basic-auth in a
// ready-to-run git command.
func (s *Server) gitRemote(hallSlug, beamSlug string) (remote, scheme, hostPath string) {
	remote = fmt.Sprintf("%s/git/%s/%s.git", s.gitBaseURL, hallSlug, beamSlug)
	scheme, hostPath = "https://", remote
	if rest, ok := strings.CutPrefix(remote, "http://"); ok {
		scheme, hostPath = "http://", rest
	} else if rest, ok := strings.CutPrefix(remote, "https://"); ok {
		hostPath = rest
	}
	return remote, scheme, hostPath
}

func (s *Server) listBeams(ctx context.Context, req *sdkmcp.CallToolRequest, args listBeamsArgs) (*sdkmcp.CallToolResult, listBeamsOut, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeBeamhallsRead)
	if err != nil {
		return nil, listBeamsOut{}, err
	}
	// Membership-scoped: an actor sees only beamhalls it belongs to (the
	// EscapeItsBeamhall isolation property — no global enumeration). IT's
	// cross-beamhall view is the Admin console, not this tool.
	mships, err := s.dir.ListMembershipsByIdentity(ctx, actor.ID)
	if err != nil {
		return nil, listBeamsOut{}, err
	}
	var out listBeamsOut
	var lines []string
	for _, m := range mships {
		bh, err := s.dir.GetBeamhall(ctx, m.BeamhallID)
		if err != nil {
			continue
		}
		if args.Beamhall != "" && bh.Slug != args.Beamhall {
			continue
		}
		beams, err := s.dir.ListBeamsByBeamhall(ctx, bh.ID)
		if err != nil {
			return nil, listBeamsOut{}, err
		}
		hb := hallBeams{Beamhall: bh.Slug, Role: string(m.Role)}
		for _, b := range beams {
			previewURL, liveURL := s.channelURLs(ctx, b.ID)
			primary := previewURL
			if liveURL != "" {
				primary = liveURL
			}
			hb.Beams = append(hb.Beams, beamSummary{
				Beam: b.Slug, DisplayName: b.DisplayName,
				Mode: string(b.Mode), State: string(b.State), URL: primary,
				PreviewURL: previewURL, LiveURL: liveURL, LiveState: string(b.LiveState),
			})
		}
		out.Beamhalls = append(out.Beamhalls, hb)

		lines = append(lines, fmt.Sprintf("%s (your role: %s) — %d active beam(s)", bh.Slug, m.Role, len(hb.Beams)))
		for _, bm := range hb.Beams {
			preview := bm.PreviewURL
			if preview == "" {
				preview = "(preview idle — resume_preview)"
			}
			line := fmt.Sprintf("  - %s [preview:%s] %s", bm.Beam, bm.State, preview)
			if bm.Mode == string(domain.ModeLive) {
				live := bm.LiveURL
				if live == "" {
					live = "(live workload down)"
				}
				line += fmt.Sprintf("  [live] %s", live)
			}
			lines = append(lines, line)
		}
	}
	if len(out.Beamhalls) == 0 {
		msg := "You are not a member of any beamhall yet — ask IT to grant you membership."
		if args.Beamhall != "" {
			msg = fmt.Sprintf("No beamhall %q among your memberships (you only see beamhalls you belong to).", args.Beamhall)
		}
		return text(msg), out, nil
	}
	return text(strings.Join(lines, "\n")), out, nil
}

func (s *Server) getRepo(ctx context.Context, req *sdkmcp.CallToolRequest, args getRepoArgs) (*sdkmcp.CallToolResult, repoOut, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeBeamsWrite)
	if err != nil {
		return nil, repoOut{}, err
	}
	if s.gitMinter == nil {
		return nil, repoOut{}, fmt.Errorf("the git transport is not enabled in this build of Beamhall")
	}
	bh, err := s.resolveBeamhall(ctx, args.Beamhall)
	if err != nil {
		return nil, repoOut{}, err
	}
	beam, err := s.resolveBeam(ctx, bh.ID, args.Beam)
	if err != nil {
		return nil, repoOut{}, err
	}
	tok, err := s.gitMinter.MintRead(bh.ID, beam.ID, actor.ID)
	if err != nil {
		return nil, repoOut{}, err
	}
	remote, scheme, hostPath := s.gitRemote(bh.Slug, beam.Slug)
	cmd := fmt.Sprintf("git clone %sx-access-token:%s@%s %s", scheme, tok, hostPath, beam.Slug)
	msg := fmt.Sprintf("Clone the source of %q (Beamhall hosts the beam's code). Run:\n\n  %s\n\n"+
		"This is a read-only, one-beam clone token; it expires shortly, so call get_repo again for a fresh one. "+
		"After editing, ship changes with deploy_beam (git push).",
		beam.Slug, cmd)
	out := repoOut{Beam: beam.Slug, Beamhall: bh.Slug, Remote: remote, CloneURL: cmd}
	return text(msg), out, nil
}

func (s *Server) createDatabase(ctx context.Context, req *sdkmcp.CallToolRequest, args createDatabaseArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeResourcesWrite)
	if err != nil {
		return nil, nil, err
	}
	bh, err := s.resolveBeamhall(ctx, args.Beamhall)
	if err != nil {
		return nil, nil, err
	}
	beam, err := s.resolveBeam(ctx, bh.ID, args.Beam)
	if err != nil {
		return nil, nil, err
	}
	key, err := s.bp.CreateDatabase(ctx, actor, bh.ID, beam.ID, args.Name)
	if err != nil {
		return nil, nil, err
	}
	return text(fmt.Sprintf("database %q provisioned. After the next deploy_beam, the PostgreSQL connection URL is the content of the file /run/secrets/%s inside the workload — read it from there; it is never shown here.",
		args.Name, key)), map[string]string{"secret_key": key, "secret_file": "/run/secrets/" + key}, nil
}

func (s *Server) provisionAuth(ctx context.Context, req *sdkmcp.CallToolRequest, args beamArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeResourcesWrite)
	if err != nil {
		return nil, nil, err
	}
	bh, err := s.resolveBeamhall(ctx, args.Beamhall)
	if err != nil {
		return nil, nil, err
	}
	beam, err := s.resolveBeam(ctx, bh.ID, args.Beam)
	if err != nil {
		return nil, nil, err
	}
	keys, err := s.bp.ProvisionAuth(ctx, actor, bh.ID, beam.ID)
	if err != nil {
		return nil, nil, authBYOErr(err)
	}
	files := make([]string, len(keys))
	for i, k := range keys {
		files[i] = "/run/secrets/" + k
	}
	msg := fmt.Sprintf("company sign-in provisioned for beam %q (mode: library). After the next deploy_beam your app reads %s and runs a standard OpenID Connect code+PKCE flow — derive the redirect URL from the request Host and read OIDC_CLIENT_ID from its file (don't hardcode) so one image works in preview and production. No secret value is ever shown; the login URLs are kept correct for you across preview-URL changes.",
		beam.Slug, strings.Join(files, ", "))
	return text(msg), map[string]any{"auth_mode": "library", "secret_keys": keys, "secret_files": files}, nil
}

func (s *Server) showAuth(ctx context.Context, req *sdkmcp.CallToolRequest, args beamArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeBeamhallsRead)
	if err != nil {
		return nil, nil, err
	}
	bh, err := s.resolveBeamhall(ctx, args.Beamhall)
	if err != nil {
		return nil, nil, err
	}
	beam, err := s.resolveBeam(ctx, bh.ID, args.Beam)
	if err != nil {
		return nil, nil, err
	}
	info, err := s.bp.ShowAuth(ctx, actor, bh.ID, beam.ID)
	if err != nil {
		return nil, nil, authBYOErr(err)
	}
	if !info.Provisioned {
		return text(fmt.Sprintf("beam %q has no company sign-in provisioned — call provision_auth to add it.", beam.Slug)), info, nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "beam %q sign-in (mode %s, issuer %s):\n", beam.Slug, info.Mode, info.Issuer)
	for _, c := range info.Channels {
		fmt.Fprintf(&b, "  - %s: client_id=%s audience=%s", c.Channel, c.ClientID, c.Audience)
		if len(c.Groups) > 0 {
			fmt.Fprintf(&b, " groups=%s", strings.Join(c.Groups, ","))
		}
		b.WriteString("\n")
	}
	return text(b.String()), info, nil
}

func (s *Server) provisionEmail(ctx context.Context, req *sdkmcp.CallToolRequest, args beamArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeResourcesWrite)
	if err != nil {
		return nil, nil, err
	}
	bh, err := s.resolveBeamhall(ctx, args.Beamhall)
	if err != nil {
		return nil, nil, err
	}
	beam, err := s.resolveBeam(ctx, bh.ID, args.Beam)
	if err != nil {
		return nil, nil, err
	}
	keys, err := s.bp.ProvisionEmail(ctx, actor, bh.ID, beam.ID)
	if err != nil {
		return nil, nil, emailDisabledErr(err)
	}
	files := make([]string, len(keys))
	for i, k := range keys {
		files[i] = "/run/secrets/" + k
	}
	msg := fmt.Sprintf("outbound email provisioned for beam %q. After the next deploy_beam your app reads %s and sends with any standard SMTP library — Beamhall relays to the company mail provider. NOTE: until an IT admin allows a sender with admin_set_email_senders, sends are rejected — ask IT for the From address/domain you need. No credential value is ever shown.",
		beam.Slug, strings.Join(files, ", "))
	return text(msg), map[string]any{"secret_keys": keys, "secret_files": files}, nil
}

func (s *Server) showEmail(ctx context.Context, req *sdkmcp.CallToolRequest, args beamArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeBeamhallsRead)
	if err != nil {
		return nil, nil, err
	}
	bh, err := s.resolveBeamhall(ctx, args.Beamhall)
	if err != nil {
		return nil, nil, err
	}
	beam, err := s.resolveBeam(ctx, bh.ID, args.Beam)
	if err != nil {
		return nil, nil, err
	}
	info, err := s.bp.ShowEmail(ctx, actor, bh.ID, beam.ID)
	if err != nil {
		return nil, nil, emailDisabledErr(err)
	}
	if !info.Provisioned {
		return text(fmt.Sprintf("beam %q has no outbound email provisioned — call provision_email to add it.", beam.Slug)), info, nil
	}
	senders := "none yet (ask IT to allow one with admin_set_email_senders — until then sends are rejected)"
	if len(info.AllowedSenders) > 0 {
		senders = strings.Join(info.AllowedSenders, ", ")
	}
	msg := fmt.Sprintf("beam %q email: sends via %s:%d as user %s; allowed senders: %s; rate limit: %d/day.",
		beam.Slug, info.Host, info.Port, info.Username, senders, info.RateLimitPerDay)
	return text(msg), info, nil
}

func (s *Server) setSecret(ctx context.Context, req *sdkmcp.CallToolRequest, args setSecretArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeSecretsWrite)
	if err != nil {
		return nil, nil, err
	}
	bh, err := s.resolveBeamhall(ctx, args.Beamhall)
	if err != nil {
		return nil, nil, err
	}
	var beamID domain.ID
	if args.Beam != "" {
		beam, err := s.resolveBeam(ctx, bh.ID, args.Beam)
		if err != nil {
			return nil, nil, err
		}
		beamID = beam.ID
	}
	if err := s.bp.SetSecret(ctx, actor, bh.ID, beamID, args.Key, []byte(args.Value)); err != nil {
		return nil, nil, err
	}
	return text(fmt.Sprintf("secret %q stored (write-only). It becomes the file /run/secrets/%s inside the workload on the next deploy_beam.",
		args.Key, args.Key)), map[string]string{"secret_file": "/run/secrets/" + args.Key}, nil
}

func (s *Server) showLogs(ctx context.Context, req *sdkmcp.CallToolRequest, args showLogsArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeLogsRead)
	if err != nil {
		return nil, nil, err
	}
	bh, err := s.resolveBeamhall(ctx, args.Beamhall)
	if err != nil {
		return nil, nil, err
	}
	beam, err := s.resolveBeam(ctx, bh.ID, args.Beam)
	if err != nil {
		return nil, nil, err
	}
	tail := args.TailLines
	if tail <= 0 {
		tail = 200
	}
	out, err := s.bp.ShowLogs(ctx, actor, bh.ID, beam.ID, driver.LogOptions{TailN: tail})
	if err != nil {
		return nil, nil, err
	}
	if len(out) == 0 {
		return text("(no log output)"), nil, nil
	}
	logs := string(out)
	// A known failure signature in a *running* beam's logs (egress denials,
	// read-only writes, …) gets named here — the constraint is invisible from
	// inside the workload, so the log line alone sends agents in circles.
	if hint := diagnose.Run(logs); hint != "" {
		logs += "\n\n[beamhall] These logs match a known constraint: " + hint
	}
	return text(logs), nil, nil
}

func (s *Server) pausePreview(ctx context.Context, req *sdkmcp.CallToolRequest, args beamArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeBeamsOperate)
	if err != nil {
		return nil, nil, err
	}
	bh, err := s.resolveBeamhall(ctx, args.Beamhall)
	if err != nil {
		return nil, nil, err
	}
	beam, err := s.resolveBeam(ctx, bh.ID, args.Beam)
	if err != nil {
		return nil, nil, err
	}
	if err := s.bp.PausePreview(ctx, actor, bh.ID, beam.ID); err != nil {
		return nil, nil, err
	}
	return text(fmt.Sprintf("beam %q paused; its preview URL is retired. resume_preview wakes it on a new URL.", beam.Slug)), nil, nil
}

func (s *Server) resumePreview(ctx context.Context, req *sdkmcp.CallToolRequest, args beamArgs) (*sdkmcp.CallToolResult, beamOut, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeBeamsOperate)
	if err != nil {
		return nil, beamOut{}, err
	}
	bh, err := s.resolveBeamhall(ctx, args.Beamhall)
	if err != nil {
		return nil, beamOut{}, err
	}
	beam, err := s.resolveBeam(ctx, bh.ID, args.Beam)
	if err != nil {
		return nil, beamOut{}, err
	}
	host, err := s.bp.ResumePreview(ctx, actor, bh.ID, beam.ID)
	if err != nil {
		return nil, beamOut{}, err
	}
	previewURL := "https://" + host
	updated, err := s.resolveBeam(ctx, bh.ID, args.Beam)
	if err != nil {
		return nil, beamOut{}, err
	}
	_, liveURL := s.channelURLs(ctx, updated.ID)
	return text(fmt.Sprintf("beam %q preview resumed at %s (previous preview URLs are dead).", beam.Slug, previewURL)),
		s.beamChannels(updated, bh.Slug, previewURL, liveURL), nil
}

func (s *Server) promoteToLive(ctx context.Context, req *sdkmcp.CallToolRequest, args beamArgs) (*sdkmcp.CallToolResult, beamOut, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeBeamsPromote)
	if err != nil {
		return nil, beamOut{}, err
	}
	bh, err := s.resolveBeamhall(ctx, args.Beamhall)
	if err != nil {
		return nil, beamOut{}, err
	}
	beam, err := s.resolveBeam(ctx, bh.ID, args.Beam)
	if err != nil {
		return nil, beamOut{}, err
	}
	// With the IT-approval gate on, the agent cannot promote directly — it files
	// a request a (different) IT operator must approve (PLAN §10).
	if s.bp.PromoteApprovalEnabled() {
		pr, err := s.bp.RequestPromotion(ctx, actor, bh.ID, beam.ID)
		if err != nil {
			return nil, beamOut{}, err
		}
		return text(fmt.Sprintf("promotion of beam %q requested (request %s) — an IT operator must approve it before it goes live.", beam.Slug, pr.ID)),
			beamOut{Beam: beam.Slug, Beamhall: bh.Slug, State: string(beam.State), Mode: string(beam.Mode)}, nil
	}
	firstPromote := beam.Mode != domain.ModeLive
	host, err := s.bp.PromoteToLive(ctx, actor, bh.ID, beam.ID)
	if err != nil {
		return nil, beamOut{}, err
	}
	liveURL := "https://" + host
	updated, err := s.resolveBeam(ctx, bh.ID, args.Beam)
	if err != nil {
		return nil, beamOut{}, err
	}
	previewURL, _ := s.channelURLs(ctx, updated.ID)
	out := s.beamChannels(updated, bh.Slug, previewURL, liveURL)
	msg := fmt.Sprintf("production for %q rolled forward to your current preview build — live at %s. Your preview channel is untouched, so you can keep iterating.", beam.Slug, liveURL)
	if firstPromote {
		msg = fmt.Sprintf("beam %q is LIVE at %s (stable URL, no auto-pause; one live slot consumed). Your preview channel keeps running on its own URL — keep iterating there and call promote_to_live again to ship the next version.", beam.Slug, liveURL)
	}
	return text(msg), out, nil
}

type promotionListArgs struct {
	Beamhall string `json:"beamhall" jsonschema:"beamhall slug"`
}

type promotionDecisionArgs struct {
	RequestID string `json:"request_id" jsonschema:"the promotion request id (from promote_to_live's reply or list_pending_promotions)"`
	Reason    string `json:"reason,omitempty" jsonschema:"reason for rejection (reject_promotion only)"`
}

func (s *Server) listPendingPromotions(ctx context.Context, req *sdkmcp.CallToolRequest, args promotionListArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	bh, err := s.resolveBeamhall(ctx, args.Beamhall)
	if err != nil {
		return nil, nil, err
	}
	reqs, err := s.bp.ListPendingPromotions(ctx, actor, bh.ID)
	if err != nil {
		return nil, nil, err
	}
	if len(reqs) == 0 {
		return text("no promotion requests are pending."), nil, nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d pending promotion request(s):\n", len(reqs))
	for _, r := range reqs {
		fmt.Fprintf(&b, "  - %s  beam=%s  requested_by=%s  at=%s\n", r.ID, r.BeamID, r.RequestedBy, r.CreatedAt.UTC().Format(time.RFC3339))
	}
	return text(b.String()), nil, nil
}

func (s *Server) approvePromotion(ctx context.Context, req *sdkmcp.CallToolRequest, args promotionDecisionArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	host, err := s.bp.ApprovePromotion(ctx, actor, domain.ID(args.RequestID))
	if err != nil {
		return nil, nil, err
	}
	return text(fmt.Sprintf("promotion %s approved — beam is LIVE at https://%s.", args.RequestID, host)), nil, nil
}

func (s *Server) rejectPromotion(ctx context.Context, req *sdkmcp.CallToolRequest, args promotionDecisionArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeAdminIT)
	if err != nil {
		return nil, nil, err
	}
	if err := s.bp.RejectPromotion(ctx, actor, domain.ID(args.RequestID), args.Reason); err != nil {
		return nil, nil, err
	}
	return text(fmt.Sprintf("promotion %s rejected.", args.RequestID)), nil, nil
}

type rollbackArgs struct {
	Beamhall  string `json:"beamhall" jsonschema:"beamhall slug"`
	Beam      string `json:"beam" jsonschema:"beam slug"`
	ToVersion int    `json:"to_version,omitempty" jsonschema:"prior production (live) release version to roll back to; omit for the most recent prior live release"`
}

func (s *Server) rollback(ctx context.Context, req *sdkmcp.CallToolRequest, args rollbackArgs) (*sdkmcp.CallToolResult, beamOut, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeBeamsDeploy)
	if err != nil {
		return nil, beamOut{}, err
	}
	bh, err := s.resolveBeamhall(ctx, args.Beamhall)
	if err != nil {
		return nil, beamOut{}, err
	}
	beam, err := s.resolveBeam(ctx, bh.ID, args.Beam)
	if err != nil {
		return nil, beamOut{}, err
	}
	target, err := s.pickRollbackTarget(ctx, beam, args.ToVersion)
	if err != nil {
		return nil, beamOut{}, err
	}
	host, err := s.bp.RollbackBeam(ctx, actor, bh.ID, beam.ID, target)
	if err != nil {
		return nil, beamOut{}, err
	}
	url := "https://" + host
	return text(fmt.Sprintf("beam %q rolled back and serving at %s.", beam.Slug, url)),
		beamOut{Beam: beam.Slug, Beamhall: bh.Slug, State: string(domain.StateRunning), Mode: string(beam.Mode), URL: url}, nil
}

// pickRollbackTarget resolves the desired prior production release. rollback
// re-pins the LIVE channel, so it only ever considers releases that served the
// live channel (never preview builds) and never the one currently serving
// production. Default: the highest-version prior live release; or a named
// to_version among the live history. Releases come back newest-version-first.
func (s *Server) pickRollbackTarget(ctx context.Context, beam domain.Beam, toVersion int) (domain.ID, error) {
	rels, err := s.dir.ListReleasesByBeam(ctx, beam.ID)
	if err != nil {
		return "", err
	}
	var prior []domain.Release
	for _, r := range rels {
		if r.Channel == domain.ChannelLive && r.ID != beam.LiveReleaseID {
			prior = append(prior, r)
		}
	}
	avail := make([]int, 0, len(prior))
	for _, r := range prior {
		avail = append(avail, r.Version)
	}
	if toVersion > 0 {
		for _, r := range prior {
			if r.Version == toVersion {
				return r.ID, nil
			}
		}
		return "", fmt.Errorf("beam %q has no prior production (live) release version %d (available: %v)", beam.Slug, toVersion, avail)
	}
	if len(prior) == 0 {
		return "", fmt.Errorf("beam %q has no earlier production release to roll back to (it has only ever run its current live build, or was never promoted)", beam.Slug)
	}
	return prior[0].ID, nil // highest version (list is newest-first)
}

func (s *Server) showMetrics(ctx context.Context, req *sdkmcp.CallToolRequest, args beamArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeMetricsRead)
	if err != nil {
		return nil, nil, err
	}
	bh, err := s.resolveBeamhall(ctx, args.Beamhall)
	if err != nil {
		return nil, nil, err
	}
	beam, err := s.resolveBeam(ctx, bh.ID, args.Beam)
	if err != nil {
		return nil, nil, err
	}
	st, err := s.bp.ShowMetrics(ctx, actor, bh.ID, beam.ID)
	if err != nil {
		return nil, nil, err
	}
	out := map[string]any{
		"cpu_pct":      st.CPUPct,
		"mem_bytes":    st.MemBytes,
		"mem_limit":    st.MemLimit,
		"net_rx_bytes": st.NetRxBytes,
		"net_tx_bytes": st.NetTxBytes,
	}
	return text(fmt.Sprintf("beam %q: CPU %.1f%%, memory %d/%d bytes, net rx/tx %d/%d bytes.",
		beam.Slug, st.CPUPct, st.MemBytes, st.MemLimit, st.NetRxBytes, st.NetTxBytes)), out, nil
}

func (s *Server) destroyBeam(ctx context.Context, req *sdkmcp.CallToolRequest, args beamArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeBeamsWrite)
	if err != nil {
		return nil, nil, err
	}
	bh, err := s.resolveBeamhall(ctx, args.Beamhall)
	if err != nil {
		return nil, nil, err
	}
	beam, err := s.resolveBeam(ctx, bh.ID, args.Beam)
	if err != nil {
		return nil, nil, err
	}
	if err := s.bp.DestroyBeam(ctx, actor, bh.ID, beam.ID); err != nil {
		return nil, nil, err
	}
	return text(fmt.Sprintf("beam %q destroyed: workload removed, URL retired, name freed for reuse.", beam.Slug)), nil, nil
}

func (s *Server) archiveBeam(ctx context.Context, req *sdkmcp.CallToolRequest, args beamArgs) (*sdkmcp.CallToolResult, any, error) {
	actor, err := s.resolveActor(ctx, req, auth.ScopeBeamsOperate)
	if err != nil {
		return nil, nil, err
	}
	bh, err := s.resolveBeamhall(ctx, args.Beamhall)
	if err != nil {
		return nil, nil, err
	}
	beam, err := s.resolveBeam(ctx, bh.ID, args.Beam)
	if err != nil {
		return nil, nil, err
	}
	if err := s.bp.ArchiveBeam(ctx, actor, bh.ID, beam.ID); err != nil {
		return nil, nil, err
	}
	return text(fmt.Sprintf("beam %q archived: workload stopped, URL retired, quota slot freed. "+
		"Source and history are retained; the name is free for reuse. This is terminal — to start again, create a new beam.", beam.Slug)), nil, nil
}
