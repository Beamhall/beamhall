package orch

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/store"
)

// The using tier: people who build nothing and only need to find the apps IT
// published to them. Access is audience-driven, not membership-driven — a user
// holds no membership anywhere, so none of this goes through the PEP matrix.
// actor.ITAdmin does NOT bypass the audience check: publication is a fact
// about an app, not a permission over a resource.

// UserTierConfig switches the using tier's two knobs.
type UserTierConfig struct {
	AutoRegister   bool // create the identity row on a first valid beams:use token
	GroupAudiences bool // a groups claim is configured; group audiences can match
}

// WithUserTier configures the using tier.
func WithUserTier(cfg UserTierConfig) Option {
	return func(o *Orchestrator) { o.userTier = cfg }
}

// UserAutoRegisterEnabled reports whether a first valid user-tier token may
// register its own identity.
func (o *Orchestrator) UserAutoRegisterEnabled() bool { return o.userTier.AutoRegister }

// GroupAudiencesEnabled reports whether a groups claim is configured (when
// false, a group-based audience can never match anyone).
func (o *Orchestrator) GroupAudiencesEnabled() bool { return o.userTier.GroupAudiences }

// ErrAppNotPublished is the uniform not-found for the using tier: an app that
// does not exist and an app not published to the caller must be
// indistinguishable, or describe_app becomes an enumeration oracle.
var ErrAppNotPublished = errors.New("not published to you")

// AmbiguousAppError reports an app slug published to the caller from more than
// one workspace.
type AmbiguousAppError struct {
	App        string
	Workspaces []string
}

func (e *AmbiguousAppError) Error() string {
	return fmt.Sprintf("app %q is published from more than one workspace: %v", e.App, e.Workspaces)
}

// AudienceSpec is the IT input for admin_set_app_audience.
type AudienceSpec struct {
	Audience       domain.Audience
	Description    string
	SetDescription bool
	Clear          bool
}

// AppView is the user-facing view of one published app: everything a person's
// own agent may know about an app it did not build. Deliberately thin — no
// release, build, secret, or channel detail crosses this boundary.
type AppView struct {
	App         string    `json:"app"`
	DisplayName string    `json:"display_name,omitempty"`
	Description string    `json:"description,omitempty"`
	Workspace   string    `json:"workspace"`
	URL         string    `json:"url,omitempty"` // live channel only; empty until promoted
	Live        bool      `json:"live"`
	SignIn      string    `json:"sign_in"` // "company_sso" | "app_managed"
	PublishedAt time.Time `json:"published_at"`
}

// SetAppAudience publishes an app to an audience (or, with spec.Clear,
// unpublishes it). it_admin only.
func (o *Orchestrator) SetAppAudience(ctx context.Context, actor Actor, beamhallID, beamID domain.ID, spec AudienceSpec) error {
	if err := o.requireIT(actor); err != nil {
		return o.itAuditBeam(ctx, actor, "admin_set_app_audience", beamhallID, beamID, err)
	}
	err := o.setAppAudience(ctx, actor, beamhallID, beamID, spec)
	return o.itAuditBeam(ctx, actor, "admin_set_app_audience", beamhallID, beamID, err)
}

func (o *Orchestrator) setAppAudience(ctx context.Context, actor Actor, beamhallID, beamID domain.ID, spec AudienceSpec) error {
	beam, err := o.operableBeam(ctx, beamhallID, beamID)
	if err != nil {
		return err
	}
	if spec.Clear {
		// The description is the builder's/IT's catalog copy, not part of the
		// publication — it survives an unpublish.
		return o.st.DeleteBeamAudience(ctx, beamID)
	}
	if spec.Audience.IsEmpty() {
		return fmt.Errorf("an audience of nobody is the same as unpublished — pass everyone, groups, or identities; to unpublish, pass clear")
	}
	if err := o.st.PutBeamAudience(ctx, domain.BeamAudience{
		BeamID:      beamID,
		BeamhallID:  beamhallID,
		Audience:    spec.Audience,
		PublishedBy: actor.ID,
	}); err != nil {
		return err
	}
	if spec.SetDescription {
		beam.Description = spec.Description
		if err := o.st.UpdateBeam(ctx, &beam); err != nil {
			return fmt.Errorf("published, but updating the description failed: %w", err)
		}
	}
	return nil
}

// ListApps returns the published apps the actor is in the audience of. Reads
// are unaudited (like list_beams) and identical for every caller.
func (o *Orchestrator) ListApps(ctx context.Context, actor Actor) ([]AppView, error) {
	pubs, err := o.st.ListBeamAudiences(ctx)
	if err != nil {
		return nil, err
	}
	var out []AppView
	for _, pub := range pubs {
		if !pub.Audience.Allows(actor.ID, actor.Groups) {
			continue
		}
		view, ok := o.appView(ctx, pub)
		if !ok {
			continue
		}
		out = append(out, view)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Workspace != out[j].Workspace {
			return out[i].Workspace < out[j].Workspace
		}
		return out[i].App < out[j].App
	})
	return out, nil
}

// DescribeApp resolves one published app by its slug, over the caller's
// published set only. workspace is needed only to disambiguate two teams
// publishing the same app name.
func (o *Orchestrator) DescribeApp(ctx context.Context, actor Actor, app, workspace string) (AppView, error) {
	views, err := o.ListApps(ctx, actor)
	if err != nil {
		return AppView{}, err
	}
	var matches []AppView
	for _, v := range views {
		if v.App != app {
			continue
		}
		if workspace != "" && v.Workspace != workspace {
			continue
		}
		matches = append(matches, v)
	}
	switch len(matches) {
	case 0:
		return AppView{}, ErrAppNotPublished
	case 1:
		return matches[0], nil
	default:
		e := &AmbiguousAppError{App: app}
		for _, m := range matches {
			e.Workspaces = append(e.Workspaces, m.Workspace)
		}
		return AppView{}, e
	}
}

// appView builds the user-facing view of one publication; ok is false when the
// beam or its beamhall is gone or archived (a stale publication row must not
// resurrect an archived app in anyone's list).
func (o *Orchestrator) appView(ctx context.Context, pub domain.BeamAudience) (AppView, bool) {
	beam, err := o.st.GetBeam(ctx, pub.BeamID)
	if err != nil || beam.Status != domain.BeamActive {
		return AppView{}, false
	}
	bh, err := o.st.GetBeamhall(ctx, pub.BeamhallID)
	if err != nil || bh.Status != domain.BeamhallActive {
		return AppView{}, false
	}
	view := AppView{
		App:         beam.Slug,
		DisplayName: beam.DisplayName,
		Description: beam.Description,
		Workspace:   bh.Slug,
		Live:        beam.LiveState == domain.StateLive,
		SignIn:      o.beamSignIn(ctx, beam.ID),
		PublishedAt: pub.PublishedAt,
	}
	if view.Live {
		view.URL = "https://" + o.liveHost(beam.Slug, bh.Slug)
	}
	return view, true
}

// beamSignIn reports how a person signs into the app: company SSO when the
// beam has a provisioned auth client, otherwise whatever the app does itself.
func (o *Orchestrator) beamSignIn(ctx context.Context, beamID domain.ID) string {
	resources, err := o.st.ListResourcesByBeam(ctx, beamID)
	if err == nil {
		for _, r := range resources {
			if r.Type == domain.ResourceAuthClient && r.Status != domain.ResourceDeleting {
				return "company_sso"
			}
		}
	}
	return "app_managed"
}

// RegisterUserIdentity is the auto-registration path for the using tier: a
// fully verified token whose (issuer, subject) has no identity row yet gets
// one, so IT never hand-registers every employee. Get-or-create — the unique
// (issuer, subject) index makes the concurrent case a conflict we re-read.
// There is no Actor here yet by construction.
func (o *Orchestrator) RegisterUserIdentity(ctx context.Context, issuer, subject, email string) (domain.Identity, error) {
	if !o.userTier.AutoRegister {
		return domain.Identity{}, fmt.Errorf("user auto-registration is disabled on this appliance")
	}
	if issuer == "" || subject == "" {
		return domain.Identity{}, fmt.Errorf("issuer and subject are required")
	}
	if existing, err := o.st.GetIdentityByIssuerSubject(ctx, issuer, subject); err == nil {
		return existing, nil
	}
	ident := &domain.Identity{
		ExternalSubject: subject, IdPIssuer: issuer, Email: email,
		DisplayName: subject, Status: domain.IdentityActive,
	}
	if err := o.st.CreateIdentity(ctx, ident); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return o.st.GetIdentityByIssuerSubject(ctx, issuer, subject)
		}
		return domain.Identity{}, err
	}
	ev := domain.AuditEvent{
		ActorID: ident.ID, Action: "user_auto_register",
		Decision: domain.DecisionAllow, ResultStatus: "ok",
	}
	if _, err := o.alog.Append(ctx, &ev); err != nil {
		o.log.Error("audit user_auto_register failed", "subject", subject, "err", err)
		return domain.Identity{}, fmt.Errorf("identity registered but could NOT be recorded on the audit chain: %w", err)
	}
	o.log.Info("user identity auto-registered", "subject", subject)
	return *ident, nil
}
