package orch

import (
	"context"
	"fmt"
	"strings"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/identityadmin"
	"github.com/Beamhall/beamhall/internal/policy"
)

// Provisioned auth (PLAN §5.10): a beam reuses the owned IdP (the bundled
// Keycloak) for its own end-user sign-in. provision_auth mints a per-beam,
// per-channel OIDC relying party and seals its issuer/client_id/client_secret as
// channel secrets — the agent learns only the KEYS and reads the values as files
// inside the workload after the next deploy, exactly like create_database. The
// load-bearing invariant is audience isolation: the app client's tokens carry
// only their own clientId as `aud`, never the Beamhall resource URI, so an app
// token cannot be replayed against the MCP backplane (enforced in CreateClient).

// The three sealed secret keys (also the /run/secrets/<key> filenames). Stable
// across URL changes, so they ride one deploy's snapshot and never need a reseal.
const (
	authIssuerKey       = "OIDC_ISSUER"
	authClientIDKey     = "OIDC_CLIENT_ID"
	authClientSecretKey = "OIDC_CLIENT_SECRET"
	// Short access-token lifespan for the regulated profile (seconds).
	authTokenTTLSeconds = 300
	authMode            = "library"
)

func authSecretKeys() []string {
	return []string{authIssuerKey, authClientIDKey, authClientSecretKey}
}

// authClientID is the stable per-beam-channel client id, e.g.
// "beam-team-blue-app-preview". It is also the token audience for that client.
func authClientID(beamhallSlug, beamSlug string, ch domain.Channel) string {
	channel := string(ch)
	if channel == "" {
		channel = "preview"
	}
	return fmt.Sprintf("beam-%s-%s-%s", beamhallSlug, beamSlug, channel)
}

// redirectsFor / webOriginsFor build the EXACT allowlist for a host. The app
// derives its callback from the request Host, so these track the live host; we
// register a couple of conventional callback paths. Empty host → empty allowlist.
func redirectsFor(host string) []string {
	if host == "" {
		return nil
	}
	return []string{
		"https://" + host + "/auth/callback",
		"https://" + host + "/callback",
	}
}

func webOriginsFor(host string) []string {
	if host == "" {
		return nil
	}
	return []string{"https://" + host}
}

func (o *Orchestrator) idpEnabled() bool { return o.idp != nil && o.idp.Enabled() }

// ProvisionAuth gives a beam company sign-in: mints the preview OIDC client and
// seals its issuer/client_id/client_secret as ChannelPreview secrets. Idempotent
// (re-returns the keys). The agent never sees the secret value. Returns
// identityadmin.ErrNotEnabled on a BYO-IdP deployment so the MCP layer can hand
// back the set_secret fallback recipe.
func (o *Orchestrator) ProvisionAuth(ctx context.Context, actor Actor, beamhallID, beamID domain.ID) (keys []string, err error) {
	if err := o.authorize(ctx, actor, policy.ActionProvisionAuth, beamhallID, beamID); err != nil {
		return nil, err
	}
	keys, err = o.provisionAuth(ctx, actor, beamhallID, beamID)
	return keys, o.outcome(ctx, actor, policy.ActionProvisionAuth, beamhallID, beamID, err)
}

func (o *Orchestrator) provisionAuth(ctx context.Context, actor Actor, beamhallID, beamID domain.ID) ([]string, error) {
	if !o.idpEnabled() {
		return nil, identityadmin.ErrNotEnabled
	}
	beam, err := o.operableBeam(ctx, beamhallID, beamID)
	if err != nil {
		return nil, err
	}
	bh, err := o.st.GetBeamhall(ctx, beamhallID)
	if err != nil {
		return nil, err
	}
	// Idempotent: a beam already provisioned for auth re-returns the same keys.
	existing, err := o.st.ListResourcesByBeamAndChannel(ctx, beamID, domain.ChannelPreview)
	if err != nil {
		return nil, err
	}
	for _, r := range existing {
		if r.Type == domain.ResourceAuthClient {
			o.log.Info("auth already provisioned; returning existing keys", "beam", beamID)
			return authSecretKeys(), nil
		}
	}

	clientID := authClientID(bh.Slug, beam.Slug, domain.ChannelPreview)
	client, err := o.idp.CreateClient(ctx, identityadmin.ClientSpec{
		ClientID:              clientID,
		RedirectURIs:          redirectsFor(beam.PreviewHost), // may be empty until first deploy; synced then
		WebOrigins:            webOriginsFor(beam.PreviewHost),
		AccessTokenTTLSeconds: authTokenTTLSeconds,
		ForbiddenAudience:     o.authAudience,
	})
	if err != nil {
		return nil, err
	}
	if err := o.sealAuthSecrets(ctx, beamhallID, beamID, domain.ChannelPreview, client, actor.ID); err != nil {
		// Don't leave a client whose secret nobody can reach.
		if derr := o.idp.DeleteClient(ctx, client.UUID); derr != nil {
			o.log.Error("rollback of provisioned auth client failed", "client", client.UUID, "err", derr)
		}
		return nil, err
	}
	res := &domain.Resource{
		BeamhallID:          beamhallID,
		BeamID:              beamID,
		Channel:             domain.ChannelPreview,
		Type:                domain.ResourceAuthClient,
		Status:              domain.ResourceReady,
		ConnectionSecretRef: domain.SecretRef{BeamhallID: beamhallID, BeamID: beamID, Key: authClientSecretKey, Channel: domain.ChannelPreview},
		Spec:                map[string]string{"client_id": clientID, "audience": clientID, "mode": authMode, "issuer": o.authIssuer},
		BackingHandle:       client.UUID,
	}
	if err := o.st.CreateResource(ctx, res); err != nil {
		return nil, err
	}
	o.log.Info("auth provisioned", "beam", beamID, "client_id", clientID)
	return authSecretKeys(), nil
}

// sealAuthSecrets seals the issuer/client_id/client_secret trio into the vault
// for a channel (the agent never sees the values; they file-inject on next deploy).
func (o *Orchestrator) sealAuthSecrets(ctx context.Context, beamhallID, beamID domain.ID, ch domain.Channel, client identityadmin.Client, by domain.ID) error {
	trio := []struct{ key, val string }{
		{authIssuerKey, o.authIssuer},
		{authClientIDKey, client.ClientID},
		{authClientSecretKey, client.Secret},
	}
	for _, kv := range trio {
		ref := domain.SecretRef{BeamhallID: beamhallID, BeamID: beamID, Key: kv.key, Channel: ch}
		if _, err := o.vault.Set(ctx, ref, []byte(kv.val), by); err != nil {
			return fmt.Errorf("seal %s: %w", kv.key, err)
		}
	}
	return nil
}

// AuthInfo is the non-secret view of a beam's provisioned auth (show_auth).
type AuthInfo struct {
	Provisioned bool              `json:"provisioned"`
	Mode        string            `json:"auth_mode,omitempty"`
	Issuer      string            `json:"issuer,omitempty"`
	Channels    []AuthChannelInfo `json:"channels,omitempty"`
}

// AuthChannelInfo describes one channel's relying party. No secret values.
type AuthChannelInfo struct {
	Channel      string   `json:"channel"`
	ClientID     string   `json:"client_id"`
	Audience     string   `json:"audience"`
	RedirectURIs []string `json:"redirect_uris,omitempty"`
	Groups       []string `json:"groups,omitempty"`
}

// ShowAuth reports a beam's provisioned-auth wiring without ever exposing a secret.
func (o *Orchestrator) ShowAuth(ctx context.Context, actor Actor, beamhallID, beamID domain.ID) (AuthInfo, error) {
	if err := o.authorize(ctx, actor, policy.ActionShowAuth, beamhallID, beamID); err != nil {
		return AuthInfo{}, err
	}
	info, err := o.showAuth(ctx, beamhallID, beamID)
	return info, o.outcome(ctx, actor, policy.ActionShowAuth, beamhallID, beamID, err)
}

func (o *Orchestrator) showAuth(ctx context.Context, beamhallID, beamID domain.ID) (AuthInfo, error) {
	beam, err := o.st.GetBeam(ctx, beamID)
	if err != nil {
		return AuthInfo{}, err
	}
	bh, err := o.st.GetBeamhall(ctx, beamhallID)
	if err != nil {
		return AuthInfo{}, err
	}
	resources, err := o.st.ListResourcesByBeam(ctx, beamID)
	if err != nil {
		return AuthInfo{}, err
	}
	info := AuthInfo{Issuer: o.authIssuer}
	for _, r := range resources {
		if r.Type != domain.ResourceAuthClient {
			continue
		}
		info.Provisioned = true
		info.Mode = r.Spec["mode"]
		host := beam.PreviewHost
		if r.Channel == domain.ChannelLive {
			host = o.liveHost(beam.Slug, bh.Slug)
		}
		ch := AuthChannelInfo{
			Channel:      string(r.Channel),
			ClientID:     r.Spec["client_id"],
			Audience:     r.Spec["audience"],
			RedirectURIs: redirectsFor(host),
		}
		if g := strings.TrimSpace(r.Spec["groups"]); g != "" {
			ch.Groups = strings.Split(g, ",")
		}
		info.Channels = append(info.Channels, ch)
	}
	return info, nil
}

// SetAuthGroups curates which realm groups a beam's app tokens may expose — the
// IT-set allowlist (separation of duties, PLAN §5.10). Applies to every channel's
// client and persists the set for show_auth. IT-only (admin:it), audited.
func (o *Orchestrator) SetAuthGroups(ctx context.Context, actor Actor, beamhallID, beamID domain.ID, groups []string) error {
	if err := o.requireIT(actor); err != nil {
		return o.itAudit(ctx, actor, "admin_set_auth_groups", beamhallID, err)
	}
	return o.itAudit(ctx, actor, "admin_set_auth_groups", beamhallID, o.setAuthGroups(ctx, beamhallID, beamID, groups))
}

func (o *Orchestrator) setAuthGroups(ctx context.Context, beamhallID, beamID domain.ID, groups []string) error {
	if !o.idpEnabled() {
		return identityadmin.ErrNotEnabled
	}
	clean := make([]string, 0, len(groups))
	for _, g := range groups {
		if g = strings.TrimSpace(g); g != "" {
			clean = append(clean, g)
		}
	}
	resources, err := o.st.ListResourcesByBeam(ctx, beamID)
	if err != nil {
		return err
	}
	applied := 0
	for i := range resources {
		r := resources[i]
		if r.Type != domain.ResourceAuthClient {
			continue
		}
		if err := o.idp.SetClientGroupRoles(ctx, r.BackingHandle, clean); err != nil {
			return fmt.Errorf("set group roles on %s client: %w", r.Channel, err)
		}
		if r.Spec == nil {
			r.Spec = map[string]string{}
		}
		r.Spec["groups"] = strings.Join(clean, ",")
		if err := o.st.UpdateResource(ctx, &r); err != nil {
			return err
		}
		applied++
	}
	if applied == 0 {
		return fmt.Errorf("beam has no provisioned auth — call provision_auth first")
	}
	return nil
}

// syncAuthRedirects re-asserts a channel's OIDC client redirect/web-origin
// allowlist to host (empty host clears it, e.g. on pause). No-op when auth isn't
// provisioned or the IdP is BYO. Best-effort on hot paths: a transient IdP error
// logs loudly but never blocks deploy/resume/promote — the creds are unaffected
// and the next URL event re-syncs.
func (o *Orchestrator) syncAuthRedirects(ctx context.Context, beamID domain.ID, ch domain.Channel, host string) {
	if !o.idpEnabled() {
		return
	}
	resources, err := o.st.ListResourcesByBeamAndChannel(ctx, beamID, ch)
	if err != nil {
		o.log.Warn("auth redirect sync: list resources", "beam", beamID, "channel", ch, "err", err)
		return
	}
	for _, r := range resources {
		if r.Type != domain.ResourceAuthClient {
			continue
		}
		if err := o.idp.SyncRedirectURIs(ctx, r.BackingHandle, redirectsFor(host), webOriginsFor(host)); err != nil {
			o.log.Warn("auth redirect sync", "beam", beamID, "channel", ch, "host", host, "err", err)
		}
	}
}

// mirrorLiveAuthClient mints the live OIDC client the first time a beam is
// promoted, mirroring its preview client (distinct secret + distinct aud +
// stable live redirect) and copying the curated group allowlist. Idempotent.
func (o *Orchestrator) mirrorLiveAuthClient(ctx context.Context, actor Actor, bh domain.Beamhall, beamSlug string, beamID domain.ID) error {
	if !o.idpEnabled() {
		return nil
	}
	previewRes, err := o.st.ListResourcesByBeamAndChannel(ctx, beamID, domain.ChannelPreview)
	if err != nil {
		return err
	}
	var previewAuth *domain.Resource
	for i := range previewRes {
		if previewRes[i].Type == domain.ResourceAuthClient {
			previewAuth = &previewRes[i]
			break
		}
	}
	if previewAuth == nil {
		return nil // no auth on this beam
	}
	liveRes, err := o.st.ListResourcesByBeamAndChannel(ctx, beamID, domain.ChannelLive)
	if err != nil {
		return err
	}
	for _, r := range liveRes {
		if r.Type == domain.ResourceAuthClient {
			return nil // already mirrored
		}
	}

	clientID := authClientID(bh.Slug, beamSlug, domain.ChannelLive)
	liveHost := o.liveHost(beamSlug, bh.Slug)
	client, err := o.idp.CreateClient(ctx, identityadmin.ClientSpec{
		ClientID:              clientID,
		RedirectURIs:          redirectsFor(liveHost),
		WebOrigins:            webOriginsFor(liveHost),
		AccessTokenTTLSeconds: authTokenTTLSeconds,
		ForbiddenAudience:     o.authAudience,
	})
	if err != nil {
		return fmt.Errorf("create live auth client: %w", err)
	}
	if err := o.sealAuthSecrets(ctx, bh.ID, beamID, domain.ChannelLive, client, actor.ID); err != nil {
		if derr := o.idp.DeleteClient(ctx, client.UUID); derr != nil {
			o.log.Error("rollback of live auth client failed", "client", client.UUID, "err", derr)
		}
		return err
	}
	// Carry the curated group allowlist to production.
	groups := previewAuth.Spec["groups"]
	if g := strings.TrimSpace(groups); g != "" {
		if err := o.idp.SetClientGroupRoles(ctx, client.UUID, strings.Split(g, ",")); err != nil {
			o.log.Warn("carry group allowlist to live auth client", "beam", beamID, "err", err)
		}
	}
	res := &domain.Resource{
		BeamhallID:          bh.ID,
		BeamID:              beamID,
		Channel:             domain.ChannelLive,
		Type:                domain.ResourceAuthClient,
		Status:              domain.ResourceReady,
		ConnectionSecretRef: domain.SecretRef{BeamhallID: bh.ID, BeamID: beamID, Key: authClientSecretKey, Channel: domain.ChannelLive},
		Spec:                map[string]string{"client_id": clientID, "audience": clientID, "mode": authMode, "issuer": o.authIssuer, "groups": groups},
		BackingHandle:       client.UUID,
	}
	if err := o.st.CreateResource(ctx, res); err != nil {
		return err
	}
	o.log.Info("live auth client provisioned", "beam", beamID, "client_id", clientID)
	return nil
}

// reclaimAuthClients deletes a beam's OIDC clients and their sealed secrets on
// archive/destroy, so a retired beam leaves no orphan client or secret. Called
// from reclaimResources for each ResourceAuthClient row.
func (o *Orchestrator) reclaimAuthClient(ctx context.Context, r domain.Resource) {
	if o.idpEnabled() && r.BackingHandle != "" {
		if err := o.idp.DeleteClient(ctx, r.BackingHandle); err != nil {
			o.log.Warn("deleting auth client on destroy", "client", r.BackingHandle, "err", err)
		}
	}
	for _, key := range authSecretKeys() {
		ref := domain.SecretRef{BeamhallID: r.BeamhallID, BeamID: r.BeamID, Key: key, Channel: r.Channel}
		if err := o.vault.Delete(ctx, ref); err != nil {
			o.log.Warn("deleting sealed auth secret on destroy", "beam", r.BeamID, "key", key, "err", err)
		}
	}
}
