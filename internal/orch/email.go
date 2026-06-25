package orch

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/facility/mail"
	"github.com/Beamhall/beamhall/internal/policy"
)

// Email delivery facility (PLAN §5.11 facility brokers; §5.12 email). A beam
// inherits outbound email the way it inherits a database: provision_email mints
// per-beam SMTP submission credentials and seals SMTP_HOST/PORT/USER/PASS as
// ChannelShared secrets, so the app reads them from /run/secrets and sends via
// stock SMTP to the shared bh-mail broker container. The broker forwards to the
// configured smarthost (Mailgun/SES/internal); the provider credential lives
// only in the broker, never in the beam, and the beam never learns the provider.
//
// The broker is driven over the §5.11 control channel (internal/facility/mail
// Client → the bh-mail control API): beamhalld config-pushes the provider and
// per-beam registrations and audit-pulls per-message events into the hash chain.
// Email creds are ChannelShared (no per-channel mirror): preview and live use
// the same submission identity, and the per-beam sender allowlist + rate limit +
// per-message audit bound the blast radius (PLAN §5.12, operator decision:
// preview delivers like live).

const (
	emailHostKey = "SMTP_HOST"
	emailPortKey = "SMTP_PORT"
	emailUserKey = "SMTP_USER"
	emailPassKey = "SMTP_PASS"
	emailCAKey   = "SMTP_CA" // the broker's STARTTLS cert (PEM), for the app to verify+upgrade before AUTH
)

func emailSecretKeys() []string {
	return []string{emailHostKey, emailPortKey, emailUserKey, emailPassKey, emailCAKey}
}

// EmailProvisioner is the email facility seam — the broker control channel.
// *mail.Client satisfies it. A backplane without one refuses provision_email.
type EmailProvisioner interface {
	Provision(ctx context.Context, req mail.ProvisionRequest) (mail.Credentials, error)
	RegisterHashed(ctx context.Context, beamID, username, passHashHex string, allowed []string, limits mail.Limits) error
	Deregister(ctx context.Context, beamID string) error
	SetSenders(ctx context.Context, beamID string, allowed []string) error
	SetProvider(ctx context.Context, cfg mail.ProviderConfig) error
	PullEvents(ctx context.Context, after int64) ([]mail.SeqEvent, int64, error)
	Status(ctx context.Context) (enabled bool, next int64, err error)
	CACert(ctx context.Context) (string, error)
}

// EmailConfig carries the non-per-beam email facility settings: the broker's
// in-bridge address beams dial (SMTP_HOST/PORT) and the default per-beam limits.
// The smarthost provider is NOT here — it's set at runtime by an IT admin
// (admin_set_email_provider) and persisted by the broker itself.
type EmailConfig struct {
	BeamHost string
	BeamPort int
	Limits   mail.Limits
	// Attach connects the shared bh-mail broker container to a beamhall bridge so
	// the beam reaches it as <BeamHost>:<BeamPort> (the bh-postgres precedent).
	// Idempotent; nil = already reachable.
	Attach func(ctx context.Context, network string) error
}

// WithEmail wires the bh-mail broker (the installer stands it up). The facility
// stays unconfigured until an IT admin sets the provider; emailEnabled is learned
// from the broker at boot (ReconcileEmail).
func WithEmail(p EmailProvisioner, cfg EmailConfig) Option {
	return func(o *Orchestrator) {
		o.emailProv = p
		if cfg.BeamHost == "" {
			cfg.BeamHost = "bh-mail"
		}
		if cfg.BeamPort == 0 {
			cfg.BeamPort = 587
		}
		o.emailCfg = cfg
	}
}

// EmailBrokerWired reports whether a bh-mail broker is wired (the installer stood
// one up). admin_set_email_provider is available when this is true, even before a
// provider is configured.
func (o *Orchestrator) EmailBrokerWired() bool { return o.emailProv != nil }

// EmailEnabled reports whether outbound email is usable — a broker is wired AND an
// IT admin has configured a provider. Gates provision_email / show_email and
// degrades them closed otherwise.
func (o *Orchestrator) EmailEnabled() bool {
	return o.emailProv != nil && o.emailEnabled.Load()
}

// ProvisionEmail gives a beam outbound email: mints per-beam SMTP submission
// credentials at the broker and seals SMTP_HOST/PORT/USER/PASS as ChannelShared
// secrets. Idempotent (re-returns the keys). The agent never sees a value. The
// beam starts with NO allowed senders — IT curates them with
// admin_set_email_senders (separation of duties, mirrors provision_auth).
// Returns mail.ErrNotEnabled when the facility is unconfigured so the MCP layer
// can hand back the set_secret fallback recipe.
func (o *Orchestrator) ProvisionEmail(ctx context.Context, actor Actor, beamhallID, beamID domain.ID) (keys []string, err error) {
	if err := o.authorize(ctx, actor, policy.ActionProvisionEmail, beamhallID, beamID); err != nil {
		return nil, err
	}
	keys, err = o.provisionEmail(ctx, actor, beamhallID, beamID)
	return keys, o.outcome(ctx, actor, policy.ActionProvisionEmail, beamhallID, beamID, err)
}

func (o *Orchestrator) provisionEmail(ctx context.Context, actor Actor, beamhallID, beamID domain.ID) ([]string, error) {
	if !o.EmailEnabled() {
		return nil, mail.ErrNotEnabled
	}
	if _, err := o.operableBeam(ctx, beamhallID, beamID); err != nil {
		return nil, err
	}
	// Idempotent: an already-provisioned beam re-returns the same keys.
	existing, err := o.st.ListResourcesByBeam(ctx, beamID)
	if err != nil {
		return nil, err
	}
	for _, r := range existing {
		if r.Type == domain.ResourceEmail {
			o.log.Info("email already provisioned; returning existing keys", "beam", beamID)
			return emailSecretKeys(), nil
		}
	}

	// Mint creds + register at the broker (empty sender allowlist — IT curates).
	creds, err := o.emailProv.Provision(ctx, mail.ProvisionRequest{
		BeamID: string(beamID),
		Limits: o.emailCfg.Limits,
	})
	if err != nil {
		return nil, err
	}

	// Make the broker reachable from this beam's bridge (bh-postgres precedent):
	// container-to-container, no host exposure, no egress hole.
	if o.emailCfg.Attach != nil {
		if err := o.emailCfg.Attach(ctx, networkName(beamhallID)); err != nil {
			if derr := o.emailProv.Deregister(ctx, string(beamID)); derr != nil {
				o.log.Error("rollback of email registration failed", "beam", beamID, "err", derr)
			}
			return nil, fmt.Errorf("attach mail broker to beam network: %w", err)
		}
	}

	// The broker's STARTTLS cert, so the app can verify the relay and upgrade
	// before AUTH (Go's net/smtp refuses plaintext AUTH off-localhost). Best-effort:
	// an empty SMTP_CA still lets libraries that allow plaintext AUTH work.
	caPEM, err := o.emailProv.CACert(ctx)
	if err != nil {
		o.log.Warn("fetch broker TLS cert for SMTP_CA", "beam", beamID, "err", err)
		caPEM = ""
	}
	values := map[string]string{
		emailHostKey: o.emailCfg.BeamHost,
		emailPortKey: strconv.Itoa(o.emailCfg.BeamPort),
		emailUserKey: creds.Username,
		emailPassKey: creds.Password,
		emailCAKey:   caPEM,
	}
	for _, key := range emailSecretKeys() {
		ref := domain.SecretRef{BeamhallID: beamhallID, BeamID: beamID, Key: key, Channel: domain.ChannelShared}
		if _, err := o.vault.Set(ctx, ref, []byte(values[key]), actor.ID); err != nil {
			// Roll back the broker registration so nothing dangles.
			if derr := o.emailProv.Deregister(ctx, string(beamID)); derr != nil {
				o.log.Error("rollback of email registration failed", "beam", beamID, "err", derr)
			}
			return nil, fmt.Errorf("seal %s: %w", key, err)
		}
	}

	res := &domain.Resource{
		BeamhallID:          beamhallID,
		BeamID:              beamID,
		Channel:             domain.ChannelShared,
		Type:                domain.ResourceEmail,
		Status:              domain.ResourceReady,
		ConnectionSecretRef: domain.SecretRef{BeamhallID: beamhallID, BeamID: beamID, Key: emailPassKey, Channel: domain.ChannelShared},
		Spec: map[string]string{
			"username":  creds.Username,
			"pass_hash": mail.PasswordHashHex(creds.Password),
			"senders":   "",
			"per_day":   strconv.Itoa(o.emailCfg.Limits.PerDay),
			"burst":     strconv.Itoa(o.emailCfg.Limits.Burst),
		},
		BackingHandle: creds.Username,
	}
	if err := o.st.CreateResource(ctx, res); err != nil {
		return nil, err
	}
	o.log.Info("email provisioned", "beam", beamID, "user", creds.Username)
	return emailSecretKeys(), nil
}

// EmailInfo is the non-secret view of a beam's email facility (show_email).
type EmailInfo struct {
	Provisioned     bool     `json:"provisioned"`
	Host            string   `json:"host,omitempty"`
	Port            int      `json:"port,omitempty"`
	Username        string   `json:"username,omitempty"`
	AllowedSenders  []string `json:"allowed_senders,omitempty"`
	RateLimitPerDay int      `json:"rate_limit_per_day,omitempty"`
}

// ShowEmail reports a beam's email wiring without exposing the password.
func (o *Orchestrator) ShowEmail(ctx context.Context, actor Actor, beamhallID, beamID domain.ID) (EmailInfo, error) {
	if err := o.authorize(ctx, actor, policy.ActionShowEmail, beamhallID, beamID); err != nil {
		return EmailInfo{}, err
	}
	info, err := o.showEmail(ctx, beamID)
	return info, o.outcome(ctx, actor, policy.ActionShowEmail, beamhallID, beamID, err)
}

func (o *Orchestrator) showEmail(ctx context.Context, beamID domain.ID) (EmailInfo, error) {
	resources, err := o.st.ListResourcesByBeam(ctx, beamID)
	if err != nil {
		return EmailInfo{}, err
	}
	for _, r := range resources {
		if r.Type != domain.ResourceEmail {
			continue
		}
		info := EmailInfo{
			Provisioned: true,
			Host:        o.emailCfg.BeamHost,
			Port:        o.emailCfg.BeamPort,
			Username:    r.Spec["username"],
		}
		if s := strings.TrimSpace(r.Spec["senders"]); s != "" {
			info.AllowedSenders = strings.Split(s, ",")
		}
		info.RateLimitPerDay, _ = strconv.Atoi(r.Spec["per_day"])
		return info, nil
	}
	return EmailInfo{Provisioned: false}, nil
}

// SetEmailSenders curates which From addresses/domains a beam may send as — the
// IT-set allowlist (separation of duties, PLAN §5.12). Set-and-replace. Pushes
// to the broker and persists the set for show_email. IT-only (admin:it), audited.
func (o *Orchestrator) SetEmailSenders(ctx context.Context, actor Actor, beamhallID, beamID domain.ID, senders []string) error {
	if err := o.requireIT(actor); err != nil {
		return o.itAudit(ctx, actor, "admin_set_email_senders", beamhallID, err)
	}
	return o.itAudit(ctx, actor, "admin_set_email_senders", beamhallID, o.setEmailSenders(ctx, beamID, senders))
}

func (o *Orchestrator) setEmailSenders(ctx context.Context, beamID domain.ID, senders []string) error {
	if !o.EmailEnabled() {
		return mail.ErrNotEnabled
	}
	clean := make([]string, 0, len(senders))
	for _, s := range senders {
		if s = strings.TrimSpace(s); s != "" {
			clean = append(clean, s)
		}
	}
	resources, err := o.st.ListResourcesByBeam(ctx, beamID)
	if err != nil {
		return err
	}
	for i := range resources {
		r := resources[i]
		if r.Type != domain.ResourceEmail {
			continue
		}
		if err := o.emailProv.SetSenders(ctx, string(beamID), clean); err != nil {
			return fmt.Errorf("set senders at broker: %w", err)
		}
		if r.Spec == nil {
			r.Spec = map[string]string{}
		}
		r.Spec["senders"] = strings.Join(clean, ",")
		return o.st.UpdateResource(ctx, &r)
	}
	return fmt.Errorf("beam has no provisioned email — call provision_email first")
}

// SetEmailProvider configures the appliance's outbound mail smarthost at runtime
// (admin_set_email_provider) — the installer ships the broker unconfigured; this
// is how IT turns email on. The broker holds + persists the credential (never the
// vault, never a beam); an empty smarthost disables delivery. IT-only, audited,
// routine (no four-eyes — it's provider plumbing, not appliance-wide auth topology).
func (o *Orchestrator) SetEmailProvider(ctx context.Context, actor Actor, smarthost, username, password string, startTLS bool) error {
	if err := o.requireIT(actor); err != nil {
		return o.itAudit(ctx, actor, "admin_set_email_provider", "", err)
	}
	return o.itAudit(ctx, actor, "admin_set_email_provider", "",
		o.setEmailProvider(ctx, smarthost, username, password, startTLS))
}

func (o *Orchestrator) setEmailProvider(ctx context.Context, smarthost, username, password string, startTLS bool) error {
	if o.emailProv == nil {
		return fmt.Errorf("no mail broker is configured on this appliance")
	}
	smarthost = strings.TrimSpace(smarthost)
	if err := o.emailProv.SetProvider(ctx, mail.ProviderConfig{
		Smarthost:       smarthost,
		Username:        username,
		Password:        password,
		DisableStartTLS: !startTLS,
	}); err != nil {
		return err
	}
	o.emailEnabled.Store(smarthost != "")
	return nil
}

// EmailProviderConfigured reports whether IT has set a smarthost (for show/report).
func (o *Orchestrator) EmailProviderConfigured() bool { return o.EmailEnabled() }

// reclaimEmail deregisters a beam at the broker and deletes its sealed SMTP
// secrets on archive/destroy (no orphans). Called from reclaimResources.
func (o *Orchestrator) reclaimEmail(ctx context.Context, r domain.Resource) {
	if o.emailProv != nil {
		if err := o.emailProv.Deregister(ctx, string(r.BeamID)); err != nil {
			o.log.Warn("deregistering email at broker on destroy", "beam", r.BeamID, "err", err)
		}
	}
	for _, key := range emailSecretKeys() {
		ref := domain.SecretRef{BeamhallID: r.BeamhallID, BeamID: r.BeamID, Key: key, Channel: domain.ChannelShared}
		if err := o.vault.Delete(ctx, ref); err != nil {
			o.log.Warn("deleting sealed email secret on destroy", "beam", r.BeamID, "key", key, "err", err)
		}
	}
}

// ReconcileEmail learns whether the broker has a provider configured (it owns +
// persists that itself, so beamhalld picks it up across restarts) and re-pushes
// every beam's registration so a restarted broker is rebuilt from the
// authoritative resource rows. Idempotent + self-healing; run at boot and on a
// tick. The provider config is NOT pushed from here — only the broker owns it.
func (o *Orchestrator) ReconcileEmail(ctx context.Context) error {
	if !o.EmailBrokerWired() {
		return nil
	}
	enabled, _, err := o.emailProv.Status(ctx)
	if err != nil {
		return fmt.Errorf("email broker status: %w", err)
	}
	o.emailEnabled.Store(enabled)
	if !enabled {
		return nil // broker present but no provider configured yet
	}
	halls, err := o.st.ListBeamhalls(ctx)
	if err != nil {
		return err
	}
	for _, h := range halls {
		resources, err := o.st.ListResourcesByBeamhall(ctx, h.ID)
		if err != nil {
			o.log.Warn("email reconcile: list resources", "beamhall", h.ID, "err", err)
			continue
		}
		for _, r := range resources {
			if r.Type != domain.ResourceEmail {
				continue
			}
			perDay, _ := strconv.Atoi(r.Spec["per_day"])
			burst, _ := strconv.Atoi(r.Spec["burst"])
			var allowed []string
			if s := strings.TrimSpace(r.Spec["senders"]); s != "" {
				allowed = strings.Split(s, ",")
			}
			if err := o.emailProv.RegisterHashed(ctx, string(r.BeamID), r.Spec["username"], r.Spec["pass_hash"],
				allowed, mail.Limits{PerDay: perDay, Burst: burst}); err != nil {
				o.log.Warn("email reconcile: register beam", "beam", r.BeamID, "err", err)
			}
		}
	}
	return nil
}

// EmailAuditCursor returns the broker's current high-water audit seq, used to
// initialise the pull cursor at boot so the backlog already in the broker ring
// isn't re-appended to the chain.
func (o *Orchestrator) EmailAuditCursor(ctx context.Context) (int64, error) {
	if !o.EmailBrokerWired() {
		return 0, nil
	}
	_, next, err := o.emailProv.Status(ctx)
	return next, err
}

// DrainEmailAudit pulls per-message events newer than after from the broker and
// appends each to the hash chain, returning the new cursor. Run on a ticker.
// Audit residual (documented): events buffered in the broker between pulls are
// lost if the broker crashes before the next pull — bounded by the pull interval.
func (o *Orchestrator) DrainEmailAudit(ctx context.Context, after int64) (int64, error) {
	if !o.EmailBrokerWired() {
		return after, nil
	}
	events, next, err := o.emailProv.PullEvents(ctx, after)
	if err != nil {
		return after, err
	}
	for _, se := range events {
		o.appendEmailAudit(ctx, se)
	}
	if next < after {
		// Broker ring reset (restart): adopt its high-water so we don't loop.
		next = after
	}
	return next, nil
}

func (o *Orchestrator) appendEmailAudit(ctx context.Context, se mail.SeqEvent) {
	beamID := domain.ID(se.BeamID)
	var beamhallID domain.ID
	if b, err := o.st.GetBeam(ctx, beamID); err == nil {
		beamhallID = b.BeamhallID
	}
	decision := domain.DecisionAllow
	if se.Result != "sent" {
		decision = domain.DecisionDeny
	}
	ev := domain.AuditEvent{
		BeamhallID:    beamhallID,
		BeamID:        beamID,
		Action:        "email_send",
		Decision:      decision,
		Reason:        se.Err,
		ResultStatus:  se.Result,
		RequestDigest: emailDigest(se.Event),
	}
	if _, err := o.alog.Append(ctx, &ev); err != nil {
		o.log.Error("append email audit event failed", "beam", beamID, "err", err)
	}
}

// emailDigest is the non-secret envelope summary recorded in the audit chain.
func emailDigest(ev mail.Event) string {
	return fmt.Sprintf("from=%s rcpts=%d size=%d subject=%q message_id=%s",
		ev.From, len(ev.To), ev.Size, ev.Subject, ev.MessageID)
}
