package mail

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	netsmtp "net/smtp"
)

// SMTPForwarder is the south-side forwarder: it relays a message to the
// configured smarthost over SMTP with STARTTLS + AUTH. One adapter covers
// external providers (Mailgun/SendGrid/SES/Postmark) and internal relays — the
// beam never sees these credentials and never learns the provider.
type SMTPForwarder struct {
	cfg  ProviderConfig
	helo string
}

// NewSMTPForwarder builds a forwarder for the given provider.
func NewSMTPForwarder(cfg ProviderConfig) *SMTPForwarder {
	helo := cfg.HeloName
	if helo == "" {
		helo = "beamhall"
	}
	return &SMTPForwarder{cfg: cfg, helo: helo}
}

// Forward delivers one message to the smarthost. The context bounds the dial;
// the SMTP exchange then runs to completion.
func (f *SMTPForwarder) Forward(ctx context.Context, env Envelope) error {
	host, _, err := net.SplitHostPort(f.cfg.Smarthost)
	if err != nil {
		return fmt.Errorf("smarthost address %q: %w", f.cfg.Smarthost, err)
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", f.cfg.Smarthost)
	if err != nil {
		return fmt.Errorf("dial smarthost: %w", err)
	}

	c, err := netsmtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer c.Close()

	if err := c.Hello(f.helo); err != nil {
		return fmt.Errorf("ehlo: %w", err)
	}

	if !f.cfg.DisableStartTLS {
		if ok, _ := c.Extension("STARTTLS"); ok {
			tcfg := &tls.Config{ServerName: host, InsecureSkipVerify: f.cfg.InsecureSkipVerify}
			if err := c.StartTLS(tcfg); err != nil {
				return fmt.Errorf("starttls: %w", err)
			}
		}
	}

	if f.cfg.Username != "" {
		if ok, _ := c.Extension("AUTH"); ok {
			if err := c.Auth(netsmtp.PlainAuth("", f.cfg.Username, f.cfg.Password, host)); err != nil {
				return fmt.Errorf("auth: %w", err)
			}
		}
	}

	if err := c.Mail(env.From); err != nil {
		return fmt.Errorf("mail from: %w", err)
	}
	for _, rcpt := range env.To {
		if err := c.Rcpt(rcpt); err != nil {
			return fmt.Errorf("rcpt to %q: %w", rcpt, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("data: %w", err)
	}
	if _, err := w.Write(env.Data); err != nil {
		return fmt.Errorf("write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close body: %w", err)
	}
	return c.Quit()
}
