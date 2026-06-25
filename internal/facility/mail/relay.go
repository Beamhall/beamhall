package mail

import (
	"crypto/tls"
	"errors"
	"io"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

// NewServer builds the in-hall SMTP submission server (the relay) bound to the
// Provisioner as its backend. A non-nil tlsCfg makes the server advertise
// STARTTLS so strict clients (Go's net/smtp) can upgrade before AUTH;
// AllowInsecureAuth stays on so libraries that send plaintext AUTH on the
// host-local bridge (nodemailer, Python smtplib) also work.
func (p *Provisioner) NewServer(addr string, tlsCfg *tls.Config) *smtp.Server {
	s := smtp.NewServer(p)
	s.Addr = addr
	s.Domain = "bh-mail"
	s.TLSConfig = tlsCfg
	s.AllowInsecureAuth = true
	s.MaxMessageBytes = 25 << 20
	s.MaxRecipients = 100
	s.ReadTimeout = 2 * time.Minute
	s.WriteTimeout = 2 * time.Minute
	return s
}

// NewSession implements smtp.Backend.
func (p *Provisioner) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &session{p: p}, nil
}

// session is one SMTP connection. It authenticates against the registry, then
// enforces the sender allowlist (at MAIL FROM) and rate limit + forward (at
// DATA). It implements smtp.AuthSession.
type session struct {
	p      *Provisioner
	authed bool
	reg    *registration
	from   string
	to     []string
}

func (s *session) AuthMechanisms() []string { return []string{"PLAIN", "LOGIN"} }

func (s *session) Auth(mech string) (sasl.Server, error) {
	switch mech {
	case "PLAIN":
		return sasl.NewPlainServer(func(_, username, password string) error {
			return s.authenticate(username, password)
		}), nil
	case "LOGIN":
		return &loginServer{authenticate: s.authenticate}, nil
	}
	return nil, smtp.ErrAuthUnknownMechanism
}

func (s *session) authenticate(username, password string) error {
	reg, ok := s.p.lookup(username)
	if !ok || !reg.checkPassword(password) {
		return smtp.ErrAuthFailed
	}
	s.authed = true
	s.reg = reg
	return nil
}

func (s *session) Mail(from string, _ *smtp.MailOptions) error {
	if !s.authed {
		return smtp.ErrAuthRequired
	}
	if !senderAllowed(from, s.reg.allowedSnapshot()) {
		s.p.emit(Event{BeamID: s.reg.beamID, From: from, Result: "rejected", Err: "sender not permitted"})
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message:      "sender address not permitted for this beam",
		}
	}
	s.from = from
	s.to = nil
	return nil
}

func (s *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	if !s.authed {
		return smtp.ErrAuthRequired
	}
	s.to = append(s.to, to)
	return nil
}

func (s *session) Data(r io.Reader) error {
	if !s.authed {
		return smtp.ErrAuthRequired
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	switch err := s.p.deliver(s.reg, s.from, s.to, data); {
	case err == nil:
		return nil
	case errors.Is(err, ErrRateLimited):
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 7, 0},
			Message:      "rate limit exceeded for this beam, retry later",
		}
	default:
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 3, 0},
			Message:      "upstream delivery failed, retry later",
		}
	}
}

func (s *session) Reset() {
	s.from = ""
	s.to = nil
}

func (s *session) Logout() error { return nil }

// loginServer is a minimal SASL LOGIN server (go-sasl ships only a LOGIN
// client). go-smtp base64-decodes client responses before calling Next, so we
// work in plain bytes.
type loginServer struct {
	authenticate func(username, password string) error
	username     string
	state        int
}

func (l *loginServer) Next(response []byte) (challenge []byte, done bool, err error) {
	switch l.state {
	case 0:
		// Some clients send the username as the initial response.
		if len(response) > 0 {
			l.username = string(response)
			l.state = 2
			return []byte("Password:"), false, nil
		}
		l.state = 1
		return []byte("Username:"), false, nil
	case 1:
		l.username = string(response)
		l.state = 2
		return []byte("Password:"), false, nil
	case 2:
		if err := l.authenticate(l.username, string(response)); err != nil {
			return nil, true, err
		}
		return nil, true, nil
	}
	return nil, true, errors.New("mail: invalid LOGIN state")
}
