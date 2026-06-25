package mail

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Client is beamhalld's side of the control channel — an HTTP client to the
// bh-mail broker's loopback-published control port. It is what the orchestrator
// holds as its email facility seam: beamhalld mints credentials and pushes
// registrations/policy to the broker, and pulls audit events back. The broker
// never reaches back to beamhalld (no container→host hop).
type Client struct {
	base  string
	token string
	hc    *http.Client
}

// NewClient builds a control-channel client for the broker at baseURL (e.g.
// "http://127.0.0.1:2526").
func NewClient(baseURL, token string) *Client {
	return &Client{
		base:  strings.TrimRight(baseURL, "/"),
		token: token,
		hc:    &http.Client{Timeout: 10 * time.Second},
	}
}

// SetProvider pushes the south-side smarthost configuration to the broker.
func (c *Client) SetProvider(ctx context.Context, cfg ProviderConfig) error {
	return c.post(ctx, "/control/provider", providerWire{
		Smarthost:          cfg.Smarthost,
		Username:           cfg.Username,
		Password:           cfg.Password,
		HeloName:           cfg.HeloName,
		DisableStartTLS:    cfg.DisableStartTLS,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}, nil)
}

// Provision mints per-beam SMTP credentials, registers the beam with the broker
// (pushing only the password hash), and returns the credentials for beamhalld
// to seal into the vault.
func (c *Client) Provision(ctx context.Context, req ProvisionRequest) (Credentials, error) {
	pw, err := randomPassword()
	if err != nil {
		return Credentials{}, err
	}
	username := beamUsername(req.BeamID)
	if err := c.RegisterHashed(ctx, req.BeamID, username, PasswordHashHex(pw), req.AllowedSenders, req.Limits); err != nil {
		return Credentials{}, err
	}
	return Credentials{Username: username, Password: pw}, nil
}

// RegisterHashed (re)registers a beam from a known username + password hash —
// the boot/reconcile path, where the password is read from the resource row,
// never re-minted.
func (c *Client) RegisterHashed(ctx context.Context, beamID, username, passHashHex string, allowed []string, limits Limits) error {
	return c.post(ctx, "/control/register", registerWire{
		BeamID:      beamID,
		Username:    username,
		PassHashHex: passHashHex,
		Allowed:     allowed,
		PerDay:      limits.PerDay,
		Burst:       limits.Burst,
	}, nil)
}

// Deregister removes a beam's binding (reclaim on archive/destroy).
func (c *Client) Deregister(ctx context.Context, beamID string) error {
	return c.post(ctx, "/control/deregister", beamWire{BeamID: beamID}, nil)
}

// SetSenders replaces a beam's allowed-sender list.
func (c *Client) SetSenders(ctx context.Context, beamID string, allowed []string) error {
	return c.post(ctx, "/control/senders", sendersWire{BeamID: beamID, Allowed: allowed}, nil)
}

// PullEvents fetches audit events with seq greater than after, returning them
// and the broker's current high-water seq.
func (c *Client) PullEvents(ctx context.Context, after int64) ([]SeqEvent, int64, error) {
	var ew eventsWire
	if err := c.get(ctx, "/control/events?after="+strconv.FormatInt(after, 10), &ew); err != nil {
		return nil, after, err
	}
	return ew.Events, ew.Next, nil
}

// Status reports whether the broker has a provider configured and its current
// high-water audit seq (used to initialise the pull cursor on boot).
func (c *Client) Status(ctx context.Context) (enabled bool, next int64, err error) {
	var sw statusWire
	if err := c.get(ctx, "/control/status", &sw); err != nil {
		return false, 0, err
	}
	return sw.Enabled, sw.Next, nil
}

// CACert fetches the broker's STARTTLS certificate (PEM) so beamhalld can inject
// it to beams as SMTP_CA. Empty if the broker has no cert.
func (c *Client) CACert(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/control/tls-cert", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("mail control /control/tls-cert: %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return string(b), err
}

func (c *Client) post(ctx context.Context, path string, body, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, out)
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return err
	}
	return c.do(req, out)
}

func (c *Client) do(req *http.Request, out any) error {
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("mail control %s: %s: %s", req.URL.Path, resp.Status, strings.TrimSpace(string(b)))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
