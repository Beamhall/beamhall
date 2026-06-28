package s3

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
// bh-objstore broker's loopback-published control port. It is what the
// orchestrator holds as its object-store facility seam: beamhalld mints
// credentials and pushes registrations/provider/quota to the broker, and pulls
// audit events back. The broker never reaches back to beamhalld (no
// container→host hop).
type Client struct {
	base  string
	token string
	hc    *http.Client
}

// NewClient builds a control-channel client for the broker at baseURL (e.g.
// "http://127.0.0.1:9001").
func NewClient(baseURL, token string) *Client {
	return &Client{
		base:  strings.TrimRight(baseURL, "/"),
		token: token,
		hc:    &http.Client{Timeout: 15 * time.Second},
	}
}

// SetProvider pushes the south-side backend configuration to the broker (empty
// Endpoint = local disk backend).
func (c *Client) SetProvider(ctx context.Context, cfg ProviderConfig) error {
	return c.post(ctx, "/control/provider", providerWire{
		Endpoint:       cfg.Endpoint,
		Region:         cfg.Region,
		Bucket:         cfg.Bucket,
		AccessKey:      cfg.AccessKey,
		SecretKey:      cfg.SecretKey,
		ForcePathStyle: cfg.ForcePathStyle,
		UseSSL:         cfg.UseSSL,
	}, nil)
}

// Provision mints per-beam S3 credentials, registers the beam+channel with the
// broker (pushing the PLAINTEXT secret, which SigV4 requires), and returns the
// credentials for beamhalld to seal into the vault.
func (c *Client) Provision(ctx context.Context, req ProvisionRequest) (Credentials, error) {
	creds, err := MintCredentials()
	if err != nil {
		return Credentials{}, err
	}
	if err := c.RegisterKey(ctx, Registration{
		BeamID:    req.BeamID,
		Channel:   req.Channel,
		AccessKey: creds.AccessKey,
		SecretKey: creds.SecretKey,
		Bucket:    req.Bucket,
		Limits:    req.Limits,
	}); err != nil {
		return Credentials{}, err
	}
	return creds, nil
}

// RegisterKey (re)registers a beam+channel from known credentials — the
// boot/reconcile path, where beamhalld reads the plaintext secret back from the
// vault and re-pushes it (the broker keeps registrations only in memory).
func (c *Client) RegisterKey(ctx context.Context, reg Registration) error {
	return c.post(ctx, "/control/register", registerWire{
		BeamID:    reg.BeamID,
		Channel:   reg.Channel,
		AccessKey: reg.AccessKey,
		SecretKey: reg.SecretKey,
		Bucket:    reg.Bucket,
		MaxBytes:  reg.Limits.MaxBytes,
	}, nil)
}

// Deregister removes a beam+channel's binding; purge also deletes its stored data.
func (c *Client) Deregister(ctx context.Context, beamID, channel string, purge bool) error {
	return c.post(ctx, "/control/deregister", deregisterWire{BeamID: beamID, Channel: channel, Purge: purge}, nil)
}

// SetQuota updates a beam+channel's storage cap.
func (c *Client) SetQuota(ctx context.Context, beamID, channel string, maxBytes int64) error {
	return c.post(ctx, "/control/quota", quotaWire{BeamID: beamID, Channel: channel, MaxBytes: maxBytes}, nil)
}

// PullEvents fetches audit events with seq greater than after, returning them and
// the broker's current high-water seq.
func (c *Client) PullEvents(ctx context.Context, after int64) ([]SeqEvent, int64, error) {
	var ew eventsWire
	if err := c.get(ctx, "/control/events?after="+strconv.FormatInt(after, 10), &ew); err != nil {
		return nil, after, err
	}
	return ew.Events, ew.Next, nil
}

// Status reports whether the broker has a backend and its current high-water
// audit seq (used to initialise the pull cursor on boot).
func (c *Client) Status(ctx context.Context) (enabled bool, next int64, err error) {
	var sw statusWire
	if err := c.get(ctx, "/control/status", &sw); err != nil {
		return false, 0, err
	}
	return sw.Enabled, sw.Next, nil
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
		return fmt.Errorf("objstore control %s: %s: %s", req.URL.Path, resp.Status, strings.TrimSpace(string(b)))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
