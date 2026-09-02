package apptools

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrNoAgentTools reports that the workload answered but does not serve the
// contract (404/405 on the manifest path) — a normal condition, not a fault:
// most apps are browser-only.
var ErrNoAgentTools = errors.New("the app does not serve agent tools")

// InvokeError is a non-2xx answer from the app's own tool handler. Body is
// app-authored and bounded; the caller must scrub it before it leaves the
// process.
type InvokeError struct {
	Status int
	Body   []byte
}

func (e *InvokeError) Error() string {
	return fmt.Sprintf("the app answered HTTP %d", e.Status)
}

// Client is the broker's HTTP side: it dials a workload's bridge address
// directly (host-originated traffic is outside the egress rules) with every
// request bounded — a paused container freezes its network stack, and an
// unbounded read would hang on it forever.
type Client struct {
	hc              *http.Client
	invokeTimeout   time.Duration
	manifestTimeout time.Duration
}

// NewClient builds a broker client. Non-positive timeouts get the defaults
// (30s invoke, 5s manifest).
func NewClient(invokeTimeout, manifestTimeout time.Duration) *Client {
	if invokeTimeout <= 0 {
		invokeTimeout = 30 * time.Second
	}
	if manifestTimeout <= 0 {
		manifestTimeout = 5 * time.Second
	}
	return &Client{hc: &http.Client{}, invokeTimeout: invokeTimeout, manifestTimeout: manifestTimeout}
}

// FetchManifest retrieves and validates the tool menu of the workload at
// backendAddr ("ip:port").
func (c *Client) FetchManifest(ctx context.Context, backendAddr, assertion string) (Manifest, error) {
	ctx, cancel := context.WithTimeout(ctx, c.manifestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+backendAddr+PathTools, nil)
	if err != nil {
		return Manifest{}, err
	}
	req.Header.Set(HeaderAssertion, assertion)
	resp, err := c.hc.Do(req)
	if err != nil {
		return Manifest{}, fmt.Errorf("the app did not answer: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed:
		return Manifest{}, ErrNoAgentTools
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBytes))
		return Manifest{}, fmt.Errorf("the app answered %s to the tool menu request: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	body, err := readCapped(resp.Body, MaxManifestBytes)
	if err != nil {
		return Manifest{}, fmt.Errorf("tool menu: %w", err)
	}
	return ParseManifest(body)
}

// Invoke calls one tool and returns the app's raw (bounded) response body.
func (c *Client) Invoke(ctx context.Context, backendAddr, tool, assertion string, args []byte) ([]byte, error) {
	if len(args) > MaxArgumentBytes {
		return nil, fmt.Errorf("arguments are %d bytes; the maximum is %d", len(args), MaxArgumentBytes)
	}
	if len(args) == 0 {
		args = []byte("{}")
	}
	ctx, cancel := context.WithTimeout(ctx, c.invokeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://"+backendAddr+PathTools+"/"+url.PathEscape(tool), bytes.NewReader(args))
	if err != nil {
		return nil, err
	}
	req.Header.Set(HeaderAssertion, assertion)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("the app did not answer: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBytes))
		return nil, &InvokeError{Status: resp.StatusCode, Body: bytes.TrimSpace(b)}
	}
	body, err := readCapped(resp.Body, MaxResultBytes)
	if err != nil {
		return nil, fmt.Errorf("tool result: %w", err)
	}
	return body, nil
}

func readCapped(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("response exceeds the %d-byte limit", limit)
	}
	return b, nil
}
