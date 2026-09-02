package c2c

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Beamhall/beamhall/internal/apptools"
	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/orch"
)

type fakeBP struct {
	authedKey string
	source    domain.ID
	peers     []orch.PeerTargetView
	callErr   error
	menu      *apptools.Manifest
	result    []byte
	lastTool  string
	lastArgs  []byte
}

func (f *fakeBP) C2CAuthenticate(_ context.Context, key, remoteIP string) (domain.ID, error) {
	if key != f.authedKey {
		return "", orch.ErrPeerAuth
	}
	return f.source, nil
}

func (f *fakeBP) C2CPeers(context.Context, domain.ID) ([]orch.PeerTargetView, error) {
	return f.peers, nil
}

func (f *fakeBP) C2CCall(_ context.Context, _ domain.ID, ws, app, tool string, args []byte) (orch.UseAppResult, error) {
	f.lastTool, f.lastArgs = tool, args
	if f.callErr != nil {
		return orch.UseAppResult{}, f.callErr
	}
	if tool == "" {
		return orch.UseAppResult{Menu: f.menu}, nil
	}
	return orch.UseAppResult{Result: f.result}, nil
}

func newTestServer(t *testing.T, bp *fakeBP) *httptest.Server {
	t.Helper()
	s := New(bp, nil)
	// httptest requests originate from loopback; declaring it a "bridge
	// subnet" is how tests pass the source gate.
	s.SetSubnets([]string{"127.0.0.0/8"})
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	return srv
}

func doReq(t *testing.T, srv *httptest.Server, method, path, key string, body []byte, hdr map[string]string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if key != "" {
		req.Header.Set(apptools.HeaderC2CKey, key)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestRelayAuthGates(t *testing.T) {
	bp := &fakeBP{authedKey: "good-key", source: "src-1"}
	srv := newTestServer(t, bp)

	// No key / wrong key: uniform 403 with the teaching hint.
	for _, key := range []string{"", "wrong"} {
		code, body := doReq(t, srv, http.MethodGet, apptools.C2CPathPeers, key, nil, nil)
		if code != http.StatusForbidden || !strings.Contains(body, "not accepted") {
			t.Fatalf("key %q: %d %s", key, code, body)
		}
	}
	// Off-bridge source: refused before authentication even runs.
	s := New(bp, nil)
	s.SetSubnets([]string{"172.18.0.0/16"})
	off := httptest.NewServer(s)
	defer off.Close()
	code, _ := doReq(t, off, http.MethodGet, apptools.C2CPathPeers, "good-key", nil, nil)
	if code != http.StatusForbidden {
		t.Fatalf("off-bridge source must 403, got %d", code)
	}
}

// TestXForwardedForIsIgnored: the remote address is authentication material —
// a workload must not be able to claim another beam's address in-band.
func TestXForwardedForIsIgnored(t *testing.T) {
	bp := &fakeBP{authedKey: "good-key", source: "src-1"}
	s := New(bp, nil)
	s.SetSubnets([]string{"172.18.0.0/16"}) // loopback NOT included
	srv := httptest.NewServer(s)
	defer srv.Close()
	code, _ := doReq(t, srv, http.MethodGet, apptools.C2CPathPeers, "good-key", nil,
		map[string]string{"X-Forwarded-For": "172.18.0.7"})
	if code != http.StatusForbidden {
		t.Fatalf("an XFF header must not stand in for the socket address, got %d", code)
	}
}

func TestRelayPeersMenuInvoke(t *testing.T) {
	bp := &fakeBP{
		authedKey: "good-key", source: "src-1",
		peers:  []orch.PeerTargetView{{Workspace: "ops", App: "handbook", Live: true, AgentTools: true}},
		menu:   &apptools.Manifest{Version: 1, Tools: []apptools.Tool{{Name: "whoami", Description: "who"}}},
		result: []byte(`{"sum":7}`),
	}
	srv := newTestServer(t, bp)

	code, body := doReq(t, srv, http.MethodGet, apptools.C2CPathPeers, "good-key", nil, nil)
	if code != http.StatusOK || !strings.Contains(body, `"handbook"`) || !strings.Contains(body, `"agent_tools":true`) {
		t.Fatalf("peers: %d %s", code, body)
	}

	code, body = doReq(t, srv, http.MethodGet, apptools.C2CPathPeer+"ops/handbook/tools", "good-key", nil, nil)
	if code != http.StatusOK || !strings.Contains(body, `"whoami"`) {
		t.Fatalf("menu: %d %s", code, body)
	}

	code, body = doReq(t, srv, http.MethodPost, apptools.C2CPathPeer+"ops/handbook/tools/add", "good-key", []byte(`{"a":3,"b":4}`), nil)
	if code != http.StatusOK || !strings.Contains(body, `"sum":7`) {
		t.Fatalf("invoke: %d %s", code, body)
	}
	if bp.lastTool != "add" || string(bp.lastArgs) != `{"a":3,"b":4}` {
		t.Fatalf("backplane saw tool=%q args=%s", bp.lastTool, bp.lastArgs)
	}

	// Oversize args refuse before the backplane is reached.
	big := bytes.Repeat([]byte("x"), apptools.MaxArgumentBytes+1)
	code, _ = doReq(t, srv, http.MethodPost, apptools.C2CPathPeer+"ops/handbook/tools/add", "good-key", big, nil)
	if code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize args: %d", code)
	}

	// Wrong shapes.
	for _, bad := range []struct{ method, path string }{
		{http.MethodPost, apptools.C2CPathPeer + "ops/handbook/tools"}, // POST the menu
		{http.MethodGet, apptools.C2CPathPeer + "ops/tools"},           // missing app
		{http.MethodGet, "/c2c/v1/other"},
	} {
		code, _ = doReq(t, srv, bad.method, bad.path, "good-key", nil, nil)
		if code == http.StatusOK {
			t.Fatalf("%s %s must not succeed", bad.method, bad.path)
		}
	}
}

func TestRelayErrorMapping(t *testing.T) {
	cases := []struct {
		err      error
		wantCode int
		wantIn   string
	}{
		{orch.ErrPeerNotGranted, http.StatusNotFound, "reachable from this beam"},
		{orch.ErrPeerNotLive, http.StatusConflict, "not live"},
		{orch.ErrAppNoTools, http.StatusNotFound, "app-tools contract"},
		{&orch.AppToolError{Status: 422, Body: `{"nope":true}`}, http.StatusBadGateway, `"status":422`},
		{fmt.Errorf("backend melted"), http.StatusServiceUnavailable, "melted"},
	}
	for _, c := range cases {
		bp := &fakeBP{authedKey: "k", source: "s", callErr: c.err}
		srv := newTestServer(t, bp)
		code, body := doReq(t, srv, http.MethodGet, apptools.C2CPathPeer+"ops/x/tools", "k", nil, nil)
		if code != c.wantCode || !strings.Contains(body, c.wantIn) {
			t.Errorf("err %v: got %d %s, want %d containing %q", c.err, code, body, c.wantCode, c.wantIn)
		}
		var parsed map[string]any
		if err := json.Unmarshal([]byte(body), &parsed); err != nil {
			t.Errorf("err %v: body is not JSON: %s", c.err, body)
		}
	}
}
