// Package c2c is the beam-to-beam relay's HTTP surface (PLAN §5.15 stage 3):
// a dedicated listener, reachable from workload bridges through the
// BEAMHALL-INPUT guard's one deliberate hole, that authenticates the CALLING
// WORKLOAD (injected key + live container address) and relays tool calls
// into granted target beams. It is never mounted on the control mux — the
// backplane's own endpoints stay unreachable from workloads.
//
// The wire contract lives in docs/app-tools.md ("Calling other apps"):
//
//	GET  /c2c/v1/peers                                → granted targets
//	GET  /c2c/v1/peer/<workspace>/<app>/tools         → target's tool menu
//	POST /c2c/v1/peer/<workspace>/<app>/tools/<name>  → invoke one tool
//
// with the key in the Beamhall-C2C-Key header. Errors are teaching JSON:
// {"error":"...","hint":"..."}.
package c2c

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/Beamhall/beamhall/internal/apptools"
	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/orch"
)

// Backplane is the narrow orchestrator slice the relay needs.
type Backplane interface {
	C2CAuthenticate(ctx context.Context, key, remoteIP string) (domain.ID, error)
	C2CPeers(ctx context.Context, source domain.ID) ([]orch.PeerTargetView, error)
	C2CCall(ctx context.Context, source domain.ID, workspace, app, tool string, args []byte) (orch.UseAppResult, error)
}

// Server is the relay's http.Handler. It reads the caller address from the
// socket only — never X-Forwarded-For: the address is authentication material
// here, and this listener has no proxy in front of it.
type Server struct {
	bp  Backplane
	log *slog.Logger

	mu      sync.RWMutex
	subnets []*net.IPNet
}

// New builds the relay handler.
func New(bp Backplane, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{bp: bp, log: log}
}

// SetSubnets replaces the bridge-subnet set requests must originate from —
// pushed by the egress sync (which runs before any fresh hall's first
// container starts), never snapshotted at boot: a hall created later must
// not be uniformly refused. Unparsable entries are skipped.
func (s *Server) SetSubnets(cidrs []string) {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	s.mu.Lock()
	s.subnets = nets
	s.mu.Unlock()
}

func (s *Server) fromBridge(ip net.IP) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, n := range s.subnets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		writeErr(w, http.StatusForbidden, "relay credentials were not accepted", "")
		return
	}
	ip := net.ParseIP(host)
	// Defense in depth behind the iptables guard: the listener binds all
	// interfaces, but only workload bridges may speak to it.
	if ip == nil || !s.fromBridge(ip) {
		writeErr(w, http.StatusForbidden, "relay credentials were not accepted", "")
		return
	}
	source, err := s.bp.C2CAuthenticate(r.Context(), r.Header.Get(apptools.HeaderC2CKey), host)
	if err != nil {
		writeErr(w, http.StatusForbidden, "relay credentials were not accepted",
			"send the key from the file named in /run/beamhall/c2c.json in the "+apptools.HeaderC2CKey+" header")
		return
	}

	switch {
	case r.URL.Path == apptools.C2CPathPeers && r.Method == http.MethodGet:
		s.handlePeers(w, r, source)
	case strings.HasPrefix(r.URL.Path, apptools.C2CPathPeer):
		s.handlePeer(w, r, source)
	default:
		writeErr(w, http.StatusNotFound, "no such relay route",
			"GET "+apptools.C2CPathPeers+", GET "+apptools.C2CPathPeer+"<workspace>/<app>/tools, or POST .../tools/<name>")
	}
}

func (s *Server) handlePeers(w http.ResponseWriter, r *http.Request, source domain.ID) {
	peers, err := s.bp.C2CPeers(r.Context(), source)
	if err != nil {
		s.relayErr(w, err)
		return
	}
	if peers == nil {
		peers = []orch.PeerTargetView{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": apptools.Version, "peers": peers})
}

// handlePeer serves /c2c/v1/peer/<workspace>/<app>/tools[/<name>].
func (s *Server) handlePeer(w http.ResponseWriter, r *http.Request, source domain.ID) {
	rest := strings.TrimPrefix(r.URL.Path, apptools.C2CPathPeer)
	parts := strings.Split(rest, "/")
	if len(parts) < 3 || parts[0] == "" || parts[1] == "" || parts[2] != "tools" || len(parts) > 4 {
		writeErr(w, http.StatusNotFound, "no such relay route",
			"the shape is "+apptools.C2CPathPeer+"<workspace>/<app>/tools[/<name>]")
		return
	}
	workspace, app := parts[0], parts[1]

	switch {
	case len(parts) == 3 && r.Method == http.MethodGet: // menu
		res, err := s.bp.C2CCall(r.Context(), source, workspace, app, "", nil)
		if err != nil {
			s.relayErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, res.Menu)
	case len(parts) == 4 && parts[3] != "" && r.Method == http.MethodPost: // invoke
		args, err := io.ReadAll(io.LimitReader(r.Body, apptools.MaxArgumentBytes+1))
		if err != nil {
			writeErr(w, http.StatusBadRequest, "could not read the argument body", "")
			return
		}
		if len(args) > apptools.MaxArgumentBytes {
			writeErr(w, http.StatusRequestEntityTooLarge, "arguments exceed the relay cap",
				"argument bodies are limited to 64 KiB")
			return
		}
		res, err := s.bp.C2CCall(r.Context(), source, workspace, app, parts[3], args)
		if err != nil {
			s.relayErr(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(res.Result)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "wrong method for this relay route",
			"GET fetches the menu; POST .../tools/<name> invokes")
	}
}

// relayErr translates orchestrator refusals into teaching JSON without ever
// widening the uniform ones.
func (s *Server) relayErr(w http.ResponseWriter, err error) {
	var ate *orch.AppToolError
	switch {
	case errors.Is(err, orch.ErrPeerNotGranted):
		writeErr(w, http.StatusNotFound, orch.ErrPeerNotGranted.Error(), "")
	case errors.Is(err, orch.ErrPeerNotLive):
		writeErr(w, http.StatusConflict, orch.ErrPeerNotLive.Error(), "")
	case errors.Is(err, orch.ErrAppNoTools):
		writeErr(w, http.StatusNotFound, "the granted app does not offer agent tools",
			"its team must serve the app-tools contract (docs/app-tools.md) on its live channel")
	case errors.As(err, &ate):
		// The target's own answer, already scrubbed and bounded — relay it.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		writeJSONBody(w, map[string]any{"error": "the app answered an error", "status": ate.Status, "body": ate.Body})
	default:
		writeErr(w, http.StatusServiceUnavailable, err.Error(), "")
	}
}

func writeErr(w http.ResponseWriter, status int, msg, hint string) {
	body := map[string]any{"error": msg}
	if hint != "" {
		body["hint"] = hint
	}
	writeJSON(w, status, body)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	writeJSONBody(w, v)
}

func writeJSONBody(w http.ResponseWriter, v any) {
	_ = json.NewEncoder(w).Encode(v)
}
