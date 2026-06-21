// Package gitserver serves the agent-facing git smart-HTTP transport
// (PLAN §5.5): the managed per-beam repositories over /git/<hall>/<beam>.git,
// authenticated by one-time beam-scoped deploy tokens. A successful push
// triggers a build+deploy of the pushed commit, with build progress streamed
// back to the pushing client over git's sideband ("remote: ..." lines). The
// agent's only credential is a token that can push to ONE repo — never Docker,
// registry, or database credentials.
package gitserver

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-git/v5/plumbing/format/pktline"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/capability"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/sideband"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/server"

	"github.com/Beamhall/beamhall/internal/domain"
)

const (
	receivePack = "git-receive-pack" // push (write)
	uploadPack  = "git-upload-pack"  // clone/fetch (read)
)

// Directory resolves the URL's beamhall/beam slugs to IDs (*store.Store
// satisfies it).
type Directory interface {
	GetBeamhallBySlug(ctx context.Context, slug string) (domain.Beamhall, error)
	GetBeamBySlug(ctx context.Context, beamhallID domain.ID, slug string) (domain.Beam, error)
}

// Deployer builds and deploys a pushed commit, streaming build progress to
// progress, and returns the resulting URL. (*orch via an adapter satisfies it.)
type Deployer func(ctx context.Context, p Principal, sha string, progress io.Writer) (url string, err error)

// Service is the git smart-HTTP handler.
type Service struct {
	dir       Directory
	tokens    *TokenStore
	deploy    Deployer
	ensure    EnsureRepo
	transport transport.Transport
	log       *slog.Logger
}

// EnsureRepo initializes the beam's bare repo if absent (build.Repos.Ensure
// adapts to it). A push to a never-built beam must find its repo, so the
// service ensures it after the deploy token validates.
type EnsureRepo func(beamhallSlug, beamSlug string) error

// New builds the service over the bare repos rooted at reposRoot (the same
// root as build.Repos). ensure provisions a beam's repo on first push.
func New(reposRoot string, dir Directory, tokens *TokenStore, deploy Deployer, ensure EnsureRepo, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{
		dir: dir, tokens: tokens, deploy: deploy, ensure: ensure, log: log,
		transport: server.NewServer(server.NewFilesystemLoader(osfs.New(reposRoot))),
	}
}

// Handler returns the http.Handler to mount at /git/.
func (s *Service) Handler() http.Handler { return http.HandlerFunc(s.serve) }

// serve routes the smart-HTTP endpoints for both push (receive-pack) and
// clone/fetch (upload-pack):
//
//	GET  /git/<hall>/<beam>.git/info/refs?service=git-receive-pack|git-upload-pack
//	POST /git/<hall>/<beam>.git/git-receive-pack   (push  — one-time push token)
//	POST /git/<hall>/<beam>.git/git-upload-pack    (clone — read token)
func (s *Service) serve(w http.ResponseWriter, r *http.Request) {
	hall, beam, rest, ok := parsePath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	// Resolve which git service the request is for; both an info/refs probe and
	// the data POST must agree on it so we authenticate with the right token kind.
	var service string
	switch {
	case r.Method == http.MethodGet && rest == "info/refs":
		service = r.URL.Query().Get("service")
	case r.Method == http.MethodPost && (rest == receivePack || rest == uploadPack):
		service = rest
	default:
		http.NotFound(w, r)
		return
	}
	if service != receivePack && service != uploadPack {
		http.Error(w, "unsupported git service", http.StatusForbidden)
		return
	}

	write := service == receivePack
	princ, repoEndpoint, ok := s.authenticate(w, r, hall, beam, write)
	if !ok {
		return
	}
	switch {
	case r.Method == http.MethodGet && write:
		s.infoRefs(w, r, repoEndpoint)
	case r.Method == http.MethodGet:
		s.uploadInfoRefs(w, r, repoEndpoint)
	case write:
		s.receivePack(w, r, repoEndpoint, princ)
	default:
		s.uploadPack(w, r, repoEndpoint)
	}
}

// parsePath splits /git/<hall>/<beam>.git/<rest...>.
func parsePath(p string) (hall, beam, rest string, ok bool) {
	p = strings.TrimPrefix(p, "/git/")
	i := strings.Index(p, ".git/")
	if i < 0 {
		return "", "", "", false
	}
	repo, rest := p[:i], p[i+len(".git/"):]
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", "", false
	}
	return parts[0], parts[1], rest, true
}

// authenticate validates the Basic-auth git token against the resolved beam and
// returns the principal plus the repo's transport endpoint. A write (push)
// request requires a push token; a read (clone/fetch) request requires a read
// token — each scoped to this one beam's repo.
func (s *Service) authenticate(w http.ResponseWriter, r *http.Request, hallSlug, beamSlug string, write bool) (Principal, *transport.Endpoint, bool) {
	_, pass, hasAuth := r.BasicAuth()
	if !hasAuth || pass == "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="Beamhall git"`)
		http.Error(w, "git token required", http.StatusUnauthorized)
		return Principal{}, nil, false
	}
	bh, err := s.dir.GetBeamhallBySlug(r.Context(), hallSlug)
	if err != nil {
		http.Error(w, "unknown repository", http.StatusNotFound)
		return Principal{}, nil, false
	}
	beam, err := s.dir.GetBeamBySlug(r.Context(), bh.ID, beamSlug)
	if err != nil {
		http.Error(w, "unknown repository", http.StatusNotFound)
		return Principal{}, nil, false
	}
	validate := s.tokens.ValidateRead
	hint := "run get_repo again to get a fresh clone command"
	if write {
		validate = s.tokens.Validate
		hint = "run deploy_beam (with no source) again to get a fresh one-time push command"
	}
	princ, ok := validate(bh.ID, beam.ID, pass)
	if !ok {
		http.Error(w, "invalid or expired git token — "+hint, http.StatusForbidden)
		return Principal{}, nil, false
	}
	// Provision the bare repo on first authorized access (a beam may never
	// have been built before its first git push).
	if s.ensure != nil {
		if err := s.ensure(hallSlug, beamSlug); err != nil {
			s.log.Error("ensure repo", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return Principal{}, nil, false
		}
	}
	ep, err := transport.NewEndpoint("/" + hallSlug + "/" + beamSlug + ".git")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return Principal{}, nil, false
	}
	return princ, ep, true
}

func (s *Service) infoRefs(w http.ResponseWriter, r *http.Request, ep *transport.Endpoint) {
	sess, err := s.transport.NewReceivePackSession(ep, nil)
	if err != nil {
		s.log.Error("git receive-pack session", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	ar, err := sess.AdvertisedReferencesContext(r.Context())
	if errors.Is(err, transport.ErrEmptyRemoteRepository) {
		ar = emptyAdvRefs() // first push to a fresh repo
	} else if err != nil {
		s.log.Error("git advertise refs", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// go-git's receive-pack advertisement omits side-band-64k; add it (and
	// report-status) so the client negotiates the sideband we stream build
	// output and the report on.
	for _, c := range []capability.Capability{capability.Sideband64k, capability.ReportStatus} {
		if !ar.Capabilities.Supports(c) {
			_ = ar.Capabilities.Add(c)
		}
	}
	w.Header().Set("Content-Type", "application/x-git-receive-pack-advertisement")
	w.Header().Set("Cache-Control", "no-cache")
	enc := pktline.NewEncoder(w)
	_ = enc.Encodef("# service=%s\n", receivePack)
	_ = enc.Flush()
	_ = ar.Encode(w)
}

// uploadInfoRefs advertises refs for a clone/fetch (upload-pack).
func (s *Service) uploadInfoRefs(w http.ResponseWriter, r *http.Request, ep *transport.Endpoint) {
	sess, err := s.transport.NewUploadPackSession(ep, nil)
	if err != nil {
		s.log.Error("git upload-pack session", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	ar, err := sess.AdvertisedReferencesContext(r.Context())
	if errors.Is(err, transport.ErrEmptyRemoteRepository) {
		// A beam created but never pushed: advertise no refs so `git clone`
		// yields an empty working copy rather than erroring.
		ar = packp.NewAdvRefs()
	} else if err != nil {
		s.log.Error("git advertise refs (upload-pack)", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
	w.Header().Set("Cache-Control", "no-cache")
	enc := pktline.NewEncoder(w)
	_ = enc.Encodef("# service=%s\n", uploadPack)
	_ = enc.Flush()
	_ = ar.Encode(w)
}

// uploadPack serves the clone/fetch packfile (upload-pack). Read-only: it never
// triggers a build.
func (s *Service) uploadPack(w http.ResponseWriter, r *http.Request, ep *transport.Endpoint) {
	body, err := decompress(r)
	if err != nil {
		http.Error(w, "bad request body", http.StatusBadRequest)
		return
	}
	defer body.Close()

	req := packp.NewUploadPackRequest()
	if err := req.Decode(body); err != nil {
		http.Error(w, "malformed upload-pack request: "+err.Error(), http.StatusBadRequest)
		return
	}
	sess, err := s.transport.NewUploadPackSession(ep, nil)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	resp, err := sess.UploadPack(r.Context(), req)
	if err != nil {
		s.log.Error("git upload-pack", "err", err)
		http.Error(w, "upload-pack failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
	if err := resp.Encode(w); err != nil {
		s.log.Error("git upload-pack encode", "err", err)
	}
}

func (s *Service) receivePack(w http.ResponseWriter, r *http.Request, ep *transport.Endpoint, princ Principal) {
	body, err := decompress(r)
	if err != nil {
		http.Error(w, "bad request body", http.StatusBadRequest)
		return
	}
	defer body.Close()

	req := packp.NewReferenceUpdateRequest()
	if err := req.Decode(body); err != nil {
		http.Error(w, "malformed receive-pack request: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Capture the negotiated capabilities and pushed SHA before applying the
	// pack. We advertise side-band-64k so the client multiplexes its response,
	// but go-git's receive-pack server rejects that capability on the request
	// — and the pushed packfile is NOT sidebanded (sideband is server→client
	// only for receive-pack). So strip it before ReceivePack and mux the
	// response ourselves.
	sideOK := req.Capabilities.Supports(capability.Sideband64k) || req.Capabilities.Supports(capability.Sideband)
	sha := pushedSHA(req)
	req.Capabilities.Delete(capability.Sideband64k)
	req.Capabilities.Delete(capability.Sideband)

	sess, err := s.transport.NewReceivePackSession(ep, nil)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	report, err := sess.ReceivePack(r.Context(), req)
	if err != nil {
		s.log.Error("git receive-pack", "err", err)
		msg := "receive-pack failed: " + err.Error()
		if strings.Contains(err.Error(), "delta") {
			// go-git can't complete a thin pack against existing objects; the
			// client must send a self-contained pack.
			msg += " — re-run your push with --no-thin, e.g. git push --no-thin <remote> HEAD:main"
		}
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/x-git-receive-pack-result")

	// A delete-only or empty push: nothing to build.
	if sha == "" {
		s.writeReport(w, report, nil, sideOK)
		return
	}

	// Build + deploy synchronously, streaming progress to the client as
	// "remote:" lines.
	var progress io.Writer = io.Discard
	var mux *sideband.Muxer
	if sideOK {
		mux = sideband.NewMuxer(sideband.Sideband64k, w)
		progress = remoteWriter{mux}
	}
	url, derr := s.deploy(r.Context(), princ, sha, progress)
	if derr != nil {
		// The build/deploy failed. The pushed commit is already on main, so
		// DON'T spend the one-time token: the user fixes their code, commits,
		// and re-runs the SAME `git push` (a fast-forward) without re-minting.
		// Spending it here is what forced agents into a 403 → re-init →
		// divergent-history spiral (lab finding).
		if mux != nil {
			_, _ = mux.WriteChannel(sideband.ErrorMessage, []byte("deploy failed: "+oneLine(derr.Error())+"\n"))
			_, _ = mux.WriteChannel(sideband.ProgressMessage,
				[]byte("the push token is still valid — fix your code, commit, and run the same git push again.\n"))
		}
		s.failCommands(report, derr)
	} else {
		// Deploy succeeded: spend the one-time token now.
		s.tokens.Consume(princ.Beamhall, princ.Beam)
		if mux != nil {
			_, _ = mux.WriteChannel(sideband.ProgressMessage, []byte("deployed; reachable at "+url+"\n"))
		}
	}
	s.writeReport(w, report, mux, sideOK)
}

// writeReport encodes the report-status, multiplexed on the sideband when the
// client negotiated it.
func (s *Service) writeReport(w http.ResponseWriter, report *packp.ReportStatus, mux *sideband.Muxer, sideOK bool) {
	if !sideOK || mux == nil {
		_ = report.Encode(w)
		return
	}
	var buf bytes.Buffer
	_ = report.Encode(&buf)
	_, _ = mux.WriteChannel(sideband.PackData, buf.Bytes())
	_ = pktline.NewEncoder(w).Flush()
}

// failCommands marks every ref update in the report as failed so `git push`
// reports a rejection with the build/deploy reason (the commit is still in the
// repo; the next push or a fix supersedes it).
func (s *Service) failCommands(report *packp.ReportStatus, err error) {
	reason := oneLine(err.Error())
	if len(reason) > 100 {
		reason = reason[:100]
	}
	for _, cs := range report.CommandStatuses {
		cs.Status = reason
	}
}

// pushedSHA returns the new commit of the first non-delete branch update.
func pushedSHA(req *packp.ReferenceUpdateRequest) string {
	for _, c := range req.Commands {
		if !c.New.IsZero() {
			return c.New.String()
		}
	}
	return ""
}

// emptyAdvRefs is the receive-pack advertisement for a repo with no refs yet:
// a single zero-id capabilities line.
func emptyAdvRefs() *packp.AdvRefs {
	ar := packp.NewAdvRefs()
	for _, c := range []capability.Capability{capability.ReportStatus, capability.DeleteRefs, capability.OFSDelta, capability.Sideband64k} {
		_ = ar.Capabilities.Add(c)
	}
	return ar
}

// decompress returns the request body, transparently gunzipping it when the
// client used Content-Encoding: gzip.
func decompress(r *http.Request) (io.ReadCloser, error) {
	if strings.Contains(r.Header.Get("Content-Encoding"), "gzip") {
		return gzip.NewReader(r.Body)
	}
	return r.Body, nil
}

// remoteWriter turns build output into sideband progress messages.
type remoteWriter struct{ mux *sideband.Muxer }

func (rw remoteWriter) Write(p []byte) (int, error) {
	if _, err := rw.mux.WriteChannel(sideband.ProgressMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func oneLine(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "\n", " ")
}
