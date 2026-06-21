package web

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/Beamhall/beamhall/internal/audit"
	"github.com/Beamhall/beamhall/internal/domain"
)

func (s *Server) base(r *http.Request, title string) base {
	return base{Title: title, Operator: operatorOf(r).Email, Flash: r.URL.Query().Get("flash"), CSRF: s.csrfToken(r)}
}

// --- dashboard ------------------------------------------------------------

type beamhallRow struct {
	domain.Beamhall
	BeamCount int
	LiveCount int
}

type dashboardData struct {
	base
	Beamhalls  []beamhallRow
	Identities []domain.Identity
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	halls, err := s.st.ListBeamhalls(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	rows := make([]beamhallRow, 0, len(halls))
	for _, h := range halls {
		bc, _ := s.st.CountBeamsByBeamhall(ctx, h.ID)
		lc, _ := s.st.CountLiveBeamsByBeamhall(ctx, h.ID)
		rows = append(rows, beamhallRow{Beamhall: h, BeamCount: bc, LiveCount: lc})
	}
	idents, err := s.st.ListIdentities(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "page-dashboard", dashboardData{base: s.base(r, "Beamhalls"), Beamhalls: rows, Identities: idents})
}

// --- beamhall detail ------------------------------------------------------

type beamRow struct {
	Beam       domain.Beam
	PreviewURL string       // the builder's iterating channel ("" when paused)
	LiveURL    string       // the pinned production channel ("" until promoted)
	LiveLog    []releaseRow // production history (live releases), newest first
}

// releaseRow is one entry in a beam's production history (a live release),
// with a clean per-beam production version label.
type releaseRow struct {
	ID      domain.ID
	Label   string // "v1", "v2", … (live history renumbered, not the raw release counter)
	Image   string // short image/digest pin
	When    string
	Current bool // the release currently serving production
}

type memberRow struct {
	Email string
	Role  domain.MembershipRole
}

type promotionRow struct {
	ID        domain.ID
	Beam      string
	Requester string
	When      string
}

type beamhallData struct {
	base
	Beamhall   domain.Beamhall
	LiveCount  int
	Beams      []beamRow
	Members    []memberRow
	Identities []domain.Identity
	// ApprovalGate is true when the IT-approval gate is on: the view hides the
	// direct promote button and surfaces Pending for approve/reject instead.
	ApprovalGate bool
	Pending      []promotionRow
	// HasProduction is true when at least one beam has a live channel (so the
	// production-history / rollback panel is worth rendering).
	HasProduction bool
}

func (s *Server) handleBeamhall(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	bh, err := s.st.GetBeamhallBySlug(ctx, r.PathValue("slug"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	beams, err := s.st.ListBeamsByBeamhall(ctx, bh.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	rows := make([]beamRow, 0, len(beams))
	hasProduction := false
	for _, b := range beams {
		preview, live := s.channelURLs(ctx, b.ID)
		rows = append(rows, beamRow{Beam: b, PreviewURL: preview, LiveURL: live, LiveLog: s.liveHistory(ctx, b)})
		if b.Mode == domain.ModeLive {
			hasProduction = true
		}
	}
	members, _ := s.st.ListMembershipsByBeamhall(ctx, bh.ID)
	mrows := make([]memberRow, 0, len(members))
	for _, m := range members {
		email := string(m.IdentityID)
		if id, err := s.st.GetIdentity(ctx, m.IdentityID); err == nil {
			email = id.Email
		}
		mrows = append(mrows, memberRow{Email: email, Role: m.Role})
	}
	idents, _ := s.st.ListIdentities(ctx)
	lc, _ := s.st.CountLiveBeamsByBeamhall(ctx, bh.ID)

	gate := s.bp.PromoteApprovalEnabled()
	var pending []promotionRow
	if gate {
		reqs, _ := s.bp.ListPendingPromotions(ctx, s.actor(r), bh.ID)
		for _, pr := range reqs {
			beamSlug := string(pr.BeamID)
			if b, err := s.st.GetBeam(ctx, pr.BeamID); err == nil {
				beamSlug = b.Slug
			}
			requester := string(pr.RequestedBy)
			if id, err := s.st.GetIdentity(ctx, pr.RequestedBy); err == nil && id.Email != "" {
				requester = id.Email
			}
			pending = append(pending, promotionRow{
				ID: pr.ID, Beam: beamSlug, Requester: requester,
				When: pr.CreatedAt.UTC().Format("2006-01-02 15:04"),
			})
		}
	}
	s.render(w, "page-beamhall", beamhallData{
		base: s.base(r, bh.Slug), Beamhall: bh, LiveCount: lc,
		Beams: rows, Members: mrows, Identities: idents,
		ApprovalGate: gate, Pending: pending, HasProduction: hasProduction,
	})
}

// channelURLs returns the beam's active preview and live route URLs as https
// URLs ("" for a channel with no active route). A dual-channel beam can show
// both at once: an iterating preview plus pinned production.
func (s *Server) channelURLs(ctx context.Context, beamID domain.ID) (preview, live string) {
	routes, err := s.st.ListRoutesByBeam(ctx, beamID)
	if err != nil {
		return "", ""
	}
	for _, rt := range routes {
		if rt.Status != domain.RouteActive {
			continue
		}
		if rt.Kind == domain.RouteLive {
			live = "https://" + rt.Hostname
		} else {
			preview = "https://" + rt.Hostname
		}
	}
	return preview, live
}

// liveHistory returns a beam's production history — its live-channel releases,
// newest first, renumbered to a clean v1,v2,… production sequence (independent
// of the raw global release counter). The release currently serving production
// is flagged Current; the rest are rollback targets.
func (s *Server) liveHistory(ctx context.Context, beam domain.Beam) []releaseRow {
	if beam.Mode != domain.ModeLive {
		return nil
	}
	rels, err := s.st.ListReleasesByBeam(ctx, beam.ID)
	if err != nil {
		return nil
	}
	// ListReleasesByBeam is newest-first; walk oldest-first to number v1,v2,…
	var rows []releaseRow
	n := 0
	for i := len(rels) - 1; i >= 0; i-- {
		r := rels[i]
		if r.Channel != domain.ChannelLive {
			continue
		}
		n++
		rows = append(rows, releaseRow{
			ID: r.ID, Label: fmt.Sprintf("v%d", n),
			Image: shortImage(r.ConfigSnapshot["pull_ref"]),
			When:  relWhen(r), Current: r.ID == beam.LiveReleaseID,
		})
	}
	// Present newest-first.
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
	return rows
}

// shortImage trims a pinned image ref (registry/host/repo@sha256:…) to a compact
// repo@digest12 for display.
func shortImage(ref string) string {
	if ref == "" {
		return "—"
	}
	if i := strings.Index(ref, "@sha256:"); i >= 0 {
		repo, dig := ref[:i], ref[i+len("@sha256:"):]
		if j := strings.LastIndex(repo, "/"); j >= 0 {
			repo = repo[j+1:]
		}
		if len(dig) > 12 {
			dig = dig[:12]
		}
		return repo + "@" + dig
	}
	return ref
}

func relWhen(r domain.Release) string {
	t := r.ActivatedAt
	if t.IsZero() {
		t = r.CreatedAt
	}
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02 15:04")
}

// --- audit ----------------------------------------------------------------

type auditRow struct {
	Seq      int64
	When     string
	Actor    string
	Action   string
	Decision string
	Result   string
	Reason   string
}

type auditData struct {
	base
	ChainOK   bool
	PruneNote string // set when the log has been pruned under a retention policy
	Events    []auditRow
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	issues, err := audit.New(s.st).Verify(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	recs, err := s.st.ListAuditEvents(ctx, 0, 300)
	if err != nil {
		s.fail(w, err)
		return
	}
	rows := make([]auditRow, 0, len(recs))
	for i := len(recs) - 1; i >= 0; i-- { // newest first
		e := recs[i]
		rows = append(rows, auditRow{
			Seq: e.Seq, When: e.Event.At.Format("2006-01-02 15:04:05"),
			Actor: short(string(e.Event.ActorID)), Action: e.Event.Action,
			Decision: string(e.Event.Decision), Result: e.Event.ResultStatus, Reason: e.Event.Reason,
		})
	}
	note := ""
	if cp, ok, cerr := s.st.LatestAuditCheckpoint(ctx); cerr == nil && ok {
		note = fmt.Sprintf("Older entries pruned through seq %d on %s by retention policy — the surviving chain below is anchored at that checkpoint.",
			cp.ThroughSeq, cp.At.Format("2006-01-02"))
	}
	s.render(w, "page-audit", auditData{base: s.base(r, "Audit log"), ChainOK: len(issues) == 0, PruneNote: note, Events: rows})
}

func short(id string) string {
	if len(id) > 8 {
		return id[len(id)-8:]
	}
	return id
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	s.log.Error("admin view", "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}
