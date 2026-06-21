package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Beamhall/beamhall/internal/domain"
	"github.com/Beamhall/beamhall/internal/orch"
)

// redirectFlash sends the operator back to a page with a flash message.
func redirectFlash(w http.ResponseWriter, r *http.Request, path, flash string) {
	http.Redirect(w, r, path+"?flash="+url.QueryEscape(flash), http.StatusSeeOther)
}

func (s *Server) actionCreateBeamhall(w http.ResponseWriter, r *http.Request) {
	if err := s.checkCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	atoi := func(k string, def int) int {
		if v, err := strconv.Atoi(r.FormValue(k)); err == nil {
			return v
		}
		return def
	}
	spec := orch.NewBeamhallSpec{
		Slug:         strings.TrimSpace(r.FormValue("slug")),
		DisplayName:  strings.TrimSpace(r.FormValue("display_name")),
		Department:   strings.TrimSpace(r.FormValue("department")),
		RuntimeClass: domain.RuntimeClass(r.FormValue("runtime_class")),
		Template:     domain.TemplateWebApp,
		LiveSlots:    atoi("live_slots", 1),
		EgressMode:   domain.EgressDenyAll,
		Quota: domain.ResourceQuota{
			MaxBeams:     atoi("max_beams", 5),
			MaxLiveSlots: atoi("live_slots", 1),
			MaxDBCount:   atoi("max_db", 2),
		},
	}
	if _, err := s.bp.CreateBeamhall(r.Context(), s.actor(r), spec); err != nil {
		redirectFlash(w, r, "/admin", "create beamhall failed: "+err.Error())
		return
	}
	redirectFlash(w, r, "/admin", "beamhall "+spec.Slug+" created")
}

func (s *Server) actionRegisterIdentity(w http.ResponseWriter, r *http.Request) {
	if err := s.checkCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	_, err := s.bp.RegisterIdentity(r.Context(), s.actor(r),
		strings.TrimSpace(r.FormValue("issuer")), strings.TrimSpace(r.FormValue("subject")),
		strings.TrimSpace(r.FormValue("email")), strings.TrimSpace(r.FormValue("display_name")))
	if err != nil {
		redirectFlash(w, r, "/admin", "register identity failed: "+err.Error())
		return
	}
	redirectFlash(w, r, "/admin", "identity registered")
}

func (s *Server) actionGrantMembership(w http.ResponseWriter, r *http.Request) {
	if err := s.checkCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	dest := "/admin/beamhalls/" + r.FormValue("slug")
	err := s.bp.GrantMembership(r.Context(), s.actor(r),
		domain.ID(r.FormValue("identity_id")), domain.ID(r.FormValue("beamhall_id")),
		domain.MembershipRole(r.FormValue("role")))
	if err != nil {
		redirectFlash(w, r, dest, "grant failed: "+err.Error())
		return
	}
	redirectFlash(w, r, dest, "membership granted")
}

func (s *Server) actionSetEgress(w http.ResponseWriter, r *http.Request) {
	if err := s.checkCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	slug := r.PathValue("slug")
	dest := "/admin/beamhalls/" + slug
	bh, err := s.st.GetBeamhallBySlug(r.Context(), slug)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var allow []string
	for _, line := range strings.Split(r.FormValue("allowlist"), "\n") {
		if e := strings.TrimSpace(line); e != "" {
			allow = append(allow, e)
		}
	}
	mode := domain.EgressMode(r.FormValue("mode"))
	if err := s.bp.SetEgress(r.Context(), s.actor(r), bh.ID, mode, allow); err != nil {
		redirectFlash(w, r, dest, "egress update failed: "+err.Error())
		return
	}
	redirectFlash(w, r, dest, "egress policy updated")
}

func (s *Server) actionPromote(w http.ResponseWriter, r *http.Request) {
	s.beamAction(w, r, func(bhID, beamID domain.ID) (string, error) {
		host, err := s.bp.PromoteToLive(r.Context(), s.actor(r), bhID, beamID)
		return "promoted to " + host, err
	})
}

func (s *Server) actionPause(w http.ResponseWriter, r *http.Request) {
	s.beamAction(w, r, func(bhID, beamID domain.ID) (string, error) {
		return "paused", s.bp.PausePreview(r.Context(), s.actor(r), bhID, beamID)
	})
}

func (s *Server) actionResume(w http.ResponseWriter, r *http.Request) {
	s.beamAction(w, r, func(bhID, beamID domain.ID) (string, error) {
		host, err := s.bp.ResumePreview(r.Context(), s.actor(r), bhID, beamID)
		if err != nil {
			return "", err
		}
		return "resumed at https://" + host + " (new URL — the previous one is retired)", nil
	})
}

// actionRollback re-pins the live channel to a prior live release (the
// production-history "roll back" button). The target release id comes from the
// form; the orchestrator enforces that it is a prior live release of this beam.
func (s *Server) actionRollback(w http.ResponseWriter, r *http.Request) {
	if err := s.checkCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	slug := r.FormValue("slug")
	dest := "/admin/beamhalls/" + slug
	bh, err := s.st.GetBeamhallBySlug(r.Context(), slug)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	beamID := domain.ID(r.PathValue("id"))
	beam, err := s.st.GetBeam(r.Context(), beamID)
	if err != nil || beam.BeamhallID != bh.ID {
		http.NotFound(w, r)
		return
	}
	target := domain.ID(r.FormValue("release_id"))
	host, err := s.bp.RollbackBeam(r.Context(), s.actor(r), bh.ID, beamID, target)
	if err != nil {
		redirectFlash(w, r, dest, beam.Slug+": "+err.Error())
		return
	}
	redirectFlash(w, r, dest, beam.Slug+" production rolled back — now serving https://"+host)
}

func (s *Server) actionDestroy(w http.ResponseWriter, r *http.Request) {
	s.beamAction(w, r, func(bhID, beamID domain.ID) (string, error) {
		return "destroyed", s.bp.DestroyBeam(r.Context(), s.actor(r), bhID, beamID)
	})
}

// beamAction resolves the beam from the path id + the form's beamhall slug,
// runs op, and redirects back to the beamhall page with the result.
func (s *Server) beamAction(w http.ResponseWriter, r *http.Request, op func(bhID, beamID domain.ID) (string, error)) {
	if err := s.checkCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	slug := r.FormValue("slug")
	dest := "/admin/beamhalls/" + slug
	bh, err := s.st.GetBeamhallBySlug(r.Context(), slug)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	beamID := domain.ID(r.PathValue("id"))
	beam, err := s.st.GetBeam(r.Context(), beamID)
	if err != nil || beam.BeamhallID != bh.ID {
		http.NotFound(w, r)
		return
	}
	msg, err := op(bh.ID, beamID)
	if err != nil {
		redirectFlash(w, r, dest, beam.Slug+": "+err.Error())
		return
	}
	redirectFlash(w, r, dest, beam.Slug+" "+msg)
}

// actionApprovePromotion approves a pending promotion request (the IT-approval
// gate). The orchestrator enforces four-eyes: the logged-in operator must not be
// the requester.
func (s *Server) actionApprovePromotion(w http.ResponseWriter, r *http.Request) {
	if err := s.checkCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	dest := "/admin/beamhalls/" + r.FormValue("slug")
	host, err := s.bp.ApprovePromotion(r.Context(), s.actor(r), domain.ID(r.PathValue("id")))
	if err != nil {
		redirectFlash(w, r, dest, "approve failed: "+err.Error())
		return
	}
	redirectFlash(w, r, dest, "promotion approved — live at "+host)
}

// actionRejectPromotion rejects a pending promotion request.
func (s *Server) actionRejectPromotion(w http.ResponseWriter, r *http.Request) {
	if err := s.checkCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	dest := "/admin/beamhalls/" + r.FormValue("slug")
	err := s.bp.RejectPromotion(r.Context(), s.actor(r), domain.ID(r.PathValue("id")), r.FormValue("reason"))
	if err != nil {
		redirectFlash(w, r, dest, "reject failed: "+err.Error())
		return
	}
	redirectFlash(w, r, dest, "promotion rejected")
}
