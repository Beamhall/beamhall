package web

import (
	"bytes"
	"embed"
	"html/template"
	"net/http"
)

//go:embed templates/*.html
var templatesFS embed.FS

func parseTemplates() (*template.Template, error) {
	return template.ParseFS(templatesFS, "templates/*.html")
}

// render executes a named page template into a buffer first, so a template
// error becomes a 500 instead of a half-written page.
func (s *Server) render(w http.ResponseWriter, name string, data any) {
	var buf bytes.Buffer
	if err := s.tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		s.log.Error("render template", "name", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

// base carries the fields every authenticated page's layout needs.
type base struct {
	Title    string
	Operator string
	Flash    string
	CSRF     string
}
