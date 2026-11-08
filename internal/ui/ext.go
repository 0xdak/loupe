package ui

import "net/http"

// listExt returns every discovered extension and its state.
func (s *Server) listExt(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.opts.Extensions.List())
}

// setExt enables or disables one extension, starting or stopping its process.
func (s *Server) setExt(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if err := s.opts.Extensions.SetEnabled(r.PathValue("name"), in.Enabled); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, s.opts.Extensions.List())
}

// reloadExt re-scans the extensions directory for newly added extensions.
func (s *Server) reloadExt(w http.ResponseWriter, r *http.Request) {
	s.opts.Extensions.Reload()
	writeJSON(w, s.opts.Extensions.List())
}

// extLogs returns an extension's recent log and stderr lines.
func (s *Server) extLogs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"logs": s.opts.Extensions.Logs(r.PathValue("name"))})
}

// listIssues returns the issues extensions have reported, newest first.
func (s *Server) listIssues(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.opts.Extensions.Issues())
}

// clearIssues drops every collected issue.
func (s *Server) clearIssues(w http.ResponseWriter, r *http.Request) {
	s.opts.Extensions.ClearIssues()
	w.WriteHeader(http.StatusNoContent)
}
