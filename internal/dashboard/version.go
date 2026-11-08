package dashboard

// /api/version tells the page which build it is talking to.
//
// The sidebar shows it so an operator can tell at a glance whether the browser
// is driving the binary they just installed. It carries nothing else: no build
// date, no host name, no paths — this endpoint stays readable by any client the
// dashboard already accepts.

import (
	"encoding/json"
	"net/http"
)

type versionResponse struct {
	Version string `json:"version"`
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(versionResponse{Version: s.versionOrDefault()})
}
