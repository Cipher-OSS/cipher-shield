package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	shield "github.com/cipher-oss/cipher-shield/internal"
)

// GET /api/v1/history?limit=50
func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	history, err := s.store.ListHistory(r.Context(), limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if history == nil {
		history = []shield.ScanResult{}
	}
	jsonOK(w, map[string]interface{}{"results": history, "count": len(history)})
}

// GET /api/v1/violations?limit=200
func (s *Server) handleListViolations(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	violations, err := s.store.ListViolations(r.Context(), limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if violations == nil {
		violations = []shield.ViolationRow{}
	}
	jsonOK(w, map[string]interface{}{"violations": violations, "count": len(violations)})
}

// POST /api/v1/violations/{id}/dismiss
func (s *Server) handleDismiss(w http.ResponseWriter, r *http.Request) {
	scanID := mux.Vars(r)["id"]
	var req struct {
		Note string `json:"note"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	claims := claimsFromCtx(r)
	dismissedBy := ""
	if claims != nil {
		dismissedBy = claims.Email
	}

	if err := s.store.DismissResult(r.Context(), scanID, dismissedBy, req.Note); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"status": "dismissed"})
}
