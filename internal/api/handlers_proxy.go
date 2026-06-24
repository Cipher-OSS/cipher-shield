package api

import (
	"encoding/json"
	"net/http"

	shield "github.com/cipher-oss/cipher-shield/internal"
)

// GET /api/v1/health
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]string{"status": "ok", "version": apiVersion})
}

// GET /api/v1/config — unauthenticated; lets clients discover server capabilities.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]interface{}{
		"version":      apiVersion,
		"auth_enabled": len(s.jwtSecret) > 0,
		"mode":         s.mode,
	})
}

// GET /api/v1/badlist — returns the loaded known-bad list as JSON.
func (s *Server) handleBadlist(w http.ResponseWriter, r *http.Request) {
	if s.badlist == nil {
		jsonOK(w, map[string]interface{}{"npm": []interface{}{}, "pypi": []interface{}{}})
		return
	}
	raw := s.badlist.RawJSON()
	if len(raw) == 0 {
		jsonOK(w, map[string]interface{}{"npm": []interface{}{}, "pypi": []interface{}{}})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(raw)
}

// POST /api/v1/report — receives a ScanResult from a proxy agent and stores it.
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	var result shield.ScanResult
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		jsonError(w, "invalid scan result: "+err.Error(), http.StatusBadRequest)
		return
	}
	if result.ScanID == "" || result.Package.Name == "" {
		jsonError(w, "scan_id and package name required", http.StatusBadRequest)
		return
	}
	if err := s.store.SaveResult(r.Context(), result); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"status": "ok"})
}
