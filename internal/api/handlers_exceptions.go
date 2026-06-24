package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	shield "github.com/cipher-oss/cipher-shield/internal"
)

// GET /api/v1/exceptions
func (s *Server) handleListExceptions(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListExceptions(r.Context())
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if list == nil {
		list = []shield.Exception{}
	}
	jsonOK(w, map[string]interface{}{"exceptions": list})
}

// POST /api/v1/exceptions
func (s *Server) handleAddException(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
		Version   string `json:"version"`
		Reason    string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.Reason == "" {
		jsonError(w, "ecosystem, name, and reason required", http.StatusBadRequest)
		return
	}
	claims := claimsFromCtx(r)
	createdBy := ""
	if claims != nil {
		createdBy = claims.Email
	}
	exc := shield.Exception{
		ExceptionID: newID(),
		Ecosystem:   shield.Ecosystem(strings.ToLower(req.Ecosystem)),
		Name:        req.Name,
		Version:     req.Version,
		Reason:      req.Reason,
		CreatedBy:   createdBy,
		CreatedAt:   time.Now().UTC(),
	}
	if err := s.store.AddException(r.Context(), exc); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, exc)
}

// DELETE /api/v1/exceptions/{id}
func (s *Server) handleDeleteException(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if err := s.store.DeleteException(r.Context(), id); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"status": "deleted"})
}

// GET /api/v1/proxy/exceptions — proxy token auth; lets dev proxies sync the exception list.
func (s *Server) handleProxyExceptions(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListExceptions(r.Context())
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	if list == nil {
		list = []shield.Exception{}
	}
	jsonOK(w, map[string]interface{}{"exceptions": list})
}
