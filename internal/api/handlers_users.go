package api

import (
	"encoding/json"
	"net/http"
	"strings"

	shield "github.com/cipher-oss/cipher-shield/internal"
)

// GET /api/v1/users — admin only
func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if users == nil {
		users = []shield.User{}
	}
	jsonOK(w, map[string]interface{}{"users": users})
}

// POST /api/v1/users — admin only after first user exists; no auth for bootstrap
func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || len(req.Password) < 8 {
		jsonError(w, "email and password of at least 8 characters required", http.StatusBadRequest)
		return
	}
	count, err := s.store.CountUsers(r.Context())
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	role := strings.ToLower(req.Role)
	if count == 0 {
		role = "admin" // bootstrap: first user is always admin
	} else if role != "admin" && role != "analyst" {
		role = "analyst"
	}
	hash, err := bcryptHash(req.Password)
	if err != nil {
		jsonError(w, "password hashing failed", http.StatusInternalServerError)
		return
	}
	user, err := s.store.CreateUser(r.Context(), req.Email, hash, role)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]interface{}{
		"user_id":    user.UserID,
		"email":      user.Email,
		"role":       user.Role,
		"created_at": user.CreatedAt,
	})
}
