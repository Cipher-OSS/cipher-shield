package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

type contextKey int

const claimsKey contextKey = 1

type Claims struct {
	UserID string `json:"sub"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	Exp    int64  `json:"exp"`
}

func claimsFromCtx(r *http.Request) *Claims {
	c, _ := r.Context().Value(claimsKey).(*Claims)
	return c
}

// requireUser middleware: validates Bearer JWT, sets claims in context.
// When jwtSecret is empty, allows all requests (dev mode).
func (s *Server) requireUser(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(s.jwtSecret) == 0 {
			next(w, r)
			return
		}
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			jsonError(w, "authentication required", http.StatusUnauthorized)
			return
		}
		claims, err := validateToken(h[7:], s.jwtSecret)
		if err != nil {
			jsonError(w, "invalid token", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), claimsKey, claims)
		next(w, r.WithContext(ctx))
	}
}

// requireAdmin wraps requireUser and additionally enforces role == "admin".
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.requireUser(func(w http.ResponseWriter, r *http.Request) {
		claims := claimsFromCtx(r)
		if claims == nil || claims.Role != "admin" {
			jsonError(w, "admin access required", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

// requireAdminOrBootstrap allows unauthenticated access only when the users
// table is empty (first-run bootstrap). Once any user exists, admin is required.
func (s *Server) requireAdminOrBootstrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		count, err := s.store.CountUsers(r.Context())
		if err != nil {
			jsonError(w, "db error", http.StatusInternalServerError)
			return
		}
		if count == 0 {
			next(w, r)
			return
		}
		s.requireAdmin(next)(w, r)
	}
}

// POST /api/v1/auth/login
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if len(s.jwtSecret) == 0 {
		jsonError(w, "JWT auth not configured — set SHIELD_JWT_SECRET", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.Password == "" {
		jsonError(w, "email and password required", http.StatusBadRequest)
		return
	}
	user, err := s.store.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	if user == nil || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
		jsonError(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	token, err := issueToken(user.UserID, user.Email, user.Role, s.jwtSecret)
	if err != nil {
		jsonError(w, "token error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]interface{}{
		"token": token,
		"user":  map[string]string{"user_id": user.UserID, "email": user.Email, "role": user.Role},
	})
}

// GET /api/v1/auth/me
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r)
	if claims == nil {
		jsonError(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	jsonOK(w, map[string]string{"email": claims.Email, "role": claims.Role})
}

// issueToken creates a signed HS256 JWT with 24h expiry.
func issueToken(userID, email, role string, secret []byte) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload, err := json.Marshal(map[string]interface{}{
		"sub":   userID,
		"email": email,
		"role":  role,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(24 * time.Hour).Unix(),
	})
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}
	payloadEnc := base64.RawURLEncoding.EncodeToString(payload)
	sig := hmacSign(secret, header+"."+payloadEnc)
	return header + "." + payloadEnc + "." + sig, nil
}

// validateToken parses and verifies a HS256 JWT.
func validateToken(token string, secret []byte) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}
	expected := hmacSign(secret, parts[0]+"."+parts[1])
	if !hmac.Equal([]byte(parts[2]), []byte(expected)) {
		return nil, fmt.Errorf("invalid signature")
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding")
	}
	var claims Claims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("invalid payload JSON")
	}
	if claims.Exp < time.Now().Unix() {
		return nil, fmt.Errorf("token expired")
	}
	return &claims, nil
}

// POST /api/v1/users/{id}/reset-password — admin only
func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Password) < 8 {
		jsonError(w, "password must be at least 8 characters", http.StatusBadRequest)
		return
	}
	user, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	if user == nil {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		jsonError(w, "password hashing failed", http.StatusInternalServerError)
		return
	}
	if err := s.store.UpdatePassword(r.Context(), id, string(hash)); err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"status": "password updated"})
}

func hmacSign(secret []byte, data string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
