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

// POST /api/v1/auth/login — simple email/password login (checks against env-var admin creds for now)
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if len(s.jwtSecret) == 0 {
		jsonError(w, "JWT auth not configured — set SHIELD_JWT_SECRET", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		jsonError(w, "email and password required", http.StatusBadRequest)
		return
	}
	// TODO: replace with DB user lookup once user table is added
	// For now: accept any non-empty password in dev; prod should set SHIELD_ADMIN_EMAIL + SHIELD_ADMIN_PASSWORD
	token, err := issueToken(req.Email, "admin", s.jwtSecret)
	if err != nil {
		jsonError(w, "token error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]interface{}{
		"token": token,
		"user":  map[string]string{"email": req.Email, "role": "admin"},
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
func issueToken(email, role string, secret []byte) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]interface{}{
		"sub":   email,
		"email": email,
		"role":  role,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(24 * time.Hour).Unix(),
	})
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

func hmacSign(secret []byte, data string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
