package api

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"io/fs"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	shield "github.com/cipher-oss/cipher-shield/internal"
	"github.com/cipher-oss/cipher-shield/internal/db"
	shieldweb "github.com/cipher-oss/cipher-shield/web"
	"golang.org/x/crypto/bcrypt"
	"strings"
)

const apiVersion = "0.1.5"

// Scanner is the minimal interface the API needs from the pipeline.
type Scanner interface {
	Analyze(ctx context.Context, pkg shield.PackageRef, tarball []byte) (*shield.ScanResult, error)
}

// Expander produces a plain-English explanation of a single finding using Claude.
type Expander interface {
	Explain(ctx context.Context, pkg shield.PackageRef, finding shield.Finding) (string, error)
}

// BadlistSource provides the known-bad list as raw JSON bytes.
type BadlistSource interface {
	RawJSON() []byte
}

// Server is the cipher-shield HTTP API server.
type Server struct {
	router       *mux.Router
	store        db.Store
	scanner      Scanner
	expander     Expander      // optional; nil when no Anthropic key
	badlist      BadlistSource // optional; nil disables /api/v1/badlist
	jwtSecret    []byte
	proxyToken   []byte
	mode         string     // enforce | warn | audit
	corsOrigin   string     // allowed CORS origin; "*" if empty
	loginLimiter *ipLimiter // 5 attempts per minute per IP
	apiLimiter   *ipLimiter // 120 requests per minute per IP
}

// New creates a Server.
func New(store db.Store, scanner Scanner, jwtSecret, proxyToken []byte, mode, corsOrigin string, expander Expander, badlist BadlistSource) *Server {
	if mode == "" {
		mode = "enforce"
	}
	s := &Server{
		router:       mux.NewRouter(),
		store:        store,
		scanner:      scanner,
		expander:     expander,
		badlist:      badlist,
		jwtSecret:    jwtSecret,
		proxyToken:   proxyToken,
		mode:         mode,
		corsOrigin:   corsOrigin,
		loginLimiter: newIPLimiter(1.0/12.0, 5), // 5 attempts per minute per IP
		apiLimiter:   newIPLimiter(2.0, 20),      // 120 requests per minute per IP
	}
	s.routes()
	return s
}

// Stop releases resources held by the server (background goroutines).
func (s *Server) Stop() {
	s.loginLimiter.stop()
	s.apiLimiter.stop()
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *Server) routes() {
	s.router.Use(s.corsMiddleware)
	s.router.Use(s.securityHeadersMiddleware)

	// Public
	s.router.HandleFunc("/api/v1/health", s.handleHealth).Methods("GET")
	s.router.HandleFunc("/api/v1/config", s.handleConfig).Methods("GET")

	// Auth
	s.router.HandleFunc("/api/v1/auth/login", s.rateLimitLogin(s.handleLogin)).Methods("POST", "OPTIONS")
	s.router.HandleFunc("/api/v1/auth/me", s.requireUser(s.handleMe)).Methods("GET", "OPTIONS")

	// Users (admin or bootstrap)
	s.router.HandleFunc("/api/v1/users", s.requireAdmin(s.handleListUsers)).Methods("GET", "OPTIONS")
	s.router.HandleFunc("/api/v1/users", s.requireAdminOrBootstrap(s.handleCreateUser)).Methods("POST", "OPTIONS")
	s.router.HandleFunc("/api/v1/users/{id}/reset-password", s.requireAdmin(s.handleResetPassword)).Methods("POST", "OPTIONS")

	// Proxy reporting + exception sync (authenticated by pre-shared proxy token)
	s.router.HandleFunc("/api/v1/report", s.requireProxyToken(s.handleReport)).Methods("POST", "OPTIONS")
	s.router.HandleFunc("/api/v1/proxy/exceptions", s.requireProxyToken(s.handleProxyExceptions)).Methods("GET", "OPTIONS")

	// Scan
	s.router.HandleFunc("/api/v1/scan/package", s.requireUser(s.rateLimitAPI(s.handleScanPackage))).Methods("POST", "OPTIONS")
	s.router.HandleFunc("/api/v1/scan/lockfile", s.requireUser(s.rateLimitAPI(s.handleScanLockfile))).Methods("POST", "OPTIONS")

	// History
	s.router.HandleFunc("/api/v1/history", s.requireUser(s.rateLimitAPI(s.handleHistory))).Methods("GET", "OPTIONS")

	// Violations + triage
	s.router.HandleFunc("/api/v1/violations", s.requireUser(s.rateLimitAPI(s.handleListViolations))).Methods("GET", "OPTIONS")
	s.router.HandleFunc("/api/v1/violations/{id}/dismiss", s.requireUser(s.rateLimitAPI(s.handleDismiss))).Methods("POST", "OPTIONS")

	// Finding explanation (Claude-powered, optional)
	s.router.HandleFunc("/api/v1/findings/expand", s.requireUser(s.handleExpandFinding)).Methods("POST", "OPTIONS")

	// Known-bad list visibility
	s.router.HandleFunc("/api/v1/badlist", s.requireUser(s.handleBadlist)).Methods("GET", "OPTIONS")

	// Exceptions
	s.router.HandleFunc("/api/v1/exceptions", s.requireUser(s.handleListExceptions)).Methods("GET", "OPTIONS")
	s.router.HandleFunc("/api/v1/exceptions", s.requireUser(s.handleAddException)).Methods("POST", "OPTIONS")
	s.router.HandleFunc("/api/v1/exceptions/{id}", s.requireUser(s.handleDeleteException)).Methods("DELETE", "OPTIONS")

	// Static dashboard — embedded at build time, no filesystem dependency
	staticFS, _ := fs.Sub(shieldweb.Static, "static")
	s.router.PathPrefix("/").Handler(http.FileServer(http.FS(staticFS)))
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.corsOrigin != "" {
			w.Header().Set("Access-Control-Allow-Origin", s.corsOrigin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		}
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// requireProxyToken validates the pre-shared proxy bearer token.
// When proxyToken is empty, all requests are allowed (dev mode).
func (s *Server) requireProxyToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(s.proxyToken) == 0 {
			next(w, r)
			return
		}
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, "Bearer ") || !hmac.Equal([]byte(h[7:]), s.proxyToken) {
			jsonError(w, "invalid proxy token", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func jsonOK(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func newID() string {
	return uuid.New().String()
}

func bcryptHash(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(b), err
}
