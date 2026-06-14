package api

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	shield "github.com/homes853/cipher-shield/internal"
	"github.com/homes853/cipher-shield/internal/db"
	"github.com/homes853/cipher-shield/internal/lockfile"
	"github.com/homes853/cipher-shield/internal/registry"
	shieldweb "github.com/homes853/cipher-shield/web"
	"golang.org/x/crypto/bcrypt"
)

const apiVersion = "0.1.0"

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
	expander     Expander     // optional; nil when no Anthropic key
	badlist      BadlistSource // optional; nil disables /api/v1/badlist
	jwtSecret    []byte
	proxyToken   []byte
	mode         string     // enforce | warn | audit
	corsOrigin   string     // allowed CORS origin; "*" if empty
	loginLimiter *ipLimiter // per-IP rate limiter for login endpoint
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
	}
	s.routes()
	return s
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
	s.router.HandleFunc("/api/v1/scan/package", s.requireUser(s.handleScanPackage)).Methods("POST", "OPTIONS")
	s.router.HandleFunc("/api/v1/scan/lockfile", s.requireUser(s.handleScanLockfile)).Methods("POST", "OPTIONS")

	// History
	s.router.HandleFunc("/api/v1/history", s.requireUser(s.handleHistory)).Methods("GET", "OPTIONS")

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

// POST /api/v1/scan/package — scan a single package by name+version
func (s *Server) handleScanPackage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
		Version   string `json:"version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.Version == "" {
		jsonError(w, "ecosystem, name, and version required", http.StatusBadRequest)
		return
	}
	eco := shield.Ecosystem(strings.ToLower(req.Ecosystem))
	if eco == "" {
		eco = shield.EcosystemNPM
	}

	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()

	// Fetch the tarball so Tier 3 (heuristic) and Tier 4 (Claude) can run.
	// Non-fatal: if unreachable we fall through with nil tarball (Tier 1+2 only).
	pkg := shield.PackageRef{Ecosystem: eco, Name: req.Name, Version: req.Version}
	tarball, err := registry.FetchTarball(ctx, pkg, "cipher-shield")
	if err != nil {
		log.Printf("[api] fetchTarball %s@%s: %v — running Tier 1+2 only", req.Name, req.Version, err)
	}

	result, err := s.scanner.Analyze(ctx, pkg, tarball)
	if err != nil {
		jsonError(w, "scan failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, result)
}


// POST /api/v1/scan/lockfile
// Accepts multipart/form-data with field "file" (filename used for format detection)
// or a raw body with ?filename=<name> query param.
func (s *Server) handleScanLockfile(w http.ResponseWriter, r *http.Request) {
	var data []byte
	var filename string

	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "multipart/") {
		if err := r.ParseMultipartForm(4 << 20); err != nil {
			jsonError(w, "multipart parse error", http.StatusBadRequest)
			return
		}
		f, fh, err := r.FormFile("file")
		if err != nil {
			jsonError(w, "field 'file' required", http.StatusBadRequest)
			return
		}
		defer f.Close()
		filename = fh.Filename
		data, err = io.ReadAll(io.LimitReader(f, 4<<20))
		if err != nil {
			jsonError(w, "read error", http.StatusBadRequest)
			return
		}
	} else {
		filename = r.URL.Query().Get("filename")
		if filename == "" {
			jsonError(w, "?filename= required for raw body upload", http.StatusBadRequest)
			return
		}
		var err error
		data, err = io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err != nil {
			jsonError(w, "read error", http.StatusBadRequest)
			return
		}
	}

	parser, err := lockfile.Detect(filename)
	if err != nil {
		jsonError(w, "unsupported lockfile format: "+filename, http.StatusBadRequest)
		return
	}
	refs, err := parser.Parse(data)
	if err != nil {
		jsonError(w, "parse error: "+err.Error(), http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	type entry struct {
		Package shield.PackageRef  `json:"package"`
		Result  *shield.ScanResult `json:"result,omitempty"`
		Error   string             `json:"error,omitempty"`
	}

	// Pass 1: Tier 1+2 only (fast, no tarball needed).
	results := make([]entry, 0, len(refs))
	for _, ref := range refs {
		result, err := s.scanner.Analyze(ctx, ref, nil)
		if err != nil {
			results = append(results, entry{Package: ref, Error: err.Error()})
			continue
		}
		results = append(results, entry{Package: ref, Result: result})
	}

	// Pass 2: for warn/block results fetch tarball and rescan (Tier 3+4).
	for i, e := range results {
		if e.Result == nil || e.Result.Verdict == shield.VerdictAllow {
			continue
		}
		tarball, err := registry.FetchTarball(ctx, e.Package, "cipher-shield")
		if err != nil || len(tarball) == 0 {
			continue
		}
		result, err := s.scanner.Analyze(ctx, e.Package, tarball)
		if err != nil {
			continue
		}
		results[i].Result = result
	}

	jsonOK(w, map[string]interface{}{"filename": filename, "count": len(results), "results": results})
}

// POST /api/v1/findings/expand — calls Claude for a plain-English explanation of one finding.
func (s *Server) handleExpandFinding(w http.ResponseWriter, r *http.Request) {
	if s.expander == nil {
		jsonError(w, "Claude analysis not enabled — set ANTHROPIC_API_KEY on the server", http.StatusNotImplemented)
		return
	}
	var req struct {
		Package shield.PackageRef `json:"package"`
		Finding shield.Finding    `json:"finding"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Finding.Type == "" {
		jsonError(w, "package and finding required", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	explanation, err := s.expander.Explain(ctx, req.Package, req.Finding)
	if err != nil {
		log.Printf("[api] expand finding: %v", err)
		jsonError(w, "explanation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"explanation": explanation})
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

// GET /api/v1/history?limit=50
func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	history, err := s.store.ListHistory(limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if history == nil {
		history = []shield.ScanResult{}
	}
	jsonOK(w, map[string]interface{}{"results": history, "count": len(history)})
}

// GET /api/v1/exceptions
func (s *Server) handleListExceptions(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListExceptions()
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
	if err := s.store.AddException(exc); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, exc)
}

// DELETE /api/v1/exceptions/{id}
func (s *Server) handleDeleteException(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if err := s.store.DeleteException(id); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"status": "deleted"})
}

// GET /api/v1/proxy/exceptions — proxy token auth; lets dev proxies sync the exception list.
func (s *Server) handleProxyExceptions(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListExceptions()
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	if list == nil {
		list = []shield.Exception{}
	}
	jsonOK(w, map[string]interface{}{"exceptions": list})
}

// GET /api/v1/users — admin only
func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers()
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.Password == "" {
		jsonError(w, "email and password required", http.StatusBadRequest)
		return
	}
	count, err := s.store.CountUsers()
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
	user, err := s.store.CreateUser(req.Email, hash, role)
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

func jsonOK(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only set CORS headers when an explicit origin is configured.
		// Default (empty) = same-origin only; browser policy applies without headers.
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

func newID() string {
	return uuid.New().String()
}

func bcryptHash(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(b), err
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
		if !strings.HasPrefix(h, "Bearer ") || h[7:] != string(s.proxyToken) {
			jsonError(w, "invalid proxy token", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// POST /api/v1/report — receives a ScanResult from a proxy agent and stores it.
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	var result shield.ScanResult
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		jsonError(w, "invalid scan result: "+err.Error(), http.StatusBadRequest)
		return
	}
	if result.Package.Name == "" {
		jsonError(w, "package name required", http.StatusBadRequest)
		return
	}
	if err := s.store.SaveResult(result); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"status": "ok"})
}
