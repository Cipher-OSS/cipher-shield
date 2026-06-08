package api

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	shield "github.com/homes853/cipher-shield/internal"
	"github.com/homes853/cipher-shield/internal/db"
	"github.com/homes853/cipher-shield/internal/lockfile"
	shieldweb "github.com/homes853/cipher-shield/web"
	"golang.org/x/crypto/bcrypt"
)

// Scanner is the minimal interface the API needs from the pipeline.
type Scanner interface {
	Analyze(ctx context.Context, pkg shield.PackageRef, tarball []byte) (*shield.ScanResult, error)
}

// Server is the cipher-shield HTTP API server.
type Server struct {
	router     *mux.Router
	store      db.Store
	scanner    Scanner
	jwtSecret  []byte
	proxyToken []byte
}

// New creates a Server.
func New(store db.Store, scanner Scanner, jwtSecret, proxyToken []byte) *Server {
	s := &Server{
		router:     mux.NewRouter(),
		store:      store,
		scanner:    scanner,
		jwtSecret:  jwtSecret,
		proxyToken: proxyToken,
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

	// Auth
	s.router.HandleFunc("/api/v1/auth/login", s.handleLogin).Methods("POST", "OPTIONS")
	s.router.HandleFunc("/api/v1/auth/me", s.requireUser(s.handleMe)).Methods("GET", "OPTIONS")

	// Users (admin or bootstrap)
	s.router.HandleFunc("/api/v1/users", s.requireAdmin(s.handleListUsers)).Methods("GET", "OPTIONS")
	s.router.HandleFunc("/api/v1/users", s.requireAdminOrBootstrap(s.handleCreateUser)).Methods("POST", "OPTIONS")

	// Proxy reporting (authenticated by pre-shared proxy token)
	s.router.HandleFunc("/api/v1/report", s.requireProxyToken(s.handleReport)).Methods("POST", "OPTIONS")

	// Scan
	s.router.HandleFunc("/api/v1/scan/package", s.requireUser(s.handleScanPackage)).Methods("POST", "OPTIONS")
	s.router.HandleFunc("/api/v1/scan/lockfile", s.requireUser(s.handleScanLockfile)).Methods("POST", "OPTIONS")

	// History
	s.router.HandleFunc("/api/v1/history", s.requireUser(s.handleHistory)).Methods("GET", "OPTIONS")

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
	jsonOK(w, map[string]string{"status": "ok", "version": "0.1.0"})
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

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	result, err := s.scanner.Analyze(ctx, shield.PackageRef{
		Ecosystem: eco,
		Name:      req.Name,
		Version:   req.Version,
	}, nil)
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
		buf := make([]byte, fh.Size)
		if _, err := f.Read(buf); err != nil {
			jsonError(w, "read error", http.StatusBadRequest)
			return
		}
		data = buf
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
		Package shield.PackageRef `json:"package"`
		Result  *shield.ScanResult `json:"result,omitempty"`
		Error   string             `json:"error,omitempty"`
	}
	results := make([]entry, 0, len(refs))
	for _, ref := range refs {
		result, err := s.scanner.Analyze(ctx, ref, nil)
		if err != nil {
			results = append(results, entry{Package: ref, Error: err.Error()})
			continue
		}
		results = append(results, entry{Package: ref, Result: result})
	}
	jsonOK(w, map[string]interface{}{"filename": filename, "count": len(results), "results": results})
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
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
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
	return strconv.FormatInt(time.Now().UnixNano(), 36)
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
