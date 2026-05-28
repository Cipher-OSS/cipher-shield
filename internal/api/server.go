package api

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	shield "github.com/homes853/cipher-shield/internal"
	"github.com/homes853/cipher-shield/internal/db"
	shieldweb "github.com/homes853/cipher-shield/web"
)

// Scanner is the minimal interface the API needs from the pipeline.
type Scanner interface {
	Analyze(ctx context.Context, pkg shield.PackageRef, tarball []byte) (*shield.ScanResult, error)
}

// Server is the cipher-shield HTTP API server.
type Server struct {
	router    *mux.Router
	store     db.Store
	scanner   Scanner
	jwtSecret []byte
}

// New creates a Server.
func New(store db.Store, scanner Scanner, jwtSecret []byte) *Server {
	s := &Server{
		router:    mux.NewRouter(),
		store:     store,
		scanner:   scanner,
		jwtSecret: jwtSecret,
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

// POST /api/v1/scan/lockfile — accepts lock file content as text body
func (s *Server) handleScanLockfile(w http.ResponseWriter, r *http.Request) {
	jsonError(w, "lockfile scan via API: upload the file content as multipart or use the CLI", http.StatusNotImplemented)
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
