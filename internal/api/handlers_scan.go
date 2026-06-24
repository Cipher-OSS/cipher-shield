package api

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	shield "github.com/cipher-oss/cipher-shield/internal"
	"github.com/cipher-oss/cipher-shield/internal/lockfile"
	"github.com/cipher-oss/cipher-shield/internal/registry"
)

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
