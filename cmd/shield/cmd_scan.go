package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	shield "github.com/cipher-oss/cipher-shield/internal"
	"github.com/cipher-oss/cipher-shield/internal/analyzer"
	"github.com/cipher-oss/cipher-shield/internal/analyzer/badlist"
	"github.com/cipher-oss/cipher-shield/internal/analyzer/claude"
	"github.com/cipher-oss/cipher-shield/internal/analyzer/cve"
	"github.com/cipher-oss/cipher-shield/internal/analyzer/heuristic"
	"github.com/cipher-oss/cipher-shield/internal/db"
	"github.com/cipher-oss/cipher-shield/internal/lockfile"
	"github.com/cipher-oss/cipher-shield/internal/pipeline"
	"github.com/cipher-oss/cipher-shield/internal/registry"
)

func runScan(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: cipher-shield scan lockfile <path>")
		fmt.Fprintln(os.Stderr, "       cipher-shield scan package <name@version> [--ecosystem npm|pypi]")
		os.Exit(1)
	}

	pl := buildPipeline()

	switch args[0] {
	case "lockfile":
		scanLockfile(pl, args[1])
	case "package":
		scanPackage(pl, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown scan subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func buildPipelineWithStore(store db.Store) *pipeline.Pipeline {
	cfg := pipeline.DefaultConfig()
	if m := os.Getenv("SHIELD_MODE"); m != "" {
		cfg.Mode = m
	}
	var claudeAnalyzer analyzer.Analyzer
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		claudeAnalyzer = claude.New(key)
	}
	overridePath := filepath.Join(dirOf(envOr("SHIELD_DB_PATH", defaultDBPath())), "known_bad.json")
	return pipeline.New(store, cfg, badlist.NewWithOverride(overridePath), cve.New(), heuristic.New(), claudeAnalyzer)
}

func buildPipeline() *pipeline.Pipeline {
	dbPath := envOr("SHIELD_DB_PATH", defaultDBPath())

	if err := os.MkdirAll(dirOf(dbPath), 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "[warn] cannot create db dir: %v — running without cache\n", err)
	}

	var store db.Store
	s, err := db.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[warn] db open failed: %v — running without cache\n", err)
		store = &noopStore{}
	} else {
		store = s
	}

	return buildPipelineWithStore(store)
}

func scanLockfile(pl *pipeline.Pipeline, path string) {
	refs, err := lockfile.ParseFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Scanning %d packages from %s...\n\n", len(refs), path)

	ctx := context.Background()
	var blocked, warned, clean int

	for _, ref := range refs {
		result, err := pl.Analyze(ctx, ref, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [error] %s@%s: %v\n", ref.Name, ref.Version, err)
			continue
		}
		switch result.Verdict {
		case shield.VerdictBlock:
			blocked++
		case shield.VerdictWarn:
			warned++
		default:
			clean++
		}
		printResult(result)
	}

	fmt.Printf("\n─────────────────────────────────────────\n")
	fmt.Printf("Summary: %d clean, %d warn, %d block\n", clean, warned, blocked)

	if blocked > 0 {
		os.Exit(2)
	}
	if warned > 0 {
		os.Exit(1)
	}
}

func scanPackage(pl *pipeline.Pipeline, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: cipher-shield scan package <name@version>")
		os.Exit(1)
	}

	nameVersion := args[0]
	eco := shield.EcosystemNPM

	for i, a := range args {
		if a == "--ecosystem" && i+1 < len(args) {
			eco = shield.Ecosystem(strings.ToLower(args[i+1]))
		}
	}

	// LastIndex handles scoped packages like @scope/name@1.0.0
	name, ver := nameVersion, "latest"
	if idx := strings.LastIndex(nameVersion, "@"); idx > 0 {
		name = nameVersion[:idx]
		ver = nameVersion[idx+1:]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if ver == "latest" {
		if resolved, err := resolveLatestVersion(ctx, eco, name); err == nil {
			ver = resolved
			fmt.Printf("Resolved %s@latest → %s\n\n", name, ver)
		}
	}

	pkg := shield.PackageRef{Ecosystem: eco, Name: name, Version: ver}
	fmt.Printf("Scanning %s@%s (%s)...\n", name, ver, eco)

	fmt.Printf("  Fetching tarball... ")
	tarball, fetchErr := registry.FetchTarball(ctx, pkg, "cipher-shield/"+version)
	if fetchErr != nil {
		fmt.Printf("skipped (%v)\n", fetchErr)
		fmt.Println("  Note: heuristic and Claude analysis unavailable without tarball")
	} else {
		fmt.Printf("%d KB\n", len(tarball)/1024)
	}
	fmt.Println()

	result, err := pl.Analyze(ctx, pkg, tarball)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	printResult(result)
	printDetails(result)

	if result.Verdict == shield.VerdictBlock {
		os.Exit(2)
	}
	if result.Verdict == shield.VerdictWarn {
		os.Exit(1)
	}
}

func resolveLatestVersion(ctx context.Context, eco shield.Ecosystem, name string) (string, error) {
	var apiURL string
	switch eco {
	case shield.EcosystemNPM:
		apiURL = fmt.Sprintf("https://registry.npmjs.org/%s/latest", name)
	case shield.EcosystemPyPI:
		apiURL = fmt.Sprintf("https://pypi.org/pypi/%s/json", name)
	default:
		return "", fmt.Errorf("unsupported ecosystem")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var raw map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return "", err
	}

	switch eco {
	case shield.EcosystemNPM:
		var v string
		json.Unmarshal(raw["version"], &v)
		if v == "" {
			return "", fmt.Errorf("version field missing in npm response")
		}
		return v, nil
	case shield.EcosystemPyPI:
		var info map[string]json.RawMessage
		json.Unmarshal(raw["info"], &info)
		var v string
		json.Unmarshal(info["version"], &v)
		if v == "" {
			return "", fmt.Errorf("info.version field missing in PyPI response")
		}
		return v, nil
	}
	return "", fmt.Errorf("could not resolve version")
}

func printResult(r *shield.ScanResult) {
	verdict := verdictStr(r.Verdict)
	fmt.Printf("  %-40s %s\n", r.Package.Name+"@"+r.Package.Version, verdict)
	for _, f := range r.Findings {
		fmt.Printf("    → [%s] %s\n", f.Severity, f.Title)
	}
}

func printDetails(r *shield.ScanResult) {
	if len(r.Findings) == 0 {
		fmt.Println("No findings — package appears clean.")
		return
	}
	fmt.Println("\nFindings:")
	for i, f := range r.Findings {
		fmt.Printf("\n  %d. [%s] %s\n", i+1, strings.ToUpper(string(f.Severity)), f.Title)
		if f.Description != "" {
			fmt.Printf("     %s\n", f.Description)
		}
		if f.CVE != "" {
			fmt.Printf("     CVE: %s (CVSS: %.1f)\n", f.CVE, f.CVSS)
		}
		for _, ref := range f.References {
			fmt.Printf("     Reference: %s\n", ref)
		}
	}
}

func verdictStr(v shield.Verdict) string {
	switch v {
	case shield.VerdictBlock:
		return "BLOCK"
	case shield.VerdictWarn:
		return "WARN "
	default:
		return "CLEAN"
	}
}
