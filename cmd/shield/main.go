package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	shield "github.com/homes853/cipher-shield/internal"
	"github.com/homes853/cipher-shield/internal/analyzer"
	"github.com/homes853/cipher-shield/internal/analyzer/badlist"
	"github.com/homes853/cipher-shield/internal/analyzer/claude"
	"github.com/homes853/cipher-shield/internal/analyzer/cve"
	"github.com/homes853/cipher-shield/internal/analyzer/heuristic"
	"github.com/homes853/cipher-shield/internal/db"
	"github.com/homes853/cipher-shield/internal/lockfile"
	"github.com/homes853/cipher-shield/internal/pipeline"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "scan":
		runScan(os.Args[2:])
	case "proxy":
		fmt.Println("proxy: use 'shield-server' for the full proxy server")
	case "version":
		fmt.Println("cipher-shield v0.1.0")
	default:
		printUsage()
		os.Exit(1)
	}
}

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

func buildPipeline() *pipeline.Pipeline {
	dbPath := envOr("SHIELD_DB_PATH", defaultDBPath())

	// Ensure parent directory exists before opening SQLite.
	if err := os.MkdirAll(dirOf(dbPath), 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "[warn] cannot create db dir: %v — running without cache\n", err)
	}

	var store db.Store
	s, err := db.Open("sqlite3", dbPath)
	if err != nil {
		// Non-fatal: run without caching.
		fmt.Fprintf(os.Stderr, "[warn] db open failed: %v — running without cache\n", err)
		store = &noopStore{}
	} else {
		store = s
	}

	cfg := pipeline.DefaultConfig()
	if m := os.Getenv("SHIELD_MODE"); m != "" {
		cfg.Mode = m
	}

	anthropicKey := os.Getenv("ANTHROPIC_API_KEY")

	var claudeAnalyzer analyzer.Analyzer
	if anthropicKey != "" {
		claudeAnalyzer = claude.New(anthropicKey)
	}

	return pipeline.New(
		store,
		cfg,
		badlist.New(),
		cve.New(),
		heuristic.New(),
		claudeAnalyzer,
	)
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
	var results []*shield.ScanResult

	for _, ref := range refs {
		result, err := pl.Analyze(ctx, ref, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [error] %s@%s: %v\n", ref.Name, ref.Version, err)
			continue
		}
		results = append(results, result)
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

	// Parse --ecosystem flag
	for i, a := range args {
		if a == "--ecosystem" && i+1 < len(args) {
			eco = shield.Ecosystem(strings.ToLower(args[i+1]))
		}
	}

	// Parse name@version
	name, version := nameVersion, "latest"
	if idx := strings.LastIndex(nameVersion, "@"); idx > 0 {
		name = nameVersion[:idx]
		version = nameVersion[idx+1:]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	fmt.Printf("Scanning %s@%s (%s)...\n\n", name, version, eco)
	result, err := pl.Analyze(ctx, shield.PackageRef{
		Ecosystem: eco,
		Name:      name,
		Version:   version,
	}, nil)
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

func printUsage() {
	fmt.Fprint(os.Stderr, `cipher-shield — AI-powered package security firewall

Usage:
  cipher-shield scan lockfile <path>              Scan a lock file (package-lock.json, requirements.txt, etc.)
  cipher-shield scan package <name@version>       Scan a single package
    [--ecosystem npm|pypi]                        (default: npm)
  cipher-shield version                           Print version

Environment:
  ANTHROPIC_API_KEY    Enable Claude Opus deep analysis
  SHIELD_MODE          enforce (default) | warn | audit
  SHIELD_DB_PATH       SQLite cache path (default: ~/.cipher-shield/shield.db)

Exit codes:
  0  All packages clean
  1  One or more warnings
  2  One or more blocked packages

`)
}

func defaultDBPath() string {
	home, _ := os.UserHomeDir()
	return home + "/.cipher-shield/shield.db"
}

func dirOf(path string) string {
	idx := strings.LastIndex(path, "/")
	if idx < 0 {
		return "."
	}
	return path[:idx]
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// noopStore satisfies db.Store with no-ops (used when DB can't be opened).
type noopStore struct{}

func (n *noopStore) GetCachedResult(_ shield.Ecosystem, _, _ string) (*shield.ScanResult, error) {
	return nil, nil
}
func (n *noopStore) SaveResult(_ shield.ScanResult) error { return nil }
func (n *noopStore) GetException(_ shield.Ecosystem, _, _ string) (*shield.Exception, error) {
	return nil, nil
}
func (n *noopStore) ListExceptions() ([]shield.Exception, error)  { return nil, nil }
func (n *noopStore) AddException(_ shield.Exception) error        { return nil }
func (n *noopStore) DeleteException(_ string) error               { return nil }
func (n *noopStore) ListHistory(_ int) ([]shield.ScanResult, error) { return nil, nil }
func (n *noopStore) Migrate() error                               { return nil }
func (n *noopStore) Close() error                                 { return nil }
