package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
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
	"github.com/homes853/cipher-shield/internal/proxy"
	"github.com/homes853/cipher-shield/internal/proxyctl"
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
		runProxy(os.Args[2:])
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

	// Parse name@version — LastIndex handles scoped packages like @scope/name@1.0.0
	name, version := nameVersion, "latest"
	if idx := strings.LastIndex(nameVersion, "@"); idx > 0 {
		name = nameVersion[:idx]
		version = nameVersion[idx+1:]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Resolve "latest" to a real version before fetching the tarball
	if version == "latest" {
		if resolved, err := resolveLatestVersion(ctx, eco, name); err == nil {
			version = resolved
			fmt.Printf("Resolved %s@latest → %s\n\n", name, version)
		}
	}

	pkg := shield.PackageRef{Ecosystem: eco, Name: name, Version: version}
	fmt.Printf("Scanning %s@%s (%s)...\n", name, version, eco)

	// Fetch the tarball so tiers 3 (heuristic) and 4 (Claude) can run
	fmt.Printf("  Fetching tarball... ")
	tarball, fetchErr := fetchTarball(ctx, pkg)
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

// fetchTarball downloads the package tarball from the upstream registry.
// npm:  https://registry.npmjs.org/{name}/-/{bareName}-{version}.tgz
// PyPI: resolves download URL via the JSON metadata API, prefers sdist.
func fetchTarball(ctx context.Context, pkg shield.PackageRef) ([]byte, error) {
	var tarURL string

	switch pkg.Ecosystem {
	case shield.EcosystemNPM:
		// Scoped packages (@scope/name) use just the bare name in the filename.
		bareName := pkg.Name
		if strings.HasPrefix(pkg.Name, "@") {
			if parts := strings.SplitN(pkg.Name[1:], "/", 2); len(parts) == 2 {
				bareName = parts[1]
			}
		}
		tarURL = fmt.Sprintf("https://registry.npmjs.org/%s/-/%s-%s.tgz",
			pkg.Name, bareName, pkg.Version)

	case shield.EcosystemPyPI:
		var err error
		tarURL, err = resolvePyPITarball(ctx, pkg.Name, pkg.Version)
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("unsupported ecosystem: %s", pkg.Ecosystem)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", tarURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "cipher-shield/0.1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", tarURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned HTTP %d for %s", resp.StatusCode, tarURL)
	}

	const maxBytes = 50 << 20 // 50 MB
	return io.ReadAll(io.LimitReader(resp.Body, maxBytes))
}

// resolvePyPITarball queries the PyPI JSON API and returns the sdist download URL.
func resolvePyPITarball(ctx context.Context, name, version string) (string, error) {
	apiURL := fmt.Sprintf("https://pypi.org/pypi/%s/%s/json", name, version)
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("pypi metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("pypi metadata: HTTP %d", resp.StatusCode)
	}

	var meta struct {
		URLs []struct {
			URL         string `json:"url"`
			PackageType string `json:"packagetype"`
		} `json:"urls"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return "", fmt.Errorf("pypi metadata decode: %w", err)
	}

	// Prefer sdist (source); fall back to any wheel if unavailable.
	var wheel string
	for _, u := range meta.URLs {
		switch u.PackageType {
		case "sdist":
			return u.URL, nil
		case "bdist_wheel":
			if wheel == "" {
				wheel = u.URL
			}
		}
	}
	if wheel != "" {
		return wheel, nil
	}
	return "", fmt.Errorf("no downloadable file found for %s@%s on PyPI", name, version)
}

// resolveLatestVersion fetches the current latest version for a package.
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

func runProxy(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: cipher-shield proxy start|stop|status")
		os.Exit(1)
	}
	switch args[0] {
	case "start":
		proxyStart(args[1:])
	case "stop":
		proxyStop()
	case "status":
		fmt.Println("proxy:", proxyctl.Status())
	default:
		fmt.Fprintf(os.Stderr, "unknown proxy subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func proxyStart(args []string) {
	addr := envOr("SHIELD_PROXY_ADDR", "127.0.0.1:7070")
	for i, a := range args {
		if a == "--addr" && i+1 < len(args) {
			addr = args[i+1]
		}
	}
	proxyURL := "http://" + addr

	if proxyctl.IsRunning() {
		fmt.Printf("cipher-shield proxy is already running (%s)\n", proxyctl.Status())
		os.Exit(0)
	}

	// Build pipeline
	pl := buildPipeline()

	// Configure npm + pip to route through proxy
	if err := proxyctl.SaveAndSetNPM(proxyURL); err != nil {
		fmt.Fprintf(os.Stderr, "[warn] npm config failed: %v\n", err)
	} else {
		fmt.Printf("✓ npm registry → %s\n", proxyURL)
	}
	if err := proxyctl.SaveAndSetPIP(proxyURL); err != nil {
		fmt.Fprintf(os.Stderr, "[warn] pip config failed: %v\n", err)
	} else {
		fmt.Printf("✓ pip index-url → %s/simple/\n", proxyURL)
	}

	// Write PID
	proxyctl.WritePID(os.Getpid())

	// Handle signals for clean shutdown
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		fmt.Println("\n→ Stopping cipher-shield proxy...")
		proxyctl.RestoreNPM()
		proxyctl.RestorePIP()
		proxyctl.RemovePID()
		fmt.Println("✓ npm and pip config restored")
		fmt.Println("✓ cipher-shield proxy stopped")
		os.Exit(0)
	}()

	fmt.Printf("\n✓ cipher-shield proxy running on %s\n", addr)
	fmt.Println("  All npm install and pip install commands are now screened.")
	fmt.Println("  Press Ctrl+C to stop and restore original settings.")

	proxyCfg := proxy.Config{
		ListenAddr: addr,
		Mode:       proxy.Mode(envOr("SHIELD_MODE", "enforce")),
		Pipeline:   pl,
	}
	if err := proxy.New(proxyCfg).Start(); err != nil {
		fmt.Fprintf(os.Stderr, "proxy error: %v\n", err)
		proxyctl.RestoreNPM()
		proxyctl.RestorePIP()
		proxyctl.RemovePID()
		os.Exit(1)
	}
}

func proxyStop() {
	pid := proxyctl.ReadPID()
	if pid == 0 {
		fmt.Println("cipher-shield proxy is not running")
		return
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		fmt.Printf("could not find process %d: %v\n", pid, err)
		proxyctl.RemovePID()
		return
	}
	proc.Signal(syscall.SIGTERM)
	fmt.Printf("→ Sent SIGTERM to proxy (pid %d)\n", pid)
	proxyctl.RestoreNPM()
	proxyctl.RestorePIP()
	proxyctl.RemovePID()
	fmt.Println("✓ cipher-shield proxy stopped")
}

func printUsage() {
	fmt.Fprint(os.Stderr, `cipher-shield — AI-powered package security firewall

Usage:
  cipher-shield scan lockfile <path>              Scan a lock file (package-lock.json, requirements.txt, etc.)
  cipher-shield scan package <name@version>       Scan a single package
    [--ecosystem npm|pypi]                        (default: npm)
  cipher-shield proxy start [--addr 127.0.0.1:7070]  Start proxy (configures npm + pip automatically)
  cipher-shield proxy stop                            Stop proxy (restores npm + pip config)
  cipher-shield proxy status                          Show proxy status
  cipher-shield version                           Print version

Environment:
  ANTHROPIC_API_KEY    Enable Claude Opus deep analysis
  SHIELD_MODE          enforce (default) | warn | audit
  SHIELD_PROXY_ADDR    Proxy listen address (default: 127.0.0.1:7070)
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
func (n *noopStore) ListHistory(_ int) ([]shield.ScanResult, error)              { return nil, nil }
func (n *noopStore) CreateUser(_, _, _ string) (*shield.User, error)             { return nil, nil }
func (n *noopStore) GetUserByEmail(_ string) (*shield.User, error)               { return nil, nil }
func (n *noopStore) CountUsers() (int, error)                                    { return 0, nil }
func (n *noopStore) ListUsers() ([]shield.User, error)                           { return nil, nil }
func (n *noopStore) Migrate() error                                              { return nil }
func (n *noopStore) Close() error                                                { return nil }
