// cmd/proxy is a lightweight standalone registry proxy.
// It runs the full scan pipeline locally and optionally ships results to a
// central cipher-shield server. Use it on developer machines that don't run
// the full server binary.
//
// Usage:
//
//	cipher-shield-proxy [flags]
//
// Environment variables (all optional):
//
//	SHIELD_PROXY_ADDR        proxy listen address (default :7070)
//	SHIELD_MODE              enforce | warn | audit (default enforce)
//	ANTHROPIC_API_KEY        enables Claude Opus analysis
//	SHIELD_SERVER_URL        central server to report results to + sync exceptions from
//	SHIELD_PROXY_TOKEN       bearer token for central server
//	SHIELD_KNOWN_BAD_PATH    override path for known_bad.json
//	SHIELD_KNOWN_BAD_URL     URL to fetch known_bad.json from (enables auto-refresh)
//	SHIELD_KNOWN_BAD_REFRESH how often to refresh (default 24h)
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/cipher-oss/cipher-shield/internal/analyzer"
	"github.com/cipher-oss/cipher-shield/internal/analyzer/badlist"
	"github.com/cipher-oss/cipher-shield/internal/analyzer/claude"
	"github.com/cipher-oss/cipher-shield/internal/analyzer/cve"
	"github.com/cipher-oss/cipher-shield/internal/analyzer/heuristic"
	"github.com/cipher-oss/cipher-shield/internal/db"
	"github.com/cipher-oss/cipher-shield/internal/pipeline"
	"github.com/cipher-oss/cipher-shield/internal/proxy"
	"github.com/cipher-oss/cipher-shield/internal/reporter"
)

var version = "dev"

func main() {
	addr             := flag.String("addr",             envOr("SHIELD_PROXY_ADDR",          ":7070"),         "Proxy listen address")
	publicURL        := flag.String("public-url",       envOr("SHIELD_PROXY_PUBLIC_URL",    ""),             "External base URL of this proxy (e.g. https://proxy.example.com) — required when running behind a load balancer or reverse proxy so tarball URLs in npm/pip metadata are rewritten correctly")
	mode             := flag.String("mode",             envOr("SHIELD_MODE",                "enforce"),      "enforce | warn | audit")
	anthropicKey     := flag.String("anthropic-key",    envOr("ANTHROPIC_API_KEY",          ""),             "Anthropic API key (enables Claude analysis)")
	serverURL        := flag.String("server",           envOr("SHIELD_SERVER_URL",          ""),             "Central server URL (enables result reporting + exception sync)")
	token            := flag.String("token",            envOr("SHIELD_PROXY_TOKEN",         ""),             "Bearer token for central server")
	dbPath           := flag.String("db",               envOr("SHIELD_DB_PATH",             defaultDBPath()), "SQLite cache path")
	knownBadPath     := flag.String("known-bad",        envOr("SHIELD_KNOWN_BAD_PATH",      ""),             "Override path for known_bad.json")
	knownBadURL      := flag.String("known-bad-url",    envOr("SHIELD_KNOWN_BAD_URL",       ""),             "URL to fetch known_bad.json from (enables auto-refresh)")
	knownBadRefresh  := flag.Duration("known-bad-refresh", envOrDuration("SHIELD_KNOWN_BAD_REFRESH", 24*time.Hour), "How often to refresh the known-bad list")
	flag.Parse()

	log.SetFlags(log.Ltime | log.Lshortfile)
	log.Printf("[proxy] cipher-shield-proxy %s (mode=%s)", version, *mode)

	// ── Local SQLite cache ────────────────────────────────────────────────────
	if err := os.MkdirAll(filepath.Dir(*dbPath), 0700); err != nil {
		log.Printf("[proxy] warning: could not create db dir: %v", err)
	}
	store, err := db.Open("sqlite3", *dbPath)
	if err != nil {
		log.Fatalf("[proxy] db open: %v", err)
	}
	if err := store.Migrate(); err != nil {
		log.Fatalf("[proxy] db migrate: %v", err)
	}
	defer store.Close()

	// ── Analysis pipeline ─────────────────────────────────────────────────────
	cfg := pipeline.DefaultConfig()
	cfg.Mode = *mode

	bl := badlist.NewLive(*knownBadPath)
	if *knownBadURL != "" {
		bl.StartAutoRefresh(context.Background(), *knownBadURL, *knownBadRefresh)
	}

	var claudeAn analyzer.Analyzer
	if *anthropicKey != "" {
		log.Printf("[proxy] Claude analysis enabled")
		claudeAn = claude.New(*anthropicKey)
	}

	pl := pipeline.New(store, cfg, bl, cve.New(), heuristic.New(), claudeAn)

	// ── Central server integration ────────────────────────────────────────────
	rep := reporter.New(*serverURL, *token)
	exc := reporter.NewExceptionCache(*serverURL, *token)

	if *serverURL != "" {
		log.Printf("[proxy] reporting to %s", *serverURL)
	} else {
		log.Printf("[proxy] standalone mode — results stored locally only")
	}

	// ── Start proxy ───────────────────────────────────────────────────────────
	proxyCfg := proxy.Config{
		ListenAddr:  *addr,
		PublicURL:   *publicURL,
		Mode:        proxy.Mode(*mode),
		Pipeline:    pl,
		NameChecker: pl,
		Exceptions:  exc,
		Reporter:    rep,
	}

	log.Printf("[proxy] listening on %s", *addr)
	log.Printf("[proxy] npm:  npm config set registry http://localhost%s", *addr)
	log.Printf("[proxy] pip:  pip install --index-url http://localhost%s/simple/ <pkg>", *addr)

	if err := proxy.New(proxyCfg).Start(); err != nil {
		log.Fatalf("[proxy] fatal: %v", err)
	}
}

func defaultDBPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cipher-shield", "proxy-cache.db")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envOrDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
