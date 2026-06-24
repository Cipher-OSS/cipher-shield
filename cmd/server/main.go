package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/cipher-oss/cipher-shield/internal/analyzer"
	"github.com/cipher-oss/cipher-shield/internal/analyzer/badlist"
	claudeanalyzer "github.com/cipher-oss/cipher-shield/internal/analyzer/claude"
	"github.com/cipher-oss/cipher-shield/internal/analyzer/cve"
	"github.com/cipher-oss/cipher-shield/internal/analyzer/heuristic"
	"github.com/cipher-oss/cipher-shield/internal/api"
	"github.com/cipher-oss/cipher-shield/internal/db"
	"github.com/cipher-oss/cipher-shield/internal/pipeline"
	"github.com/cipher-oss/cipher-shield/internal/proxy"
)

// version is set at build time via -ldflags "-X main.version=<tag>".
var version = "dev"

func main() {
	proxyAddr      := flag.String("proxy-addr",       envOr("SHIELD_PROXY_ADDR",       ":7070"),          "Registry proxy listen address")
	apiAddr        := flag.String("api-addr",         envOr("SHIELD_API_ADDR",         ":8080"),          "API + dashboard listen address")
	dbURL          := flag.String("db",               envOr("DATABASE_URL",             ""),              "Postgres DSN (leave empty for SQLite)")
	dbPath         := flag.String("db-path",          envOr("SHIELD_DB_PATH",           defaultDBPath()),  "SQLite file path")
	mode           := flag.String("mode",             envOr("SHIELD_MODE",              "enforce"),       "enforce | warn | audit")
	anthropicKey   := flag.String("anthropic-key",    envOr("ANTHROPIC_API_KEY",       ""),              "Anthropic API key (enables Claude analysis)")
	jwtSecret      := flag.String("jwt-secret",       envOr("SHIELD_JWT_SECRET",       ""),              "JWT signing secret")
	proxyToken     := flag.String("proxy-token",      envOr("SHIELD_PROXY_TOKEN",      ""),              "Pre-shared token for proxy agent reporting")
	tlsCert        := flag.String("tls-cert",         envOr("SHIELD_TLS_CERT",         ""),              "Path to TLS certificate file (enables HTTPS on API port)")
	tlsKey         := flag.String("tls-key",          envOr("SHIELD_TLS_KEY",          ""),              "Path to TLS private key file")
	proxyTLSCert   := flag.String("proxy-tls-cert",   envOr("SHIELD_PROXY_TLS_CERT",   ""),              "Path to TLS cert for the proxy port (enables HTTPS on port 7070)")
	proxyTLSKey    := flag.String("proxy-tls-key",    envOr("SHIELD_PROXY_TLS_KEY",    ""),              "Path to TLS key for the proxy port")
	corsOrigin     := flag.String("cors-origin",      envOr("SHIELD_CORS_ORIGIN",      ""),              "Allowed CORS origin (e.g. https://shield.company.com); default: *")
	historyDays    := flag.Int("history-days",        envOrInt("SHIELD_HISTORY_DAYS", 30),               "Days of scan history to retain (0 = keep forever)")
	flag.Parse()

	// Reject partial TLS configuration — both cert and key must be set together.
	if (*tlsCert == "") != (*tlsKey == "") {
		log.Fatalf("[startup] SHIELD_TLS_CERT and SHIELD_TLS_KEY must both be set or both be empty")
	}
	if (*proxyTLSCert == "") != (*proxyTLSKey == "") {
		log.Fatalf("[startup] SHIELD_PROXY_TLS_CERT and SHIELD_PROXY_TLS_KEY must both be set or both be empty")
	}

	log.SetFlags(log.Ltime | log.Lshortfile)
	log.Printf("╔══════════════════════════════════════╗")
	log.Printf("║  cipher-shield  %-20s║", version)
	log.Printf("║  AI-powered package security firewall║")
	log.Printf("╚══════════════════════════════════════╝")

	// ── Database ──────────────────────────────────────────────────────────────
	var store db.Store
	var err error
	if *dbURL != "" {
		log.Printf("[startup] connecting to Postgres: %s", maskDSN(*dbURL))
		store, err = db.Open("postgres", *dbURL)
	} else {
		log.Printf("[startup] using SQLite: %s", *dbPath)
		if err2 := os.MkdirAll(filepath.Dir(*dbPath), 0700); err2 != nil {
			log.Printf("[startup] warning: could not create db dir: %v", err2)
		}
		store, err = db.Open("sqlite3", *dbPath)
	}
	if err != nil {
		log.Fatalf("[startup] db open: %v", err)
	}
	defer store.Close()

	// ── Analysis pipeline ─────────────────────────────────────────────────────
	cfg := pipeline.DefaultConfig()
	cfg.Mode = *mode

	var claudeAn analyzer.Analyzer
	var expander *claudeanalyzer.Expander
	if *anthropicKey != "" {
		log.Printf("[startup] Claude Opus analysis enabled")
		claudeAn = claudeanalyzer.New(*anthropicKey)
		expander = claudeanalyzer.NewExpander(*anthropicKey)
	} else {
		log.Printf("[startup] Claude analysis disabled (set ANTHROPIC_API_KEY to enable)")
	}

	bl := badlist.NewFull("")
	pl := pipeline.New(
		store,
		cfg,
		bl,
		cve.New(),
		heuristic.New(),
		claudeAn,
	)

	// ── History pruning ───────────────────────────────────────────────────────
	if *historyDays > 0 {
		go func() {
			ticker := time.NewTicker(24 * time.Hour)
			defer ticker.Stop()
			for ; ; <-ticker.C {
				n, err := store.PruneHistory(context.Background(), *historyDays)
				if err != nil {
					log.Printf("[prune] error: %v", err)
				} else if n > 0 {
					log.Printf("[prune] removed %d scan history rows older than %d days", n, *historyDays)
				}
			}
		}()
	}

	// ── Registry proxy ────────────────────────────────────────────────────────
	proxyCfg := proxy.Config{
		ListenAddr:  *proxyAddr,
		Mode:        proxy.Mode(*mode),
		Pipeline:    pl,
		NameChecker: pl,
		TLSCertFile: *proxyTLSCert,
		TLSKeyFile:  *proxyTLSKey,
	}
	proxyScheme := "http"
	if *proxyTLSCert != "" && *proxyTLSKey != "" {
		proxyScheme = "https"
	}
	go func() {
		if err := proxy.New(proxyCfg).Start(); err != nil {
			log.Fatalf("[proxy] fatal: %v", err)
		}
	}()
	log.Printf("[startup] proxy listening on %s://localhost%s", proxyScheme, *proxyAddr)

	// ── API + dashboard ───────────────────────────────────────────────────────
	log.Printf("[startup] API + dashboard on %s", *apiAddr)
	log.Printf("[startup] npm:  npm config set registry %s://localhost%s", proxyScheme, *proxyAddr)
	log.Printf("[startup] pip:  pip install --index-url %s://localhost%s/simple/ <pkg>", proxyScheme, *proxyAddr)

	if len(*jwtSecret) == 0 {
		log.Printf("[startup] WARNING: SHIELD_JWT_SECRET not set — API auth disabled (dev mode)")
	}

	if *proxyToken == "" {
		log.Printf("[startup] WARNING: SHIELD_PROXY_TOKEN not set — proxy reporting unauthenticated (dev mode)")
	}

	srv := api.New(store, pl, []byte(*jwtSecret), []byte(*proxyToken), *mode, *corsOrigin, expander, bl)

	if *tlsCert != "" && *tlsKey != "" {
		log.Printf("[startup] TLS enabled — API + dashboard on https://%s", *apiAddr)
		if err := http.ListenAndServeTLS(*apiAddr, *tlsCert, *tlsKey, srv); err != nil {
			log.Fatalf("[server] fatal: %v", err)
		}
	} else {
		log.Printf("[startup] TLS not configured — serving HTTP (set SHIELD_TLS_CERT + SHIELD_TLS_KEY for HTTPS)")
		if err := http.ListenAndServe(*apiAddr, srv); err != nil {
			log.Fatalf("[server] fatal: %v", err)
		}
	}
}

func defaultDBPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cipher-shield", "shield.db")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envOrInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func maskDSN(dsn string) string {
	if i := indexPassword(dsn); i >= 0 {
		j := indexAfterPassword(dsn, i)
		return dsn[:i] + "***" + dsn[j:]
	}
	return dsn
}

func indexPassword(dsn string) int {
	schemeEnd := len("postgres://")
	if len(dsn) <= schemeEnd {
		return -1
	}
	sub := dsn[schemeEnd:]
	ci := indexOf(sub, ':')
	if ci < 0 {
		return -1
	}
	return schemeEnd + ci + 1
}

func indexAfterPassword(dsn string, from int) int {
	for i := from; i < len(dsn); i++ {
		if dsn[i] == '@' {
			return i
		}
	}
	return len(dsn)
}

func indexOf(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
