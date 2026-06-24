package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// version is set at build time via -ldflags "-X main.version=<tag>".
var version = "dev"

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
	case "explain":
		runExplain(os.Args[2:])
	case "update":
		runUpdate()
	case "version":
		fmt.Printf("cipher-shield %s\n", version)
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `cipher-shield — AI-powered package security firewall

Usage:
  cipher-shield scan lockfile <path>              Scan a lock file (package-lock.json, requirements.txt, etc.)
  cipher-shield scan package <name@version>       Scan a single package
    [--ecosystem npm|pypi]                        (default: npm)
  cipher-shield explain <name[@version]>          Show full findings for a blocked/warned package
  cipher-shield proxy start [--addr 127.0.0.1:7070]  Start proxy (configures npm + pip automatically)
  cipher-shield proxy stop                            Stop proxy (restores npm + pip config)
  cipher-shield proxy status                          Show proxy status
  cipher-shield proxy restore                         Restore npm + pip if proxy stopped unexpectedly
  cipher-shield update                            Fetch latest known-bad list from GitHub
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
	return filepath.Join(home, ".cipher-shield", "shield.db")
}

func dirOf(path string) string {
	return filepath.Dir(path)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
