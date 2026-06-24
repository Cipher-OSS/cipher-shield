package main

import (
	"fmt"
	"os"
	"runtime"
	"syscall"

	"github.com/cipher-oss/cipher-shield/internal/proxy"
	"github.com/cipher-oss/cipher-shield/internal/proxyctl"
	"github.com/cipher-oss/cipher-shield/internal/reporter"
	"os/signal"
)

func runProxy(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: cipher-shield proxy start|stop|status|restore")
		os.Exit(1)
	}
	switch args[0] {
	case "start":
		proxyStart(args[1:])
	case "stop":
		proxyStop()
	case "status":
		fmt.Println("proxy:", proxyctl.Status())
	case "restore":
		proxyRestore()
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

	// Resolve scheme before configuring npm/pip so TLS mode gets the right URL.
	tlsCert := envOr("SHIELD_PROXY_TLS_CERT", "")
	tlsKey := envOr("SHIELD_PROXY_TLS_KEY", "")
	scheme := "http"
	if tlsCert != "" && tlsKey != "" {
		scheme = "https"
	}
	proxyURL := scheme + "://" + addr

	if proxyctl.IsRunning() {
		fmt.Printf("cipher-shield proxy is already running (%s)\n", proxyctl.Status())
		os.Exit(0)
	}

	// Heal stale state before saving originals: if a previous run left npm/pip
	// pointing at the proxy without cleaning up, restore them first so we don't
	// accidentally save the proxy URL as the "original" to restore to later.
	if proxyctl.IsStale() {
		fmt.Println("→ Detected stale configuration from previous run — restoring npm/pip first...")
		proxyctl.RestoreNPM()
		proxyctl.RestorePIP()
		proxyctl.RemovePID()
		fmt.Println("✓ Restored")
	}

	pl := buildPipeline()

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

	proxyctl.WritePID(os.Getpid())

	// Handle signals for clean shutdown.
	// SIGTERM is not available on Windows; os.Interrupt (Ctrl+C) covers that platform.
	go func() {
		c := make(chan os.Signal, 1)
		sigs := []os.Signal{os.Interrupt}
		if runtime.GOOS != "windows" {
			sigs = append(sigs, syscall.SIGTERM)
		}
		signal.Notify(c, sigs...)
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
		ListenAddr:  addr,
		Mode:        proxy.Mode(envOr("SHIELD_MODE", "enforce")),
		Pipeline:    pl,
		NameChecker: pl,
		TLSCertFile: tlsCert,
		TLSKeyFile:  tlsKey,
	}
	if serverURL := envOr("SHIELD_SERVER_URL", ""); serverURL != "" {
		token := envOr("SHIELD_PROXY_TOKEN", "")
		proxyCfg.Reporter = reporter.New(serverURL, token)
		proxyCfg.Exceptions = reporter.NewExceptionCache(serverURL, token)
		fmt.Printf("✓ reporting results to %s\n", serverURL)
		fmt.Printf("✓ syncing exceptions from %s\n", serverURL)
		if token == "" {
			fmt.Fprintln(os.Stderr, "  [warn] SHIELD_PROXY_TOKEN not set — reports and exceptions will be unauthenticated")
		}
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
	if runtime.GOOS == "windows" {
		proc.Kill()
	} else {
		proc.Signal(syscall.SIGTERM)
	}
	fmt.Printf("→ Stopped proxy (pid %d)\n", pid)
	proxyctl.RestoreNPM()
	proxyctl.RestorePIP()
	proxyctl.RemovePID()
	fmt.Println("✓ cipher-shield proxy stopped")
}

func proxyRestore() {
	if proxyctl.IsRunning() {
		fmt.Println("Proxy is still running — use 'cipher-shield proxy stop' to stop it cleanly.")
		os.Exit(1)
	}
	if !proxyctl.IsStale() {
		fmt.Println("npm and pip are already using their original registries — nothing to restore.")
		return
	}
	proxyctl.RestoreNPM()
	proxyctl.RestorePIP()
	proxyctl.RemovePID()
	fmt.Println("✓ npm and pip config restored to original registries")
}
