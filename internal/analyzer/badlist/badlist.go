package badlist

import (
	_ "embed"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	shield "github.com/cipher-oss/cipher-shield/internal"
	analyzer "github.com/cipher-oss/cipher-shield/internal/analyzer"
)

//go:embed data/known_bad.json
var knownBadJSON []byte

type badEntry struct {
	Name     string `json:"name"`
	Version  string `json:"version"` // "*" = all versions
	Reason   string `json:"reason"`
	Severity string `json:"severity"`
}

type badlistData struct {
	NPM  []badEntry `json:"npm"`
	PyPI []badEntry `json:"pypi"`
}

type badlistAnalyzer struct {
	npm  map[string][]badEntry // name → entries
	pypi map[string][]badEntry
	raw  []byte // original JSON, returned by RawJSON for API exposure
}

// FullAnalyzer combines the Analyzer interface with raw JSON access for API exposure.
type FullAnalyzer interface {
	analyzer.Analyzer
	RawJSON() []byte
}

// New loads the embedded known-bad list and returns an Analyzer.
func New() analyzer.Analyzer {
	return NewLive("")
}

// NewFull returns a FullAnalyzer (Analyzer + RawJSON) with an optional override path.
// The returned *liveAnalyzer supports StartAutoRefresh for periodic updates.
func NewFull(overridePath string) FullAnalyzer {
	return NewLive(overridePath)
}

// NewWithOverride loads from overridePath if the file exists, otherwise falls
// back to the embedded list. Pass "" to always use the embedded list.
func NewWithOverride(overridePath string) analyzer.Analyzer {
	return NewLive(overridePath)
}

// NewLive returns a thread-safe FullAnalyzer. Call StartAutoRefresh to enable
// periodic background updates from a remote URL.
func NewLive(overridePath string) *liveAnalyzer {
	return &liveAnalyzer{current: newBadlist(overridePath)}
}

// liveAnalyzer wraps badlistAnalyzer with a RWMutex to allow atomic live swaps
// while concurrent Analyze calls are in flight.
type liveAnalyzer struct {
	mu      sync.RWMutex
	current *badlistAnalyzer
}

// StartAutoRefresh fetches url immediately at startup, then re-fetches every
// interval. On any failure it logs and keeps the existing list (fail safe).
// Stops when ctx is cancelled.
func (l *liveAnalyzer) StartAutoRefresh(ctx context.Context, url string, interval time.Duration) {
	if err := l.fetchAndSwap(url); err != nil {
		log.Printf("[badlist] initial fetch from %s failed: %v (using embedded list)", url, err)
	} else {
		l.mu.RLock()
		npm, pypi := len(l.current.npm), len(l.current.pypi)
		l.mu.RUnlock()
		log.Printf("[badlist] loaded %d npm + %d pypi entries from %s", npm, pypi, url)
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := l.fetchAndSwap(url); err != nil {
					log.Printf("[badlist] refresh failed: %v (keeping existing list)", err)
				} else {
					log.Printf("[badlist] refreshed from %s", url)
				}
			}
		}
	}()
}

func (l *liveAnalyzer) fetchAndSwap(url string) error {
	raw, err := fetchURL(url)
	if err != nil {
		return err
	}
	next, err := newBadlistFromBytes(raw)
	if err != nil {
		return fmt.Errorf("invalid JSON from %s: %w", url, err)
	}
	l.mu.Lock()
	l.current = next
	l.mu.Unlock()
	return nil
}

func (l *liveAnalyzer) Name() string { return "known-bad" }

func (l *liveAnalyzer) RawJSON() []byte {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.current.raw
}

func (l *liveAnalyzer) Analyze(ctx context.Context, pkg shield.PackageRef, tarball []byte) ([]shield.Finding, error) {
	l.mu.RLock()
	a := l.current
	l.mu.RUnlock()
	return a.Analyze(ctx, pkg, tarball)
}

func newBadlist(overridePath string) *badlistAnalyzer {
	raw := knownBadJSON
	if overridePath != "" {
		if data, err := os.ReadFile(overridePath); err == nil {
			raw = data
		}
	}
	a, err := newBadlistFromBytes(raw)
	if err != nil {
		panic(fmt.Sprintf("badlist: parse known_bad.json: %v", err))
	}
	return a
}

func newBadlistFromBytes(raw []byte) (*badlistAnalyzer, error) {
	var data badlistData
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, err
	}
	a := &badlistAnalyzer{
		npm:  make(map[string][]badEntry),
		pypi: make(map[string][]badEntry),
		raw:  raw,
	}
	for _, e := range data.NPM {
		a.npm[strings.ToLower(e.Name)] = append(a.npm[strings.ToLower(e.Name)], e)
	}
	for _, e := range data.PyPI {
		a.pypi[strings.ToLower(e.Name)] = append(a.pypi[strings.ToLower(e.Name)], e)
	}
	return a, nil
}

func fetchURL(url string) ([]byte, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func (b *badlistAnalyzer) Name() string { return "known-bad" }

// RawJSON returns the known-bad list as the original JSON bytes (for API exposure).
func (b *badlistAnalyzer) RawJSON() []byte { return b.raw }

func (b *badlistAnalyzer) Analyze(_ context.Context, pkg shield.PackageRef, _ []byte) ([]shield.Finding, error) {
	var entries []badEntry
	switch pkg.Ecosystem {
	case shield.EcosystemNPM:
		entries = b.npm[strings.ToLower(pkg.Name)]
	case shield.EcosystemPyPI:
		entries = b.pypi[strings.ToLower(pkg.Name)]
	}

	var findings []shield.Finding
	for _, e := range entries {
		// Empty pkg.Version = name-only check (metadata level) — match any version entry.
		// Non-empty pkg.Version = tarball check — match only the specific version or wildcard.
		if pkg.Version != "" && e.Version != "*" && e.Version != "" && e.Version != pkg.Version {
			continue
		}
		findings = append(findings, shield.Finding{
			Type:        "known-bad",
			Severity:    mapSev(e.Severity),
			Title:       fmt.Sprintf("Known malicious package: %s", pkg.Name),
			Description: e.Reason,
		})
	}

	// Typosquatting check — scale threshold with name length to avoid false
	// positives on short names (e.g. gopd → got). Names < 8 chars need
	// distance 1; longer names allow distance 2.
	if len(findings) == 0 && len(pkg.Name) >= 5 {
		target, dist := typosquatTarget(pkg.Name, string(pkg.Ecosystem))
		maxDist := 2
		if len(pkg.Name) < 8 {
			maxDist = 1
		}
		if dist <= maxDist && target != "" {
			findings = append(findings, shield.Finding{
				Type:     "typosquat",
				Severity: shield.SeverityHigh,
				Title:    fmt.Sprintf("Possible typosquatting of '%s'", target),
				Description: fmt.Sprintf(
					"Package '%s' is %d edit(s) away from the popular package '%s'. Verify this is the intended package.",
					pkg.Name, dist, target,
				),
			})
		}
	}

	return findings, nil
}

func mapSev(s string) shield.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return shield.SeverityCritical
	case "high":
		return shield.SeverityHigh
	case "medium":
		return shield.SeverityMedium
	case "low":
		return shield.SeverityLow
	}
	return shield.SeverityInfo
}
