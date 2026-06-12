package badlist

import (
	_ "embed"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	analyzer "github.com/homes853/cipher-shield/internal/analyzer"
	shield "github.com/homes853/cipher-shield/internal"
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
	return NewWithOverride("")
}

// NewFull returns a FullAnalyzer (Analyzer + RawJSON) with an optional override path.
func NewFull(overridePath string) FullAnalyzer {
	return newBadlist(overridePath)
}

// NewWithOverride loads from overridePath if the file exists, otherwise falls
// back to the embedded list. Pass "" to always use the embedded list.
func NewWithOverride(overridePath string) analyzer.Analyzer {
	return newBadlist(overridePath)
}

func newBadlist(overridePath string) *badlistAnalyzer {
	raw := knownBadJSON
	if overridePath != "" {
		if data, err := os.ReadFile(overridePath); err == nil {
			raw = data
		}
	}
	var data badlistData
	if err := json.Unmarshal(raw, &data); err != nil {
		panic(fmt.Sprintf("badlist: parse known_bad.json: %v", err))
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
	return a
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

	// Typosquatting check — only flag if edit distance <= 2 and name length >= 4
	if len(findings) == 0 && len(pkg.Name) >= 4 {
		target, dist := typosquatTarget(pkg.Name, string(pkg.Ecosystem))
		if dist <= 2 && target != "" {
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
