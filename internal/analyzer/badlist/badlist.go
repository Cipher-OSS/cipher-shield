package badlist

import (
	_ "embed"
	"encoding/json"
	"context"
	"fmt"
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
}

// New loads the embedded known-bad list and returns an Analyzer.
func New() analyzer.Analyzer {
	var data badlistData
	if err := json.Unmarshal(knownBadJSON, &data); err != nil {
		panic(fmt.Sprintf("badlist: parse known_bad.json: %v", err))
	}
	a := &badlistAnalyzer{
		npm:  make(map[string][]badEntry),
		pypi: make(map[string][]badEntry),
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
