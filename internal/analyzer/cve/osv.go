package cve

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	shield "github.com/homes853/cipher-shield/internal"
	analyzer "github.com/homes853/cipher-shield/internal/analyzer"
)

const osvURL = "https://api.osv.dev/v1/query"

type osvClient struct {
	http *http.Client
}

// New returns an Analyzer that queries OSV.dev for known CVEs.
func New() analyzer.Analyzer {
	return &osvClient{
		http: &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *osvClient) Name() string { return "cve" }

func (c *osvClient) Analyze(ctx context.Context, pkg shield.PackageRef, _ []byte) ([]shield.Finding, error) {
	// Map our ecosystem names to OSV ecosystem names
	osvEco := map[shield.Ecosystem]string{
		shield.EcosystemNPM:  "npm",
		shield.EcosystemPyPI: "PyPI",
	}[pkg.Ecosystem]
	if osvEco == "" {
		return nil, nil
	}

	body, _ := json.Marshal(map[string]interface{}{
		"version": pkg.Version,
		"package": map[string]string{
			"name":      pkg.Name,
			"ecosystem": osvEco,
		},
	})

	req, err := http.NewRequestWithContext(ctx, "POST", osvURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("osv request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv query: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Vulns []struct {
			ID       string   `json:"id"`
			Aliases  []string `json:"aliases"`
			Summary  string   `json:"summary"`
			Details  string   `json:"details"`
			Severity []struct {
				Type  string `json:"type"`
				Score string `json:"score"`
			} `json:"severity"`
			DatabaseSpecific struct {
				Severity string `json:"severity"`
			} `json:"database_specific"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"vulns"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("osv decode: %w", err)
	}

	var findings []shield.Finding
	for _, v := range result.Vulns {
		// Find the CVE alias (prefer CVE- prefix)
		cveID := v.ID
		for _, a := range v.Aliases {
			if strings.HasPrefix(a, "CVE-") {
				cveID = a
				break
			}
		}

		// Parse CVSS score from severity array
		cvss := parseCVSS(v.Severity)

		// Map database_specific.severity to our Severity type
		sev := mapSeverity(v.DatabaseSpecific.Severity, cvss)

		refs := make([]string, 0, len(v.References))
		for _, r := range v.References {
			if r.URL != "" {
				refs = append(refs, r.URL)
			}
		}

		desc := v.Summary
		if v.Details != "" && len(v.Details) < 500 {
			desc = v.Details
		}

		findings = append(findings, shield.Finding{
			Type:        "cve",
			Severity:    sev,
			Title:       cveID + ": " + v.Summary,
			Description: desc,
			References:  refs,
			CVE:         cveID,
			CVSS:        cvss,
		})
	}
	return findings, nil
}

// parseCVSS extracts a numeric CVSS base score from the severity array.
// Returns 0 if no CVSS_V3 score is found.
func parseCVSS(severities []struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}) float64 {
	for _, s := range severities {
		if s.Type == "CVSS_V3" {
			// Score is a CVSS vector string like "CVSS:3.1/AV:N/AC:L/.../8.8"
			// The base score is the last slash-delimited segment.
			parts := strings.Split(s.Score, "/")
			if len(parts) > 0 {
				var score float64
				fmt.Sscanf(parts[len(parts)-1], "%f", &score)
				return score
			}
		}
	}
	return 0
}

func mapSeverity(dbSeverity string, cvss float64) shield.Severity {
	switch strings.ToUpper(dbSeverity) {
	case "CRITICAL":
		return shield.SeverityCritical
	case "HIGH":
		return shield.SeverityHigh
	case "MEDIUM", "MODERATE":
		return shield.SeverityMedium
	case "LOW":
		return shield.SeverityLow
	}
	// Fall back to CVSS score ranges
	switch {
	case cvss >= 9.0:
		return shield.SeverityCritical
	case cvss >= 7.0:
		return shield.SeverityHigh
	case cvss >= 4.0:
		return shield.SeverityMedium
	case cvss > 0:
		return shield.SeverityLow
	}
	return shield.SeverityInfo
}
