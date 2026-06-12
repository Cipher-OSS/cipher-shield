package claude

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	analyzer "github.com/homes853/cipher-shield/internal/analyzer"
	shield "github.com/homes853/cipher-shield/internal"
)

const (
	anthropicAPIURL = "https://api.anthropic.com/v1/messages"
	model           = "claude-opus-4-7"
	maxTokens       = 1024
	analysisTimeout = 30 * time.Second
)

// ErrNoContent is returned when the tarball contains nothing worth sending to Claude.
// The pipeline treats this as a clean skip, not an error.
var ErrNoContent = fmt.Errorf("claude: no analyzable content in tarball")

// claudeAnalyzer calls Claude Opus for deep package analysis.
type claudeAnalyzer struct {
	apiKey string
	http   *http.Client
}

// New returns a Claude Opus Analyzer. apiKey is the Anthropic API key.
func New(apiKey string) analyzer.Analyzer {
	return &claudeAnalyzer{
		apiKey: apiKey,
		http:   &http.Client{Timeout: analysisTimeout},
	}
}

func (c *claudeAnalyzer) Name() string { return "claude" }

func (c *claudeAnalyzer) Analyze(ctx context.Context, pkg shield.PackageRef, tarball []byte) ([]shield.Finding, error) {
	if c.apiKey == "" {
		return nil, nil
	}

	// Extract install scripts and suspicious snippets from tarball
	installScripts, snippets, err := extractForAnalysis(pkg.Ecosystem, tarball)
	if err != nil {
		return nil, nil
	}
	if len(installScripts) == 0 && len(snippets) == 0 {
		return nil, ErrNoContent
	}

	prompt := buildPrompt(pkg, installScripts, snippets)

	reqBody, _ := json.Marshal(map[string]interface{}{
		"model":      model,
		"max_tokens": maxTokens,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	})

	req, err := http.NewRequestWithContext(ctx, "POST", anthropicAPIURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("claude request: %w", err)
	}
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("content-type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("claude api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("claude api %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	var apiResp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("claude decode: %w", err)
	}

	if len(apiResp.Content) == 0 || apiResp.Content[0].Type != "text" {
		return nil, fmt.Errorf("claude: unexpected response structure")
	}

	return parseClaudeResponse(apiResp.Content[0].Text, pkg)
}

// parseClaudeResponse extracts findings from Claude's JSON response.
func parseClaudeResponse(text string, pkg shield.PackageRef) ([]shield.Finding, error) {
	// Find the JSON object in the response (Claude sometimes adds preamble)
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start == -1 || end == -1 || end <= start {
		return nil, fmt.Errorf("claude: no JSON in response")
	}
	jsonStr := text[start : end+1]

	var result struct {
		MaliceScore int    `json:"malice_score"`
		Verdict     string `json:"verdict"`
		Reasoning   string `json:"reasoning"`
		Findings    []struct {
			Type        string `json:"type"`
			Severity    string `json:"severity"`
			Title       string `json:"title"`
			Description string `json:"description"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return nil, fmt.Errorf("claude: parse response: %w", err)
	}

	log.Printf("[claude] %s@%s malice_score=%d verdict=%s", pkg.Name, pkg.Version, result.MaliceScore, result.Verdict)

	var findings []shield.Finding
	for _, f := range result.Findings {
		findings = append(findings, shield.Finding{
			Type:        "claude",
			Severity:    parseSeverity(f.Severity),
			Title:       f.Title,
			Description: f.Description,
		})
	}

	// If Claude says warn/block but returned no findings, synthesize one from reasoning
	if len(findings) == 0 && result.Verdict != "allow" && result.Reasoning != "" {
		sev := shield.SeverityMedium
		if result.Verdict == "block" {
			sev = shield.SeverityHigh
		}
		findings = append(findings, shield.Finding{
			Type:        "claude",
			Severity:    sev,
			Title:       fmt.Sprintf("Claude Opus: %s flagged as suspicious", pkg.Name),
			Description: result.Reasoning,
		})
	}

	return findings, nil
}

// extractForAnalysis pulls install scripts and suspicious source snippets from a tarball.
func extractForAnalysis(eco shield.Ecosystem, data []byte) (map[string]string, []sourceSnippet, error) {
	files, err := extractTGZ(data)
	if err != nil {
		// Try as zip (PyPI wheel)
		files, err = extractZip(data)
		if err != nil {
			return nil, nil, err
		}
	}

	installScripts := map[string]string{}
	var snippets []sourceSnippet

	for _, f := range files {
		base := strings.ToLower(filepath.Base(f.path))
		content := string(f.content)

		if base == "package.json" {
			var pkg struct {
				Scripts map[string]string `json:"scripts"`
			}
			if json.Unmarshal(f.content, &pkg) == nil {
				for _, hook := range []string{"preinstall", "install", "postinstall"} {
					if cmd, ok := pkg.Scripts[hook]; ok && cmd != "" {
						installScripts[hook] = cmd
					}
				}
			}
		}

		if base == "setup.py" {
			installScripts["setup.py"] = truncate(content, 2000)
		}

		// Include short suspicious-looking source files as snippets
		if (strings.HasSuffix(base, ".js") || strings.HasSuffix(base, ".mjs") ||
			strings.HasSuffix(base, ".cjs") || strings.HasSuffix(base, ".py")) &&
			len(f.content) < 8000 && isSuspiciousContent(content) {
			snippets = append(snippets, sourceSnippet{
				path:    f.path,
				content: truncate(content, 2000),
			})
			if len(snippets) >= 5 {
				break
			}
		}
	}

	return installScripts, snippets, nil
}

func isSuspiciousContent(content string) bool {
	lc := strings.ToLower(content)
	indicators := []string{
		"eval(", "base64", "atob(", "process.env", "os.environ",
		"child_process", "execsync", "curl ", "wget ", "fetch(",
	}
	count := 0
	for _, ind := range indicators {
		if strings.Contains(lc, ind) {
			count++
		}
	}
	return count >= 2
}

type fileEntry struct {
	path    string
	content []byte
}

func extractTGZ(data []byte) ([]fileEntry, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	var files []fileEntry
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Size > 256*1024 {
			continue
		}
		base := strings.ToLower(filepath.Base(hdr.Name))
		ext := strings.ToLower(filepath.Ext(hdr.Name))
		if base != "package.json" && base != "setup.py" && ext != ".js" && ext != ".mjs" && ext != ".cjs" && ext != ".py" {
			continue
		}
		buf := &bytes.Buffer{}
		io.Copy(buf, tr)
		files = append(files, fileEntry{path: hdr.Name, content: buf.Bytes()})
		if len(files) >= 50 {
			break
		}
	}
	return files, nil
}

func extractZip(data []byte) ([]fileEntry, error) {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	var files []fileEntry
	for _, f := range r.File {
		if f.FileInfo().IsDir() || f.UncompressedSize64 > 256*1024 {
			continue
		}
		base := strings.ToLower(filepath.Base(f.Name))
		ext := strings.ToLower(filepath.Ext(f.Name))
		if base != "setup.py" && ext != ".py" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		buf := &bytes.Buffer{}
		io.Copy(buf, rc)
		rc.Close()
		files = append(files, fileEntry{path: f.Name, content: buf.Bytes()})
		if len(files) >= 50 {
			break
		}
	}
	return files, nil
}

// ── Finding Expander ──────────────────────────────────────────────────────────

// Expander calls Claude to produce a detailed explanation of a single finding.
type Expander struct {
	apiKey string
	http   *http.Client
}

// NewExpander returns an Expander. Returns nil when apiKey is empty.
func NewExpander(apiKey string) *Expander {
	if apiKey == "" {
		return nil
	}
	return &Expander{apiKey: apiKey, http: &http.Client{Timeout: analysisTimeout}}
}

// Explain asks Claude to explain a finding in plain English.
func (e *Expander) Explain(ctx context.Context, pkg shield.PackageRef, finding shield.Finding) (string, error) {
	if e == nil {
		return "", fmt.Errorf("claude: expander not configured (no API key)")
	}

	prompt := fmt.Sprintf(`You are a package security analyst reviewing a dependency finding.

Package: %s/%s@%s
Finding type: %s
Severity: %s
Title: %s
Description: %s

Provide a plain-English explanation with these sections (use short paragraphs, no markdown headers):
1. What this finding means and what the suspicious code pattern does
2. The likely intent or impact if this is malicious (data theft, supply chain attack, persistence, etc.)
3. Whether this looks like a genuine threat or a possible false positive, and why
4. What the developer should do (remove the package, investigate further, add an exception, etc.)

Be concise — 3 to 4 short paragraphs total.`,
		pkg.Ecosystem, pkg.Name, pkg.Version,
		finding.Type, finding.Severity, finding.Title, finding.Description,
	)

	reqBody, _ := json.Marshal(map[string]interface{}{
		"model":      model,
		"max_tokens": 512,
		"messages":   []map[string]string{{"role": "user", "content": prompt}},
	})

	req, err := http.NewRequestWithContext(ctx, "POST", anthropicAPIURL, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("expander request: %w", err)
	}
	req.Header.Set("x-api-key", e.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("content-type", "application/json")

	resp, err := e.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("expander api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("expander api %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	var apiResp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return "", fmt.Errorf("expander decode: %w", err)
	}
	if len(apiResp.Content) == 0 || apiResp.Content[0].Type != "text" {
		return "", fmt.Errorf("expander: unexpected response structure")
	}

	return apiResp.Content[0].Text, nil
}

func parseSeverity(s string) shield.Severity {
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
