package heuristic

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	shield "github.com/homes853/cipher-shield/internal"
)

// Score weights — sum determines whether Claude gets invoked.
// These are exported so the pipeline can read them.
const (
	ScoreNetworkInInstall = 40 // curl/wget/fetch in install script
	ScoreBase64Exec       = 35 // base64 decode + exec pattern
	ScoreEnvExfil         = 35 // reads env vars + makes network call
	ScoreObfuscation      = 30 // eval(atob(...)) or similar
	ScoreChildProcess     = 20 // spawn/exec in install script
	ScoreRemoteScript     = 25 // downloads and executes remote script
	ScoreSuspiciousDomain = 20 // calls to non-CDN, non-registry domains
	ScoreNewMaintainer    = 10 // package very new (from metadata)
	ScoreNoReadme         = 5  // no README file in package
	ScoreManyInstallHooks = 15 // multiple install lifecycle scripts
)

// Result is returned alongside findings to let the pipeline decide
// whether to invoke Claude.
type Result struct {
	Score    int
	Findings []shield.Finding
}

type heuristicAnalyzer struct{}

// New returns a heuristicAnalyzer. The concrete type is returned so callers
// can use it as a pipeline.heuristicAnalyzer (which requires ScoreOnly).
func New() *heuristicAnalyzer { return &heuristicAnalyzer{} }

func (h *heuristicAnalyzer) Name() string { return "heuristic" }

func (h *heuristicAnalyzer) Analyze(_ context.Context, pkg shield.PackageRef, tarball []byte) ([]shield.Finding, error) {
	if len(tarball) == 0 {
		return nil, nil
	}
	r, err := extract(pkg.Ecosystem, tarball)
	if err != nil {
		return nil, nil // non-fatal: can't extract = pass through
	}
	res := analyzeFiles(r)
	return res.Findings, nil
}

// ScoreOnly returns the risk score without producing findings (used by pipeline to gate Claude).
func (h *heuristicAnalyzer) ScoreOnly(_ context.Context, pkg shield.PackageRef, tarball []byte) int {
	return Score(pkg, tarball)
}

// Score returns the heuristic risk score for the tarball (0-100).
// Used by the pipeline to decide whether to invoke Claude.
func Score(pkg shield.PackageRef, tarball []byte) int {
	if len(tarball) == 0 {
		return 0
	}
	r, err := extract(pkg.Ecosystem, tarball)
	if err != nil {
		return 0
	}
	return analyzeFiles(r).Score
}

// fileEntry holds the path and content of a file extracted from the tarball.
type fileEntry struct {
	path    string
	content []byte
}

// extract unpacks an npm .tgz or PyPI .whl/.tar.gz into memory.
// Returns at most 200 files (install scripts + source files).
func extract(eco shield.Ecosystem, data []byte) ([]fileEntry, error) {
	switch eco {
	case shield.EcosystemNPM:
		return extractTGZ(data)
	case shield.EcosystemPyPI:
		// Try zip (wheel) first, then tar.gz (sdist)
		if files, err := extractZip(data); err == nil {
			return files, nil
		}
		return extractTGZ(data)
	}
	return nil, fmt.Errorf("unknown ecosystem")
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
		if hdr.Typeflag != tar.TypeReg || hdr.Size > 512*1024 {
			continue // skip non-files and large files
		}
		if !interestingFile(hdr.Name) {
			continue
		}
		buf := new(bytes.Buffer)
		buf.Grow(int(hdr.Size))
		buf.ReadFrom(tr)
		files = append(files, fileEntry{path: hdr.Name, content: buf.Bytes()})
		if len(files) >= 200 {
			break
		}
	}
	return files, nil
}

func extractZip(data []byte) ([]fileEntry, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	var files []fileEntry
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || f.UncompressedSize64 > 512*1024 {
			continue
		}
		if !interestingFile(f.Name) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		buf := new(bytes.Buffer)
		buf.ReadFrom(rc)
		rc.Close()
		files = append(files, fileEntry{path: f.Name, content: buf.Bytes()})
		if len(files) >= 200 {
			break
		}
	}
	return files, nil
}

func interestingFile(name string) bool {
	base := strings.ToLower(filepath.Base(name))
	ext := strings.ToLower(filepath.Ext(name))
	// Always include package manifest and install scripts
	interesting := []string{"package.json", "setup.py", "setup.cfg", "pyproject.toml",
		"binding.gyp", "install.js", "postinstall.js", "preinstall.js"}
	for _, n := range interesting {
		if base == n {
			return true
		}
	}
	// Include source files but not tests/docs
	if strings.Contains(name, "test") || strings.Contains(name, "spec") ||
		strings.Contains(name, "docs") || strings.Contains(name, "__pycache__") {
		return false
	}
	return ext == ".js" || ext == ".py" || ext == ".sh" || ext == ".ts"
}

// Suspicious patterns compiled once at package init.
var (
	reNetworkInScript = regexp.MustCompile("(?i)(curl|wget|fetch|http\\.get|https\\.get|axios|request)\\s*[\\(`'\"\\s]*http")
	reBase64Exec      = regexp.MustCompile("(?i)(eval|exec|spawn)\\s*\\(\\s*(atob|base64|Buffer\\.from)")
	reObfuscation     = regexp.MustCompile("(?i)eval\\s*\\(\\s*atob\\s*\\(")
	reEnvExfil        = regexp.MustCompile("(?i)(process\\.env|os\\.environ|getenv).{0,200}(fetch|curl|wget|http|request)")
	reChildProc       = regexp.MustCompile("(?i)(child_process|spawn|execSync|exec\\s*\\()[\\s\\(`'\"\\\\]")
	reRemoteScript    = regexp.MustCompile("(?i)(curl|wget).{0,50}(sh|bash|python|node)\\b")
)

func analyzeFiles(files []fileEntry) Result {
	var res Result
	addFinding := func(score int, sev shield.Severity, title, desc string) {
		res.Score += score
		res.Findings = append(res.Findings, shield.Finding{
			Type:        "heuristic",
			Severity:    sev,
			Title:       title,
			Description: desc,
		})
	}

	installScriptCount := 0
	hasReadme := false

	for _, f := range files {
		base := strings.ToLower(filepath.Base(f.path))
		content := string(f.content)

		if strings.HasPrefix(base, "readme") {
			hasReadme = true
		}

		// package.json: check lifecycle scripts
		if base == "package.json" {
			scripts := extractNPMScripts(f.content)
			for _, hook := range []string{"preinstall", "install", "postinstall"} {
				if cmd, ok := scripts[hook]; ok {
					installScriptCount++
					if reNetworkInScript.MatchString(cmd) {
						addFinding(ScoreNetworkInInstall, shield.SeverityHigh,
							"Install script makes network request",
							fmt.Sprintf("The '%s' script downloads from the network: %s", hook, truncate(cmd, 120)))
					}
					if reRemoteScript.MatchString(cmd) {
						addFinding(ScoreRemoteScript, shield.SeverityCritical,
							"Install script downloads and executes remote code",
							fmt.Sprintf("'%s' script pipes remote content to a shell: %s", hook, truncate(cmd, 120)))
					}
					if reChildProc.MatchString(cmd) {
						addFinding(ScoreChildProcess, shield.SeverityMedium,
							"Install script spawns child processes",
							fmt.Sprintf("'%s' script: %s", hook, truncate(cmd, 120)))
					}
				}
			}
			if installScriptCount > 2 {
				addFinding(ScoreManyInstallHooks, shield.SeverityMedium,
					"Package has multiple install lifecycle hooks",
					fmt.Sprintf("%d install hooks (preinstall, install, postinstall) — unusual for legitimate packages", installScriptCount))
			}
		}

		// setup.py / install scripts: check for suspicious patterns
		if base == "setup.py" || strings.HasSuffix(base, "install.js") ||
			strings.HasSuffix(base, "postinstall.js") || strings.HasSuffix(base, "preinstall.js") {
			if reNetworkInScript.MatchString(content) {
				addFinding(ScoreNetworkInInstall, shield.SeverityHigh,
					"Install script makes network request",
					fmt.Sprintf("File %s downloads from the network during install", filepath.Base(f.path)))
			}
			if reRemoteScript.MatchString(content) {
				addFinding(ScoreRemoteScript, shield.SeverityCritical,
					"Install script downloads and executes remote code",
					fmt.Sprintf("File %s pipes remote content to a shell", filepath.Base(f.path)))
			}
		}

		// All source files: check for obfuscation and env exfil
		if reBase64Exec.MatchString(content) {
			addFinding(ScoreBase64Exec, shield.SeverityHigh,
				"Base64-encoded code execution detected",
				fmt.Sprintf("File %s decodes and executes base64-encoded content", filepath.Base(f.path)))
		}
		if reObfuscation.MatchString(content) {
			addFinding(ScoreObfuscation, shield.SeverityHigh,
				"Obfuscated code execution (eval+atob)",
				fmt.Sprintf("File %s uses eval(atob(...)) — classic obfuscation pattern", filepath.Base(f.path)))
		}
		if reEnvExfil.MatchString(content) {
			addFinding(ScoreEnvExfil, shield.SeverityHigh,
				"Possible environment variable exfiltration",
				fmt.Sprintf("File %s reads environment variables and makes network calls in proximity", filepath.Base(f.path)))
		}
	}

	if !hasReadme && len(files) > 0 {
		addFinding(ScoreNoReadme, shield.SeverityInfo,
			"Package has no README",
			"Legitimate packages almost always include a README file")
	}

	if res.Score > 100 {
		res.Score = 100
	}
	return res
}

// extractNPMScripts parses the "scripts" field from package.json.
func extractNPMScripts(data []byte) map[string]string {
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}
	return pkg.Scripts
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
