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
	ScoreFunctionCtor     = 30 // new Function() dynamic code construction
	ScoreCharCodeObfusc   = 25 // String.fromCharCode() with many args
	ScoreJSObfuscator     = 25 // _0x variable pattern from js-obfuscator
	ScoreWebhookExfil     = 40 // Discord/Slack/Telegram webhook URL in source
	ScoreStagingDomain    = 20 // raw.githubusercontent/pastebin used as payload stage
	ScoreNativeBinary     = 15 // precompiled .node/.so/.dll binary present
)

// Result is returned alongside findings to let the pipeline decide
// whether to invoke Claude.
type Result struct {
	Score     int
	Findings  []shield.Finding
	HasReadme bool
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
	res := analyzeFiles(r.files, r.hasReadme, r.hasBinary)
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
	return analyzeFiles(r.files, r.hasReadme, r.hasBinary).Score
}

// fileEntry holds the path and content of a file extracted from the tarball.
type fileEntry struct {
	path    string
	content []byte
}

type extractResult struct {
	files     []fileEntry
	hasReadme bool
	hasBinary bool
}

// extract unpacks an npm .tgz or PyPI .whl/.tar.gz into memory.
// Returns at most 200 files (install scripts + source files).
func extract(eco shield.Ecosystem, data []byte) (extractResult, error) {
	switch eco {
	case shield.EcosystemNPM:
		files, err := extractTGZ(data)
		return extractResult{
			files:     files,
			hasReadme: tgzHasReadme(data),
			hasBinary: tgzHasBinary(data),
		}, err
	case shield.EcosystemPyPI:
		// Try zip (wheel) first, then tar.gz (sdist)
		if files, err := extractZip(data); err == nil {
			return extractResult{files: files, hasReadme: zipHasReadme(data), hasBinary: zipHasBinary(data)}, nil
		}
		files, err := extractTGZ(data)
		return extractResult{
			files:     files,
			hasReadme: tgzHasReadme(data),
			hasBinary: tgzHasBinary(data),
		}, err
	}
	return extractResult{}, fmt.Errorf("unknown ecosystem")
}

// tgzHasReadme scans all entries in a .tar.gz without the file limit, checking for a README.
func tgzHasReadme(data []byte) bool {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return false
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if strings.HasPrefix(strings.ToLower(filepath.Base(hdr.Name)), "readme") {
			return true
		}
	}
	return false
}

// zipHasReadme scans all entries in a .zip without the file limit, checking for a README.
func zipHasReadme(data []byte) bool {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return false
	}
	for _, f := range r.File {
		if strings.HasPrefix(strings.ToLower(filepath.Base(f.Name)), "readme") {
			return true
		}
	}
	return false
}

var binaryExts = map[string]bool{
	".node": true, // compiled Node.js native addon
	".so":   true, // Linux shared object
	".dll":  true, // Windows DLL
	".exe":  true, // Windows executable
	".dylib": true, // macOS shared library
}

func tgzHasBinary(data []byte) bool {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return false
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if binaryExts[strings.ToLower(filepath.Ext(hdr.Name))] {
			return true
		}
	}
	return false
}

func zipHasBinary(data []byte) bool {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return false
	}
	for _, f := range r.File {
		if binaryExts[strings.ToLower(filepath.Ext(f.Name))] {
			return true
		}
	}
	return false
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
	return ext == ".js" || ext == ".mjs" || ext == ".cjs" || ext == ".py" || ext == ".sh" || ext == ".ts"
}

// Suspicious patterns compiled once at package init.
var (
	reNetworkInScript = regexp.MustCompile("(?i)(curl|wget|fetch|http\\.get|https\\.get|axios|request)\\s*[\\(`'\"\\s]*http")
	reBase64Exec      = regexp.MustCompile("(?i)(eval|exec|spawn)\\s*\\(\\s*(atob|base64|Buffer\\.from)")
	reObfuscation     = regexp.MustCompile("(?i)eval\\s*\\(\\s*atob\\s*\\(")
	reEnvExfil        = regexp.MustCompile("(?i)(process\\.env|os\\.environ|getenv).{0,200}(fetch|curl|wget|http|request)")
	reChildProc       = regexp.MustCompile("(?i)(child_process|spawn|execSync|exec\\s*\\()[\\s\\(`'\"\\\\]")
	reRemoteScript    = regexp.MustCompile("(?i)(curl|wget).{0,50}(sh|bash|python|node)\\b")

	// Dynamic code construction via Function constructor: new Function("return ...")
	reFunctionCtor = regexp.MustCompile(`(?i)new\s+Function\s*\(`)
	// String.fromCharCode with 3+ args — almost always character-array obfuscation
	reCharCodeObfusc = regexp.MustCompile(`String\.fromCharCode\s*\(\s*\d+\s*,\s*\d+\s*,\s*\d+`)
	// _0x-prefixed variable names — signature of js-obfuscator and similar tools
	reJSObfuscator = regexp.MustCompile(`_0x[0-9a-fA-F]{4,}\b`)
	// Webhook URLs used for credential/secret exfiltration
	reWebhookExfil = regexp.MustCompile(`(?i)(discord\.com/api/webhooks|hooks\.slack\.com|api\.telegram\.org/bot)`)
	// Staging domains used to serve payloads or receive exfiltrated data
	reStagingDomain = regexp.MustCompile(`(?i)(raw\.githubusercontent\.com|gist\.githubusercontent\.com|pastebin\.com/raw|transfer\.sh)`)
)

func analyzeFiles(files []fileEntry, hasReadme bool, hasBinary bool) Result {
	var res Result
	addFinding := func(score int, findingType string, sev shield.Severity, title, desc string) {
		res.Score += score
		res.Findings = append(res.Findings, shield.Finding{
			Type:        findingType,
			Severity:    sev,
			Title:       title,
			Description: desc,
		})
	}

	installScriptCount := 0

	for _, f := range files {
		base := strings.ToLower(filepath.Base(f.path))
		content := string(f.content)

		// package.json: check lifecycle scripts
		if base == "package.json" {
			scripts := extractNPMScripts(f.content)
			for _, hook := range []string{"preinstall", "install", "postinstall"} {
				if cmd, ok := scripts[hook]; ok {
					installScriptCount++
					if reNetworkInScript.MatchString(cmd) {
						addFinding(ScoreNetworkInInstall, "network-in-install", shield.SeverityHigh,
							"Install script makes network request",
							fmt.Sprintf("The '%s' script downloads from the network: %s", hook, truncate(cmd, 120)))
					}
					if reRemoteScript.MatchString(cmd) {
						addFinding(ScoreRemoteScript, "remote-script", shield.SeverityCritical,
							"Install script downloads and executes remote code",
							fmt.Sprintf("'%s' script pipes remote content to a shell: %s", hook, truncate(cmd, 120)))
					}
					if reChildProc.MatchString(cmd) {
						addFinding(ScoreChildProcess, "child-proc", shield.SeverityMedium,
							"Install script spawns child processes",
							fmt.Sprintf("'%s' script: %s", hook, truncate(cmd, 120)))
					}
				}
			}
			if installScriptCount > 2 {
				addFinding(ScoreManyInstallHooks, "many-install-hooks", shield.SeverityMedium,
					"Package has multiple install lifecycle hooks",
					fmt.Sprintf("%d install hooks (preinstall, install, postinstall) — unusual for legitimate packages", installScriptCount))
			}
		}

		// setup.py / install scripts: check for suspicious patterns
		if base == "setup.py" || strings.HasSuffix(base, "install.js") ||
			strings.HasSuffix(base, "postinstall.js") || strings.HasSuffix(base, "preinstall.js") {
			if reNetworkInScript.MatchString(content) {
				addFinding(ScoreNetworkInInstall, "network-in-install", shield.SeverityHigh,
					"Install script makes network request",
					fmt.Sprintf("File %s downloads from the network during install", filepath.Base(f.path)))
			}
			if reRemoteScript.MatchString(content) {
				addFinding(ScoreRemoteScript, "remote-script", shield.SeverityCritical,
					"Install script downloads and executes remote code",
					fmt.Sprintf("File %s pipes remote content to a shell", filepath.Base(f.path)))
			}
		}

		// All source files: check for obfuscation and env exfil
		if reBase64Exec.MatchString(content) {
			addFinding(ScoreBase64Exec, "obfuscation", shield.SeverityHigh,
				"Base64-encoded code execution detected",
				fmt.Sprintf("File %s decodes and executes base64-encoded content", filepath.Base(f.path)))
		}
		if reObfuscation.MatchString(content) {
			addFinding(ScoreObfuscation, "obfuscation", shield.SeverityHigh,
				"Obfuscated code execution (eval+atob)",
				fmt.Sprintf("File %s uses eval(atob(...)) — classic obfuscation pattern", filepath.Base(f.path)))
		}
		if reEnvExfil.MatchString(content) {
			addFinding(ScoreEnvExfil, "env-exfil", shield.SeverityHigh,
				"Possible environment variable exfiltration",
				fmt.Sprintf("File %s reads environment variables and makes network calls in proximity", filepath.Base(f.path)))
		}
		if reFunctionCtor.MatchString(content) {
			addFinding(ScoreFunctionCtor, "obfuscation", shield.SeverityHigh,
				"Dynamic code construction via Function constructor",
				fmt.Sprintf("File %s uses new Function() to construct and execute code at runtime", filepath.Base(f.path)))
		}
		if reCharCodeObfusc.MatchString(content) {
			addFinding(ScoreCharCodeObfusc, "obfuscation", shield.SeverityHigh,
				"Character-code obfuscation detected",
				fmt.Sprintf("File %s builds strings via String.fromCharCode() — common obfuscation technique", filepath.Base(f.path)))
		}
		if reJSObfuscator.MatchString(content) {
			addFinding(ScoreJSObfuscator, "obfuscation", shield.SeverityMedium,
				"JS obfuscator output detected (_0x variables)",
				fmt.Sprintf("File %s contains _0x-prefixed identifiers characteristic of automated JS obfuscators", filepath.Base(f.path)))
		}
		if reWebhookExfil.MatchString(content) {
			addFinding(ScoreWebhookExfil, "webhook-exfil", shield.SeverityCritical,
				"Webhook exfiltration endpoint in source",
				fmt.Sprintf("File %s contains a Discord/Slack/Telegram webhook URL — common data exfiltration channel", filepath.Base(f.path)))
		}
		if reStagingDomain.MatchString(content) {
			addFinding(ScoreStagingDomain, "staging-domain", shield.SeverityHigh,
				"Known payload-staging domain referenced",
				fmt.Sprintf("File %s references a domain commonly used to stage attack payloads (raw.githubusercontent.com, pastebin, etc.)", filepath.Base(f.path)))
		}
	}

	if hasBinary {
		addFinding(ScoreNativeBinary, "native-binary", shield.SeverityMedium,
			"Precompiled native binary included in package",
			"Package contains a compiled binary (.node, .so, .dll, .dylib) — cannot be statically analyzed for malicious behavior")
	}

	if !hasReadme && len(files) > 0 {
		addFinding(ScoreNoReadme, "no-readme", shield.SeverityInfo,
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
