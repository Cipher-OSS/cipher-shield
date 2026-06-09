package pipeline

import (
	"context"
	"fmt"
	"log"
	"time"

	shield "github.com/homes853/cipher-shield/internal"
	"github.com/homes853/cipher-shield/internal/analyzer"
	"github.com/homes853/cipher-shield/internal/db"
)

// Config controls pipeline behavior.
type Config struct {
	// ClaudeTriggerScore is the minimum heuristic score that triggers Claude analysis.
	// Default: 30. Set to 101 to disable Claude entirely.
	ClaudeTriggerScore int

	// BlockCVSSThreshold is the minimum CVSS score that causes a block verdict.
	// Default: 7.0. Findings below this threshold produce warn instead.
	BlockCVSSThreshold float64

	// Mode controls enforcement: "enforce" blocks, "warn" never blocks, "audit" logs only.
	Mode string
}

// DefaultConfig returns sensible production defaults.
func DefaultConfig() Config {
	return Config{
		ClaudeTriggerScore: 30,
		BlockCVSSThreshold: 7.0,
		Mode:               "enforce",
	}
}

// Pipeline runs the tiered analysis for a package.
type Pipeline struct {
	cfg       Config
	store     db.Store
	badlist   analyzer.Analyzer // tier 1
	cve       analyzer.Analyzer // tier 2
	heuristic heuristicAnalyzer // tier 3 — special interface for score
	claude    analyzer.Analyzer // tier 4 — optional, nil if no API key
}

// heuristicAnalyzer extends Analyzer with a Score method used to gate Claude.
type heuristicAnalyzer interface {
	analyzer.Analyzer
	// ScoreOnly returns a 0-100 risk score without producing findings.
	// Called before Analyze to decide whether Claude should run.
	ScoreOnly(ctx context.Context, pkg shield.PackageRef, tarball []byte) int
}

// New creates a Pipeline. Pass nil for claude to disable Claude analysis.
func New(store db.Store, cfg Config, badlist, cve analyzer.Analyzer, heuristic heuristicAnalyzer, claude analyzer.Analyzer) *Pipeline {
	if cfg.ClaudeTriggerScore == 0 {
		cfg.ClaudeTriggerScore = 30
	}
	if cfg.BlockCVSSThreshold == 0 {
		cfg.BlockCVSSThreshold = 7.0
	}
	if cfg.Mode == "" {
		cfg.Mode = "enforce"
	}
	return &Pipeline{
		cfg:       cfg,
		store:     store,
		badlist:   badlist,
		cve:       cve,
		heuristic: heuristic,
		claude:    claude,
	}
}

// Analyze runs the full tiered analysis for a package.
// tarball may be nil for lockfile scans (CVE + known-bad only; heuristic and Claude skipped).
func (p *Pipeline) Analyze(ctx context.Context, pkg shield.PackageRef, tarball []byte) (*shield.ScanResult, error) {
	start := time.Now()

	// Check cache first
	if cached, err := p.store.GetCachedResult(pkg.Ecosystem, pkg.Name, pkg.Version); err == nil && cached != nil {
		log.Printf("[pipeline] cache hit: %s@%s (%s)", pkg.Name, pkg.Version, cached.Verdict)
		return cached, nil
	}

	// Check exceptions — if package is explicitly allowed, skip analysis
	if exc, err := p.store.GetException(pkg.Ecosystem, pkg.Name, pkg.Version); err == nil && exc != nil {
		log.Printf("[pipeline] exception: %s@%s — %s", pkg.Name, pkg.Version, exc.Reason)
		result := &shield.ScanResult{
			ScanID:     newScanID(),
			Package:    pkg,
			Verdict:    shield.VerdictAllow,
			Findings:   nil,
			ScannedAt:  time.Now().UTC(),
			DurationMs: time.Since(start).Milliseconds(),
		}
		return result, nil
	}

	var allFindings []shield.Finding
	claudeNeeded := false

	// Tier 1: Known-bad list (fast, in-memory)
	if p.badlist != nil {
		findings, err := p.badlist.Analyze(ctx, pkg, nil)
		if err != nil {
			log.Printf("[pipeline] badlist error: %v", err)
		}
		allFindings = append(allFindings, findings...)
		if hasCriticalOrBlock(findings) {
			claudeNeeded = true // still run Claude to confirm + get details
			log.Printf("[pipeline] %s@%s: known-bad hit, %d findings", pkg.Name, pkg.Version, len(findings))
		}
	}

	// Tier 2: CVE check (network)
	if p.cve != nil {
		findings, err := p.cve.Analyze(ctx, pkg, nil)
		if err != nil {
			log.Printf("[pipeline] cve error: %v", err)
		}
		allFindings = append(allFindings, findings...)
		if hasHighCVSS(findings, p.cfg.BlockCVSSThreshold) {
			claudeNeeded = true
		}
	}

	// Tier 3: Heuristic scan (only if tarball provided)
	if len(tarball) > 0 && p.heuristic != nil {
		score := p.heuristic.ScoreOnly(ctx, pkg, tarball)
		log.Printf("[pipeline] %s@%s heuristic score=%d", pkg.Name, pkg.Version, score)
		if score >= p.cfg.ClaudeTriggerScore {
			claudeNeeded = true
		}
		findings, err := p.heuristic.Analyze(ctx, pkg, tarball)
		if err != nil {
			log.Printf("[pipeline] heuristic error: %v", err)
		}
		allFindings = append(allFindings, findings...)
	}

	// Tier 4: Claude Opus (only when needed)
	if claudeNeeded && p.claude != nil && len(tarball) > 0 {
		log.Printf("[pipeline] %s@%s: invoking Claude Opus", pkg.Name, pkg.Version)
		findings, err := p.claude.Analyze(ctx, pkg, tarball)
		if err != nil {
			log.Printf("[pipeline] claude error: %v", err)
		} else {
			allFindings = append(allFindings, findings...)
		}
	}

	verdict := p.computeVerdict(allFindings)
	result := &shield.ScanResult{
		ScanID:     newScanID(),
		Package:    pkg,
		Verdict:    verdict,
		Findings:   allFindings,
		ClaudeUsed: claudeNeeded && p.claude != nil,
		ScannedAt:  time.Now().UTC(),
		DurationMs: time.Since(start).Milliseconds(),
	}

	// Persist to cache + history
	if err := p.store.SaveResult(*result); err != nil {
		log.Printf("[pipeline] save result: %v", err)
	}

	log.Printf("[pipeline] %s@%s verdict=%s findings=%d duration=%dms",
		pkg.Name, pkg.Version, verdict, len(allFindings), result.DurationMs)
	return result, nil
}

// computeVerdict derives the overall verdict from the aggregate findings.
// In warn/audit mode, never returns block.
func (p *Pipeline) computeVerdict(findings []shield.Finding) shield.Verdict {
	verdict := shield.VerdictAllow
	for _, f := range findings {
		switch f.Severity {
		case shield.SeverityCritical, shield.SeverityHigh:
			if p.cfg.Mode == "enforce" {
				return shield.VerdictBlock
			}
			verdict = shield.VerdictWarn
		case shield.SeverityMedium:
			if verdict == shield.VerdictAllow {
				verdict = shield.VerdictWarn
			}
		}
	}
	return verdict
}

func hasCriticalOrBlock(findings []shield.Finding) bool {
	for _, f := range findings {
		if f.Severity == shield.SeverityCritical || f.Severity == shield.SeverityHigh {
			return true
		}
	}
	return false
}

func hasHighCVSS(findings []shield.Finding, threshold float64) bool {
	for _, f := range findings {
		if f.CVE != "" && f.CVSS >= threshold {
			return true
		}
	}
	return false
}

// CheckName runs only Tier 1 (known-bad + typosquatting) against a package name.
// Used by the proxy for metadata-level checks without needing a tarball.
func (p *Pipeline) CheckName(ctx context.Context, pkg shield.PackageRef) ([]shield.Finding, error) {
	if p.badlist == nil {
		return nil, nil
	}
	return p.badlist.Analyze(ctx, pkg, nil)
}

func newScanID() string {
	return fmt.Sprintf("scan-%d", time.Now().UnixNano())
}
