package pipeline_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	shield "github.com/homes853/cipher-shield/internal"
	"github.com/homes853/cipher-shield/internal/pipeline"
)

// ── Test doubles ──────────────────────────────────────────────────────────────

// memStore is an in-memory Store implementation for testing.
type memStore struct {
	cache      map[string]*shield.ScanResult
	exceptions map[string]*shield.Exception
	saveCount  int
}

func newMemStore() *memStore {
	return &memStore{
		cache:      make(map[string]*shield.ScanResult),
		exceptions: make(map[string]*shield.Exception),
	}
}

func storeKey(eco shield.Ecosystem, name, version string) string {
	return string(eco) + ":" + name + ":" + version
}

func (m *memStore) GetCachedResult(eco shield.Ecosystem, name, version string) (*shield.ScanResult, error) {
	r := m.cache[storeKey(eco, name, version)]
	if r != nil {
		now := time.Now()
		copy := *r
		copy.CachedAt = &now
		return &copy, nil
	}
	return nil, nil
}

func (m *memStore) SaveResult(r shield.ScanResult) error {
	m.saveCount++
	m.cache[storeKey(r.Package.Ecosystem, r.Package.Name, r.Package.Version)] = &r
	return nil
}

func (m *memStore) GetException(eco shield.Ecosystem, name, version string) (*shield.Exception, error) {
	if e, ok := m.exceptions[storeKey(eco, name, version)]; ok {
		return e, nil
	}
	// wildcard (version = "")
	if e, ok := m.exceptions[storeKey(eco, name, "")]; ok {
		return e, nil
	}
	return nil, nil
}

func (m *memStore) ListExceptions() ([]shield.Exception, error)              { return nil, nil }
func (m *memStore) AddException(e shield.Exception) error                    { return nil }
func (m *memStore) DeleteException(_ string) error                           { return nil }
func (m *memStore) ListHistory(_ int) ([]shield.ScanResult, error)           { return nil, nil }
func (m *memStore) CreateUser(_, _, _ string) (*shield.User, error)          { return nil, nil }
func (m *memStore) GetUserByEmail(_ string) (*shield.User, error)            { return nil, nil }
func (m *memStore) GetUserByID(_ string) (*shield.User, error)               { return nil, nil }
func (m *memStore) UpdatePassword(_, _ string) error                         { return nil }
func (m *memStore) CountUsers() (int, error)                                 { return 0, nil }
func (m *memStore) ListUsers() ([]shield.User, error)                        { return nil, nil }
func (m *memStore) PruneHistory(_ int) (int64, error)                        { return 0, nil }
func (m *memStore) Migrate() error                                           { return nil }
func (m *memStore) Close() error                                             { return nil }

// stubAnalyzer returns preconfigured findings. Tracks call count atomically.
type stubAnalyzer struct {
	name     string
	findings []shield.Finding
	err      error
	called   int32
}

func (s *stubAnalyzer) Name() string { return s.name }
func (s *stubAnalyzer) Analyze(_ context.Context, _ shield.PackageRef, _ []byte) ([]shield.Finding, error) {
	atomic.AddInt32(&s.called, 1)
	return s.findings, s.err
}

// stubHeuristic satisfies the unexported pipeline.heuristicAnalyzer interface (AnalyzeFull).
type stubHeuristic struct {
	findings []shield.Finding
	score    int
	err      error
	called   int32
}

func (s *stubHeuristic) AnalyzeFull(_ context.Context, _ shield.PackageRef, tarball []byte) ([]shield.Finding, int, error) {
	if len(tarball) == 0 {
		return nil, 0, nil
	}
	atomic.AddInt32(&s.called, 1)
	return s.findings, s.score, s.err
}

// ── Finding factories ─────────────────────────────────────────────────────────

func criticalFinding() shield.Finding {
	return shield.Finding{Type: "known-bad", Severity: shield.SeverityCritical, Title: "Known malicious package"}
}

func cveFinding(severity shield.Severity, cvss float64) shield.Finding {
	return shield.Finding{Type: "cve", Severity: severity, Title: "CVE-TEST", CVE: "CVE-2024-9999", CVSS: cvss}
}

func mediumFinding() shield.Finding {
	return shield.Finding{Type: "heuristic", Severity: shield.SeverityMedium, Title: "Suspicious install script"}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func npmPkg(name, version string) shield.PackageRef {
	return shield.PackageRef{Ecosystem: shield.EcosystemNPM, Name: name, Version: version}
}

func noopHeuristic() *stubHeuristic { return &stubHeuristic{} }

// ── Tests ─────────────────────────────────────────────────────────────────────

func TestCacheHit(t *testing.T) {
	store := newMemStore()
	p := npmPkg("lodash", "4.17.21")
	store.cache[storeKey(p.Ecosystem, p.Name, p.Version)] = &shield.ScanResult{
		ScanID:    "cached-scan",
		Package:   p,
		Verdict:   shield.VerdictAllow,
		ScannedAt: time.Now(),
	}

	bad := &stubAnalyzer{name: "bad"}
	pl := pipeline.New(store, pipeline.DefaultConfig(), bad, bad, noopHeuristic(), bad)

	result, err := pl.Analyze(context.Background(), p, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ScanID != "cached-scan" {
		t.Errorf("want cached result, got scan_id=%s", result.ScanID)
	}
	if atomic.LoadInt32(&bad.called) != 0 {
		t.Error("analyzers must not run on cache hit")
	}
}

func TestExceptionBypass(t *testing.T) {
	store := newMemStore()
	p := npmPkg("internal-tool", "1.0.0")
	store.exceptions[storeKey(p.Ecosystem, p.Name, p.Version)] = &shield.Exception{
		ExceptionID: "exc-1", Ecosystem: p.Ecosystem,
		Name: p.Name, Version: p.Version,
		Reason: "internal package", CreatedAt: time.Now(),
	}

	bad := &stubAnalyzer{name: "bad", findings: []shield.Finding{criticalFinding()}}
	pl := pipeline.New(store, pipeline.DefaultConfig(), bad, bad, noopHeuristic(), bad)

	result, err := pl.Analyze(context.Background(), p, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Verdict != shield.VerdictAllow {
		t.Errorf("excepted package: want allow, got %s", result.Verdict)
	}
	if atomic.LoadInt32(&bad.called) != 0 {
		t.Error("analyzers must not run for excepted packages")
	}
}

func TestExceptionWildcardVersion(t *testing.T) {
	store := newMemStore()
	// version="" is a wildcard that matches any version
	store.exceptions[storeKey(shield.EcosystemNPM, "internal-lib", "")] = &shield.Exception{
		ExceptionID: "exc-wc", Ecosystem: shield.EcosystemNPM,
		Name: "internal-lib", Version: "",
		Reason: "internal, all versions allowed", CreatedAt: time.Now(),
	}

	bad := &stubAnalyzer{name: "bad", findings: []shield.Finding{criticalFinding()}}
	pl := pipeline.New(store, pipeline.DefaultConfig(), bad, bad, noopHeuristic(), nil)

	result, err := pl.Analyze(context.Background(), npmPkg("internal-lib", "9.9.9"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Verdict != shield.VerdictAllow {
		t.Errorf("wildcard exception: want allow, got %s", result.Verdict)
	}
}

func TestCleanPackage(t *testing.T) {
	store := newMemStore()
	pl := pipeline.New(store, pipeline.DefaultConfig(),
		&stubAnalyzer{name: "badlist"},
		&stubAnalyzer{name: "cve"},
		noopHeuristic(),
		nil,
	)

	result, err := pl.Analyze(context.Background(), npmPkg("clean-pkg", "1.0.0"), []byte("tarball"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Verdict != shield.VerdictAllow {
		t.Errorf("clean package: want allow, got %s", result.Verdict)
	}
	if len(result.Findings) != 0 {
		t.Errorf("clean package: want 0 findings, got %d", len(result.Findings))
	}
}

func TestBadlistBlockInEnforce(t *testing.T) {
	store := newMemStore()
	pl := pipeline.New(store, pipeline.DefaultConfig(),
		&stubAnalyzer{name: "badlist", findings: []shield.Finding{criticalFinding()}},
		&stubAnalyzer{name: "cve"},
		noopHeuristic(),
		nil,
	)

	result, err := pl.Analyze(context.Background(), npmPkg("evil-pkg", "1.0.0"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Verdict != shield.VerdictBlock {
		t.Errorf("critical finding in enforce mode: want block, got %s", result.Verdict)
	}
}

func TestBadlistWarnInWarnMode(t *testing.T) {
	store := newMemStore()
	cfg := pipeline.DefaultConfig()
	cfg.Mode = "warn"
	pl := pipeline.New(store, cfg,
		&stubAnalyzer{name: "badlist", findings: []shield.Finding{criticalFinding()}},
		&stubAnalyzer{name: "cve"},
		noopHeuristic(),
		nil,
	)

	result, err := pl.Analyze(context.Background(), npmPkg("evil-pkg", "1.0.0"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Verdict != shield.VerdictWarn {
		t.Errorf("critical finding in warn mode: want warn, got %s", result.Verdict)
	}
}

func TestAuditModeNeverBlocks(t *testing.T) {
	store := newMemStore()
	cfg := pipeline.DefaultConfig()
	cfg.Mode = "audit"
	pl := pipeline.New(store, cfg,
		&stubAnalyzer{name: "badlist", findings: []shield.Finding{criticalFinding()}},
		&stubAnalyzer{name: "cve"},
		noopHeuristic(),
		nil,
	)

	result, err := pl.Analyze(context.Background(), npmPkg("evil-pkg", "1.0.0"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Verdict == shield.VerdictBlock {
		t.Error("audit mode must never block")
	}
}

func TestHighSeverityCVEBlocks(t *testing.T) {
	store := newMemStore()
	pl := pipeline.New(store, pipeline.DefaultConfig(),
		&stubAnalyzer{name: "badlist"},
		&stubAnalyzer{name: "cve", findings: []shield.Finding{cveFinding(shield.SeverityHigh, 9.0)}},
		noopHeuristic(),
		nil,
	)

	result, err := pl.Analyze(context.Background(), npmPkg("vuln-pkg", "1.0.0"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Verdict != shield.VerdictBlock {
		t.Errorf("high-severity CVE in enforce mode: want block, got %s", result.Verdict)
	}
}

func TestMediumSeverityCVEWarn(t *testing.T) {
	store := newMemStore()
	pl := pipeline.New(store, pipeline.DefaultConfig(),
		&stubAnalyzer{name: "badlist"},
		&stubAnalyzer{name: "cve", findings: []shield.Finding{cveFinding(shield.SeverityMedium, 4.0)}},
		noopHeuristic(),
		nil,
	)

	result, err := pl.Analyze(context.Background(), npmPkg("vuln-pkg", "1.0.0"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Verdict != shield.VerdictWarn {
		t.Errorf("medium-severity CVE: want warn, got %s", result.Verdict)
	}
}

// BlockCVSSThreshold gates whether Claude runs, not the verdict itself.
// CVSS >= threshold triggers Claude; below does not.
func TestCVSSThresholdGatesClaude(t *testing.T) {
	store := newMemStore()
	cl := &stubAnalyzer{name: "claude"}
	pl := pipeline.New(store, pipeline.DefaultConfig(), // threshold = 7.0
		&stubAnalyzer{name: "badlist"},
		&stubAnalyzer{name: "cve", findings: []shield.Finding{cveFinding(shield.SeverityHigh, 9.0)}},
		noopHeuristic(),
		cl,
	)

	_, err := pl.Analyze(context.Background(), npmPkg("vuln-pkg", "1.0.0"), []byte("tarball"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if atomic.LoadInt32(&cl.called) == 0 {
		t.Error("CVSS 9.0 >= threshold 7.0: Claude should have been triggered")
	}
}

func TestMediumSeverityWarn(t *testing.T) {
	store := newMemStore()
	pl := pipeline.New(store, pipeline.DefaultConfig(),
		&stubAnalyzer{name: "badlist", findings: []shield.Finding{mediumFinding()}},
		&stubAnalyzer{name: "cve"},
		noopHeuristic(),
		nil,
	)

	result, err := pl.Analyze(context.Background(), npmPkg("sus-pkg", "1.0.0"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Verdict != shield.VerdictWarn {
		t.Errorf("medium finding: want warn, got %s", result.Verdict)
	}
}

func TestHeuristicAboveThresholdTriggersClause(t *testing.T) {
	store := newMemStore()
	cl := &stubAnalyzer{name: "claude"}
	h := &stubHeuristic{score: 50} // default trigger = 30

	pl := pipeline.New(store, pipeline.DefaultConfig(),
		&stubAnalyzer{name: "badlist"},
		&stubAnalyzer{name: "cve"},
		h, cl,
	)
	_, err := pl.Analyze(context.Background(), npmPkg("sus-pkg", "1.0.0"), []byte("tarball"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if atomic.LoadInt32(&cl.called) == 0 {
		t.Error("heuristic score 50 >= trigger 30: Claude should have been called")
	}
}

func TestHeuristicBelowThresholdSkipsClaude(t *testing.T) {
	store := newMemStore()
	cl := &stubAnalyzer{name: "claude"}
	h := &stubHeuristic{score: 10} // below default trigger of 30

	pl := pipeline.New(store, pipeline.DefaultConfig(),
		&stubAnalyzer{name: "badlist"},
		&stubAnalyzer{name: "cve"},
		h, cl,
	)
	_, err := pl.Analyze(context.Background(), npmPkg("clean-pkg", "1.0.0"), []byte("tarball"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if atomic.LoadInt32(&cl.called) != 0 {
		t.Error("heuristic score 10 < trigger 30: Claude must not be called")
	}
}

func TestNilTarballSkipsHeuristicAndClaude(t *testing.T) {
	store := newMemStore()
	// badlist returns critical so claudeNeeded=true — but no tarball, so Claude still must not run
	bad := &stubAnalyzer{name: "badlist", findings: []shield.Finding{criticalFinding()}}
	cl := &stubAnalyzer{name: "claude"}
	h := &stubHeuristic{score: 100}

	pl := pipeline.New(store, pipeline.DefaultConfig(), bad, &stubAnalyzer{name: "cve"}, h, cl)
	_, err := pl.Analyze(context.Background(), npmPkg("lockfile-pkg", "1.0.0"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if atomic.LoadInt32(&h.called) != 0 {
		t.Error("heuristic Analyze must not run without a tarball")
	}
	if atomic.LoadInt32(&cl.called) != 0 {
		t.Error("Claude must not run without a tarball even when claudeNeeded=true")
	}
}

func TestNilClaudeDoesNotPanic(t *testing.T) {
	store := newMemStore()
	// High heuristic score + critical finding → claudeNeeded=true, but claude is nil
	h := &stubHeuristic{score: 80}
	bad := &stubAnalyzer{name: "badlist", findings: []shield.Finding{criticalFinding()}}

	pl := pipeline.New(store, pipeline.DefaultConfig(), bad, &stubAnalyzer{name: "cve"}, h, nil)
	result, err := pl.Analyze(context.Background(), npmPkg("evil-pkg", "1.0.0"), []byte("tarball"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ClaudeUsed {
		t.Error("ClaudeUsed must be false when claude analyzer is nil")
	}
}

func TestResultPersistedToStore(t *testing.T) {
	store := newMemStore()
	pl := pipeline.New(store, pipeline.DefaultConfig(),
		&stubAnalyzer{name: "badlist"},
		&stubAnalyzer{name: "cve"},
		noopHeuristic(),
		nil,
	)

	p := npmPkg("new-pkg", "2.0.0")
	_, err := pl.Analyze(context.Background(), p, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if store.saveCount == 0 {
		t.Error("result must be saved to store after scan")
	}
	if _, ok := store.cache[storeKey(p.Ecosystem, p.Name, p.Version)]; !ok {
		t.Error("result must be in cache after scan")
	}
}

func TestSecondCallHitsCache(t *testing.T) {
	store := newMemStore()
	bad := &stubAnalyzer{name: "badlist"}
	pl := pipeline.New(store, pipeline.DefaultConfig(), bad, &stubAnalyzer{name: "cve"}, noopHeuristic(), nil)

	p := npmPkg("repeat-pkg", "1.0.0")

	_, err := pl.Analyze(context.Background(), p, nil)
	if err != nil {
		t.Fatalf("first scan error: %v", err)
	}
	firstCallCount := atomic.LoadInt32(&bad.called)

	result2, err := pl.Analyze(context.Background(), p, nil)
	if err != nil {
		t.Fatalf("second scan error: %v", err)
	}
	if result2.CachedAt == nil {
		t.Error("second call: CachedAt must be set")
	}
	if atomic.LoadInt32(&bad.called) != firstCallCount {
		t.Error("second call: analyzers must not run (cache hit)")
	}
}

func TestAnalyzerErrorNonFatal(t *testing.T) {
	store := newMemStore()
	pl := pipeline.New(store, pipeline.DefaultConfig(),
		&stubAnalyzer{name: "badlist", err: errors.New("transient error")},
		&stubAnalyzer{name: "cve"},
		noopHeuristic(),
		nil,
	)

	result, err := pl.Analyze(context.Background(), npmPkg("some-pkg", "1.0.0"), nil)
	if err != nil {
		t.Fatalf("pipeline must not surface analyzer errors: %v", err)
	}
	if result == nil {
		t.Error("result must be non-nil even when an analyzer errors")
	}
}

func TestCustomCVSSThresholdSkipsClaude(t *testing.T) {
	store := newMemStore()
	cfg := pipeline.DefaultConfig()
	cfg.BlockCVSSThreshold = 9.0 // raise so CVSS 8.0 does NOT trigger Claude

	cl := &stubAnalyzer{name: "claude"}
	pl := pipeline.New(store, cfg,
		&stubAnalyzer{name: "badlist"},
		&stubAnalyzer{name: "cve", findings: []shield.Finding{cveFinding(shield.SeverityHigh, 8.0)}},
		noopHeuristic(),
		cl,
	)

	_, err := pl.Analyze(context.Background(), npmPkg("vuln-pkg", "1.0.0"), []byte("tarball"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if atomic.LoadInt32(&cl.called) != 0 {
		t.Error("CVSS 8.0 < raised threshold 9.0: Claude must not be triggered")
	}
}

func TestCustomClaudeTriggerScore(t *testing.T) {
	store := newMemStore()
	cfg := pipeline.DefaultConfig()
	cfg.ClaudeTriggerScore = 80 // raise trigger so score=50 does NOT invoke Claude

	cl := &stubAnalyzer{name: "claude"}
	h := &stubHeuristic{score: 50}

	pl := pipeline.New(store, cfg, &stubAnalyzer{name: "badlist"}, &stubAnalyzer{name: "cve"}, h, cl)
	_, err := pl.Analyze(context.Background(), npmPkg("some-pkg", "1.0.0"), []byte("tarball"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if atomic.LoadInt32(&cl.called) != 0 {
		t.Error("heuristic score 50 < custom trigger 80: Claude must not be called")
	}
}
