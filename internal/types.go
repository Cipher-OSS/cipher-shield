package shield

import "time"

type Ecosystem string

const (
	EcosystemNPM  Ecosystem = "npm"
	EcosystemPyPI Ecosystem = "pypi"
)

type Verdict string

const (
	VerdictAllow Verdict = "allow"
	VerdictWarn  Verdict = "warn"
	VerdictBlock Verdict = "block"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type PackageRef struct {
	Ecosystem Ecosystem `json:"ecosystem"`
	Name      string    `json:"name"`
	Version   string    `json:"version"`
}

type Finding struct {
	Type        string   `json:"type"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	References  []string `json:"references,omitempty"`
	CVE         string   `json:"cve,omitempty"`
	CVSS        float64  `json:"cvss,omitempty"`
}

type ScanResult struct {
	ScanID      string     `json:"scan_id"`
	Package     PackageRef `json:"package"`
	Verdict     Verdict    `json:"verdict"`
	Findings    []Finding  `json:"findings"`
	ClaudeUsed  bool       `json:"claude_used"`
	ClaudeScore int        `json:"claude_score,omitempty"`
	ScannedAt   time.Time  `json:"scanned_at"`
	CachedAt    *time.Time `json:"cached_at,omitempty"`
	DurationMs  int64      `json:"duration_ms"`
}

type Exception struct {
	ExceptionID string     `json:"exception_id"`
	Ecosystem   Ecosystem  `json:"ecosystem"`
	Name        string     `json:"name"`
	Version     string     `json:"version"` // "" = wildcard
	Reason      string     `json:"reason"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}
