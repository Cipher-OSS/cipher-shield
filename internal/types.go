package shield

import "time"

type User struct {
	UserID       string    `json:"user_id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"` // "admin" | "analyst"
	CreatedAt    time.Time `json:"created_at"`
}

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

type Dismissal struct {
	ScanID      string    `json:"scan_id"`
	DismissedBy string    `json:"dismissed_by"`
	Note        string    `json:"note,omitempty"`
	DismissedAt time.Time `json:"dismissed_at"`
}

type ViolationRow struct {
	ScanResult
	Dismissed   bool       `json:"dismissed"`
	Dismissal   *Dismissal `json:"dismissal,omitempty"`
}

// DownloadEvent is recorded every time a package tarball passes through the proxy,
// regardless of whether a full scan ran (cached results still produce an event).
// MachineID is the hostname of the machine running the proxy agent.
type DownloadEvent struct {
	EventID     string    `json:"event_id"`
	Package     PackageRef `json:"package"`
	MachineID   string    `json:"machine_id"`
	Verdict     Verdict   `json:"verdict"`
	ScanID      string    `json:"scan_id"`
	DownloadedAt time.Time `json:"downloaded_at"`
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
