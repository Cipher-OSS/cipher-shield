package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
	shield "github.com/cipher-oss/cipher-shield/internal"
)

type sqliteStore struct {
	db *sql.DB
}

func openSQLite(path string) (*sqliteStore, error) {
	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_busy_timeout=5000", path)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite3: %w", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping sqlite3: %w", err)
	}
	s := &sqliteStore{db: db}
	if err := s.Migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

// sqliteMigrations lists sequential schema migrations. Each entry is applied
// exactly once; the version number is stored in the schema_version table.
var sqliteMigrations = []string{
	// v1: initial schema
	`CREATE TABLE IF NOT EXISTS scan_cache (
    id          TEXT PRIMARY KEY,
    ecosystem   TEXT NOT NULL,
    name        TEXT NOT NULL,
    version     TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    result_json TEXT NOT NULL,
    scanned_at  DATETIME NOT NULL,
    expires_at  DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS exceptions (
    exception_id TEXT PRIMARY KEY,
    ecosystem    TEXT NOT NULL,
    name         TEXT NOT NULL,
    version      TEXT NOT NULL DEFAULT '',
    reason       TEXT NOT NULL,
    created_by   TEXT NOT NULL DEFAULT '',
    created_at   DATETIME NOT NULL,
    expires_at   DATETIME
);
CREATE TABLE IF NOT EXISTS scan_history (
    scan_id     TEXT PRIMARY KEY,
    ecosystem   TEXT NOT NULL,
    name        TEXT NOT NULL,
    version     TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    result_json TEXT NOT NULL,
    scanned_at  DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    user_id       TEXT PRIMARY KEY,
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'analyst',
    created_at    DATETIME NOT NULL
);`,

	// v2: dismissals table for triage attribution
	`CREATE TABLE IF NOT EXISTS dismissals (
    scan_id      TEXT PRIMARY KEY,
    dismissed_by TEXT NOT NULL,
    note         TEXT NOT NULL DEFAULT '',
    dismissed_at DATETIME NOT NULL
);`,
}

func (s *sqliteStore) Migrate() error {
	// Ensure schema_version table exists before anything else.
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("migrate: create schema_version: %w", err)
	}

	var current int
	row := s.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_version`)
	if err := row.Scan(&current); err != nil {
		return fmt.Errorf("migrate: read version: %w", err)
	}

	for i := current; i < len(sqliteMigrations); i++ {
		tx, err := s.db.Begin()
		if err != nil {
			return fmt.Errorf("migrate v%d: begin: %w", i+1, err)
		}
		if _, err := tx.Exec(sqliteMigrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migrate v%d: %w", i+1, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_version (version) VALUES (?)`, i+1); err != nil {
			tx.Rollback()
			return fmt.Errorf("migrate v%d: record version: %w", i+1, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("migrate v%d: commit: %w", i+1, err)
		}
	}
	return nil
}

func (s *sqliteStore) CreateUser(email, passwordHash, role string) (*shield.User, error) {
	id := newUserID()
	now := time.Now().UTC()
	_, err := s.db.Exec(
		`INSERT INTO users (user_id, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)`,
		id, email, passwordHash, role, now,
	)
	if err != nil {
		return nil, fmt.Errorf("CreateUser: %w", err)
	}
	return &shield.User{UserID: id, Email: email, PasswordHash: passwordHash, Role: role, CreatedAt: now}, nil
}

func (s *sqliteStore) GetUserByEmail(email string) (*shield.User, error) {
	row := s.db.QueryRow(
		`SELECT user_id, email, password_hash, role, created_at FROM users WHERE email = ?`, email,
	)
	return scanUserRow(row)
}

func (s *sqliteStore) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (s *sqliteStore) GetUserByID(userID string) (*shield.User, error) {
	row := s.db.QueryRow(
		`SELECT user_id, email, password_hash, role, created_at FROM users WHERE user_id = ?`, userID,
	)
	return scanUserRow(row)
}

func (s *sqliteStore) UpdatePassword(userID, passwordHash string) error {
	_, err := s.db.Exec(`UPDATE users SET password_hash = ? WHERE user_id = ?`, passwordHash, userID)
	return err
}

func (s *sqliteStore) ListUsers() ([]shield.User, error) {
	rows, err := s.db.Query(
		`SELECT user_id, email, password_hash, role, created_at FROM users ORDER BY created_at ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("ListUsers query: %w", err)
	}
	defer rows.Close()
	return scanUserRows(rows)
}

func (s *sqliteStore) DismissResult(scanID, dismissedBy, note string) error {
	_, err := s.db.Exec(`
INSERT INTO dismissals (scan_id, dismissed_by, note, dismissed_at)
VALUES (?, ?, ?, ?)
ON CONFLICT(scan_id) DO UPDATE SET
    dismissed_by = excluded.dismissed_by,
    note         = excluded.note,
    dismissed_at = excluded.dismissed_at
`, scanID, dismissedBy, note, time.Now().UTC())
	return err
}

func (s *sqliteStore) ListViolations(limit int) ([]shield.ViolationRow, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.Query(`
SELECT h.result_json,
       d.scan_id      AS dis_scan_id,
       d.dismissed_by,
       d.note,
       d.dismissed_at
FROM scan_history h
LEFT JOIN dismissals d ON d.scan_id = h.scan_id
WHERE h.verdict IN ('block', 'warn')
ORDER BY h.scanned_at DESC
LIMIT ?
`, limit)
	if err != nil {
		return nil, fmt.Errorf("ListViolations query: %w", err)
	}
	defer rows.Close()

	var out []shield.ViolationRow
	for rows.Next() {
		var rawJSON string
		var disScanID sql.NullString
		var dismissedBy, note sql.NullString
		var dismissedAt sql.NullTime
		if err := rows.Scan(&rawJSON, &disScanID, &dismissedBy, &note, &dismissedAt); err != nil {
			return nil, fmt.Errorf("ListViolations scan: %w", err)
		}
		var sr shield.ScanResult
		if err := json.Unmarshal([]byte(rawJSON), &sr); err != nil {
			return nil, fmt.Errorf("ListViolations unmarshal: %w", err)
		}
		vr := shield.ViolationRow{ScanResult: sr}
		if disScanID.Valid {
			vr.Dismissed = true
			vr.Dismissal = &shield.Dismissal{
				ScanID:      disScanID.String,
				DismissedBy: dismissedBy.String,
				Note:        note.String,
				DismissedAt: dismissedAt.Time,
			}
		}
		out = append(out, vr)
	}
	return out, rows.Err()
}

func (s *sqliteStore) Close() error {
	return s.db.Close()
}

func cacheKey(eco shield.Ecosystem, name, version string) string {
	return fmt.Sprintf("%s:%s:%s", eco, name, version)
}

// GetCachedResult looks up a scan result by ecosystem/name/version.
// Returns nil, nil if not found or expired.
func (s *sqliteStore) GetCachedResult(eco shield.Ecosystem, name, version string) (*shield.ScanResult, error) {
	id := cacheKey(eco, name, version)
	row := s.db.QueryRow(
		`SELECT result_json, scanned_at FROM scan_cache WHERE id = ? AND expires_at > datetime('now')`,
		id,
	)
	var rawJSON string
	var scannedAt time.Time
	if err := row.Scan(&rawJSON, &scannedAt); err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("GetCachedResult scan: %w", err)
	}

	var r shield.ScanResult
	if err := json.Unmarshal([]byte(rawJSON), &r); err != nil {
		return nil, fmt.Errorf("GetCachedResult unmarshal: %w", err)
	}
	now := time.Now()
	r.CachedAt = &now
	return &r, nil
}

// Cache TTLs. Allow is short enough that a newly-published CVE becomes visible
// on the next install within a few hours; warn/block refresh more aggressively.
const (
	cacheTTLAllow = 4 * time.Hour
	cacheTTLFlag  = time.Hour
)

// SaveResult upserts into scan_cache (TTL: 4h allow, 1h warn/block)
// and appends to scan_history, pruning to last 1000 rows.
func (s *sqliteStore) SaveResult(r shield.ScanResult) error {
	id := cacheKey(r.Package.Ecosystem, r.Package.Name, r.Package.Version)

	ttl := cacheTTLAllow
	if r.Verdict == shield.VerdictWarn || r.Verdict == shield.VerdictBlock {
		ttl = cacheTTLFlag
	}
	expiresAt := r.ScannedAt.Add(ttl)

	raw, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("SaveResult marshal: %w", err)
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("SaveResult begin tx: %w", err)
	}
	defer tx.Rollback()

	// Upsert cache
	_, err = tx.Exec(`
INSERT INTO scan_cache (id, ecosystem, name, version, verdict, result_json, scanned_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
    verdict     = excluded.verdict,
    result_json = excluded.result_json,
    scanned_at  = excluded.scanned_at,
    expires_at  = excluded.expires_at
`,
		id,
		string(r.Package.Ecosystem),
		r.Package.Name,
		r.Package.Version,
		string(r.Verdict),
		string(raw),
		r.ScannedAt,
		expiresAt,
	)
	if err != nil {
		return fmt.Errorf("SaveResult upsert cache: %w", err)
	}

	// Insert history (ignore duplicates by scan_id)
	_, err = tx.Exec(`
INSERT OR IGNORE INTO scan_history (scan_id, ecosystem, name, version, verdict, result_json, scanned_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
`,
		r.ScanID,
		string(r.Package.Ecosystem),
		r.Package.Name,
		r.Package.Version,
		string(r.Verdict),
		string(raw),
		r.ScannedAt,
	)
	if err != nil {
		return fmt.Errorf("SaveResult insert history: %w", err)
	}

	// Prune history to last 1000 rows
	_, err = tx.Exec(`
DELETE FROM scan_history WHERE scan_id NOT IN (
    SELECT scan_id FROM scan_history ORDER BY scanned_at DESC LIMIT 1000
)
`)
	if err != nil {
		return fmt.Errorf("SaveResult prune history: %w", err)
	}

	return tx.Commit()
}

// GetException checks for exact match (name+version) or wildcard (version='').
// Returns nil, nil if no active exception found.
func (s *sqliteStore) GetException(eco shield.Ecosystem, name, version string) (*shield.Exception, error) {
	// Exact match first, then wildcard; prefer non-expired or no expiry
	row := s.db.QueryRow(`
SELECT exception_id, ecosystem, name, version, reason, created_by, created_at, expires_at
FROM exceptions
WHERE ecosystem = ?
  AND name = ?
  AND (version = ? OR version = '')
  AND (expires_at IS NULL OR expires_at > datetime('now'))
ORDER BY
    CASE WHEN version = ? THEN 0 ELSE 1 END,
    created_at DESC
LIMIT 1
`, string(eco), name, version, version)

	return scanException(row)
}

func scanException(row *sql.Row) (*shield.Exception, error) {
	var e shield.Exception
	var eco string
	var expiresAt sql.NullTime
	err := row.Scan(
		&e.ExceptionID,
		&eco,
		&e.Name,
		&e.Version,
		&e.Reason,
		&e.CreatedBy,
		&e.CreatedAt,
		&expiresAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scanException: %w", err)
	}
	e.Ecosystem = shield.Ecosystem(eco)
	if expiresAt.Valid {
		t := expiresAt.Time
		e.ExpiresAt = &t
	}
	return &e, nil
}

func (s *sqliteStore) ListExceptions() ([]shield.Exception, error) {
	rows, err := s.db.Query(`
SELECT exception_id, ecosystem, name, version, reason, created_by, created_at, expires_at
FROM exceptions
ORDER BY created_at DESC
`)
	if err != nil {
		return nil, fmt.Errorf("ListExceptions query: %w", err)
	}
	defer rows.Close()

	var out []shield.Exception
	for rows.Next() {
		var e shield.Exception
		var eco string
		var expiresAt sql.NullTime
		if err := rows.Scan(
			&e.ExceptionID, &eco, &e.Name, &e.Version,
			&e.Reason, &e.CreatedBy, &e.CreatedAt, &expiresAt,
		); err != nil {
			return nil, fmt.Errorf("ListExceptions scan row: %w", err)
		}
		e.Ecosystem = shield.Ecosystem(eco)
		if expiresAt.Valid {
			t := expiresAt.Time
			e.ExpiresAt = &t
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *sqliteStore) AddException(e shield.Exception) error {
	_, err := s.db.Exec(`
INSERT INTO exceptions (exception_id, ecosystem, name, version, reason, created_by, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`,
		e.ExceptionID,
		string(e.Ecosystem),
		e.Name,
		e.Version,
		e.Reason,
		e.CreatedBy,
		e.CreatedAt,
		nullTime(e.ExpiresAt),
	)
	if err != nil {
		return fmt.Errorf("AddException: %w", err)
	}
	return nil
}

func (s *sqliteStore) DeleteException(id string) error {
	res, err := s.db.Exec(`DELETE FROM exceptions WHERE exception_id = ?`, id)
	if err != nil {
		return fmt.Errorf("DeleteException: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("exception not found: %s", id)
	}
	return nil
}

func (s *sqliteStore) ListHistory(limit int) ([]shield.ScanResult, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`
SELECT result_json FROM scan_history
ORDER BY scanned_at DESC
LIMIT ?
`, limit)
	if err != nil {
		return nil, fmt.Errorf("ListHistory query: %w", err)
	}
	defer rows.Close()

	var out []shield.ScanResult
	for rows.Next() {
		var rawJSON string
		if err := rows.Scan(&rawJSON); err != nil {
			return nil, fmt.Errorf("ListHistory scan row: %w", err)
		}
		var r shield.ScanResult
		if err := json.Unmarshal([]byte(rawJSON), &r); err != nil {
			return nil, fmt.Errorf("ListHistory unmarshal: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *sqliteStore) PruneHistory(retentionDays int) (int64, error) {
	res, err := s.db.Exec(
		`DELETE FROM scan_history WHERE scanned_at < datetime('now', ? || ' days')`,
		fmt.Sprintf("-%d", retentionDays),
	)
	if err != nil {
		return 0, fmt.Errorf("PruneHistory: %w", err)
	}
	return res.RowsAffected()
}

// nullTime converts *time.Time to sql.NullTime for nullable DB columns.
func nullTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}
