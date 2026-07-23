package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	shield "github.com/cipher-oss/cipher-shield/internal"
)

type dbKind uint8

const (
	dbSQLite   dbKind = iota
	dbPostgres
)

type sqlStore struct {
	db   *sql.DB
	kind dbKind
}

// ph returns the SQL placeholder for the nth parameter (1-indexed).
// SQLite uses ? for every position; Postgres uses $N.
func (s *sqlStore) ph(n int) string {
	if s.kind == dbSQLite {
		return "?"
	}
	return fmt.Sprintf("$%d", n)
}

// phs returns a comma-separated list of placeholders from `from` to `to` (1-indexed, inclusive).
func (s *sqlStore) phs(from, to int) string {
	parts := make([]string, to-from+1)
	for i := range parts {
		parts[i] = s.ph(from + i)
	}
	return strings.Join(parts, ", ")
}

// now returns the SQL expression for the current UTC timestamp.
func (s *sqlStore) now() string {
	if s.kind == dbSQLite {
		return "datetime('now')"
	}
	return "NOW()"
}

func openSQLite(path string) (*sqlStore, error) {
	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_busy_timeout=5000", path)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite3: %w", err)
	}
	// SQLite supports only one writer at a time even in WAL mode.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping sqlite3: %w", err)
	}
	s := &sqlStore{db: db, kind: dbSQLite}
	if err := s.Migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func openPostgres(dsn string) (*sqlStore, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	s := &sqlStore{db: db, kind: dbPostgres}
	if err := s.Migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

// migrations holds dialect-specific schema DDL indexed by dbKind.
// Each slice entry is applied exactly once in order.
var migrations = [2][]string{
	// dbSQLite
	{
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
		`CREATE TABLE IF NOT EXISTS dismissals (
    scan_id      TEXT PRIMARY KEY,
    dismissed_by TEXT NOT NULL,
    note         TEXT NOT NULL DEFAULT '',
    dismissed_at DATETIME NOT NULL
);`,
		`CREATE TABLE IF NOT EXISTS download_events (
    event_id      TEXT PRIMARY KEY,
    ecosystem     TEXT NOT NULL,
    name          TEXT NOT NULL,
    version       TEXT NOT NULL,
    machine_id    TEXT NOT NULL DEFAULT '',
    verdict       TEXT NOT NULL,
    scan_id       TEXT NOT NULL DEFAULT '',
    downloaded_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS download_events_downloaded_at ON download_events(downloaded_at DESC);`,
	},
	// dbPostgres
	{
		`CREATE TABLE IF NOT EXISTS scan_cache (
    id          TEXT PRIMARY KEY,
    ecosystem   TEXT NOT NULL,
    name        TEXT NOT NULL,
    version     TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    result_json TEXT NOT NULL,
    scanned_at  TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS exceptions (
    exception_id TEXT PRIMARY KEY,
    ecosystem    TEXT NOT NULL,
    name         TEXT NOT NULL,
    version      TEXT NOT NULL DEFAULT '',
    reason       TEXT NOT NULL,
    created_by   TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL,
    expires_at   TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS scan_history (
    scan_id     TEXT PRIMARY KEY,
    ecosystem   TEXT NOT NULL,
    name        TEXT NOT NULL,
    version     TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    result_json TEXT NOT NULL,
    scanned_at  TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    user_id       TEXT PRIMARY KEY,
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'analyst',
    created_at    TIMESTAMPTZ NOT NULL
);`,
		`CREATE TABLE IF NOT EXISTS dismissals (
    scan_id      TEXT PRIMARY KEY,
    dismissed_by TEXT NOT NULL,
    note         TEXT NOT NULL DEFAULT '',
    dismissed_at TIMESTAMPTZ NOT NULL
);`,
		`CREATE TABLE IF NOT EXISTS download_events (
    event_id      TEXT PRIMARY KEY,
    ecosystem     TEXT NOT NULL,
    name          TEXT NOT NULL,
    version       TEXT NOT NULL,
    machine_id    TEXT NOT NULL DEFAULT '',
    verdict       TEXT NOT NULL,
    scan_id       TEXT NOT NULL DEFAULT '',
    downloaded_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS download_events_downloaded_at ON download_events(downloaded_at DESC);`,
	},
}

func (s *sqlStore) Migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("migrate: create schema_version: %w", err)
	}
	var current int
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&current); err != nil {
		return fmt.Errorf("migrate: read version: %w", err)
	}
	stmts := migrations[s.kind]
	for i := current; i < len(stmts); i++ {
		tx, err := s.db.Begin()
		if err != nil {
			return fmt.Errorf("migrate v%d: begin: %w", i+1, err)
		}
		if _, err := tx.Exec(stmts[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migrate v%d: %w", i+1, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_version (version) VALUES (`+s.ph(1)+`)`, i+1); err != nil {
			tx.Rollback()
			return fmt.Errorf("migrate v%d: record version: %w", i+1, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("migrate v%d: commit: %w", i+1, err)
		}
	}
	return nil
}

func (s *sqlStore) Close() error { return s.db.Close() }

// ── Users ──────────────────────────────────────────────────────────────────────

func (s *sqlStore) CreateUser(ctx context.Context, email, passwordHash, role string) (*shield.User, error) {
	id := newUserID()
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users (user_id, email, password_hash, role, created_at) VALUES (`+s.phs(1, 5)+`)`,
		id, email, passwordHash, role, now,
	)
	if err != nil {
		return nil, fmt.Errorf("CreateUser: %w", err)
	}
	return &shield.User{UserID: id, Email: email, PasswordHash: passwordHash, Role: role, CreatedAt: now}, nil
}

func (s *sqlStore) GetUserByEmail(ctx context.Context, email string) (*shield.User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT user_id, email, password_hash, role, created_at FROM users WHERE email = `+s.ph(1),
		email,
	)
	return scanUserRow(row)
}

func (s *sqlStore) GetUserByID(ctx context.Context, userID string) (*shield.User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT user_id, email, password_hash, role, created_at FROM users WHERE user_id = `+s.ph(1),
		userID,
	)
	return scanUserRow(row)
}

func (s *sqlStore) UpdatePassword(ctx context.Context, userID, passwordHash string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET password_hash = `+s.ph(1)+` WHERE user_id = `+s.ph(2),
		passwordHash, userID,
	)
	return err
}

func (s *sqlStore) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (s *sqlStore) ListUsers(ctx context.Context) ([]shield.User, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT user_id, email, password_hash, role, created_at FROM users ORDER BY created_at ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("ListUsers query: %w", err)
	}
	defer rows.Close()
	return scanUserRows(rows)
}

// ── Scan cache ─────────────────────────────────────────────────────────────────

const (
	cacheTTLAllow = 4 * time.Hour
	cacheTTLFlag  = time.Hour
)

func (s *sqlStore) GetCachedResult(ctx context.Context, eco shield.Ecosystem, name, version string) (*shield.ScanResult, error) {
	id := cacheKey(eco, name, version)
	row := s.db.QueryRowContext(ctx,
		`SELECT result_json, scanned_at FROM scan_cache WHERE id = `+s.ph(1)+` AND expires_at > `+s.now(),
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

func (s *sqlStore) SaveResult(ctx context.Context, r shield.ScanResult) error {
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

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("SaveResult begin tx: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, `
INSERT INTO scan_cache (id, ecosystem, name, version, verdict, result_json, scanned_at, expires_at)
VALUES (`+s.phs(1, 8)+`)
ON CONFLICT(id) DO UPDATE SET
    verdict     = EXCLUDED.verdict,
    result_json = EXCLUDED.result_json,
    scanned_at  = EXCLUDED.scanned_at,
    expires_at  = EXCLUDED.expires_at`,
		id, string(r.Package.Ecosystem), r.Package.Name, r.Package.Version,
		string(r.Verdict), string(raw), r.ScannedAt, expiresAt,
	)
	if err != nil {
		return fmt.Errorf("SaveResult upsert cache: %w", err)
	}

	// SQLite uses INSERT OR IGNORE; Postgres uses ON CONFLICT ... DO NOTHING.
	var histSQL string
	if s.kind == dbSQLite {
		histSQL = `INSERT OR IGNORE INTO scan_history (scan_id, ecosystem, name, version, verdict, result_json, scanned_at) VALUES (` + s.phs(1, 7) + `)`
	} else {
		histSQL = `INSERT INTO scan_history (scan_id, ecosystem, name, version, verdict, result_json, scanned_at) VALUES (` + s.phs(1, 7) + `) ON CONFLICT(scan_id) DO NOTHING`
	}
	_, err = tx.ExecContext(ctx, histSQL,
		r.ScanID, string(r.Package.Ecosystem), r.Package.Name, r.Package.Version,
		string(r.Verdict), string(raw), r.ScannedAt,
	)
	if err != nil {
		return fmt.Errorf("SaveResult insert history: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
DELETE FROM scan_history WHERE scan_id NOT IN (
    SELECT scan_id FROM scan_history ORDER BY scanned_at DESC LIMIT 1000
)`)
	if err != nil {
		return fmt.Errorf("SaveResult prune history: %w", err)
	}

	return tx.Commit()
}

// ── Exceptions ─────────────────────────────────────────────────────────────────

func (s *sqlStore) GetException(ctx context.Context, eco shield.Ecosystem, name, version string) (*shield.Exception, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT exception_id, ecosystem, name, version, reason, created_by, created_at, expires_at
FROM exceptions
WHERE ecosystem = `+s.ph(1)+`
  AND name = `+s.ph(2)+`
  AND (version = `+s.ph(3)+` OR version = '')
  AND (expires_at IS NULL OR expires_at > `+s.now()+`)
ORDER BY
    CASE WHEN version = `+s.ph(4)+` THEN 0 ELSE 1 END,
    created_at DESC
LIMIT 1`,
		string(eco), name, version, version,
	)
	return scanException(row)
}

func (s *sqlStore) ListExceptions(ctx context.Context) ([]shield.Exception, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT exception_id, ecosystem, name, version, reason, created_by, created_at, expires_at
FROM exceptions
ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("ListExceptions query: %w", err)
	}
	defer rows.Close()

	var out []shield.Exception
	for rows.Next() {
		var e shield.Exception
		var eco string
		var expiresAt sql.NullTime
		if err := rows.Scan(&e.ExceptionID, &eco, &e.Name, &e.Version, &e.Reason, &e.CreatedBy, &e.CreatedAt, &expiresAt); err != nil {
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

func (s *sqlStore) AddException(ctx context.Context, e shield.Exception) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO exceptions (exception_id, ecosystem, name, version, reason, created_by, created_at, expires_at)
VALUES (`+s.phs(1, 8)+`)`,
		e.ExceptionID, string(e.Ecosystem), e.Name, e.Version,
		e.Reason, e.CreatedBy, e.CreatedAt, nullTime(e.ExpiresAt),
	)
	if err != nil {
		return fmt.Errorf("AddException: %w", err)
	}
	return nil
}

func (s *sqlStore) DeleteException(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM exceptions WHERE exception_id = `+s.ph(1), id)
	if err != nil {
		return fmt.Errorf("DeleteException: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("exception not found: %s", id)
	}
	return nil
}

// ── Scan history ───────────────────────────────────────────────────────────────

func (s *sqlStore) ListHistory(ctx context.Context, limit int) ([]shield.ScanResult, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT result_json FROM scan_history ORDER BY scanned_at DESC LIMIT `+s.ph(1),
		limit,
	)
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

func (s *sqlStore) PruneHistory(ctx context.Context, retentionDays int) (int64, error) {
	var res sql.Result
	var err error
	// The interval expression differs between dialects.
	if s.kind == dbSQLite {
		res, err = s.db.ExecContext(ctx,
			`DELETE FROM scan_history WHERE scanned_at < datetime('now', `+s.ph(1)+` || ' days')`,
			fmt.Sprintf("-%d", retentionDays),
		)
	} else {
		res, err = s.db.ExecContext(ctx,
			`DELETE FROM scan_history WHERE scanned_at < NOW() - (`+s.ph(1)+` || ' days')::interval`,
			retentionDays,
		)
	}
	if err != nil {
		return 0, fmt.Errorf("PruneHistory: %w", err)
	}
	return res.RowsAffected()
}

// ── Violations + triage ────────────────────────────────────────────────────────

func (s *sqlStore) DismissResult(ctx context.Context, scanID, dismissedBy, note string) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO dismissals (scan_id, dismissed_by, note, dismissed_at)
VALUES (`+s.phs(1, 4)+`)
ON CONFLICT(scan_id) DO UPDATE SET
    dismissed_by = EXCLUDED.dismissed_by,
    note         = EXCLUDED.note,
    dismissed_at = EXCLUDED.dismissed_at`,
		scanID, dismissedBy, note, time.Now().UTC(),
	)
	return err
}

func (s *sqlStore) ListViolations(ctx context.Context, limit int) ([]shield.ViolationRow, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT h.result_json,
       d.scan_id      AS dis_scan_id,
       d.dismissed_by,
       d.note,
       d.dismissed_at
FROM scan_history h
LEFT JOIN dismissals d ON d.scan_id = h.scan_id
WHERE h.verdict IN ('block', 'warn')
ORDER BY h.scanned_at DESC
LIMIT `+s.ph(1), limit)
	if err != nil {
		return nil, fmt.Errorf("ListViolations query: %w", err)
	}
	defer rows.Close()

	var out []shield.ViolationRow
	for rows.Next() {
		var rawJSON string
		var disScanID, dismissedBy, note sql.NullString
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

// ── Download events ────────────────────────────────────────────────────────────

func (s *sqlStore) SaveDownload(ctx context.Context, e shield.DownloadEvent) error {
	var q string
	if s.kind == dbSQLite {
		q = `INSERT OR IGNORE INTO download_events (event_id, ecosystem, name, version, machine_id, verdict, scan_id, downloaded_at) VALUES (` + s.phs(1, 8) + `)`
	} else {
		q = `INSERT INTO download_events (event_id, ecosystem, name, version, machine_id, verdict, scan_id, downloaded_at) VALUES (` + s.phs(1, 8) + `) ON CONFLICT(event_id) DO NOTHING`
	}
	_, err := s.db.ExecContext(ctx, q,
		e.EventID, string(e.Package.Ecosystem), e.Package.Name, e.Package.Version,
		e.MachineID, string(e.Verdict), e.ScanID, e.DownloadedAt,
	)
	return err
}

func (s *sqlStore) ListDownloads(ctx context.Context, limit int) ([]shield.DownloadEvent, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT event_id, ecosystem, name, version, machine_id, verdict, scan_id, downloaded_at
		 FROM download_events ORDER BY downloaded_at DESC LIMIT `+s.ph(1),
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("ListDownloads query: %w", err)
	}
	defer rows.Close()

	var out []shield.DownloadEvent
	for rows.Next() {
		var e shield.DownloadEvent
		var eco string
		if err := rows.Scan(&e.EventID, &eco, &e.Package.Name, &e.Package.Version,
			&e.MachineID, &e.Verdict, &e.ScanID, &e.DownloadedAt); err != nil {
			return nil, fmt.Errorf("ListDownloads scan row: %w", err)
		}
		e.Package.Ecosystem = shield.Ecosystem(eco)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ── Helpers ────────────────────────────────────────────────────────────────────

func cacheKey(eco shield.Ecosystem, name, version string) string {
	return fmt.Sprintf("%s:%s:%s", eco, name, version)
}

func scanException(row *sql.Row) (*shield.Exception, error) {
	var e shield.Exception
	var eco string
	var expiresAt sql.NullTime
	err := row.Scan(&e.ExceptionID, &eco, &e.Name, &e.Version, &e.Reason, &e.CreatedBy, &e.CreatedAt, &expiresAt)
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

func nullTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}
