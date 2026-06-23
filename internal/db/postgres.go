package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/lib/pq"
	shield "github.com/cipher-oss/cipher-shield/internal"
)

type postgresStore struct {
	db *sql.DB
}

func openPostgres(dsn string) (*postgresStore, error) {
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
	s := &postgresStore{db: db}
	if err := s.Migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

var postgresMigrations = []string{
	// v1: initial schema
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

	// v2: dismissals table for triage attribution
	`CREATE TABLE IF NOT EXISTS dismissals (
    scan_id      TEXT PRIMARY KEY,
    dismissed_by TEXT NOT NULL,
    note         TEXT NOT NULL DEFAULT '',
    dismissed_at TIMESTAMPTZ NOT NULL
);`,
}

func (s *postgresStore) Migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("migrate: create schema_version: %w", err)
	}

	var current int
	row := s.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_version`)
	if err := row.Scan(&current); err != nil {
		return fmt.Errorf("migrate: read version: %w", err)
	}

	for i := current; i < len(postgresMigrations); i++ {
		tx, err := s.db.Begin()
		if err != nil {
			return fmt.Errorf("migrate v%d: begin: %w", i+1, err)
		}
		if _, err := tx.Exec(postgresMigrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migrate v%d: %w", i+1, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_version (version) VALUES ($1)`, i+1); err != nil {
			tx.Rollback()
			return fmt.Errorf("migrate v%d: record version: %w", i+1, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("migrate v%d: commit: %w", i+1, err)
		}
	}
	return nil
}

func (s *postgresStore) CreateUser(email, passwordHash, role string) (*shield.User, error) {
	id := newUserID()
	now := time.Now().UTC()
	_, err := s.db.Exec(
		`INSERT INTO users (user_id, email, password_hash, role, created_at) VALUES ($1, $2, $3, $4, $5)`,
		id, email, passwordHash, role, now,
	)
	if err != nil {
		return nil, fmt.Errorf("CreateUser: %w", err)
	}
	return &shield.User{UserID: id, Email: email, PasswordHash: passwordHash, Role: role, CreatedAt: now}, nil
}

func (s *postgresStore) GetUserByEmail(email string) (*shield.User, error) {
	row := s.db.QueryRow(
		`SELECT user_id, email, password_hash, role, created_at FROM users WHERE email = $1`, email,
	)
	return scanUserRow(row)
}

func (s *postgresStore) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (s *postgresStore) GetUserByID(userID string) (*shield.User, error) {
	row := s.db.QueryRow(
		`SELECT user_id, email, password_hash, role, created_at FROM users WHERE user_id = $1`, userID,
	)
	return scanUserRow(row)
}

func (s *postgresStore) UpdatePassword(userID, passwordHash string) error {
	_, err := s.db.Exec(`UPDATE users SET password_hash = $1 WHERE user_id = $2`, passwordHash, userID)
	return err
}

func (s *postgresStore) ListUsers() ([]shield.User, error) {
	rows, err := s.db.Query(
		`SELECT user_id, email, password_hash, role, created_at FROM users ORDER BY created_at ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("ListUsers query: %w", err)
	}
	defer rows.Close()
	return scanUserRows(rows)
}

func (s *postgresStore) Close() error { return s.db.Close() }

func (s *postgresStore) GetCachedResult(eco shield.Ecosystem, name, version string) (*shield.ScanResult, error) {
	id := cacheKey(eco, name, version)
	row := s.db.QueryRow(
		`SELECT result_json, scanned_at FROM scan_cache WHERE id = $1 AND expires_at > NOW()`,
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

func (s *postgresStore) SaveResult(r shield.ScanResult) error {
	id := cacheKey(r.Package.Ecosystem, r.Package.Name, r.Package.Version)

	ttl := 4 * time.Hour
	if r.Verdict == shield.VerdictWarn || r.Verdict == shield.VerdictBlock {
		ttl = time.Hour
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

	_, err = tx.Exec(`
INSERT INTO scan_cache (id, ecosystem, name, version, verdict, result_json, scanned_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (id) DO UPDATE SET
    verdict     = EXCLUDED.verdict,
    result_json = EXCLUDED.result_json,
    scanned_at  = EXCLUDED.scanned_at,
    expires_at  = EXCLUDED.expires_at
`,
		id, string(r.Package.Ecosystem), r.Package.Name, r.Package.Version,
		string(r.Verdict), string(raw), r.ScannedAt, expiresAt,
	)
	if err != nil {
		return fmt.Errorf("SaveResult upsert cache: %w", err)
	}

	_, err = tx.Exec(`
INSERT INTO scan_history (scan_id, ecosystem, name, version, verdict, result_json, scanned_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (scan_id) DO NOTHING
`,
		r.ScanID, string(r.Package.Ecosystem), r.Package.Name, r.Package.Version,
		string(r.Verdict), string(raw), r.ScannedAt,
	)
	if err != nil {
		return fmt.Errorf("SaveResult insert history: %w", err)
	}

	// Prune to last 1000 rows
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

func (s *postgresStore) GetException(eco shield.Ecosystem, name, version string) (*shield.Exception, error) {
	row := s.db.QueryRow(`
SELECT exception_id, ecosystem, name, version, reason, created_by, created_at, expires_at
FROM exceptions
WHERE ecosystem = $1
  AND name = $2
  AND (version = $3 OR version = '')
  AND (expires_at IS NULL OR expires_at > NOW())
ORDER BY
    CASE WHEN version = $4 THEN 0 ELSE 1 END,
    created_at DESC
LIMIT 1
`, string(eco), name, version, version)
	return scanException(row)
}

func (s *postgresStore) ListExceptions() ([]shield.Exception, error) {
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

func (s *postgresStore) AddException(e shield.Exception) error {
	_, err := s.db.Exec(`
INSERT INTO exceptions (exception_id, ecosystem, name, version, reason, created_by, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
`,
		e.ExceptionID, string(e.Ecosystem), e.Name, e.Version,
		e.Reason, e.CreatedBy, e.CreatedAt, nullTime(e.ExpiresAt),
	)
	if err != nil {
		return fmt.Errorf("AddException: %w", err)
	}
	return nil
}

func (s *postgresStore) DeleteException(id string) error {
	res, err := s.db.Exec(`DELETE FROM exceptions WHERE exception_id = $1`, id)
	if err != nil {
		return fmt.Errorf("DeleteException: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("exception not found: %s", id)
	}
	return nil
}

func (s *postgresStore) PruneHistory(retentionDays int) (int64, error) {
	res, err := s.db.Exec(
		`DELETE FROM scan_history WHERE scanned_at < NOW() - ($1 || ' days')::interval`,
		retentionDays,
	)
	if err != nil {
		return 0, fmt.Errorf("PruneHistory: %w", err)
	}
	return res.RowsAffected()
}

func (s *postgresStore) DismissResult(scanID, dismissedBy, note string) error {
	_, err := s.db.Exec(`
INSERT INTO dismissals (scan_id, dismissed_by, note, dismissed_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (scan_id) DO UPDATE SET
    dismissed_by = EXCLUDED.dismissed_by,
    note         = EXCLUDED.note,
    dismissed_at = EXCLUDED.dismissed_at
`, scanID, dismissedBy, note, time.Now().UTC())
	return err
}

func (s *postgresStore) ListViolations(limit int) ([]shield.ViolationRow, error) {
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
LIMIT $1
`, limit)
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

func (s *postgresStore) ListHistory(limit int) ([]shield.ScanResult, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`
SELECT result_json FROM scan_history
ORDER BY scanned_at DESC
LIMIT $1
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
