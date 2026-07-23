package db

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	shield "github.com/cipher-oss/cipher-shield/internal"
)

// Store is the persistence interface for both SQLite and Postgres backends.
type Store interface {
	// Scan cache
	GetCachedResult(ctx context.Context, eco shield.Ecosystem, name, version string) (*shield.ScanResult, error)
	SaveResult(ctx context.Context, r shield.ScanResult) error

	// Exceptions
	GetException(ctx context.Context, eco shield.Ecosystem, name, version string) (*shield.Exception, error)
	ListExceptions(ctx context.Context) ([]shield.Exception, error)
	AddException(ctx context.Context, e shield.Exception) error
	DeleteException(ctx context.Context, id string) error

	// Scan history
	ListHistory(ctx context.Context, limit int) ([]shield.ScanResult, error)
	PruneHistory(ctx context.Context, retentionDays int) (int64, error)

	// Violations + triage
	ListViolations(ctx context.Context, limit int) ([]shield.ViolationRow, error)
	DismissResult(ctx context.Context, scanID, dismissedBy, note string) error

	// Download events
	SaveDownload(ctx context.Context, e shield.DownloadEvent) error
	ListDownloads(ctx context.Context, limit int) ([]shield.DownloadEvent, error)

	// Users
	CreateUser(ctx context.Context, email, passwordHash, role string) (*shield.User, error)
	GetUserByEmail(ctx context.Context, email string) (*shield.User, error)
	GetUserByID(ctx context.Context, userID string) (*shield.User, error)
	UpdatePassword(ctx context.Context, userID, passwordHash string) error
	CountUsers(ctx context.Context) (int, error)
	ListUsers(ctx context.Context) ([]shield.User, error)

	Migrate() error
	Close() error
}

func newUserID() string { return uuid.New().String() }

func scanUserRow(row *sql.Row) (*shield.User, error) {
	var u shield.User
	err := row.Scan(&u.UserID, &u.Email, &u.PasswordHash, &u.Role, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scanUser: %w", err)
	}
	return &u, nil
}

func scanUserRows(rows *sql.Rows) ([]shield.User, error) {
	var out []shield.User
	for rows.Next() {
		var u shield.User
		if err := rows.Scan(&u.UserID, &u.Email, &u.PasswordHash, &u.Role, &u.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanUserRows: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// Open returns a Store for the given driver ("sqlite3" or "postgres") and DSN.
func Open(driver, dsn string) (Store, error) {
	switch driver {
	case "sqlite3":
		return openSQLite(dsn)
	case "postgres":
		return openPostgres(dsn)
	default:
		return nil, fmt.Errorf("unsupported db driver: %s", driver)
	}
}
