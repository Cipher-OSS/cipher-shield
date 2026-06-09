package db

import (
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	shield "github.com/homes853/cipher-shield/internal"
)

// Store is the persistence interface. SQLite implements this for local mode.
type Store interface {
	// Scan cache
	GetCachedResult(eco shield.Ecosystem, name, version string) (*shield.ScanResult, error)
	SaveResult(r shield.ScanResult) error

	// Exceptions
	GetException(eco shield.Ecosystem, name, version string) (*shield.Exception, error)
	ListExceptions() ([]shield.Exception, error)
	AddException(e shield.Exception) error
	DeleteException(id string) error

	// Scan history (recent scans for dashboard)
	ListHistory(limit int) ([]shield.ScanResult, error)

	// Users
	CreateUser(email, passwordHash, role string) (*shield.User, error)
	GetUserByEmail(email string) (*shield.User, error)
	GetUserByID(userID string) (*shield.User, error)
	UpdatePassword(userID, passwordHash string) error
	CountUsers() (int, error)
	ListUsers() ([]shield.User, error)

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
