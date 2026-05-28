package db

import (
	"fmt"

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

	Migrate() error
	Close() error
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
