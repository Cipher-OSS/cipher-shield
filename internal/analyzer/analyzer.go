package analyzer

import (
	"context"

	shield "github.com/homes853/cipher-shield/internal"
)

// Analyzer is implemented by each detection layer.
type Analyzer interface {
	// Name returns the analyzer identifier used in Finding.Type.
	Name() string
	// Analyze inspects a package and returns zero or more findings.
	// It must return quickly — Claude analyzer has its own timeout internally.
	Analyze(ctx context.Context, pkg shield.PackageRef, tarball []byte) ([]shield.Finding, error)
}
