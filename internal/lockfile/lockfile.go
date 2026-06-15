package lockfile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	shield "github.com/cipher-oss/cipher-shield/internal"
)

// Parser extracts PackageRef entries from a lock file.
type Parser interface {
	Name() string
	Detect(filename string) bool
	Parse(data []byte) ([]shield.PackageRef, error)
}

var parsers = []Parser{
	&NPMParser{},
	&YarnParser{},
	&RequirementsParser{},
	&PoetryParser{},
}

// Detect returns the appropriate parser for the given file path.
func Detect(path string) (Parser, error) {
	base := strings.ToLower(filepath.Base(path))
	for _, p := range parsers {
		if p.Detect(base) {
			return p, nil
		}
	}
	return nil, fmt.Errorf("no parser found for %s", filepath.Base(path))
}

// ParseFile detects the parser, reads the file, and returns all package refs.
func ParseFile(path string) ([]shield.PackageRef, error) {
	p, err := Detect(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return p.Parse(data)
}
