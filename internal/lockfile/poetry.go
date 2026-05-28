package lockfile

import (
	"bufio"
	"bytes"
	"strings"

	shield "github.com/homes853/cipher-shield/internal"
)

type PoetryParser struct{}

func (p *PoetryParser) Name() string                { return "poetry.lock" }
func (p *PoetryParser) Detect(filename string) bool { return filename == "poetry.lock" }

// Parse extracts pinned packages from poetry.lock.
// poetry.lock is TOML with repeated [[package]] blocks.
// We parse it line-by-line to avoid a TOML dependency.
func (p *PoetryParser) Parse(data []byte) ([]shield.PackageRef, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var refs []shield.PackageRef

	var inPackage bool
	var currentName, currentVersion string
	var isDev bool

	flush := func() {
		if inPackage && currentName != "" && currentVersion != "" && !isDev {
			refs = append(refs, shield.PackageRef{
				Ecosystem: shield.EcosystemPyPI,
				Name:      normalizePoetry(currentName),
				Version:   currentVersion,
			})
		}
		currentName, currentVersion = "", ""
		isDev = false
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "[[package]]" {
			flush()
			inPackage = true
			continue
		}
		if strings.HasPrefix(line, "[[") || strings.HasPrefix(line, "[metadata") {
			flush()
			inPackage = false
			continue
		}
		if !inPackage {
			continue
		}

		if k, v, ok := parseKV(line); ok {
			switch k {
			case "name":
				currentName = v
			case "version":
				currentVersion = v
			case "category":
				if v == "dev" {
					isDev = true
				}
			case "optional":
				if v == "true" {
					isDev = true
				}
			}
		}
	}
	flush()
	return refs, scanner.Err()
}

func normalizePoetry(name string) string {
	return strings.ReplaceAll(strings.ToLower(name), "_", "-")
}

// parseKV extracts key and value from a TOML line like `name = "foo"`.
func parseKV(line string) (key, val string, ok bool) {
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return
	}
	key = strings.TrimSpace(parts[0])
	val = strings.Trim(strings.TrimSpace(parts[1]), "\"")
	ok = true
	return
}
