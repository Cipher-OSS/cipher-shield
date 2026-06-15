package lockfile

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"

	shield "github.com/cipher-oss/cipher-shield/internal"
)

type RequirementsParser struct{}

func (p *RequirementsParser) Name() string { return "requirements.txt" }
func (p *RequirementsParser) Detect(filename string) bool {
	return filename == "requirements.txt" || strings.HasSuffix(filename, "-requirements.txt")
}

// pinnedRe matches "package==1.2.3" or "package[extra]==1.2.3"
var pinnedRe = regexp.MustCompile(`^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?==([A-Za-z0-9_.+-]+)`)

func (p *RequirementsParser) Parse(data []byte) ([]shield.PackageRef, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var refs []shield.PackageRef
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip comments, blank lines, options (-r, -c, --hash, etc.)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Remove inline comment
		if idx := strings.Index(line, " #"); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}
		m := pinnedRe.FindStringSubmatch(line)
		if len(m) == 3 {
			refs = append(refs, shield.PackageRef{
				Ecosystem: shield.EcosystemPyPI,
				Name:      normalizePyPI(m[1]),
				Version:   m[2],
			})
		}
		// Unpinned deps (>, >=, ~=, etc.) are skipped — can't scan without a version
	}
	return refs, scanner.Err()
}

// normalizePyPI lowercases and replaces _ and . with - (PEP 503 normalization).
func normalizePyPI(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.ReplaceAll(name, ".", "-")
	return name
}
