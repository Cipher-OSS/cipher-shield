package lockfile

import (
	"bufio"
	"bytes"
	"strings"

	shield "github.com/homes853/cipher-shield/internal"
)

type YarnParser struct{}

func (p *YarnParser) Name() string                { return "yarn.lock" }
func (p *YarnParser) Detect(filename string) bool { return filename == "yarn.lock" }

// Parse handles Yarn v1 classic lockfile format.
// Format: blocks of "pkg@version:" followed by "  version \"x.y.z\""
func (p *YarnParser) Parse(data []byte) ([]shield.PackageRef, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	seen := map[string]bool{}
	var refs []shield.PackageRef

	var currentName string
	for scanner.Scan() {
		line := scanner.Text()

		// Skip comments and blank lines
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}

		// Block header: `"pkg@^1.0.0, pkg@^1.0.1":` or `pkg@^1.0.0:`
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(strings.TrimSpace(line), ":") {
			// Extract base package name from the first spec
			header := strings.TrimSuffix(strings.TrimSpace(line), ":")
			header = strings.Trim(header, "\"")
			// Take the first entry if comma-separated
			first := strings.SplitN(header, ",", 2)[0]
			first = strings.TrimSpace(first)
			// Name is everything before the last "@" (handles scoped packages)
			if idx := strings.LastIndex(first, "@"); idx > 0 {
				currentName = first[:idx]
			} else {
				currentName = first
			}
			continue
		}

		// Version line inside a block: `  version "1.2.3"`
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "version ") && currentName != "" {
			version := strings.Trim(strings.TrimPrefix(trimmed, "version "), "\"")
			key := currentName + "@" + version
			if !seen[key] && version != "" {
				seen[key] = true
				refs = append(refs, shield.PackageRef{
					Ecosystem: shield.EcosystemNPM,
					Name:      currentName,
					Version:   version,
				})
			}
			currentName = ""
		}
	}
	return refs, scanner.Err()
}
