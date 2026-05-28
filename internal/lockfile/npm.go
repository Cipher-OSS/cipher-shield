package lockfile

import (
	"encoding/json"
	"strings"

	shield "github.com/homes853/cipher-shield/internal"
)

type NPMParser struct{}

func (p *NPMParser) Name() string                  { return "package-lock.json" }
func (p *NPMParser) Detect(filename string) bool   { return filename == "package-lock.json" }

func (p *NPMParser) Parse(data []byte) ([]shield.PackageRef, error) {
	var lock struct {
		LockfileVersion int `json:"lockfileVersion"`
		// v2/v3: "packages" map — keys are "node_modules/pkgname" or "node_modules/scope/pkg"
		Packages map[string]struct {
			Version  string `json:"version"`
			Dev      bool   `json:"dev"`
			Peer     bool   `json:"peer"`
			Optional bool   `json:"optional"`
		} `json:"packages"`
		// v1 fallback: "dependencies" map
		Dependencies map[string]struct {
			Version string `json:"version"`
			Dev     bool   `json:"dev"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var refs []shield.PackageRef

	if len(lock.Packages) > 0 {
		// v2/v3 format
		for key, pkg := range lock.Packages {
			if key == "" {
				continue
			} // root package
			if pkg.Dev || pkg.Peer || pkg.Optional {
				continue
			}
			// Strip "node_modules/" prefix; handle scoped: "node_modules/@scope/name"
			name := strings.TrimPrefix(key, "node_modules/")
			if pkg.Version == "" || seen[name+pkg.Version] {
				continue
			}
			seen[name+pkg.Version] = true
			refs = append(refs, shield.PackageRef{
				Ecosystem: shield.EcosystemNPM,
				Name:      name,
				Version:   pkg.Version,
			})
		}
	} else {
		// v1 format
		for name, dep := range lock.Dependencies {
			if dep.Dev || dep.Version == "" || seen[name+dep.Version] {
				continue
			}
			seen[name+dep.Version] = true
			refs = append(refs, shield.PackageRef{
				Ecosystem: shield.EcosystemNPM,
				Name:      name,
				Version:   dep.Version,
			})
		}
	}
	return refs, nil
}
