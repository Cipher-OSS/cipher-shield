package lockfile_test

import (
	"testing"

	shield "github.com/cipher-oss/cipher-shield/internal"
	"github.com/cipher-oss/cipher-shield/internal/lockfile"
)

// findPkg returns true if name@version is present in refs.
func findPkg(refs []shield.PackageRef, name, version string) bool {
	for _, r := range refs {
		if r.Name == name && r.Version == version {
			return true
		}
	}
	return false
}

// countPkg counts how many times name@version appears in refs.
func countPkg(refs []shield.PackageRef, name, version string) int {
	n := 0
	for _, r := range refs {
		if r.Name == name && r.Version == version {
			n++
		}
	}
	return n
}

// ── Detect ────────────────────────────────────────────────────────────────────

func TestDetect(t *testing.T) {
	cases := []struct {
		path     string
		wantName string
		wantErr  bool
	}{
		{"package-lock.json", "package-lock.json", false},
		{"/some/path/package-lock.json", "package-lock.json", false},
		{"yarn.lock", "yarn.lock", false},
		{"requirements.txt", "requirements.txt", false},
		{"production-requirements.txt", "requirements.txt", false},
		{"test-requirements.txt", "requirements.txt", false},
		{"poetry.lock", "poetry.lock", false},
		{"composer.lock", "", true},
		{"Pipfile.lock", "", true},
		{"go.sum", "", true},
	}
	for _, tc := range cases {
		p, err := lockfile.Detect(tc.path)
		if tc.wantErr {
			if err == nil {
				t.Errorf("Detect(%q): expected error, got parser %q", tc.path, p.Name())
			}
			continue
		}
		if err != nil {
			t.Errorf("Detect(%q): unexpected error: %v", tc.path, err)
			continue
		}
		if p.Name() != tc.wantName {
			t.Errorf("Detect(%q): got %q, want %q", tc.path, p.Name(), tc.wantName)
		}
	}
}

// ── NPM (package-lock.json) ───────────────────────────────────────────────────

func TestNPMParserV2Basic(t *testing.T) {
	data := []byte(`{
		"lockfileVersion": 2,
		"packages": {
			"": {"version": "1.0.0"},
			"node_modules/lodash": {"version": "4.17.21"},
			"node_modules/axios": {"version": "1.6.0"},
			"node_modules/@babel/core": {"version": "7.23.0"},
			"node_modules/jest": {"version": "29.0.0", "dev": true}
		}
	}`)
	p := &lockfile.NPMParser{}
	refs, err := p.Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !findPkg(refs, "lodash", "4.17.21") {
		t.Error("missing lodash@4.17.21")
	}
	if !findPkg(refs, "axios", "1.6.0") {
		t.Error("missing axios@1.6.0")
	}
	if !findPkg(refs, "@babel/core", "7.23.0") {
		t.Error("missing @babel/core@7.23.0")
	}
	if findPkg(refs, "jest", "29.0.0") {
		t.Error("dev dep jest must be excluded")
	}
	for _, r := range refs {
		if r.Name == "" {
			t.Error("root package entry (key=\"\") must be excluded")
		}
	}
}

func TestNPMParserV2ExcludesPeerAndOptional(t *testing.T) {
	data := []byte(`{
		"lockfileVersion": 2,
		"packages": {
			"node_modules/peer-pkg":     {"version": "1.0.0", "peer": true},
			"node_modules/optional-pkg": {"version": "1.0.0", "optional": true},
			"node_modules/normal-pkg":   {"version": "1.0.0"}
		}
	}`)
	p := &lockfile.NPMParser{}
	refs, err := p.Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if findPkg(refs, "peer-pkg", "1.0.0") {
		t.Error("peer dep must be excluded")
	}
	if findPkg(refs, "optional-pkg", "1.0.0") {
		t.Error("optional dep must be excluded")
	}
	if !findPkg(refs, "normal-pkg", "1.0.0") {
		t.Error("normal dep must be included")
	}
}

func TestNPMParserV1Basic(t *testing.T) {
	data := []byte(`{
		"lockfileVersion": 1,
		"dependencies": {
			"lodash":  {"version": "4.17.21"},
			"express": {"version": "4.18.0"},
			"jest":    {"version": "29.0.0", "dev": true}
		}
	}`)
	p := &lockfile.NPMParser{}
	refs, err := p.Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !findPkg(refs, "lodash", "4.17.21") {
		t.Error("missing lodash@4.17.21")
	}
	if !findPkg(refs, "express", "4.18.0") {
		t.Error("missing express@4.18.0")
	}
	if findPkg(refs, "jest", "29.0.0") {
		t.Error("dev dep jest must be excluded")
	}
}

func TestNPMParserV2Deduplication(t *testing.T) {
	// The same logical package must appear at most once.
	data := []byte(`{
		"lockfileVersion": 2,
		"packages": {
			"node_modules/lodash": {"version": "4.17.21"},
			"node_modules/lodash": {"version": "4.17.21"}
		}
	}`)
	// Go's JSON decoder will use the last duplicate key value; the seen-map
	// still ensures at most one entry per name+version.
	p := &lockfile.NPMParser{}
	refs, err := p.Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n := countPkg(refs, "lodash", "4.17.21"); n != 1 {
		t.Errorf("lodash@4.17.21 should appear exactly once, got %d", n)
	}
}

func TestNPMParserInvalidJSON(t *testing.T) {
	p := &lockfile.NPMParser{}
	_, err := p.Parse([]byte("not valid json {{{"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// ── Yarn ──────────────────────────────────────────────────────────────────────

func TestYarnParserBasic(t *testing.T) {
	data := []byte(`# yarn lockfile v1

lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"

"@babel/core@^7.0.0, @babel/core@^7.1.0":
  version "7.23.0"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.23.0.tgz"
`)
	p := &lockfile.YarnParser{}
	refs, err := p.Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !findPkg(refs, "lodash", "4.17.21") {
		t.Error("missing lodash@4.17.21")
	}
	if !findPkg(refs, "@babel/core", "7.23.0") {
		t.Error("missing @babel/core@7.23.0")
	}
}

func TestYarnParserMultipleSpecsSameVersion(t *testing.T) {
	// Two version specs that resolve to the same version must produce one entry.
	data := []byte(`# yarn lockfile v1

express@^4.0.0, express@^4.18.0:
  version "4.18.0"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.0.tgz"
`)
	p := &lockfile.YarnParser{}
	refs, err := p.Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n := countPkg(refs, "express", "4.18.0"); n != 1 {
		t.Errorf("express@4.18.0 should appear exactly once, got %d", n)
	}
}

func TestYarnParserSkipsBlankLinesAndComments(t *testing.T) {
	data := []byte(`# This is a comment

# Another comment

lodash@^4.17.21:
  version "4.17.21"
  resolved "https://..."

`)
	p := &lockfile.YarnParser{}
	refs, err := p.Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 1 {
		t.Errorf("expected 1 package, got %d", len(refs))
	}
	if !findPkg(refs, "lodash", "4.17.21") {
		t.Error("missing lodash@4.17.21")
	}
}

func TestYarnParserEmpty(t *testing.T) {
	p := &lockfile.YarnParser{}
	refs, err := p.Parse([]byte("# yarn lockfile v1\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 0 {
		t.Errorf("expected 0 packages, got %d", len(refs))
	}
}

// ── Requirements.txt ──────────────────────────────────────────────────────────

func TestRequirementsParserPinned(t *testing.T) {
	data := []byte(`# comment
requests==2.31.0
numpy==1.24.0  # inline comment
Flask>=2.0.0
-r other.txt
--hash=sha256:abc
my_package==1.0.0
pandas[excel]==2.0.0
`)
	p := &lockfile.RequirementsParser{}
	refs, err := p.Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !findPkg(refs, "requests", "2.31.0") {
		t.Error("missing requests==2.31.0")
	}
	if !findPkg(refs, "numpy", "1.24.0") {
		t.Error("missing numpy==1.24.0")
	}
	if !findPkg(refs, "my-package", "1.0.0") {
		t.Error("my_package should be normalized to my-package")
	}
	if !findPkg(refs, "pandas", "2.0.0") {
		t.Error("pandas[excel] extras should be stripped → pandas==2.0.0")
	}
	if findPkg(refs, "flask", "2.0.0") || findPkg(refs, "Flask", "2.0.0") {
		t.Error("unpinned Flask>=2.0.0 must be excluded")
	}
}

func TestRequirementsParserNormalization(t *testing.T) {
	data := []byte(`My_Package==1.0.0
My.Other.Package==2.0.0
REQUESTS==3.0.0
`)
	p := &lockfile.RequirementsParser{}
	refs, err := p.Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !findPkg(refs, "my-package", "1.0.0") {
		t.Error("underscore must normalize to hyphen")
	}
	if !findPkg(refs, "my-other-package", "2.0.0") {
		t.Error("dot must normalize to hyphen")
	}
	if !findPkg(refs, "requests", "3.0.0") {
		t.Error("name must be lowercased")
	}
}

func TestRequirementsParserSkipsUnpinned(t *testing.T) {
	data := []byte(`requests>=2.0.0
numpy~=1.24
flask
`)
	p := &lockfile.RequirementsParser{}
	refs, err := p.Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 0 {
		t.Errorf("unpinned deps must be skipped, got %d: %+v", len(refs), refs)
	}
}

func TestRequirementsParserDetect(t *testing.T) {
	p := &lockfile.RequirementsParser{}
	for _, name := range []string{"requirements.txt", "production-requirements.txt", "test-requirements.txt", "dev-requirements.txt"} {
		if !p.Detect(name) {
			t.Errorf("Detect(%q): expected true", name)
		}
	}
	for _, name := range []string{"setup.py", "pyproject.toml", "requirements.in"} {
		if p.Detect(name) {
			t.Errorf("Detect(%q): expected false", name)
		}
	}
}

// ── Poetry.lock ───────────────────────────────────────────────────────────────

func TestPoetryParserBasic(t *testing.T) {
	data := []byte(`[[package]]
name = "requests"
version = "2.31.0"
description = "HTTP library"

[[package]]
name = "pytest"
version = "7.4.0"
description = "Testing framework"
category = "dev"

[[package]]
name = "optional-pkg"
version = "1.0.0"
optional = "true"

[[package]]
name = "my_lib"
version = "1.5.0"

[metadata]
lock-version = "1.1"
python-versions = "^3.9"
`)
	p := &lockfile.PoetryParser{}
	refs, err := p.Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !findPkg(refs, "requests", "2.31.0") {
		t.Error("missing requests@2.31.0")
	}
	if !findPkg(refs, "my-lib", "1.5.0") {
		t.Error("my_lib should normalize to my-lib")
	}
	if findPkg(refs, "pytest", "7.4.0") {
		t.Error("dev dep pytest must be excluded")
	}
	if findPkg(refs, "optional-pkg", "1.0.0") {
		t.Error("optional package must be excluded")
	}
}

func TestPoetryParserNormalization(t *testing.T) {
	data := []byte(`[[package]]
name = "My_Package"
version = "1.0.0"
`)
	p := &lockfile.PoetryParser{}
	refs, err := p.Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !findPkg(refs, "my-package", "1.0.0") {
		t.Errorf("underscore must normalize to hyphen, got: %+v", refs)
	}
}

func TestPoetryParserEmptyInput(t *testing.T) {
	p := &lockfile.PoetryParser{}
	refs, err := p.Parse([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(refs) != 0 {
		t.Errorf("expected 0 refs for empty input, got %d", len(refs))
	}
}

func TestPoetryParserMetadataSectionTerminates(t *testing.T) {
	// Packages after [metadata] must not be parsed as [[package]] blocks.
	data := []byte(`[[package]]
name = "real-pkg"
version = "1.0.0"

[metadata]
name = "should-not-appear"
version = "9.9.9"
`)
	p := &lockfile.PoetryParser{}
	refs, err := p.Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !findPkg(refs, "real-pkg", "1.0.0") {
		t.Error("missing real-pkg@1.0.0")
	}
	if findPkg(refs, "should-not-appear", "9.9.9") {
		t.Error("content under [metadata] must not be parsed as a package")
	}
}
