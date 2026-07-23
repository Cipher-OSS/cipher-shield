package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	shield "github.com/cipher-oss/cipher-shield/internal"
)

// ── detectTarball ──────────────────────────────────────────────────────────

func TestDetectTarball_NPM(t *testing.T) {
	cases := []struct {
		path    string
		name    string
		version string
	}{
		{"/lodash/-/lodash-4.17.21.tgz", "lodash", "4.17.21"},
		{"/express/-/express-4.18.2.tgz", "express", "4.18.2"},
		{"/@babel/core/-/core-7.21.0.tgz", "@babel/core", "7.21.0"},
		{"/@types/node/-/node-20.0.0.tgz", "@types/node", "20.0.0"},
		{"/react/-/react-18.2.0.tgz", "react", "18.2.0"},
	}
	for _, tc := range cases {
		req := &http.Request{URL: &url.URL{Path: tc.path}, Method: "GET"}
		pkg, ok := detectTarball(req)
		if !ok {
			t.Errorf("path %q: expected tarball match, got none", tc.path)
			continue
		}
		if pkg.Ecosystem != shield.EcosystemNPM {
			t.Errorf("path %q: expected npm, got %s", tc.path, pkg.Ecosystem)
		}
		if pkg.Name != tc.name {
			t.Errorf("path %q: name: want %q, got %q", tc.path, tc.name, pkg.Name)
		}
		if pkg.Version != tc.version {
			t.Errorf("path %q: version: want %q, got %q", tc.path, tc.version, pkg.Version)
		}
	}
}

func TestDetectTarball_PyPI(t *testing.T) {
	cases := []struct {
		path    string
		name    string
		version string
	}{
		{
			"/packages/ab/cd/ef/requests-2.31.0.tar.gz",
			"requests", "2.31.0",
		},
		{
			// wheel filename: version stops at the first hyphen (before py/abi/platform tags)
			"/packages/12/34/56/numpy-1.24.0-cp311-cp311-manylinux.whl",
			"numpy", "1.24.0",
		},
		{
			"/packages/ab/cd/ef/requests-2.34.2-py3-none-any.whl",
			"requests", "2.34.2",
		},
		{
			"/packages/aa/bb/cc/Pillow-9.5.0.tar.gz",
			"pillow", "9.5.0", // normalized to lowercase
		},
		{
			"/packages/xx/yy/zz/my_package-1.0.0.tar.gz",
			"my-package", "1.0.0", // underscore → hyphen
		},
	}
	for _, tc := range cases {
		req := &http.Request{URL: &url.URL{Path: tc.path}, Method: "GET"}
		pkg, ok := detectTarball(req)
		if !ok {
			t.Errorf("path %q: expected tarball match, got none", tc.path)
			continue
		}
		if pkg.Ecosystem != shield.EcosystemPyPI {
			t.Errorf("path %q: expected pypi, got %s", tc.path, pkg.Ecosystem)
		}
		if pkg.Name != tc.name {
			t.Errorf("path %q: name: want %q, got %q", tc.path, tc.name, pkg.Name)
		}
		if pkg.Version != tc.version {
			t.Errorf("path %q: version: want %q, got %q", tc.path, tc.version, pkg.Version)
		}
	}
}

func TestDetectTarball_NoMatch(t *testing.T) {
	paths := []string{
		"/lodash",                     // metadata, not tarball
		"/@babel/core",                // scoped metadata
		"/simple/requests/",          // pypi simple API
		"/",
		"/favicon.ico",
	}
	for _, path := range paths {
		req := &http.Request{URL: &url.URL{Path: path}, Method: "GET"}
		_, ok := detectTarball(req)
		if ok {
			t.Errorf("path %q: expected no tarball match, got one", path)
		}
	}
}

// ── detectNPMMeta ──────────────────────────────────────────────────────────

func TestDetectNPMMeta(t *testing.T) {
	cases := []struct {
		path string
		name string
		ok   bool
	}{
		{"/lodash", "lodash", true},
		{"/@babel/core", "@babel/core", true},
		{"/@types/node", "@types/node", true},
		{"/lodash/-/lodash-4.17.21.tgz", "", false}, // is a tarball
		{"/simple/requests/", "", false},             // pypi path
		{"/packages/aa/bb/requests-2.31.0.tar.gz", "", false},
	}
	for _, tc := range cases {
		req := &http.Request{
			Method: "GET",
			URL:    &url.URL{Path: tc.path},
		}
		name, ok := detectNPMMeta(req)
		if ok != tc.ok {
			t.Errorf("path %q: ok: want %v, got %v", tc.path, tc.ok, ok)
			continue
		}
		if ok && name != tc.name {
			t.Errorf("path %q: name: want %q, got %q", tc.path, tc.name, name)
		}
	}
}

func TestDetectNPMMeta_NonGETIgnored(t *testing.T) {
	req := &http.Request{Method: "POST", URL: &url.URL{Path: "/lodash"}}
	_, ok := detectNPMMeta(req)
	if ok {
		t.Error("POST /lodash should not be detected as npm metadata")
	}
}

// ── upstreamURL ────────────────────────────────────────────────────────────

func TestUpstreamURL_NPM(t *testing.T) {
	req := &http.Request{URL: &url.URL{Path: "/lodash/-/lodash-4.17.21.tgz"}}
	u := upstreamURL(req)
	if u.Host != "registry.npmjs.org" {
		t.Errorf("npm path: want host registry.npmjs.org, got %s", u.Host)
	}
	if u.Scheme != "https" {
		t.Errorf("npm path: want https, got %s", u.Scheme)
	}
}

func TestUpstreamURL_PyPISimple(t *testing.T) {
	req := &http.Request{URL: &url.URL{Path: "/simple/requests/"}}
	u := upstreamURL(req)
	if u.Host != "pypi.org" {
		t.Errorf("pypi simple: want host pypi.org, got %s", u.Host)
	}
}

func TestUpstreamURL_PyPIPackage(t *testing.T) {
	req := &http.Request{URL: &url.URL{Path: "/packages/aa/bb/cc/requests-2.31.0.tar.gz"}}
	u := upstreamURL(req)
	if u.Host != "files.pythonhosted.org" {
		t.Errorf("pypi tarball: want host files.pythonhosted.org, got %s", u.Host)
	}
}

// ── normalizePyPI ──────────────────────────────────────────────────────────

func TestNormalizePyPI(t *testing.T) {
	cases := [][2]string{
		{"Requests", "requests"},
		{"my_package", "my-package"},
		{"My.Package", "my-package"},
		{"numpy", "numpy"},
	}
	for _, tc := range cases {
		got := normalizePyPI(tc[0])
		if got != tc[1] {
			t.Errorf("normalizePyPI(%q): want %q, got %q", tc[0], tc[1], got)
		}
	}
}

// ── isPyPISimple ───────────────────────────────────────────────────────────

func TestIsPyPISimple(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/simple/requests/", true},
		{"/simple/numpy", true},
		{"/packages/aa/bb/cc/requests-2.31.0.tar.gz", false},
		{"/lodash", false},
		{"/", false},
	}
	for _, tc := range cases {
		got := isPyPISimple(tc.path)
		if got != tc.want {
			t.Errorf("isPyPISimple(%q): want %v, got %v", tc.path, tc.want, got)
		}
	}
}

// ── proxyBaseURL ───────────────────────────────────────────────────────────

func TestProxyBaseURL(t *testing.T) {
	cases := []struct {
		listenAddr string
		publicURL  string
		want       string
	}{
		{":7070", "", "http://localhost:7070"},
		{"127.0.0.1:7070", "", "http://127.0.0.1:7070"},
		{"", "", "http://localhost"},
		{":7070", "https://proxy.example.com", "https://proxy.example.com"},
		{":7070", "https://proxy.example.com/", "https://proxy.example.com"}, // trailing slash stripped
	}
	for _, tc := range cases {
		p := &Proxy{cfg: Config{ListenAddr: tc.listenAddr, PublicURL: tc.publicURL}}
		got := p.proxyBaseURL()
		if got != tc.want {
			t.Errorf("listenAddr=%q publicURL=%q: want %q, got %q", tc.listenAddr, tc.publicURL, tc.want, got)
		}
	}
}

// ── resilientTransport ─────────────────────────────────────────────────────

// mockRT is a fake RoundTripper that returns a canned status or error.
type mockRT struct {
	status int
	err    error
	called bool
}

func (m *mockRT) RoundTrip(_ *http.Request) (*http.Response, error) {
	m.called = true
	if m.err != nil {
		return nil, m.err
	}
	return &http.Response{
		StatusCode: m.status,
		Body:       io.NopCloser(strings.NewReader("")),
	}, nil
}

func fakeProxyFn(u *url.URL) func(*http.Request) (*url.URL, error) {
	return func(_ *http.Request) (*url.URL, error) { return u, nil }
}

func noProxyFn(_ *http.Request) (*url.URL, error) { return nil, nil }

// TestResilientTransport_NoProxy — no proxy configured, goes direct.
func TestResilientTransport_NoProxy(t *testing.T) {
	direct := &mockRT{status: http.StatusOK}
	proxied := &mockRT{status: http.StatusOK}

	rt := &resilientTransport{proxied: proxied, direct: direct, proxyFn: noProxyFn}
	req, _ := http.NewRequest("GET", "http://registry.npmjs.org/lodash", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()

	if proxied.called {
		t.Error("proxied transport should not be called when no proxy is configured")
	}
	if !direct.called {
		t.Error("direct transport should be called when no proxy is configured")
	}
}

// TestResilientTransport_ProxyWorks — proxy is reachable, response comes from it.
func TestResilientTransport_ProxyWorks(t *testing.T) {
	proxyURL, _ := url.Parse("http://corporate-proxy:8080")
	direct := &mockRT{status: http.StatusOK}
	proxied := &mockRT{status: http.StatusOK}

	rt := &resilientTransport{proxied: proxied, direct: direct, proxyFn: fakeProxyFn(proxyURL)}
	req, _ := http.NewRequest("GET", "http://registry.npmjs.org/lodash", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()

	if !proxied.called {
		t.Error("proxied transport should be called when proxy is configured")
	}
	if direct.called {
		t.Error("direct transport should not be called when proxy succeeds")
	}
}

// TestResilientTransport_ProxyUnreachable — proxy errors, falls back to direct.
func TestResilientTransport_ProxyUnreachable(t *testing.T) {
	proxyURL, _ := url.Parse("http://dead-proxy:9999")
	direct := &mockRT{status: http.StatusOK}
	proxied := &mockRT{err: errors.New("connection refused")}

	rt := &resilientTransport{proxied: proxied, direct: direct, proxyFn: fakeProxyFn(proxyURL)}
	req, _ := http.NewRequest("GET", "http://registry.npmjs.org/lodash", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("expected fallback to direct, got error: %v", err)
	}
	resp.Body.Close()

	if !proxied.called {
		t.Error("proxied transport should have been attempted")
	}
	if !direct.called {
		t.Error("direct transport should be called as fallback when proxy is unreachable")
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("want 200 from direct fallback, got %d", resp.StatusCode)
	}
}

// TestResilientTransport_Proxy407 — proxy returns 407, returns actionable error (no silent bypass).
func TestResilientTransport_Proxy407(t *testing.T) {
	proxyURL, _ := url.Parse("http://auth-proxy:8080")
	direct := &mockRT{status: http.StatusOK}
	proxied := &mockRT{status: http.StatusProxyAuthRequired}

	rt := &resilientTransport{proxied: proxied, direct: direct, proxyFn: fakeProxyFn(proxyURL)}
	req, _ := http.NewRequest("GET", "http://registry.npmjs.org/lodash", nil)
	_, err := rt.RoundTrip(req)
	if err == nil {
		t.Fatal("expected error on 407, got nil — proxy auth must not be silently bypassed")
	}
	if !proxied.called {
		t.Error("proxied transport should have been attempted")
	}
	if direct.called {
		t.Error("direct transport must not be called as fallback on 407 — that bypasses the security gateway")
	}
}

// ── handleTarball: download event integration ──────────────────────────────────

// stubPipeline is a fake Analyzer that always returns an allow verdict.
type stubPipeline struct{}

func (s *stubPipeline) Analyze(_ context.Context, pkg shield.PackageRef, _ []byte) (*shield.ScanResult, error) {
	return &shield.ScanResult{
		ScanID:    "stub-scan-id",
		Package:   pkg,
		Verdict:   shield.VerdictAllow,
		ScannedAt: time.Now().UTC(),
	}, nil
}

// stubReporter captures Report and ReportDownload calls synchronously.
type stubReporter struct {
	results   []*shield.ScanResult
	downloads []*shield.DownloadEvent
}

func (r *stubReporter) Report(result *shield.ScanResult) {
	r.results = append(r.results, result)
}

func (r *stubReporter) ReportDownload(e *shield.DownloadEvent) {
	r.downloads = append(r.downloads, e)
}

// TestHandleTarballFiresDownloadEvent verifies that handleTarball calls both
// Report and ReportDownload on the configured reporter after a successful scan.
func TestHandleTarballFiresDownloadEvent(t *testing.T) {
	// Fake upstream: returns a minimal tarball body.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("fake-tarball-content"))
	}))
	defer upstream.Close()

	rep := &stubReporter{}
	p := &Proxy{
		cfg: Config{
			Mode:     ModeEnforce,
			Reporter: rep,
			Pipeline: &stubPipeline{},
		},
		transport: http.DefaultTransport,
	}

	upURL, err := url.Parse(upstream.URL + "/lodash/-/lodash-4.17.21.tgz")
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	req := &http.Request{
		Method: "GET",
		URL:    upURL,
		Header: make(http.Header),
	}
	pkg := shield.PackageRef{Ecosystem: shield.EcosystemNPM, Name: "lodash", Version: "4.17.21"}

	// net.Pipe gives two ends of an in-memory synchronous connection.
	// handleTarball writes the HTTP response to server; we drain from client.
	client, server := net.Pipe()

	done := make(chan struct{})
	go func() {
		defer close(done)
		p.handleTarball(server, req, pkg)
		server.Close()
	}()

	// Drain the response so the goroutine can finish writing.
	io.Copy(io.Discard, client)
	client.Close()
	<-done

	if len(rep.downloads) != 1 {
		t.Fatalf("want 1 download event fired, got %d", len(rep.downloads))
	}
	dl := rep.downloads[0]
	if dl.Package.Name != "lodash" {
		t.Errorf("download.package.name: want lodash, got %q", dl.Package.Name)
	}
	if dl.Package.Version != "4.17.21" {
		t.Errorf("download.package.version: want 4.17.21, got %q", dl.Package.Version)
	}
	if dl.Package.Ecosystem != shield.EcosystemNPM {
		t.Errorf("download.package.ecosystem: want npm, got %q", dl.Package.Ecosystem)
	}
	if dl.EventID == "" {
		t.Error("download.event_id must be populated (uuid)")
	}
	if dl.Verdict != shield.VerdictAllow {
		t.Errorf("download.verdict: want allow, got %q", dl.Verdict)
	}
	if dl.ScanID == "" {
		t.Error("download.scan_id must be populated")
	}
	if dl.DownloadedAt.IsZero() {
		t.Error("download.downloaded_at must be set")
	}
	if dl.MachineID == "" {
		t.Error("download.machine_id must be set (hostname)")
	}
	if len(rep.results) != 1 {
		t.Errorf("want 1 scan result reported, got %d", len(rep.results))
	}
	if rep.results[0].Package.Name != "lodash" {
		t.Errorf("result.package.name: want lodash, got %q", rep.results[0].Package.Name)
	}
}

// TestHandleTarballNilReporter verifies that handleTarball doesn't panic when
// no reporter is configured.
func TestHandleTarballNilReporter(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("fake-tarball"))
	}))
	defer upstream.Close()

	p := &Proxy{
		cfg: Config{
			Mode:     ModeWarn,
			Reporter: nil, // no reporter
			Pipeline: &stubPipeline{},
		},
		transport: http.DefaultTransport,
	}

	upURL, _ := url.Parse(upstream.URL + "/express/-/express-4.18.0.tgz")
	req := &http.Request{
		Method: "GET",
		URL:    upURL,
		Header: make(http.Header),
	}
	pkg := shield.PackageRef{Ecosystem: shield.EcosystemNPM, Name: "express", Version: "4.18.0"}

	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.handleTarball(server, req, pkg)
		server.Close()
	}()

	io.Copy(io.Discard, client)
	client.Close()
	<-done
	// If we reach here without panic, the test passes.
}

// TestResilientTransport_ProxyReturns4xx — non-407 errors from destination pass through unchanged.
func TestResilientTransport_ProxyReturns4xx(t *testing.T) {
	proxyURL, _ := url.Parse("http://corporate-proxy:8080")
	direct := &mockRT{status: http.StatusOK}
	proxied := &mockRT{status: http.StatusNotFound} // upstream 404, not a proxy error

	rt := &resilientTransport{proxied: proxied, direct: direct, proxyFn: fakeProxyFn(proxyURL)}
	req, _ := http.NewRequest("GET", "http://registry.npmjs.org/nonexistent", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()

	if direct.called {
		t.Error("direct transport should NOT be called for upstream 404 — that is not a proxy failure")
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("want 404 passed through, got %d", resp.StatusCode)
	}
}
