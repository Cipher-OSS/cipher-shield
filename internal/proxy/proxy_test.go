package proxy

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

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
