package proxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	shield "github.com/homes853/cipher-shield/internal"
)

// Mode controls enforcement behavior.
type Mode string

const (
	ModeEnforce Mode = "enforce" // block malicious packages
	ModeWarn    Mode = "warn"    // log warnings but never block
	ModeAudit   Mode = "audit"   // log only, transparent
)

// Analyzer is the minimal interface the proxy needs from the pipeline.
type Analyzer interface {
	Analyze(ctx context.Context, pkg shield.PackageRef, tarball []byte) (*shield.ScanResult, error)
}

// NameChecker runs Tier 1 against a package name only (no tarball required).
type NameChecker interface {
	CheckName(ctx context.Context, pkg shield.PackageRef) ([]shield.Finding, error)
}

// ExceptionChecker reports whether a package is on the server-managed exception list.
type ExceptionChecker interface {
	IsExcepted(eco shield.Ecosystem, name, version string) bool
}

// ResultReporter ships scan results to a central server.
type ResultReporter interface {
	Report(result *shield.ScanResult)
}

// Config holds proxy startup configuration.
type Config struct {
	ListenAddr   string          // e.g. "127.0.0.1:7070"
	Mode         Mode
	MaxBodyBytes int64           // max tarball to buffer (default 50MB)
	Pipeline     Analyzer        // nil = pass everything through (audit)
	NameChecker  NameChecker     // nil = no metadata-level Tier 1 check
	Exceptions   ExceptionChecker // nil = no server-side exception sync
	Reporter     ResultReporter  // nil = local-only, no central reporting
}

// Proxy is the package registry interception proxy.
type Proxy struct {
	cfg       Config
	transport *http.Transport
}

// New creates a Proxy from config.
func New(cfg Config) *Proxy {
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = 50 << 20 // 50 MB
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:7070"
	}
	return &Proxy{
		cfg: cfg,
		transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
		},
	}
}

// Start begins accepting connections. Blocks until error.
func (p *Proxy) Start() error {
	ln, err := net.Listen("tcp", p.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("proxy listen %s: %w", p.cfg.ListenAddr, err)
	}
	log.Printf("[proxy] listening on %s (mode=%s)", p.cfg.ListenAddr, p.cfg.Mode)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[proxy] accept error: %v", err)
			continue
		}
		go p.serve(conn)
	}
}

// serve handles one client connection.
func (p *Proxy) serve(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(120 * time.Second))

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	// Fix up the request URL (proxy requests have absolute URIs)
	if req.URL.Host == "" && req.Host != "" {
		req.URL.Host = req.Host
	}
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}

	// Rewrite the URL to point at the real upstream registry.
	// npm/pip clients send requests to http://localhost:7070/..., so we must
	// redirect the host to registry.npmjs.org or pypi.org before forwarding.
	req.URL = upstreamURL(req)
	req.Host = req.URL.Host

	// PyPI simple API — rewrite download URLs and optionally check package name
	if isPyPISimple(req.URL.Path) {
		p.handlePyPISimple(conn, req)
		return
	}

	// Check if this is a tarball request we should intercept
	pkg, isTarball := detectTarball(req)
	if isTarball && p.cfg.Pipeline != nil {
		p.handleTarball(conn, req, pkg)
		return
	}

	// npm metadata request — check package name against Tier 1 before forwarding
	if name, ok := detectNPMMeta(req); ok {
		if p.shouldBlockName(context.Background(), shield.EcosystemNPM, name) {
			writeError(conn, http.StatusForbidden, fmt.Sprintf(
				"BLOCKED: %s — known malicious package\nRun 'cipher-shield explain %s' for details.", name, name))
			return
		}
	}

	// All other requests: transparent proxy
	p.proxyTransparent(conn, req)
}

// handleTarball fetches the tarball, analyzes it, then passes through or blocks.
func (p *Proxy) handleTarball(conn net.Conn, req *http.Request, pkg shield.PackageRef) {
	log.Printf("[proxy] intercepting %s@%s (%s)", pkg.Name, pkg.Version, pkg.Ecosystem)

	// Fetch from upstream
	upResp, err := p.transport.RoundTrip(req)
	if err != nil {
		writeError(conn, http.StatusBadGateway, fmt.Sprintf("upstream fetch failed: %v", err))
		return
	}
	defer upResp.Body.Close()

	if upResp.StatusCode != http.StatusOK {
		// Non-200 upstream: pass through as-is
		p.forwardResponse(conn, upResp, nil)
		return
	}

	// Buffer the tarball (limited to MaxBodyBytes)
	lr := io.LimitReader(upResp.Body, p.cfg.MaxBodyBytes)
	tarball, err := io.ReadAll(lr)
	if err != nil {
		writeError(conn, http.StatusBadGateway, "failed to read tarball")
		return
	}

	// Analyze
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	result, err := p.cfg.Pipeline.Analyze(ctx, pkg, tarball)
	if err != nil {
		log.Printf("[proxy] analysis error for %s@%s: %v — passing through", pkg.Name, pkg.Version, err)
		p.forwardResponse(conn, upResp, tarball)
		return
	}

	log.Printf("[proxy] %s@%s verdict=%s", pkg.Name, pkg.Version, result.Verdict)

	// Ship result to central server if configured (non-blocking)
	if p.cfg.Reporter != nil {
		p.cfg.Reporter.Report(result)
	}

	// Block if verdict is block and mode is enforce
	if result.Verdict == shield.VerdictBlock && p.cfg.Mode == ModeEnforce {
		// Check server exception list before returning 403
		if p.cfg.Exceptions != nil && p.cfg.Exceptions.IsExcepted(pkg.Ecosystem, pkg.Name, pkg.Version) {
			log.Printf("[proxy] %s@%s blocked by pipeline but excepted — passing through", pkg.Name, pkg.Version)
			p.forwardResponse(conn, upResp, tarball)
			return
		}
		reason := "malicious package blocked by cipher-shield"
		if len(result.Findings) > 0 {
			reason = result.Findings[0].Title
		}
		writeError(conn, http.StatusForbidden, fmt.Sprintf(
			"BLOCKED: %s@%s — %s\nRun 'cipher-shield explain %s' for details.",
			pkg.Name, pkg.Version, reason, pkg.Name,
		))
		return
	}

	// Pass through (with warning logged for warn verdict)
	if result.Verdict == shield.VerdictWarn {
		log.Printf("[proxy] WARNING: %s@%s has %d finding(s) — passing through (mode=%s)",
			pkg.Name, pkg.Version, len(result.Findings), p.cfg.Mode)
	}

	p.forwardResponse(conn, upResp, tarball)
}

// proxyTransparent forwards the request to the upstream and pipes the response back.
func (p *Proxy) proxyTransparent(conn net.Conn, req *http.Request) {
	// Remove hop-by-hop headers
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")
	req.RequestURI = ""

	resp, err := p.transport.RoundTrip(req)
	if err != nil {
		writeError(conn, http.StatusBadGateway, err.Error())
		return
	}
	defer resp.Body.Close()
	p.forwardResponse(conn, resp, nil)
}

// forwardResponse writes an HTTP response back to the client connection.
// If body is non-nil it overrides resp.Body (used after buffering the tarball).
func (p *Proxy) forwardResponse(conn net.Conn, resp *http.Response, body []byte) {
	if body != nil {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
	}
	resp.Write(conn)
}

// writeError writes a plain HTTP error response directly to the connection.
func writeError(conn net.Conn, code int, msg string) {
	body := []byte(msg)
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nX-Cipher-Shield: blocked\r\n\r\n%s",
		code, http.StatusText(code), len(body), body)
}

// npm tarball pattern: /pkgname/-/pkgname-1.2.3.tgz or /@scope/pkg/-/pkg-1.2.3.tgz
var npmTarballRe = regexp.MustCompile(`^/(@[^/]+/[^/]+|[^@/][^/]*)/-/[^/]+-(\d[^/]*)\.tgz$`)

// pypi sdist/wheel: /packages/.../*.tar.gz or /packages/.../*.whl
var pypiTarballRe = regexp.MustCompile(`/packages/[^/]+/[^/]+/[^/]+/([^/-]+)-([^/-][^/]*)(?:-[^/]+)?\.(?:tar\.gz|whl)$`)

// detectTarball checks whether the request is fetching a package tarball.
// Returns the PackageRef and true if it is, or zero value and false otherwise.
func detectTarball(req *http.Request) (shield.PackageRef, bool) {
	path := req.URL.Path

	// npm
	if m := npmTarballRe.FindStringSubmatch(path); m != nil {
		name := m[1]
		version := strings.TrimSuffix(m[2], ".tgz")
		return shield.PackageRef{
			Ecosystem: shield.EcosystemNPM,
			Name:      name,
			Version:   version,
		}, true
	}

	// PyPI
	if m := pypiTarballRe.FindStringSubmatch(path); m != nil {
		name := normalizePyPI(m[1])
		version := m[2]
		return shield.PackageRef{
			Ecosystem: shield.EcosystemPyPI,
			Name:      name,
			Version:   version,
		}, true
	}

	return shield.PackageRef{}, false
}

func normalizePyPI(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "-")
	return strings.ReplaceAll(name, ".", "-")
}

func isPyPISimple(path string) bool {
	return strings.HasPrefix(path, "/simple/") && !strings.HasPrefix(path, "/packages/")
}

// shouldBlockName checks a package name against Tier 1 and the exception list.
// In enforce mode it returns true (block). In warn/audit mode it logs a warning
// but always returns false so the request passes through.
func (p *Proxy) shouldBlockName(ctx context.Context, eco shield.Ecosystem, name string) bool {
	if p.cfg.NameChecker == nil {
		return false
	}
	pkg := shield.PackageRef{Ecosystem: eco, Name: name}
	findings, err := p.cfg.NameChecker.CheckName(ctx, pkg)
	if err != nil || len(findings) == 0 {
		return false
	}
	for _, f := range findings {
		if f.Severity != shield.SeverityCritical && f.Severity != shield.SeverityHigh {
			continue
		}
		if p.cfg.Exceptions != nil && p.cfg.Exceptions.IsExcepted(eco, name, "") {
			log.Printf("[proxy] name check: %s (%s) known-bad but excepted — passing through", name, eco)
			return false
		}
		if p.cfg.Mode == ModeEnforce {
			log.Printf("[proxy] name check: %s (%s) BLOCKED at metadata level", name, eco)
			return true
		}
		// warn / audit: flag it but do not block
		log.Printf("[proxy] WARNING: %s (%s) is known-bad — passing through (mode=%s)", name, eco, p.cfg.Mode)
		return false
	}
	return false
}

// detectNPMMeta returns the package name if the request is an npm metadata
// lookup (not a tarball). Scoped packages (@scope/name) are handled correctly.
var npmMetaRe = regexp.MustCompile(`^/(@[^/]+/[^/]+|[^@/][^/]*)`)

func detectNPMMeta(req *http.Request) (string, bool) {
	if req.Method != "GET" {
		return "", false
	}
	path := req.URL.Path
	if npmTarballRe.MatchString(path) || isPyPIPath(path) {
		return "", false
	}
	m := npmMetaRe.FindStringSubmatch(path)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// handlePyPISimple fetches a PyPI simple API page and rewrites all download
// URLs to route back through this proxy, so the tarball intercept fires.
func (p *Proxy) handlePyPISimple(conn net.Conn, req *http.Request) {
	// Extract package name from /simple/<name>/ and check Tier 1
	parts := strings.SplitN(strings.Trim(req.URL.Path, "/"), "/", 3)
	if len(parts) >= 2 && parts[0] == "simple" && parts[1] != "" {
		if p.shouldBlockName(context.Background(), shield.EcosystemPyPI, parts[1]) {
			writeError(conn, http.StatusForbidden, fmt.Sprintf(
				"BLOCKED: %s — known malicious package\nRun 'cipher-shield explain %s' for details.", parts[1], parts[1]))
			return
		}
	}
	upstream := *req.URL
	upstream.Scheme = "https"
	upstream.Host = "pypi.org"
	upReq, err := http.NewRequest("GET", upstream.String(), nil)
	if err != nil {
		writeError(conn, http.StatusBadGateway, "bad simple request")
		return
	}
	upReq.Header.Set("Accept", req.Header.Get("Accept"))
	upReq.Header.Set("User-Agent", req.Header.Get("User-Agent"))

	resp, err := p.transport.RoundTrip(upReq)
	if err != nil {
		writeError(conn, http.StatusBadGateway, err.Error())
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		writeError(conn, http.StatusBadGateway, "read error")
		return
	}

	// Rewrite https://files.pythonhosted.org/packages/... → /packages/...
	// so pip downloads tarballs through this proxy instead of directly.
	// Use the address pip actually connected to, not the raw listen address
	// (which may be ":7070" with no host when bound to all interfaces).
	proxyHost := p.cfg.ListenAddr
	if proxyHost == "" || proxyHost[0] == ':' {
		proxyHost = "localhost" + proxyHost
	}
	rewritten := strings.ReplaceAll(string(body), "https://files.pythonhosted.org", "http://"+proxyHost)

	resp.Body = io.NopCloser(strings.NewReader(rewritten))
	resp.ContentLength = int64(len(rewritten))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(rewritten)))
	resp.Write(conn)
}

// upstreamURL rewrites the request URL to point to the real upstream registry.
// npm proxy: point to registry.npmjs.org
// PyPI proxy: detect by path prefix since the client always hits 127.0.0.1
func upstreamURL(req *http.Request) *url.URL {
	u := *req.URL
	path := req.URL.Path
	switch {
	case isPyPIPath(path):
		if strings.HasPrefix(path, "/packages/") {
			// Tarball download — hosted on files.pythonhosted.org, not pypi.org
			u.Host = "files.pythonhosted.org"
		} else {
			u.Host = "pypi.org"
		}
	default:
		u.Host = "registry.npmjs.org"
	}
	u.Scheme = "https"
	return &u
}

func isPyPIPath(path string) bool {
	return strings.HasPrefix(path, "/simple/") || strings.HasPrefix(path, "/packages/")
}
