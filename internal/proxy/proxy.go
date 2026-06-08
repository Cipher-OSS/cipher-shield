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

// ResultReporter ships scan results to a central server.
type ResultReporter interface {
	Report(result *shield.ScanResult)
}

// Config holds proxy startup configuration.
type Config struct {
	ListenAddr   string         // e.g. "127.0.0.1:7070"
	Mode         Mode
	MaxBodyBytes int64          // max tarball to buffer (default 50MB)
	Pipeline     Analyzer       // nil = pass everything through (audit)
	Reporter     ResultReporter // nil = local-only, no central reporting
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

	// Check if this is a tarball request we should intercept
	pkg, isTarball := detectTarball(req)
	if isTarball && p.cfg.Pipeline != nil {
		p.handleTarball(conn, req, pkg)
		return
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

// upstreamURL rewrites the request URL to point to the real upstream registry.
// npm proxy: point to registry.npmjs.org
// PyPI proxy: point to pypi.org
func upstreamURL(req *http.Request) *url.URL {
	u := *req.URL
	host := strings.ToLower(req.Host)
	switch {
	case strings.Contains(host, "pypi"):
		u.Host = "pypi.org"
	default:
		u.Host = "registry.npmjs.org"
	}
	u.Scheme = "https"
	return &u
}
