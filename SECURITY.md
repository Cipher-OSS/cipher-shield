# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | yes       |

We support the latest release only. Please update before reporting a vulnerability.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email **security@cipher-ai.app** with:

- A description of the vulnerability and its potential impact
- Steps to reproduce
- Affected versions
- Any suggested mitigations (optional)

You will receive an acknowledgement within 48 hours and a status update within 7 days.

We follow coordinated disclosure: we ask that you give us 90 days to investigate and ship a fix before publishing details publicly.

## Scope

In scope:
- The registry proxy (package interception logic)
- The analysis pipeline (false negatives that allow malicious packages through)
- The REST API and dashboard (auth, injection, data exposure)
- The Docker image and release binaries

Out of scope:
- Vulnerabilities in upstream registries (npm, PyPI)
- Vulnerabilities in packages cipher-shield scans (report those to the package maintainer)
- Denial of service against the proxy via crafted packages that cause the analyzer to error or time out — in `enforce` mode the proxy fails closed (blocks the install) rather than shipping an unscanned package, so the worst case is a blocked install, not a bypassed scan

## Security Design Notes

- The proxy speaks plain HTTP on `127.0.0.1:7070` by default. For team deployments where developer machines connect over a network, configure `SHIELD_PROXY_TLS_CERT` and `SHIELD_PROXY_TLS_KEY` to enable HTTPS on the proxy port.
- Passwords are hashed with bcrypt (cost 12).
- JWTs are signed HS256 with a secret you provide via `SHIELD_JWT_SECRET`. Use `openssl rand -hex 32` to generate one.
- Claude Opus analysis sends package source code to the Anthropic API. If your packages contain proprietary source, review Anthropic's data handling policy before enabling Tier 4.
- If `Pipeline.Analyze()` errors (scanner unreachable, Claude/CVE lookup timeout, etc.) in `enforce` mode, the proxy blocks the install rather than passing the package through unscanned — fail closed, not fail open. In `warn`/`audit` mode, which are defined to never block, the error is logged and the package passes through, consistent with those modes' semantics.
- The API's per-IP rate limiters (login attempts and general API traffic) trust the `X-Forwarded-For` header unconditionally, with no trusted-proxy allowlist. If the API is reachable directly from the internet or an untrusted network, a client can spoof a new `X-Forwarded-For` value on every request to get a fresh rate-limit bucket each time, defeating both limiters. **Do not rely on these limiters as your only brute-force defense in that deployment shape.** Put the API behind infrastructure that terminates and re-issues client IP truthfully and/or enforces its own request throttling:
  - **AWS**: AWS WAF (rate-based rule) in front of the ALB, or restrict the ALB security group to known CIDRs
  - **GCP**: Cloud Armor rate-limiting policy on the load balancer in front of Cloud Run
  - **Azure**: Front Door WAF with a rate-limiting rule, or restrict Container Apps ingress to known IPs
  - **Self-hosted/Docker**: an IP allowlist or rate limit at your reverse proxy (nginx `limit_req`, Caddy `rate_limit`, etc.) — see [docs/deploy-docker.md](docs/deploy-docker.md)

  If you do put a trusted reverse proxy or load balancer in front of cipher-shield and want it to see the real client IP for its own logs, that's independent of this limitation — cipher-shield's own rate limiter still shouldn't be treated as authoritative unless you've verified nothing upstream lets a client set `X-Forwarded-For` directly.
