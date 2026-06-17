# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | yes       |

We support the latest release only. Please update before reporting a vulnerability.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email **security@cipher-shield.io** with:

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
- The installer scripts (`install.sh`, `install.ps1`)

Out of scope:
- Vulnerabilities in upstream registries (npm, PyPI)
- Vulnerabilities in packages cipher-shield scans (report those to the package maintainer)
- Denial of service against the proxy via crafted packages (log and pass-through is the design)

## Security Design Notes

- The proxy speaks plain HTTP on `127.0.0.1:7070` by default. For team deployments where developer machines connect over a network, configure `SHIELD_PROXY_TLS_CERT` and `SHIELD_PROXY_TLS_KEY` to enable HTTPS on the proxy port.
- Passwords are hashed with bcrypt (cost 12).
- JWTs are signed HS256 with a secret you provide via `SHIELD_JWT_SECRET`. Use `openssl rand -hex 32` to generate one.
- Claude Opus analysis sends package source code to the Anthropic API. If your packages contain proprietary source, review Anthropic's data handling policy before enabling Tier 4.
