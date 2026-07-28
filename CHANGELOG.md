# Changelog

All notable changes to cipher-shield are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions correspond to GitHub releases.

---

## [Unreleased]

### Added
- Multi-arch Docker image — `linux/amd64` and `linux/arm64` published on every release tag
- `data/known_bad.json` published at the repo root; point `SHIELD_KNOWN_BAD_URL` at the raw GitHub URL to receive out-of-band threat updates between releases
- Configurable auto-scaling limits for GCP and Azure Terraform (`api_max_count`, `proxy_max_count`, default 10)
- Proxy token rotation procedure documented in FAQ

### Changed
- GitHub Actions pinned to commit SHAs across all workflows (supply chain hardening)
- AWS Terraform auto-scaling cooldowns corrected: scale-out 60 s, scale-in 300 s

### Removed
- Developer CLI (`cmd/shield`) and `internal/proxyctl` — will be reintroduced when the platform is solid

---

## [1.3.0] — 2026-07-23

### Added
- Download event tracking — every tarball fetch is now recorded separately from scan results; visible via `/api/v1/downloads`
- AWS Terraform ECS auto-scaling for both API and proxy services (`api_max_count`, `proxy_max_count`)
- Integration test suite covering the proxy-to-API reporting path

---

## [1.2.0] — 2026-07-21

### Fixed
- npm installs were not being scanned — the proxy rewrote metadata responses but left tarball URLs pointing at the upstream registry, bypassing the scan on download. Tarball URLs are now rewritten to route through the proxy.

---

## [1.1.0] — 2026-07-21

### Added
- `SHIELD_KNOWN_BAD_URL` and `SHIELD_KNOWN_BAD_REFRESH` — pull live known-bad list updates between releases without redeployment
- Terraform modules for AWS (ECS + RDS), GCP (Cloud Run + Cloud SQL), and Azure (Container Apps + PostgreSQL)
- Manual CLI deployment guides for all three clouds
- Network requirements doc covering SWG/corporate proxy configuration (Zscaler, Umbrella, Netskope)
- Standalone proxy binary (`cmd/proxy`) — deployed as a separate service in cloud setups, no direct DB connection required
- Metadata-level Tier 1 blocking — known-bad packages blocked at the name-check stage before the tarball is ever requested
- Exception sync from central server to proxies (60-second TTL)
- TLS support on the proxy port (`SHIELD_PROXY_TLS_CERT` / `SHIELD_PROXY_TLS_KEY`)
- Admin password reset via API (`POST /api/v1/users/{id}/reset-password`)

### Fixed
- Typosquat false positives on short package names (Levenshtein distance now gated by name length)
- Metadata-level name checks now respect version-specific exceptions
- GCP Terraform security hardening — private VPC, Secret Manager for all secrets, no public DB access
- Resilient proxy — auto-heals on start, retries failed reports to server
- Multiple bug fixes: CVSS parsing, PyPI URL rewriting, heuristic double extraction, warn-mode name check, multipart read, duplicate migrations

---

## [1.0.0] — 2026-06-15

First stable release under the [Cipher-OSS](https://github.com/Cipher-OSS) organization (previously `homes853`).

### Added
- HTTPS support on the proxy port
- CORS lockdown (`SHIELD_CORS_ORIGIN`)
- Per-IP rate limiting on login and API endpoints
- `/api/v1/config` endpoint — exposes server capabilities without auth
- Release workflow with build-time version injection
- Lockfile scan UI in the dashboard
- Complete dashboard: scan history, violations, exceptions, user management, findings expander

### Changed
- Unified SQLite and Postgres store implementations behind a single `Store` interface
- Collision-safe scan IDs; `scan_id` validated in `/api/v1/report`

---

## [0.1.x] — 2026-06-17 to 2026-07-15

Pre-release iteration. Highlights:

- Four-tier analysis pipeline: known-bad list, OSV.dev CVE lookup, heuristic scoring, Claude Opus deep analysis
- Proxy → server result reporting with retry and history pruning
- Typosquatting detection via Levenshtein distance against 125+ popular packages
- PyPI proxy intercept fix — silent bypass patched
- Test suite: badlist, lockfile parsers, pipeline, proxy, API handlers (80+ tests)
- Deployment guides for Docker, AWS, GCP, and Azure

---

[Unreleased]: https://github.com/Cipher-OSS/cipher-shield/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/Cipher-OSS/cipher-shield/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/Cipher-OSS/cipher-shield/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Cipher-OSS/cipher-shield/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Cipher-OSS/cipher-shield/compare/v0.1.6...v1.0.0
