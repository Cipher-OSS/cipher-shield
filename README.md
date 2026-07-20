# cipher-shield

**Open-source AI package firewall for npm and PyPI.**

cipher-shield intercepts every package install request before it reaches the registry — checking names, versions, CVEs, and source code in real time. Malicious packages are blocked before a single line of code ever runs on your machine or in your pipeline.

It runs entirely in your infrastructure. No package data leaves your network.

---

## How it works

cipher-shield sits between your developers and the public registry. Every `npm install` and `pip install` passes through it automatically — no code changes, no wrappers, no developer friction.

```
npm install axios          pip install requests
        │                          │
        ▼                          ▼
┌─────────────────────────────────────────┐
│          cipher-shield proxy            │
│                                         │
│  ── Intercept 1: metadata request ──   │
│  Tier 1 — Known-bad list     (instant)  │
│                                         │
│  ── Intercept 2: tarball download ──   │
│  Tier 1 — Known-bad list     (instant)  │
│  Tier 2 — CVE / OSV.dev      (network)  │
│  Tier 3 — Heuristic scan     (CPU)      │
│  Tier 4 — Claude Opus        (API)      │
│                                         │
│  verdict: allow / warn / block          │
└─────────────────────────────────────────┘
        │
   allow → package downloaded normally
   warn  → package installed, warning logged
   block → 403 returned, install aborted
```

Packages are intercepted at two points: when the package manager requests metadata (name check) and when it downloads the tarball (full analysis). This means cipher-shield catches malicious packages even when they've been removed from the registry and have no tarball to scan.

Direct and transitive dependencies are both covered — if a dependency of a dependency is malicious, it's blocked.

---

## Analysis pipeline

cipher-shield runs up to four tiers of analysis on every unique package version. Results are cached (4 h allow, 1 h warn/block) so each version is only analyzed once across your team.

**Tier 1 — Known-bad list** *(always on)*
Matches against a curated list of confirmed malicious packages. Typosquatting detection via Levenshtein distance against 125+ popular npm and PyPI packages catches `colourama`, `reqeusts`, `lodahs`, and similar attacks instantly.

**Tier 2 — CVE lookup** *(always on)*
Queries [OSV.dev](https://osv.dev) for published vulnerabilities. No API key required. Covers the full npm and PyPI ecosystems.

**Tier 3 — Heuristic analysis** *(always on)*
Extracts and scores the package source for suspicious patterns: network calls in install scripts, base64+exec chains, environment variable exfiltration, obfuscation, and remote code execution patterns. Produces a risk score from 0–100.

**Tier 4 — Claude Opus** *(optional, requires `ANTHROPIC_API_KEY`)*
Triggers when the heuristic score is ≥ 30 or a high-CVSS CVE is found. Claude reads the actual install scripts and source code and returns a structured verdict with plain-English reasoning — real code comprehension, not just pattern matching. Without an API key, Tiers 1–3 still run and catch the vast majority of threats.

---

## Why self-hosted?

cipher-shield runs entirely in your environment. Package names, versions, and source code never leave your network or touch a third-party API (except OSV.dev for CVE lookups, and optionally Anthropic for Tier 4 analysis).

- **Data stays in your infrastructure** — your packages, your logs, your database
- **Open source** — AGPL v3, auditable, no black boxes
- **No per-seat pricing** — run it for your entire org, deploy it in CI, use the API, all included
- **Bring your own AI** — Tier 4 uses your Anthropic API key billed directly to you, not a markup

---

## Dashboard

The cipher-shield web dashboard gives your security team real-time visibility into package activity across your organization.

- **Scan history** — every package analyzed, with verdict, tier, and full findings
- **Blocked events** — see exactly what was stopped and why, in real time
- **Exception management** — allow known-safe packages with a reason; exceptions sync to all developer proxies within 60 seconds
- **User management** — invite team members, assign admin roles, reset passwords
- **Findings explorer** — click any finding to get a plain-English explanation from Claude

The dashboard is served at `:8080` alongside the REST API. The registry proxy runs on `:7070`.

---

## Deployment

cipher-shield can be deployed two ways depending on your team size and infrastructure requirements.

### Self-hosted team server (Docker)

Runs the full cipher-shield server — registry proxy, dashboard, and API — in Docker with a Postgres database. Deploy it once; point your whole team at it.

Developers point their package managers at the server's proxy address. No local install required on each machine.

See **[Self-hosted deployment guide →](docs/deploy-docker.md)**

---

### Cloud deployment

Deploy cipher-shield into your existing cloud infrastructure. Terraform modules are included in `infra/`. Each guide covers networking, database, container deployment, first-user bootstrap, and teardown.

| Cloud | Terraform | Manual CLI | Architecture | Est. cost |
|---|---|---|---|---|
| AWS | [deploy-aws.md](docs/deploy-aws.md) | [deploy-aws-manual.md](docs/deploy-aws-manual.md) | ECS Fargate + RDS PostgreSQL | ~$50–80/mo |
| GCP | [deploy-gcp-terraform.md](docs/deploy-gcp-terraform.md) | [deploy-gcp.md](docs/deploy-gcp.md) | Cloud Run + Cloud SQL | ~$15–30/mo |
| Azure | [deploy-azure-terraform.md](docs/deploy-azure-terraform.md) | [deploy-azure.md](docs/deploy-azure.md) | Container Apps + PostgreSQL Flexible Server | ~$20–40/mo |

---

## Exceptions

When a package is flagged but known-safe in your environment, add an exception via the dashboard or API. Exceptions are respected at both interception points and sync to all developer proxies within 60 seconds.

```sh
# Allow a specific version
curl -X POST http://<your-server>:8080/api/v1/exceptions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ecosystem":"npm","name":"left-pad","version":"1.3.0","reason":"used by legacy build, reviewed"}'

# Allow all versions (use for internal packages you fully control)
curl -X POST http://<your-server>:8080/api/v1/exceptions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ecosystem":"npm","name":"@company/internal-lib","version":"","reason":"internal package"}'
```

---

## Configuration

| Variable | Default | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | Enables Claude Opus analysis (Tier 4). Without it, only Tiers 1–3 run. |
| `SHIELD_MODE` | `enforce` | `enforce` blocks malicious packages. `warn` logs but never blocks. `audit` is fully transparent. Start with `warn` to validate before enforcing. |
| `SHIELD_PROXY_ADDR` | `:7070` | Registry proxy listen address. |
| `SHIELD_API_ADDR` | `:8080` | Dashboard + API listen address (server binary only). |
| `SHIELD_JWT_SECRET` | — | Secret for signing dashboard JWTs. Required for auth. Generate with `openssl rand -hex 32`. |
| `SHIELD_PROXY_TOKEN` | — | Pre-shared token authenticating dev proxies to the central server. Generate with `openssl rand -hex 32`. |
| `SHIELD_SERVER_URL` | — | URL of the central server. Used by the standalone proxy to ship results and sync exceptions. |
| `SHIELD_TLS_CERT` | — | Path to TLS cert. Enables HTTPS on the API/dashboard port when set with `SHIELD_TLS_KEY`. |
| `SHIELD_TLS_KEY` | — | Path to TLS private key. |
| `SHIELD_PROXY_TLS_CERT` | — | Path to TLS cert for the proxy port (7070). Enables HTTPS on the proxy when set with `SHIELD_PROXY_TLS_KEY`. |
| `SHIELD_PROXY_TLS_KEY` | — | Path to TLS private key for the proxy port. |
| `SHIELD_CORS_ORIGIN` | same-origin | Allowed CORS origin for the API. |
| `SHIELD_DB_PATH` | `~/.cipher-shield/shield.db` | SQLite path. Used when `DATABASE_URL` is not set. |
| `DATABASE_URL` | — | Postgres DSN (`postgres://user:pass@host:5432/shield`). When set, uses Postgres instead of SQLite. |
| `SHIELD_HISTORY_DAYS` | `30` | Days of scan history to retain. `0` keeps forever. |
| `SHIELD_KNOWN_BAD_PATH` | — | Path to a local `known_bad.json` override. Takes precedence over the embedded list. |

---

## API

All authenticated endpoints require `Authorization: Bearer <token>`. Obtain a token from `POST /api/v1/auth/login`.

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/v1/health` | none | Liveness check. |
| `GET` | `/api/v1/config` | none | Server capabilities: `auth_enabled`, `mode`, `version`. |
| `POST` | `/api/v1/auth/login` | none | `{email, password}` → `{token}`. |
| `GET` | `/api/v1/auth/me` | JWT | Returns the current user from the token. |
| `GET` | `/api/v1/users` | admin JWT | List all users. |
| `POST` | `/api/v1/users` | admin JWT (or none on empty table) | Create a user. First request creates an admin with no auth required. |
| `POST` | `/api/v1/users/{id}/reset-password` | admin JWT | Reset a user's password. |
| `POST` | `/api/v1/scan/package` | JWT | Scan `{ecosystem, name, version}`. Downloads tarball, runs all four tiers. |
| `POST` | `/api/v1/scan/lockfile` | JWT | Scan an uploaded lockfile. Accepts multipart or raw body with `?filename=`. |
| `GET` | `/api/v1/history` | JWT | Recent scan results. Optional `?limit=N` (max 500). |
| `GET` | `/api/v1/badlist` | JWT | Full known-bad list with reasons and severity. |
| `POST` | `/api/v1/findings/expand` | JWT | `{package, finding}` → `{explanation}`. Claude explains a finding in plain English. Returns 501 without `ANTHROPIC_API_KEY`. |
| `GET` | `/api/v1/exceptions` | JWT | List active exceptions. |
| `POST` | `/api/v1/exceptions` | JWT | Add an exception `{ecosystem, name, version, reason}`. |
| `DELETE` | `/api/v1/exceptions/{id}` | JWT | Remove an exception. |
| `POST` | `/api/v1/report` | proxy token | Internal — dev proxy ships a scan result to the server. |
| `GET` | `/api/v1/proxy/exceptions` | proxy token | Internal — dev proxy fetches the current exception list. |

---

## Build from source

```sh
git clone https://github.com/cipher-oss/cipher-shield
cd cipher-shield
go build ./cmd/server     # team server (proxy + API + dashboard)
go build ./cmd/proxy      # standalone proxy (reports to server, no dashboard)
```

Requires Go 1.26+. CGO must be enabled (`go-sqlite3` requires it).

---

## Architecture

```
cmd/
  server/       Team server — registry proxy + REST API + web dashboard
  proxy/        Standalone proxy — lightweight, reports to server, no dashboard

internal/
  pipeline/     Orchestrates the four analysis tiers
  analyzer/
    badlist/    Known-bad list + typosquatting (Levenshtein distance)
    cve/        OSV.dev CVE lookup
    heuristic/  Tarball scoring — pattern matching on install scripts + source
    claude/     Claude Opus deep analysis + finding expander
  proxy/        HTTP proxy — intercepts npm/pip metadata and tarball requests
  proxyctl/     npm/pip registry config management
  reporter/     Ships scan results to central server; caches exception list (60s)
  lockfile/     Parsers: package-lock.json, yarn.lock, requirements.txt, poetry.lock
  db/           Store interface — SQLite (local/dev) + Postgres (team/production)
  api/          REST API handlers, JWT auth, rate limiting
```

