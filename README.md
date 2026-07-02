# cipher-shield

AI-powered package firewall for npm and PyPI. Blocks malicious packages before they install — on developer workstations, in CI, and at the team level.

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

**Tier 1 — Known-bad list**: Confirmed malicious packages matched by name and version. Typosquatting detection via Levenshtein distance against 125+ popular npm and PyPI packages. Runs at metadata time — blocks before the tarball is ever downloaded.

**Tier 2 — CVE**: Queries [OSV.dev](https://osv.dev) for known vulnerabilities. No API key required.

**Tier 3 — Heuristic**: Scores the tarball for suspicious patterns — network calls in install scripts, base64+exec chains, env-var exfiltration, obfuscation, remote script execution.

**Tier 4 — Claude Opus** *(optional)*: Runs when the heuristic score ≥ 30 or a high-CVSS CVE is found. Reads the actual install scripts and source code and returns a structured verdict with reasoning. Requires `ANTHROPIC_API_KEY`. Without it, Tiers 1–3 still run and catch the vast majority of threats.

Results are cached (4 h allow, 1 h warn/block) so each package version is only analyzed once.

---

## Get started

### Developer workstation

Install the binary and start the local proxy. npm and pip are configured automatically.

**macOS / Linux**
```sh
export ANTHROPIC_API_KEY=sk-ant-...   # optional — enables Tier 4
curl -fsSL https://raw.githubusercontent.com/cipher-oss/cipher-shield/master/install.sh | sh
cipher-shield proxy start
```

**Windows (PowerShell)**
```powershell
$env:ANTHROPIC_API_KEY = "sk-ant-..."   # optional — enables Tier 4
irm https://raw.githubusercontent.com/cipher-oss/cipher-shield/master/install.ps1 | iex
cipher-shield proxy start
```

The proxy runs on `127.0.0.1:7070`. All npm and pip installs are now screened. Stop with `cipher-shield proxy stop`.

---

### Self-hosted (Docker)

Runs the team server — registry proxy on `:7070`, dashboard + API on `:8080`.

```sh
git clone https://github.com/cipher-oss/cipher-shield
cd cipher-shield

export SHIELD_JWT_SECRET=$(openssl rand -hex 32)
export SHIELD_PROXY_TOKEN=$(openssl rand -hex 32)
export DB_PASSWORD=$(openssl rand -hex 16)
export ANTHROPIC_API_KEY=sk-ant-...   # optional
export SHIELD_MODE=warn               # start in warn mode; switch to enforce after review

docker compose -f configs/docker-compose.yml up -d
```

Bootstrap the first admin account (open endpoint when the users table is empty):

```sh
curl -X POST http://localhost:8080/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{"email":"you@company.com","password":"changeme","role":"admin"}'
```

Open `http://localhost:8080` and log in.

Point developer machines at the server (no local install required):

```sh
npm config set registry http://shield.internal:7070
pip config set global.index-url http://shield.internal:7070/simple/
```

Or run `cipher-shield proxy start` locally with `SHIELD_SERVER_URL=http://shield.internal:8080` to ship results to the central dashboard.

---

### Cloud deployment

Step-by-step Terraform guides for each cloud:

| Cloud | Guide | Architecture | Est. cost |
|---|---|---|---|
| AWS | [docs/deploy-aws.md](docs/deploy-aws.md) | ECS Fargate + RDS PostgreSQL | ~$35–60/mo |
| GCP | [docs/deploy-gcp.md](docs/deploy-gcp.md) | Cloud Run + Cloud SQL | ~$15–30/mo |
| Azure | [docs/deploy-azure.md](docs/deploy-azure.md) | Container Apps + PostgreSQL Flexible Server | ~$20–40/mo |

Each guide covers networking, database setup, container deployment, first-user bootstrap, developer machine configuration, and teardown. Terraform files are in [cipher-shield-infra](https://github.com/Cipher-OSS/cipher-shield-infra).

---

## CI integration

```yaml
# GitHub Actions
- name: Scan dependencies
  run: |
    curl -fsSL https://raw.githubusercontent.com/cipher-oss/cipher-shield/master/install.sh | sh
    cipher-shield scan lockfile package-lock.json
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

Exit codes: `0` clean, `1` warnings, `2` blocked packages. Exit `2` fails the workflow by default.

Supported lockfiles: `package-lock.json`, `yarn.lock`, `requirements.txt`, `poetry.lock`.

---

## CLI reference

```sh
# Proxy
cipher-shield proxy start [--addr 127.0.0.1:7070]   # start proxy, configure npm + pip
cipher-shield proxy stop                              # stop proxy, restore npm + pip
cipher-shield proxy status                            # show proxy status

# Scan
cipher-shield scan lockfile <file>                   # scan lockfile (Tier 1+2, no download)
cipher-shield scan package <name@version>            # scan single package (all tiers)
  --ecosystem npm|pypi

# Explain a block
cipher-shield explain <name[@version]>               # show full findings for a package

# Update known-bad list
cipher-shield update                                 # fetch latest known_bad.json from GitHub
```

---

## Build from source

```sh
git clone https://github.com/cipher-oss/cipher-shield
cd cipher-shield
go build ./cmd/shield     # CLI + local proxy
go build ./cmd/server     # team server (proxy + API + dashboard)
go build ./cmd/proxy      # standalone proxy (no dashboard)
```

Requires Go 1.26+. CGO must be enabled (`go-sqlite3` requires it).

---

## Configuration

| Variable | Default | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | Enables Claude Opus analysis (Tier 4). Without it, only Tiers 1–3 run. |
| `SHIELD_MODE` | `enforce` | `enforce` blocks malicious packages. `warn` logs but never blocks. `audit` is fully transparent. |
| `SHIELD_PROXY_ADDR` | `:7070` (server), `127.0.0.1:7070` (CLI) | Registry proxy listen address. The server binary binds all interfaces by default; the CLI dev proxy binds loopback only. |
| `SHIELD_API_ADDR` | `:8080` | Dashboard + API listen address (server binary only). |
| `SHIELD_JWT_SECRET` | — | Secret for signing dashboard JWTs. Required for dashboard auth. Generate with `openssl rand -hex 32`. |
| `SHIELD_PROXY_TOKEN` | — | Pre-shared token that authenticates dev proxies to the central server. Generate with `openssl rand -hex 32`. |
| `SHIELD_SERVER_URL` | — | URL of the central server. When set, the local proxy ships scan results to the server and syncs exceptions from it. |
| `SHIELD_TLS_CERT` | — | Path to TLS certificate file. Enables HTTPS on the API/dashboard port when set with `SHIELD_TLS_KEY`. |
| `SHIELD_TLS_KEY` | — | Path to TLS private key file. |
| `SHIELD_PROXY_TLS_CERT` | — | Path to TLS certificate for the proxy port (7070). Enables HTTPS on the proxy when set with `SHIELD_PROXY_TLS_KEY`. |
| `SHIELD_PROXY_TLS_KEY` | — | Path to TLS private key for the proxy port. |
| `SHIELD_CORS_ORIGIN` | same-origin | Allowed CORS origin for the API. |
| `SHIELD_DB_PATH` | `~/.cipher-shield/shield.db` | SQLite database path. Used when `DATABASE_URL` is not set. |
| `DATABASE_URL` | — | Postgres DSN (`postgres://user:pass@host:5432/shield`). When set, uses Postgres instead of SQLite. |
| `SHIELD_HISTORY_DAYS` | `30` | Days of scan history to retain. `0` keeps forever. |
| `SHIELD_KNOWN_BAD_PATH` | — | Path to a local `known_bad.json` override. Takes precedence over the embedded list. |

---

## Exceptions

When a package is flagged but known-safe in your environment, add an exception via the dashboard or API. Exceptions are checked before any block verdict at both the metadata and tarball level. Local proxies sync exceptions from the server every 60 seconds.

```sh
# Allow a specific version
curl -X POST http://localhost:8080/api/v1/exceptions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ecosystem":"npm","name":"left-pad","version":"1.3.0","reason":"used by legacy build, reviewed"}'

# Allow all versions (use for packages you fully control)
curl -X POST http://localhost:8080/api/v1/exceptions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ecosystem":"npm","name":"@company/internal-lib","version":"","reason":"internal package"}'
```

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
| `POST` | `/api/v1/scan/package` | JWT | Scan `{ecosystem, name, version}`. Downloads tarball and runs all four tiers. |
| `POST` | `/api/v1/scan/lockfile` | JWT | Scan an uploaded lockfile. Accepts multipart or raw body with `?filename=`. |
| `GET` | `/api/v1/history` | JWT | Recent scan results. Optional `?limit=N` (max 500). |
| `GET` | `/api/v1/badlist` | JWT | Full known-bad package list with reasons and severity. |
| `POST` | `/api/v1/findings/expand` | JWT | `{package, finding}` → `{explanation}`. Claude explains a finding in plain English. Returns 501 without `ANTHROPIC_API_KEY`. |
| `GET` | `/api/v1/exceptions` | JWT | List active exceptions. |
| `POST` | `/api/v1/exceptions` | JWT | Add an exception `{ecosystem, name, version, reason}`. |
| `DELETE` | `/api/v1/exceptions/{id}` | JWT | Remove an exception. |
| `POST` | `/api/v1/report` | proxy token | Internal — dev proxy ships a scan result to the server. |
| `GET` | `/api/v1/proxy/exceptions` | proxy token | Internal — dev proxy fetches the current exception list. |

---

## Architecture

```
cmd/
  shield/       CLI binary — scan commands + local proxy start/stop/status
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
  proxyctl/     PID management, npm/pip registry config save/restore
  reporter/     Ships scan results to central server; caches exception list (60s)
  lockfile/     Parsers: package-lock.json, yarn.lock, requirements.txt, poetry.lock
  db/           Store interface — SQLite (local/dev) + Postgres (team/production)
  api/          REST API handlers, JWT auth, rate limiting
```

---

## Uninstall

**macOS / Linux**
```sh
curl -fsSL https://raw.githubusercontent.com/cipher-oss/cipher-shield/master/uninstall.sh | sh
```

**Windows**
```powershell
irm https://raw.githubusercontent.com/cipher-oss/cipher-shield/master/uninstall.ps1 | iex
```

Removes the binary, stops the daemon, and restores your original npm/pip registry configuration.
