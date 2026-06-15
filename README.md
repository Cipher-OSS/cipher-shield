# cipher-shield

AI-powered package security firewall for npm and PyPI. Blocks malicious packages before they install — on developer workstations and in CI.

## How it works

Every package passes through two interception points and up to four tiers of analysis.

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

**Intercept 1 — metadata request**: When npm or pip asks the registry for package metadata, the proxy checks the name against the known-bad list before the registry even responds. This catches packages that have been removed from the registry (no tarball to scan) and stops the install at the earliest possible point.

**Intercept 2 — tarball download**: The full four-tier pipeline runs against the actual package file.

**Tier 1 — Known-bad list**: Confirmed malicious packages (event-stream, colourama, etc.) matched by name and version. Typosquatting detection via Levenshtein distance against 125+ popular npm and PyPI packages.

**Tier 2 — CVE**: Queries [OSV.dev](https://osv.dev) for known vulnerabilities. No API key required.

**Tier 3 — Heuristic**: Extracts the tarball and scores the code for suspicious patterns: network calls in install scripts, base64+exec chains, env-var exfiltration, obfuscation, remote script execution. Score 0–100.

**Tier 4 — Claude Opus**: Runs only when the heuristic score ≥ 30 or a high-CVSS CVE is found. Claude reads the actual install scripts and source code and returns a structured verdict with reasoning. This is the main differentiator — real code comprehension, not just signatures.

Results are cached (4 h for clean packages, 1 h for warn/block) so each unique package version is only analyzed once across your team.

---

## Quickstart for teams

This is the recommended path for engineering organizations. It takes about 10 minutes.

**1. Deploy the team server**

```sh
git clone https://github.com/homes853/cipher-shield
cd cipher-shield

# Generate secrets
export SHIELD_JWT_SECRET=$(openssl rand -hex 32)
export SHIELD_PROXY_TOKEN=$(openssl rand -hex 32)
export DB_PASSWORD=$(openssl rand -hex 16)
export ANTHROPIC_API_KEY=sk-ant-...   # optional but recommended

docker compose -f configs/docker-compose.yml up -d
```

The server starts two listeners:
- `:7070` — registry proxy (point npm/pip here)
- `:8080` — web dashboard + REST API

**2. Create your first admin account**

The first `POST /api/v1/users` request requires no authentication and creates an admin account. After that, the endpoint requires an admin JWT.

```sh
curl -s -X POST http://localhost:8080/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{"email":"you@company.com","password":"changeme","role":"admin"}' | jq
```

Open `http://localhost:8080` and log in.

**3. Configure developer machines**

Each developer runs the local proxy, connected to the team server:

```sh
export SHIELD_SERVER_URL=https://shield.internal:8080
export SHIELD_PROXY_TOKEN=<the token from step 1>
cipher-shield proxy start
```

That's it. All npm and pip installs are now screened. Scan results appear on the team dashboard in real time. Exceptions added on the dashboard sync to all dev machines within 60 seconds.

---

## Install

### Developer workstation (one-liner)

**macOS / Linux**

```sh
export ANTHROPIC_API_KEY=sk-ant-...   # optional — enables Claude analysis
curl -fsSL https://raw.githubusercontent.com/homes853/cipher-shield/master/install.sh | sh
```

The installer:
- Downloads the `cipher-shield` binary to `/usr/local/bin`
- Installs a macOS LaunchAgent or Linux systemd user unit so the proxy starts on login
- Saves `ANTHROPIC_API_KEY` to `~/.cipher-shield/cipher-shield.env`

**Windows (PowerShell)**

```powershell
$env:ANTHROPIC_API_KEY = "sk-ant-..."   # optional — enables Claude analysis
irm https://raw.githubusercontent.com/homes853/cipher-shield/master/install.ps1 | iex
```

The installer:
- Downloads `cipher-shield.exe` to `%LOCALAPPDATA%\cipher-shield\bin`
- Adds that directory to your user PATH
- Saves `ANTHROPIC_API_KEY` to `%USERPROFILE%\.cipher-shield\cipher-shield.env`

Restart your terminal after install for PATH changes to take effect.

### Build from source

```sh
git clone https://github.com/homes853/cipher-shield
cd cipher-shield
go build ./cmd/shield     # CLI + local proxy daemon
go build ./cmd/server     # team server (proxy + API + dashboard)
go build ./cmd/proxy      # standalone proxy (lightweight, no dashboard)
```

Requires Go 1.22+. CGO must be enabled for SQLite (`go-sqlite3`).

---

## Usage

### Proxy mode (recommended for dev workstations)

```sh
# Start — automatically configures npm and pip to route through the proxy
cipher-shield proxy start

# All installs are now screened:
npm install lodash          # passes through
npm install colourama       # BLOCKED — known typosquatter of colorama
pip install reqeusts        # BLOCKED — typosquatter of requests

# Stop — restores original npm/pip configuration
cipher-shield proxy stop

# Status
cipher-shield proxy status
```

The proxy listens on `127.0.0.1:7070` by default. Change with `SHIELD_PROXY_ADDR`.

### CLI scan

```sh
# Scan a lockfile (fast — Tier 1+2 only, no tarball download)
cipher-shield scan lockfile package-lock.json
cipher-shield scan lockfile requirements.txt
cipher-shield scan lockfile yarn.lock
cipher-shield scan lockfile poetry.lock

# Scan a single package (downloads tarball — all four tiers run)
cipher-shield scan package lodash@4.17.21
cipher-shield scan package requests@2.31.0 --ecosystem pypi

# Exit codes:
#  0 — all packages clean
#  1 — one or more warnings
#  2 — one or more blocked packages
```

Example output:

```
Scanning 147 packages from package-lock.json...

  lodash@4.17.21                           CLEAN
  axios@1.6.0                              CLEAN
  event-stream@3.3.6                       BLOCK
    → [critical] Known malicious package (cryptocurrency theft)

─────────────────────────────────────────
Summary: 146 clean, 0 warn, 1 block
```

### Explain a blocked package

When the proxy blocks an install, it tells you to run `cipher-shield explain <name>`. This looks up the last cached scan result and prints the full findings:

```sh
cipher-shield explain colourama
# Package:  colourama@0.4.3 (npm)
# Verdict:  BLOCK
# Scanned:  2024-06-12 14:32 UTC
#
# Findings:
#   1. [CRITICAL] Known malicious package: colourama
#      Confirmed typosquatter of colorama. Contains credential-stealing code.
```

If the package hasn't been scanned yet, it tells you to run `cipher-shield scan package <name>` first.

### Update the known-bad list

The known-bad list is embedded at build time. To fetch the latest list without rebuilding:

```sh
cipher-shield update
```

This downloads the latest `known_bad.json` to `~/.cipher-shield/known_bad.json`, which takes precedence over the embedded list on the next proxy start.

### Team server

For shared infrastructure, run the server binary which combines the registry proxy, REST API, and web dashboard:

```sh
# Using Docker Compose (recommended)
cp configs/docker-compose.yml .
SHIELD_JWT_SECRET=$(openssl rand -hex 32) \
SHIELD_PROXY_TOKEN=$(openssl rand -hex 32) \
ANTHROPIC_API_KEY=sk-ant-... \
DB_PASSWORD=changeme \
docker compose up -d

# Proxy:     localhost:7070
# Dashboard: localhost:8080
```

After starting the server, create your first admin user (see [Quickstart](#quickstart-for-teams)).

---

## Deployment

### Model A — Central proxy (simplest)

The team server acts as the registry. All developer machines point their npm and pip directly at it. No local agent required.

```sh
# Run once on each developer machine (or push via MDM/Ansible)
npm config set registry http://shield.internal:7070
pip config set global.index-url http://shield.internal:7070/simple/
```

Best for: small teams, locked-down environments, CI-only usage.

### Model B — Local proxy, no central server

Each developer runs `cipher-shield proxy start` on their own machine. Analysis runs locally. No central server or dashboard — scan results stay on the developer's machine.

```sh
# On each developer machine
cipher-shield proxy start
```

Best for: individual developers, open source contributors, offline environments.

### Model C — Local proxy + central server (recommended)

Each developer runs `cipher-shield proxy start` locally. Analysis runs on the developer's machine for speed. The central server provides the shared dashboard, scan history, and exception management. Exceptions sync to all local proxies every 60 seconds.

```sh
# On each developer machine
export SHIELD_SERVER_URL=https://shield.internal:8080
export SHIELD_PROXY_TOKEN=<shared token>
cipher-shield proxy start
```

Best for: engineering organizations that want central visibility and shared exception management.

### Cloud deployment guides

Step-by-step guides for deploying the team server:

| Cloud | Guide | Architecture | Est. cost |
|---|---|---|---|
| AWS | [docs/deploy-aws.md](docs/deploy-aws.md) | EC2 + RDS PostgreSQL | ~$30/mo |
| GCP | [docs/deploy-gcp.md](docs/deploy-gcp.md) | Cloud Run + Cloud SQL | ~$15/mo |
| Azure | [docs/deploy-azure.md](docs/deploy-azure.md) | Container Instances + PostgreSQL Flexible Server | ~$35/mo |

All guides cover: database setup, container deployment, first-user bootstrap, developer machine configuration, and teardown.

---

## Configuration

| Variable | Default | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | Enables Claude Opus analysis (Tier 4). Without it, only Tiers 1–3 run. |
| `SHIELD_MODE` | `enforce` | `enforce` blocks malicious packages. `warn` logs but never blocks. `audit` is fully transparent. |
| `SHIELD_PROXY_ADDR` | `127.0.0.1:7070` | Registry proxy listen address. |
| `SHIELD_API_ADDR` | `:8080` | Dashboard + API listen address (server binary only). |
| `SHIELD_JWT_SECRET` | — | Secret for signing dashboard JWTs. Required for dashboard auth. Generate with `openssl rand -hex 32`. |
| `SHIELD_PROXY_TOKEN` | — | Pre-shared token that authenticates dev proxies to the central server. Generate with `openssl rand -hex 32`. |
| `SHIELD_SERVER_URL` | — | URL of the central server. When set, the local proxy ships scan results to the server and syncs exceptions from it. |
| `SHIELD_TLS_CERT` | — | Path to TLS certificate file. When set alongside `SHIELD_TLS_KEY`, enables HTTPS on the API/dashboard port. |
| `SHIELD_TLS_KEY` | — | Path to TLS private key file. |
| `SHIELD_PROXY_TLS_CERT` | — | Path to TLS certificate file for the registry proxy port (7070). When set alongside `SHIELD_PROXY_TLS_KEY`, the proxy speaks HTTPS instead of HTTP. Required for Model A deployments where developer machines connect over a network. |
| `SHIELD_PROXY_TLS_KEY` | — | Path to TLS private key file for the registry proxy port. |
| `SHIELD_CORS_ORIGIN` | same-origin | Allowed CORS origin for the API. Set to a specific origin (e.g. `https://shield.company.com`) to enable cross-origin requests. |
| `SHIELD_DB_PATH` | `~/.cipher-shield/shield.db` | SQLite database path. Used when `DATABASE_URL` is not set. |
| `DATABASE_URL` | — | Postgres DSN (e.g. `postgres://user:pass@host:5432/shield`). When set, uses Postgres instead of SQLite. |
| `SHIELD_HISTORY_DAYS` | `30` | Days of scan history to retain. Set to `0` to keep forever. |
| `SHIELD_KNOWN_BAD_PATH` | — | Path to a local `known_bad.json` override. Takes precedence over the embedded list. Updated by `cipher-shield update`. |

---

## Exceptions

When a package is flagged but known-safe in your environment, add an exception via the dashboard or API. Exceptions are checked before any block verdict is returned, at both the metadata and tarball level.

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

**Model A / team server**: exceptions take effect immediately for all traffic through the server proxy.

**Model C / local proxies**: exceptions sync from the server every 60 seconds. A new exception reaches all developer machines within a minute with no restarts.

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
| `POST` | `/api/v1/users` | admin JWT (or none on empty table) | Create a user. The very first request requires no auth and creates an admin account. |
| `POST` | `/api/v1/users/{id}/reset-password` | admin JWT | Reset a user's password. |
| `POST` | `/api/v1/scan/package` | JWT | Scan `{ecosystem, name, version}`. Downloads the tarball and runs all four tiers. |
| `POST` | `/api/v1/scan/lockfile` | JWT | Scan an uploaded lockfile. Accepts multipart or raw body with `?filename=`. |
| `GET` | `/api/v1/history` | JWT | Recent scan results. Optional `?limit=N` (max 500). |
| `GET` | `/api/v1/badlist` | JWT | Returns the full known-bad package list (npm + PyPI entries with reasons and severity). |
| `POST` | `/api/v1/findings/expand` | JWT | `{package, finding}` → `{explanation}`. Asks Claude Opus to explain a finding in plain English. Returns 501 if `ANTHROPIC_API_KEY` is not set. |
| `GET` | `/api/v1/exceptions` | JWT | List active exceptions. |
| `POST` | `/api/v1/exceptions` | JWT | Add an exception `{ecosystem, name, version, reason}`. |
| `DELETE` | `/api/v1/exceptions/{id}` | JWT | Remove an exception. |
| `POST` | `/api/v1/report` | proxy token | Internal — dev proxy ships a scan result to the server. |
| `GET` | `/api/v1/proxy/exceptions` | proxy token | Internal — dev proxy fetches the current exception list. |

---

## CI integration

Add cipher-shield to your CI pipeline to catch malicious or vulnerable dependencies before they reach production.

```yaml
# GitHub Actions
- name: Scan dependencies
  run: |
    curl -fsSL https://raw.githubusercontent.com/homes853/cipher-shield/master/install.sh | sh
    cipher-shield scan lockfile package-lock.json
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

The CLI exits `2` on any blocked package, failing the workflow. Exit `1` means warnings only (configure your pipeline to treat this as a failure or not, depending on your policy).

---

## Architecture

```
cmd/
  shield/       CLI binary — scan commands + local proxy start/stop/status
  server/       Team server — registry proxy + REST API + web dashboard
  proxy/        Standalone proxy — lightweight, local pipeline, no dashboard
                (use when you want a local proxy without running the full server)

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
curl -fsSL https://raw.githubusercontent.com/homes853/cipher-shield/master/uninstall.sh | sh
```

**Windows**

```powershell
irm https://raw.githubusercontent.com/homes853/cipher-shield/master/uninstall.ps1 | iex
```

Removes the binary, stops and removes the daemon, and restores your original npm/pip registry configuration.
