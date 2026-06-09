# cipher-shield

AI-powered package security firewall for npm and PyPI. Blocks malicious packages before they install — on dev workstations and in CI.

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
   warn  → package installed, alert logged
   block → 403 returned, install aborted
```

**Intercept 1 — metadata request**: When npm or pip asks the registry for package metadata, the proxy checks the package name against the known-bad list before the registry even responds. This catches packages that have been removed from the registry (no tarball exists to scan) and stops the install at the earliest possible point.

**Intercept 2 — tarball download**: The full four-tier pipeline runs against the actual package file.

**Tier 1 — Known-bad list**: ~30 confirmed malicious packages (event-stream, colourama, etc.) matched by name + version. Typosquatting detection via Levenshtein distance against 125+ popular npm and PyPI packages.

**Tier 2 — CVE**: Queries [OSV.dev](https://osv.dev) for known vulnerabilities. No API key required.

**Tier 3 — Heuristic**: Extracts the tarball and scores the code for suspicious patterns: network calls in install scripts, base64+exec chains, env-var exfiltration, obfuscation, remote script execution. Score 0–100.

**Tier 4 — Claude Opus**: Runs only when the heuristic score ≥ 30 or a high-CVSS CVE is found. Claude reads the actual install scripts and source code and returns a structured verdict with reasoning. This is the main differentiator — real code comprehension, not just signatures.

Results are cached (24 h for clean, 1 h for warn/block) so each unique package version is only analyzed once.

---

## Install

### Dev workstation (one-liner)

```sh
curl -fsSL https://raw.githubusercontent.com/homes853/cipher-shield/master/install.sh | sh
```

The installer:
- Downloads the `cipher-shield` binary to `/usr/local/bin`
- Installs a macOS LaunchAgent or Linux systemd user unit so the proxy starts automatically on login
- Saves your `ANTHROPIC_API_KEY` to `~/.cipher-shield/cipher-shield.env`

To enable Claude Opus analysis, set your API key before running:

```sh
export ANTHROPIC_API_KEY=sk-ant-...
curl -fsSL .../install.sh | sh
```

### Build from source

```sh
git clone https://github.com/homes853/cipher-shield
cd cipher-shield
go build ./cmd/shield     # CLI + proxy daemon
go build ./cmd/server     # team server (proxy + API + dashboard)
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

# Stop — restores original npm/pip config
cipher-shield proxy stop

# Status
cipher-shield proxy status
```

The proxy listens on `127.0.0.1:7070` by default. Change with `--addr` or `SHIELD_PROXY_ADDR`.

### CLI scan

```sh
# Scan a lockfile (all packages, no tarball — tiers 1+2 only)
cipher-shield scan lockfile package-lock.json
cipher-shield scan lockfile requirements.txt
cipher-shield scan lockfile yarn.lock
cipher-shield scan lockfile poetry.lock

# Scan a single package (downloads tarball — all four tiers)
cipher-shield scan package lodash@4.17.21
cipher-shield scan package requests@2.31.0 --ecosystem pypi

# Exit codes for CI integration:
# 0 — all clean
# 1 — one or more warnings
# 2 — one or more blocked packages
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

### Team server

For shared infrastructure, run the server binary which combines the registry proxy, REST API, and web dashboard on a single process:

```sh
# Using docker-compose (recommended)
cp configs/docker-compose.yml .
SHIELD_JWT_SECRET=$(openssl rand -hex 32) \
SHIELD_PROXY_TOKEN=$(openssl rand -hex 32) \
ANTHROPIC_API_KEY=sk-ant-... \
DB_PASSWORD=changeme \
docker compose up -d

# Proxy:     localhost:7070
# Dashboard: localhost:8080
```

---

## Deployment

### Model A — Central proxy (simplest)

Everyone points their npm and pip at the team server. All analysis runs centrally.

```sh
# On each dev machine
npm config set registry http://shield.internal:7070
pip config set global.index-url http://shield.internal:7070/simple/
```

### Model C — Local proxy + central server (recommended for teams)

Each developer runs `cipher-shield proxy start` on their own machine. Analysis runs locally for speed. The central server provides the dashboard, scan history, and exception management — and pushes exceptions back to each local proxy.

```sh
# On each dev machine — connect the local proxy to the team server
export SHIELD_SERVER_URL=https://shield.internal:8080
export SHIELD_PROXY_TOKEN=<shared token from server config>
cipher-shield proxy start
```

When `SHIELD_SERVER_URL` is set, the local proxy:
- Sends every scan result to the central server (visible on the dashboard)
- Fetches the exception list from the server on startup and refreshes it every 60 seconds

This means a security engineer can add an exception on the dashboard and it reaches all dev machines within a minute, without anyone restarting anything.

### Cloud deployment guides

Step-by-step guides for deploying the team server:

| Cloud | Guide | Architecture | Est. cost |
|---|---|---|---|
| AWS | [docs/deploy-aws.md](docs/deploy-aws.md) | EC2 + RDS PostgreSQL | ~$30/mo |
| GCP | [docs/deploy-gcp.md](docs/deploy-gcp.md) | Cloud Run + Cloud SQL | ~$15/mo |
| Azure | [docs/deploy-azure.md](docs/deploy-azure.md) | Container Instances + PostgreSQL Flexible Server | ~$35/mo |

All guides cover: database setup, container deployment, first-user bootstrap, dev machine configuration, and teardown.

---

## Configuration

| Variable | Default | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | Enables Claude Opus analysis. Without it, only tiers 1–3 run. |
| `SHIELD_MODE` | `enforce` | `enforce` blocks, `warn` logs but never blocks, `audit` is fully transparent |
| `SHIELD_PROXY_ADDR` | `127.0.0.1:7070` | Proxy listen address |
| `SHIELD_API_ADDR` | `:8080` | API + dashboard listen address (server only) |
| `SHIELD_JWT_SECRET` | — | Required for dashboard auth. Generate with `openssl rand -hex 32`. |
| `SHIELD_PROXY_TOKEN` | — | Pre-shared token authenticating dev proxies to the central server. Generate with `openssl rand -hex 32`. |
| `SHIELD_SERVER_URL` | — | URL of the central server. When set, the local proxy ships scan results to the server and syncs exceptions from it. |
| `SHIELD_TLS_CERT` | — | Path to TLS certificate file. When set (with `SHIELD_TLS_KEY`), enables HTTPS on the API port. |
| `SHIELD_TLS_KEY` | — | Path to TLS private key file. |
| `SHIELD_CORS_ORIGIN` | `*` | Restrict CORS to a specific origin, e.g. `https://shield.company.com`. |
| `SHIELD_DB_PATH` | `~/.cipher-shield/shield.db` | SQLite path (local mode) |
| `DATABASE_URL` | — | Postgres DSN. When set, uses Postgres instead of SQLite. |

---

## Exceptions

When a package is flagged but intentional, add an exception through the dashboard or API. Exceptions are checked before any block verdict is returned — at both the metadata and tarball level.

```sh
# Allow a specific version
curl -X POST http://localhost:8080/api/v1/exceptions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ecosystem":"npm","name":"left-pad","version":"1.3.0","reason":"used by legacy build, reviewed"}'

# Wildcard — allow all versions (use for packages you fully control)
  -d '{"ecosystem":"npm","name":"@company/internal-lib","version":"","reason":"internal package"}'
```

**On the team server**: exceptions take effect immediately for all traffic flowing through the server's proxy.

**On dev proxies (Model C)**: exceptions are synced from the server every 60 seconds. A newly added exception reaches all dev machines within a minute without any restart.

---

## API

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/v1/health` | none | Liveness check |
| `GET` | `/api/v1/config` | none | Server capabilities (`auth_enabled`, `mode`, `version`) |
| `POST` | `/api/v1/auth/login` | none | `{email, password}` → `{token}` |
| `GET` | `/api/v1/auth/me` | JWT | Current user from token |
| `GET` | `/api/v1/users` | admin JWT | List all users |
| `POST` | `/api/v1/users` | admin JWT (or none when empty) | Create user; first user auto-becomes admin |
| `POST` | `/api/v1/users/{id}/reset-password` | admin JWT | Reset a user's password |
| `POST` | `/api/v1/scan/package` | JWT | Scan `{ecosystem, name, version}` |
| `POST` | `/api/v1/scan/lockfile` | JWT | Scan uploaded lockfile |
| `GET` | `/api/v1/history` | JWT | Recent scan results |
| `GET` | `/api/v1/exceptions` | JWT | List exceptions |
| `POST` | `/api/v1/exceptions` | JWT | Add exception |
| `DELETE` | `/api/v1/exceptions/{id}` | JWT | Remove exception |
| `POST` | `/api/v1/report` | proxy token | Dev proxy ships a scan result to the server |
| `GET` | `/api/v1/proxy/exceptions` | proxy token | Dev proxy fetches the current exception list |

---

## CI integration

```yaml
# GitHub Actions
- name: Scan dependencies
  run: |
    curl -fsSL https://raw.githubusercontent.com/homes853/cipher-shield/master/install.sh | sh
    cipher-shield scan lockfile package-lock.json
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

The CLI exits 2 on any blocked package, failing the workflow.

---

## Architecture

```
cmd/
  shield/       CLI binary — scan + proxy start/stop/status
  server/       Server binary — proxy + API + dashboard

internal/
  pipeline/     Orchestrates the four analysis tiers
  analyzer/
    badlist/    Known-bad list + typosquatting (Levenshtein)
    cve/        OSV.dev CVE lookup
    heuristic/  Tarball scoring — regex patterns on install scripts
    claude/     Claude Opus deep analysis
  proxy/        HTTP proxy — intercepts npm/pip metadata + tarballs
  proxyctl/     PID management, npm/pip registry save/restore
  reporter/     Ships scan results to central server; caches exception list
  lockfile/     Parsers for package-lock.json, yarn.lock, requirements.txt, poetry.lock
  db/           Store interface — SQLite (local) + Postgres (team)
  api/          REST API + JWT auth
```

---

## Uninstall

```sh
curl -fsSL https://raw.githubusercontent.com/homes853/cipher-shield/master/uninstall.sh | sh
```

Removes the binary, daemon, and restores your original npm/pip configuration.
