# cipher-shield

AI-powered package security firewall for npm and PyPI. Blocks malicious packages before they install — on dev workstations and in CI.

## How it works

Every package passes through four tiers of analysis in order. Each tier is faster and cheaper than the next; later tiers only run when earlier ones raise suspicion.

```
npm install axios          pip install requests
        │                          │
        ▼                          ▼
┌─────────────────────────────────────────┐
│          cipher-shield proxy            │
│                                         │
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
ANTHROPIC_API_KEY=sk-ant-... \
DB_PASSWORD=changeme \
docker compose up -d

# Proxy:     localhost:7070  →  point npm/pip here
# Dashboard: localhost:8080
```

Point all developers at the shared proxy:

```sh
npm config set registry http://shield.internal:7070
pip config set global.index-url http://shield.internal:7070/simple/
```

---

## Configuration

| Variable | Default | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | Enables Claude Opus analysis. Without it, only tiers 1–3 run. |
| `SHIELD_MODE` | `enforce` | `enforce` blocks, `warn` logs but never blocks, `audit` is fully transparent |
| `SHIELD_PROXY_ADDR` | `127.0.0.1:7070` | Proxy listen address |
| `SHIELD_API_ADDR` | `:8080` | API + dashboard listen address (server only) |
| `SHIELD_JWT_SECRET` | — | Required for dashboard auth. Generate with `openssl rand -hex 32`. |
| `SHIELD_DB_PATH` | `~/.cipher-shield/shield.db` | SQLite path (local mode) |
| `DATABASE_URL` | — | Postgres DSN. When set, uses Postgres instead of SQLite. |

---

## Exceptions

When a package is flagged but intentional, add an exception through the dashboard or API instead of disabling enforcement globally.

```sh
# Allow a specific version
curl -X POST http://localhost:8080/api/v1/exceptions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ecosystem":"npm","name":"left-pad","version":"1.3.0","reason":"used by legacy build, reviewed"}'

# Wildcard — allow all versions (use sparingly)
  -d '{"ecosystem":"npm","name":"internal-lib","version":"","reason":"internal package"}'
```

Exceptions are stored in the database and respected by all tiers. An excepted package returns `allow` immediately without running any analysis.

---

## API

All endpoints except `/api/v1/health` require `Authorization: Bearer <jwt>`.

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/health` | Liveness check |
| `POST` | `/api/v1/auth/login` | `{email, password}` → `{token}` |
| `GET` | `/api/v1/auth/me` | Current user from JWT |
| `POST` | `/api/v1/scan/package` | Scan `{ecosystem, name, version}` |
| `POST` | `/api/v1/scan/lockfile` | Scan uploaded lockfile |
| `GET` | `/api/v1/history` | Recent scan results |
| `GET` | `/api/v1/exceptions` | List exceptions |
| `POST` | `/api/v1/exceptions` | Add exception |
| `DELETE` | `/api/v1/exceptions/{id}` | Remove exception |

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
  proxy/        HTTP forward proxy — intercepts npm/pip tarballs
  proxyctl/     PID management, npm/pip registry save/restore
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
