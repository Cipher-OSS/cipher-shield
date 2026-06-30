# cipher-shield — FAQ & Troubleshooting

Answers to common questions and issues encountered during deployment and testing.

---

## Setup & Configuration

### What does cipher-shield actually change on my machine?

When you run `cipher-shield proxy start`, it makes two config changes:

```
npm config set registry http://127.0.0.1:7070
pip config set global.index-url http://127.0.0.1:7070/simple/
```

These are written to `~/.npmrc` and `~/.config/pip/pip.conf` (or `~/.pip/pip.conf` on older systems). The original values are saved to `~/.cipher-shield/npm-registry.bak` and `~/.cipher-shield/pip-index-url.bak`.

Running `cipher-shield proxy stop` (or pressing Ctrl+C) restores both files exactly.

### How do I verify the proxy is actually intercepting my installs?

```sh
npm config get registry
# should print: http://127.0.0.1:7070

pip config get global.index-url
# should print: http://127.0.0.1:7070/simple/
```

You can also watch the proxy log in real time:

```sh
# Start in the foreground so you see every intercepted request
cipher-shield proxy start
# In another terminal:
npm install lodash
# You'll see the request logged in the proxy terminal
```

### What's the right mode to start with?

Always start with `SHIELD_MODE=warn` for the first week. In warn mode, cipher-shield logs and alerts on suspicious packages but **never blocks** an install. This lets your team see what it would have caught without any risk of breaking builds.

Switch to `enforce` only after you've confirmed no legitimate internal packages are being flagged.

```sh
export SHIELD_MODE=warn
cipher-shield proxy start
```

---

## VPN & Network Issues

### Installs fail or hang after I connect to VPN

VPN clients often replace routing rules when they connect, which can break the local proxy. Symptoms:
- `npm install` hangs indefinitely
- `pip install` times out
- You see "ECONNREFUSED" or "connection refused" errors

**Fix:** Stop the proxy, reconnect VPN, then restart the proxy:

```sh
cipher-shield proxy stop
# reconnect VPN
cipher-shield proxy start
```

Some VPN clients (Cisco AnyConnect, GlobalProtect) also push DNS or split-tunnel rules that intercept `127.0.0.1` traffic. If restarts don't help, check whether your VPN is routing loopback traffic — this is a VPN misconfiguration and needs to be fixed at the VPN policy level.

### Docker containers can't reach the internet after connecting VPN

This isn't caused by cipher-shield — it's a known side effect of many VPN clients (Cisco AnyConnect, GlobalProtect, etc.) on Linux. When VPN connects, it rewrites iptables rules and can wipe the NAT rule Docker needs for outbound traffic. It can happen on any machine running Docker, regardless of whether cipher-shield is installed.

**Diagnosis:**
```sh
sudo iptables -t nat -L POSTROUTING -n | grep MASQUERADE
# If this returns nothing, Docker's NAT rule is gone
```

**Fix (non-destructive, survives until next reboot):**
```sh
sudo iptables -t nat -A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
```

**Permanent fix:** Add the rule to your VPN reconnect hook, or add it to `/etc/iptables/rules.v4` via iptables-persistent.

### The proxy works on my machine but not in CI

CI environments (GitHub Actions, GitLab CI, Jenkins) typically don't have the proxy running. For CI, use `cipher-shield scan lockfile` directly instead of the proxy:

```yaml
# GitHub Actions example
- name: Scan dependencies
  run: cipher-shield scan lockfile package-lock.json
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

See the [CI integration section in the README](../README.md#ci-integration).

---

## Package Flagging & Exceptions

### A legitimate internal package is being blocked

Add an exception through the dashboard (Exceptions tab) or via the API:

```sh
# Allow a specific version
curl -X POST http://shield.internal:8080/api/v1/exceptions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ecosystem": "npm",
    "name": "@company/internal-lib",
    "version": "2.1.0",
    "reason": "Internal package — reviewed by security team"
  }'

# Wildcard: allow all versions (use for packages you fully control)
  -d '{
    "ecosystem": "npm",
    "name": "@company/internal-lib",
    "version": "",
    "reason": "Internal package — all versions allowed"
  }'
```

Exceptions take effect immediately and are respected by all four analysis tiers.

### A package is flagged but I disagree with the verdict

If Claude Opus flagged a package you believe is safe:

1. Add an exception with a clear reason (this creates an audit trail).
2. Optionally, paste the Claude reasoning into your internal security ticket for review.

If the heuristic scored a package high but it looks clean on inspection, this is a false positive from Tier 3. The package may use patterns common in legitimate tooling (e.g., network calls in postinstall, base64-encoded strings in build output). Add an exception and note the reason.

### Why did cipher-shield block a package that OSV.dev doesn't know about?

Tier 1 (known-bad list) and Tier 3 (heuristic) can block packages that have no CVE assigned yet. A typosquatter with no CVE will still be caught by Levenshtein distance matching against popular package names.

If you believe a Tier 1 or Tier 3 block is wrong, please [open an issue](https://github.com/cipher-oss/cipher-shield/issues) with the package name and version.

---

## Docker

cipher-shield's Docker image (`ghcr.io/cipher-oss/cipher-shield`) is for running the **team server** — not the dev workstation proxy. The dev-side proxy (`cipher-shield proxy start`) runs as a native binary directly on each developer's machine and is not Dockerized.

### Running the team server in Docker

The recommended way is `docker-compose`:

```sh
cp configs/docker-compose.yml .
SHIELD_JWT_SECRET=$(openssl rand -hex 32) \
SHIELD_PROXY_TOKEN=$(openssl rand -hex 32) \
DB_PASSWORD=$(openssl rand -hex 16) \
ANTHROPIC_API_KEY=sk-ant-... \
docker compose up -d
```

This starts two containers: the cipher-shield server (ports 7070 + 8080) and a Postgres database. See the deployment guides for cloud-specific setups.

### The container starts but port 7070 doesn't respond

The container exposes both ports, but the registry proxy (7070) only makes sense for dev machines that can route `npm install` traffic to it. In a typical setup you'd point developers at the server's IP:

```sh
# On each dev machine
npm config set registry http://shield.internal:7070
pip config set global.index-url http://shield.internal:7070/simple/
```

If the proxy port isn't responding, check that Docker published the port correctly:

```sh
docker ps | grep cipher-shield
# Should show: 0.0.0.0:7070->7070/tcp, 0.0.0.0:8080->8080/tcp
```

### Environment variables aren't reaching the container

Docker Compose reads from the `.env` file in the same directory, or from variables exported in your shell. If secrets aren't being picked up:

```sh
# Confirm they're in scope
docker compose config | grep -E "JWT|TOKEN|PASSWORD"
```

For production, use Docker secrets or your cloud provider's secret manager rather than plain environment variables. See the TLS + secrets sections in the relevant deployment guide.

---

## Team Server

### What ports does the server use and what firewall rules do I need?

| Port | Purpose | Who needs access |
|------|---------|-----------------|
| 7070 | Registry proxy (npm/pip traffic) | All developer machines |
| 8080 | Dashboard + REST API | Security team, optionally all developers |

If you're using a VPN or private network, restrict port 8080 to your VPN subnet.

### The first admin user bootstrap isn't working

`POST /api/v1/users` requires no auth only when the users table is completely empty. If a previous attempt partially created a user, the table may not be empty. Check:

```sh
# SQLite (local)
sqlite3 ~/.cipher-shield/shield.db "SELECT * FROM users;"

# Postgres
psql $DATABASE_URL -c "SELECT user_id, email, role FROM users;"
```

If there's a broken user entry, delete it and retry:

```sh
sqlite3 ~/.cipher-shield/shield.db "DELETE FROM users;"
```

### How do I reset a user's password?

Admins can reset any user's password via the API:

```sh
# Get user IDs
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://shield.internal:8080/api/v1/users

# Reset password
curl -X POST http://shield.internal:8080/api/v1/users/{user_id}/reset-password \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"password": "newpassword123"}'
```

There is no self-service password reset (no email flow). Password resets go through an admin.

### How do I enable HTTPS on the dashboard?

Pass your certificate and key at startup:

```sh
shield-server \
  --tls-cert /etc/ssl/cipher-shield.crt \
  --tls-key  /etc/ssl/cipher-shield.key
```

Or via environment variables:

```sh
SHIELD_TLS_CERT=/etc/ssl/cipher-shield.crt
SHIELD_TLS_KEY=/etc/ssl/cipher-shield.key
```

You can use [Let's Encrypt with certbot](https://certbot.eff.org/) to get a free cert. Once HTTPS is enabled, lock down CORS:

```sh
SHIELD_CORS_ORIGIN=https://shield.yourcompany.com
```

If you're using the docker-compose setup, mount your certificates into the container:

```yaml
volumes:
  - /etc/ssl/cipher-shield.crt:/certs/shield.crt:ro
  - /etc/ssl/cipher-shield.key:/certs/shield.key:ro
environment:
  - SHIELD_TLS_CERT=/certs/shield.crt
  - SHIELD_TLS_KEY=/certs/shield.key
  - SHIELD_CORS_ORIGIN=https://shield.yourcompany.com
```

> **Note:** Port 7070 (the registry proxy) stays plain HTTP — don't expose it to the public internet. Keep it on your internal network or VPN.

### npm/pip reject my self-signed certificate

If you put a self-signed cert in front of the proxy port, package managers will reject it by default.

**For npm:**
```sh
npm config set strict-ssl false
# Or point at your CA cert:
npm config set cafile /path/to/your-ca.crt
```

**For pip:**
```sh
pip config set global.cert /path/to/your-ca.crt
```

We recommend a proper CA-signed certificate (Let's Encrypt is free) to avoid configuring each developer's machine.

---

## Performance & Claude Analysis

### Installs feel slower since I turned on the proxy

Each package passes through Tier 1 (instant) and Tier 2 (OSV.dev network lookup) before being allowed. Tier 2 adds ~100–300 ms per unique package.

Once a package is scanned, the result is cached for 4 hours (allow) or 1 hour (warn/block). Repeat installs of the same version are instant.

If Claude Opus (Tier 4) triggers — only for packages with suspicious heuristic scores or high-severity CVEs — that adds 5–15 seconds. This is intentional: Claude only runs when a package looks genuinely dangerous.

### I don't have an Anthropic API key. What do I miss?

Without `ANTHROPIC_API_KEY`, only Tiers 1–3 run:
- Known-bad list and typosquatting detection: still works
- CVE lookup via OSV.dev: still works
- Heuristic scoring (code pattern analysis): still works
- Claude Opus deep analysis: **disabled**

For most organizations, Tiers 1–3 catch the vast majority of threats. Claude adds the deepest analysis for novel or obfuscated attacks.

### How much does Claude analysis cost?

Claude is only invoked when the heuristic score is ≥ 30 or a high-CVSS CVE is found — typically a small fraction of packages. For a team doing ~500 unique package installs per week, expect fewer than 20 Claude calls, costing roughly $0.10–0.50/week at current API pricing.

---

## Restoring to Normal

### How do I completely remove cipher-shield?

```sh
curl -fsSL https://raw.githubusercontent.com/cipher-oss/cipher-shield/master/uninstall.sh | sh
```

This removes the binary, the systemd/LaunchAgent daemon, and restores your original npm/pip configuration.

### My npm/pip config is broken after cipher-shield crashed

If the proxy crashed without a clean shutdown, npm/pip may still point at `127.0.0.1:7070` causing installs to fail with connection refused.

**Fix:**
```sh
# Restore from cipher-shield's backup (if it exists)
[ -f ~/.cipher-shield/npm-registry.bak ] && \
  npm config set registry "$(cat ~/.cipher-shield/npm-registry.bak)"

[ -f ~/.cipher-shield/pip-index-url.bak ] && \
  pip config set global.index-url "$(cat ~/.cipher-shield/pip-index-url.bak)"

# Or reset to defaults manually
npm config set registry https://registry.npmjs.org/
pip config unset global.index-url
```

---

## Windows

The `install.sh` one-liner is for macOS and Linux only. On Windows:

1. Download `cipher-shield-windows-amd64.exe` from the [releases page](https://github.com/cipher-oss/cipher-shield/releases/latest).
2. Rename it to `cipher-shield.exe` and add it to your `PATH`.
3. Run from PowerShell: `cipher-shield proxy start`

npm/pip config is managed identically on Windows (`cipher-shield` calls `npm config set` and `pip config set`). No admin rights required.

---

## Linux

### Managing the systemd user service

The installer creates a user-level systemd unit (no root required). Useful commands:

```sh
# Check whether the service is running
systemctl --user status cipher-shield

# View live logs
journalctl --user -u cipher-shield -f

# Stop the service
systemctl --user stop cipher-shield

# Disable auto-start on login
systemctl --user disable cipher-shield

# Re-enable and start
systemctl --user enable --now cipher-shield
```

The unit file lives at `~/.config/systemd/user/cipher-shield.service` if you need to edit it (e.g. to change the listen address or mode).

### The service starts but npm/pip installs still go to the public registry

The systemd service runs `cipher-shield proxy start`, which sets npm/pip config in your user environment. If you opened a terminal before the service started, that shell's environment may have cached the old registry value.

**Fix:** Open a new terminal, or re-source your shell config:

```sh
# Verify it's been set
npm config get registry       # should be http://127.0.0.1:7070
pip config get global.index-url  # should be http://127.0.0.1:7070/simple/
```

### snap or flatpak npm/pip isn't being intercepted

Snap and Flatpak apps run in isolated environments and ignore your user-level `~/.npmrc` and `~/.config/pip/pip.conf`. If your team uses `snap install node`, the npm inside that snap won't route through the proxy.

**Fix:** Use the `cipher-shield scan lockfile` CLI in CI instead of relying on the proxy for snap-managed runtimes. Alternatively, switch to a non-snap Node.js install (e.g. [nvm](https://github.com/nvm-sh/nvm) or the NodeSource apt repo).

### Port 7070 is already in use

```sh
# Find what's using it
ss -tlnp | grep 7070
# or
lsof -i :7070

# Start on a different port
cipher-shield proxy start --addr 127.0.0.1:7071
```

If you change the port, update npm and pip manually:

```sh
npm config set registry http://127.0.0.1:7071
pip config set global.index-url http://127.0.0.1:7071/simple/
```

---

## macOS Gatekeeper

On macOS, a downloaded binary may be blocked ("cipher-shield cannot be opened because the developer cannot be verified"). Remove the quarantine attribute:

```sh
xattr -d com.apple.quarantine /usr/local/bin/cipher-shield
```

Or right-click → Open in Finder and click "Open" when prompted.
