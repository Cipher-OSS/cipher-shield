# cipher-shield — FAQ & Troubleshooting

Answers to common questions and issues encountered during deployment and testing.

---

## Setup & Configuration

### What's the right mode to start with?

Always start with `SHIELD_MODE=warn` for the first week. In warn mode, cipher-shield logs and alerts on suspicious packages but **never blocks** an install. This lets your team see what it would have caught without any risk of breaking builds.

Switch to `enforce` only after you've confirmed no legitimate internal packages are being flagged. Update `shield_mode` in `terraform.tfvars` (or `SHIELD_MODE` in your Docker config) and redeploy.

### Docker containers can't reach the internet after connecting VPN

This isn't caused by cipher-shield — it's a known side effect of many VPN clients (Cisco AnyConnect, GlobalProtect, etc.) on Linux. When VPN connects, it rewrites iptables rules and can wipe the NAT rule Docker needs for outbound traffic.

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

### How do I scan dependencies in CI?

Use the REST API directly from your CI pipeline:

```yaml
# GitHub Actions example
- name: Scan lock file
  run: |
    curl -s -X POST https://shield.yourdomain.com/api/v1/scan/lockfile \
      -H "Authorization: Bearer ${{ secrets.CIPHER_SHIELD_TOKEN }}" \
      -F "file=@package-lock.json" \
      | jq -e '.verdict != "block"'
```

See the [API reference](../README.md#api) for full details.

---

## Package Flagging & Exceptions

### A legitimate internal package is being blocked

Add an exception through the dashboard (Exceptions tab) or via the API:

```sh
# Allow a specific version
curl -X POST https://shield.yourdomain.com/api/v1/exceptions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ecosystem": "npm",
    "name": "@company/internal-lib",
    "version": "2.1.0",
    "reason": "Internal package — reviewed by security team"
  }'

# Wildcard: allow all versions (use for packages you fully control)
curl -X POST https://shield.yourdomain.com/api/v1/exceptions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ecosystem": "npm",
    "name": "@company/internal-lib",
    "version": "",
    "reason": "Internal package — all versions allowed"
  }'
```

Exceptions take effect immediately and are respected by all four analysis tiers.

### A package is flagged but I disagree with the verdict

If Claude flagged a package you believe is safe:

1. Add an exception with a clear reason (this creates an audit trail).
2. Optionally, paste the Claude reasoning into your internal security ticket for review.

If the heuristic scored a package high but it looks clean on inspection, this is a false positive from Tier 3. The package may use patterns common in legitimate tooling (e.g., network calls in postinstall, base64-encoded strings in build output). Add an exception and note the reason.

### Why did cipher-shield block a package that OSV.dev doesn't know about?

Tier 1 (known-bad list) and Tier 3 (heuristic) can block packages that have no CVE assigned yet. A typosquatter with no CVE will still be caught by Levenshtein distance matching against popular package names.

If you believe a Tier 1 or Tier 3 block is wrong, please [open an issue](https://github.com/cipher-oss/cipher-shield/issues) with the package name and version.

---

## Docker

cipher-shield's Docker image (`ghcr.io/cipher-oss/cipher-shield`) runs the **team server** — registry proxy, dashboard, and API in a single container.

### Running the team server in Docker

```sh
SHIELD_JWT_SECRET=$(openssl rand -hex 32) \
SHIELD_PROXY_TOKEN=$(openssl rand -hex 32) \
DB_PASSWORD=$(openssl rand -hex 32) \
ANTHROPIC_API_KEY="" \
docker compose -f configs/docker-compose.yml up -d
```

See [deploy-docker.md](deploy-docker.md) for the full setup guide.

### The container starts but port 7070 doesn't respond

The container exposes both ports, but the registry proxy (7070) only makes sense for dev machines that can route `npm install` traffic to it. In a typical setup you'd point developers at the server's IP or domain:

```sh
# On each dev machine (or push via MDM/Ansible)
npm config set registry https://proxy.yourdomain.com/
pip config set global.index-url https://proxy.yourdomain.com/simple/
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

For production, use your cloud provider's secret manager rather than plain environment variables. See the relevant deployment guide.

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
psql $DATABASE_URL -c "SELECT user_id, email, role FROM users;"
```

If there's a broken user entry, delete it and retry:

```sh
psql $DATABASE_URL -c "DELETE FROM users;"
```

### How do I rotate the proxy token?

`SHIELD_PROXY_TOKEN` is the pre-shared secret that authenticates developer proxies to the central server. Rotate it by updating the secret in your environment and redeploying — no downtime to developer installs, though there's a brief window where proxies can't ship scan results to the server.

**1. Generate a new token:**
```sh
NEW_TOKEN=$(openssl rand -hex 32)
echo "New token: $NEW_TOKEN — save this before proceeding"
```

**2. Update the secret in your environment:**

- **Docker:** Update `SHIELD_PROXY_TOKEN` in your `.env` or secrets config, then `docker compose up -d`.
- **AWS:** Update the `cipher-proxy-token` secret in Secrets Manager, then force a new ECS deployment on both services.
- **GCP:** `echo -n "$NEW_TOKEN" | gcloud secrets versions add cipher-proxy-token --data-file=-`, then `gcloud run services update` on both services.
- **Azure:** `az containerapp secret set --name cipher-shield-api ... --secrets "proxy-token=$NEW_TOKEN"`, then `az containerapp update` on both apps.

**3. Redeploy order:**

Update the API service first, then the proxy service(s). During the gap between the two deployments, proxies using the old token will get 401s from the API and scan results won't be shipped — but proxies still intercept and block packages locally. Once the proxy service is redeployed with the new token, reporting resumes.

> Dashboard data will have a gap for any packages installed during the rotation window. Blocking is unaffected throughout.

### How do I reset a user's password?

Admins can reset any user's password via the API:

```sh
# Get user IDs
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://shield.yourdomain.com/api/v1/users

# Reset password
curl -X POST https://shield.yourdomain.com/api/v1/users/{user_id}/reset-password \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"password": "newpassword123"}'
```

There is no self-service password reset (no email flow). Password resets go through an admin.

### How do I enable HTTPS on the dashboard?

Pass your certificate and key via environment variables:

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

If Claude (Tier 4) triggers — only for packages with suspicious heuristic scores or high-severity CVEs — that adds 5–15 seconds. This is intentional: Claude only runs when a package looks genuinely dangerous.

### I don't have an Anthropic API key. What do I miss?

Without `ANTHROPIC_API_KEY`, only Tiers 1–3 run:
- Known-bad list and typosquatting detection: still works
- CVE lookup via OSV.dev: still works
- Heuristic scoring (code pattern analysis): still works
- Claude deep analysis: **disabled**

For most organizations, Tiers 1–3 catch the vast majority of threats. Claude adds the deepest analysis for novel or obfuscated attacks.

### How much does Claude analysis cost?

Claude is only invoked when the heuristic score is ≥ 30 or a high-CVSS CVE is found — typically a small fraction of packages. For a team doing ~500 unique package installs per week, expect fewer than 20 Claude calls, costing roughly $0.10–0.50/week at current API pricing.
