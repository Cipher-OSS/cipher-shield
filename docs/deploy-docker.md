# Self-hosted deployment (Docker)

Runs the full cipher-shield team server using Docker Compose — registry proxy on `:7070`, dashboard + API on `:8080`, Postgres database managed by Compose.

**Estimated cost:** Self-managed infrastructure. Runs on any Linux VM, home lab, or private server.

---

## Prerequisites

- Docker and Docker Compose installed
- Ports 7070 and 8080 accessible from developer machines

---

## 1. Clone and generate secrets

```sh
git clone https://github.com/cipher-oss/cipher-shield
cd cipher-shield

export SHIELD_JWT_SECRET=$(openssl rand -hex 32)
export SHIELD_PROXY_TOKEN=$(openssl rand -hex 32)
export DB_PASSWORD=$(openssl rand -hex 16)
export ANTHROPIC_API_KEY=sk-ant-...   # optional — enables Tier 4 Claude analysis
```

Save these values somewhere secure — you'll need `SHIELD_PROXY_TOKEN` when configuring developer machines.

---

## 2. Start the server

Start in `warn` mode first. In warn mode cipher-shield logs threats but never blocks installs, giving you time to review what it would have caught before enforcing.

```sh
SHIELD_MODE=warn \
SHIELD_JWT_SECRET=$SHIELD_JWT_SECRET \
SHIELD_PROXY_TOKEN=$SHIELD_PROXY_TOKEN \
DB_PASSWORD=$DB_PASSWORD \
ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
docker compose -f configs/docker-compose.yml up -d
```

Verify it's running:

```sh
curl http://<your-server>:8080/api/v1/health
# {"status":"ok","version":"0.1.5"}
```

---

## 3. Create the first admin account

The first `POST /api/v1/users` request requires no authentication and creates an admin account. After that, the endpoint requires an admin JWT.

```sh
ADMIN_PASSWORD=$(openssl rand -hex 12)
echo "Admin password: $ADMIN_PASSWORD — save this before proceeding"
curl -X POST http://<your-server>:8080/api/v1/users \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"you@company.com\",\"password\":\"${ADMIN_PASSWORD}\",\"role\":\"admin\"}"
```

Open `http://<your-server>:8080` and log in.

---

## 4. Configure developer machines

> **Complete the HTTPS section below before pointing developer machines at the server.** The proxy port transmits every package name your developers install — plain HTTP exposes that traffic to passive observation and MITM attacks.

Point npm and pip directly at the server. All installs are intercepted and scanned at the server.

```sh
npm config set registry https://proxy.yourdomain.com/
pip config set global.index-url https://proxy.yourdomain.com/simple/
```

Push this via MDM, Ansible, or your onboarding scripts. Scan results appear on the dashboard at `https://shield.yourdomain.com` automatically.

---

## 5. Switch to enforce mode

After reviewing a week of warn-mode activity and confirming no legitimate packages are being flagged, switch to enforce:

```sh
# Edit docker-compose.yml or re-run with SHIELD_MODE=enforce
SHIELD_MODE=enforce \
SHIELD_JWT_SECRET=$SHIELD_JWT_SECRET \
SHIELD_PROXY_TOKEN=$SHIELD_PROXY_TOKEN \
DB_PASSWORD=$DB_PASSWORD \
ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
docker compose -f configs/docker-compose.yml up -d
```

---

## HTTPS (required for production)

> **The proxy port (7070) transmits every package name your developers install.** Running it over plain HTTP exposes that traffic to passive observation and MITM attacks. Do not expose a plain HTTP proxy to anything outside a trusted LAN.

Expose cipher-shield behind a reverse proxy (nginx, Caddy, Traefik) that handles TLS termination, or pass a certificate directly. Either way, restart with `SHIELD_CORS_ORIGIN` set so the dashboard can make API calls from the browser:

```sh
SHIELD_MODE=warn \
SHIELD_JWT_SECRET=$SHIELD_JWT_SECRET \
SHIELD_PROXY_TOKEN=$SHIELD_PROXY_TOKEN \
DB_PASSWORD=$DB_PASSWORD \
ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
SHIELD_CORS_ORIGIN=https://shield.yourdomain.com \
SHIELD_TLS_CERT=/etc/ssl/cipher-shield.crt \
SHIELD_TLS_KEY=/etc/ssl/cipher-shield.key \
docker compose -f configs/docker-compose.yml up -d
```

If you're terminating TLS at a reverse proxy instead, omit `SHIELD_TLS_CERT` and `SHIELD_TLS_KEY` — but still set `SHIELD_CORS_ORIGIN` to your dashboard's public URL.

> The proxy port (7070) should remain on your internal network or VPN — do not expose it to the public internet without TLS.

---

## Teardown

```sh
# Stop services, keep the database
docker compose -f configs/docker-compose.yml down

# Full teardown including database data (irreversible)
docker compose -f configs/docker-compose.yml down -v
```

---

## Corporate proxies and secure web gateways

If your organization runs Cisco Umbrella, Zscaler, Netskope, or a similar SWG, see **[Network and corporate proxy requirements →](network.md)** for the one-time policy changes needed to allow cipher-shield traffic through.

---

## Next steps

- [Configure exceptions](../README.md#exceptions) — allow known-safe internal packages
- [API reference](../README.md#api) — automate exception management or query scan history
