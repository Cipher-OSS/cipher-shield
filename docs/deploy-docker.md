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
export DB_PASSWORD=$(openssl rand -hex 32)
export ANTHROPIC_API_KEY=""   # optional — set to your Anthropic API key to enable Claude analysis
export SHIELD_ADMIN_EMAIL="admin@yourcompany.com"
export SHIELD_ADMIN_PASSWORD=$(openssl rand -hex 12)
echo "Admin password: $SHIELD_ADMIN_PASSWORD — save this before proceeding"
```

Save all values somewhere secure before continuing. `SHIELD_PROXY_TOKEN` is needed when configuring developer machines. `SHIELD_ADMIN_PASSWORD` can be discarded after first login.

---

## 2. Start the server

Start in `warn` mode first. In warn mode cipher-shield logs threats but never blocks installs, giving you time to review what it would have caught before enforcing.

> By default the compose file pulls `ghcr.io/cipher-oss/cipher-shield:latest`. For production, pin a specific release tag by setting `SHIELD_IMAGE_TAG=1.3.0` (check [releases](https://github.com/Cipher-OSS/cipher-shield/releases) for the latest). Using `latest` means an unexpected breaking change in a new release could affect your deployment on the next restart.

```sh
SHIELD_MODE=warn \
SHIELD_JWT_SECRET=$SHIELD_JWT_SECRET \
SHIELD_PROXY_TOKEN=$SHIELD_PROXY_TOKEN \
DB_PASSWORD=$DB_PASSWORD \
ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
SHIELD_ADMIN_EMAIL=$SHIELD_ADMIN_EMAIL \
SHIELD_ADMIN_PASSWORD=$SHIELD_ADMIN_PASSWORD \
docker compose -f configs/docker-compose.yml up -d
```

On first startup, the server creates the admin account and logs `[bootstrap] admin created: admin@yourcompany.com`. Verify it's running:

```sh
curl http://<your-server>:8080/api/v1/health
# {"status":"ok","version":"1.3.0"}
```

Open `http://<your-server>:8080` and log in with the admin credentials. After confirming access, remove `SHIELD_ADMIN_PASSWORD` from your environment and restart the container — it's no longer needed.

---

## 3. Configure developer machines

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
