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
# {"status":"ok","version":"0.1.4"}
```

---

## 3. Create the first admin account

The first `POST /api/v1/users` request requires no authentication and creates an admin account. After that, the endpoint requires an admin JWT.

```sh
curl -X POST http://<your-server>:8080/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{"email":"you@company.com","password":"changeme","role":"admin"}'
```

Open `http://<your-server>:8080` and log in.

---

## 4. Configure developer machines

**Option A — centralized proxy (no local install required)**

Point npm and pip directly at the server. All installs are intercepted and scanned at the server.

```sh
npm config set registry http://<your-server>:7070
pip config set global.index-url http://<your-server>:7070/simple/
```

Push this via MDM, Ansible, or your onboarding scripts. Scan results appear on the dashboard automatically.

**Option B — local proxy reporting to central server**

Developers install cipher-shield locally. The local proxy handles interception; results are shipped to the central server for dashboard visibility and exception sync.

```sh
export SHIELD_SERVER_URL=http://<your-server>:8080
export SHIELD_PROXY_TOKEN=<the token from step 1>
cipher-shield proxy start
```

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

## HTTPS (recommended for production)

The dashboard and API run plain HTTP by default. For production deployments expose cipher-shield behind a reverse proxy (nginx, Caddy, Traefik) that handles TLS termination, or pass a certificate directly:

```sh
SHIELD_TLS_CERT=/etc/ssl/cipher-shield.crt \
SHIELD_TLS_KEY=/etc/ssl/cipher-shield.key \
...
docker compose -f configs/docker-compose.yml up -d
```

Once HTTPS is enabled, lock CORS:

```sh
SHIELD_CORS_ORIGIN=https://shield.yourcompany.com
```

> The proxy port (7070) should remain on your internal network or VPN — do not expose it to the public internet without TLS.

---

## Teardown

```sh
docker compose -f configs/docker-compose.yml down -v
```

The `-v` flag removes the Postgres volume. Omit it if you want to keep the database.

---

## Next steps

- [Configure exceptions](../README.md#exceptions) for known-safe internal packages
- [CI integration](../README.md#ci-integration) — scan lockfiles in your pipeline
- [API reference](../README.md#api) — automate exception management or query scan history
