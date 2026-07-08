# Deploying cipher-shield on GCP

**Architecture:** Cloud Run + Cloud SQL PostgreSQL.  
Serverless containers — scales to zero when idle, auto-scales under load, fully managed.  
**Estimated cost:** ~$15–30/month (Cloud Run billing is per-request when scaled to zero).

> **Production deployments** — For a custom domain (`npm.yourcompany.com`) with a Google-managed certificate and Global Load Balancer, use the Terraform in [cipher-shield-infra](https://github.com/Cipher-OSS/cipher-shield-infra). This guide covers the manual CLI path for evaluation and testing.

---

## Prerequisites

- `gcloud` CLI installed and authenticated (`gcloud auth login`)
- A GCP project with billing enabled

Enable all required APIs, including `servicenetworking` (required for Cloud SQL private IP):

```bash
gcloud services enable \
  run.googleapis.com \
  sqladmin.googleapis.com \
  secretmanager.googleapis.com \
  vpcaccess.googleapis.com \
  servicenetworking.googleapis.com
```

---

## 1. Set variables

```bash
export PROJECT_ID=$(gcloud config get-value project)
export REGION=us-central1
export SQL_INSTANCE=cipher-shield-pg
export IMAGE=ghcr.io/cipher-oss/cipher-shield:latest
```

---

## 2. Store secrets in Secret Manager

```bash
JWT_SECRET=$(openssl rand -hex 32)
PROXY_TOKEN=$(openssl rand -hex 32)
DB_PASSWORD=$(openssl rand -hex 16)

echo -n "$JWT_SECRET"  | gcloud secrets create cipher-jwt-secret  --data-file=- --project=$PROJECT_ID
echo -n "$PROXY_TOKEN" | gcloud secrets create cipher-proxy-token --data-file=- --project=$PROJECT_ID
echo -n "$DB_PASSWORD" | gcloud secrets create cipher-db-password --data-file=- --project=$PROJECT_ID
```

---

## 3. Set up private service access for Cloud SQL

Cloud SQL private IP requires VPC peering between your VPC and Google's service network. This only needs to be done once per project.

```bash
# Allocate an IP range for Google-managed services
gcloud compute addresses create google-managed-services-default \
  --global \
  --purpose=VPC_PEERING \
  --prefix-length=16 \
  --network=default \
  --project=$PROJECT_ID

# Create the VPC peering connection
gcloud services vpc-peerings connect \
  --service=servicenetworking.googleapis.com \
  --ranges=google-managed-services-default \
  --network=default \
  --project=$PROJECT_ID
```

> If your project already has private service access configured, skip this step. The `gcloud sql instances create` command will error with a VPC peering message if it's missing.

---

## 4. Create Cloud SQL PostgreSQL

```bash
gcloud sql instances create $SQL_INSTANCE \
  --database-version=POSTGRES_16 \
  --tier=db-f1-micro \
  --region=$REGION \
  --no-assign-ip \
  --network=default

gcloud sql databases create shield --instance=$SQL_INSTANCE
gcloud sql users create shield --instance=$SQL_INSTANCE --password="$DB_PASSWORD"

DB_PRIVATE_IP=$(gcloud sql instances describe $SQL_INSTANCE --format=json \
  | jq -r '.ipAddresses[] | select(.type=="PRIVATE") | .ipAddress')
echo "DB_PRIVATE_IP=$DB_PRIVATE_IP"

DB_URL="postgres://shield:${DB_PASSWORD}@${DB_PRIVATE_IP}:5432/shield?sslmode=require"
echo -n "$DB_URL" | gcloud secrets create cipher-db-url --data-file=- --project=$PROJECT_ID
```

---

## 5. Create a VPC connector

Cloud Run needs a VPC connector to reach the Cloud SQL private IP.

```bash
gcloud compute networks vpc-access connectors create cipher-connector \
  --region=$REGION \
  --network=default \
  --range=10.8.0.0/28
```

---

## 6. Grant Secret Manager access to Cloud Run

```bash
PROJECT_NUMBER=$(gcloud projects describe $PROJECT_ID --format='value(projectNumber)')
SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"

for SECRET in cipher-jwt-secret cipher-proxy-token cipher-db-password cipher-db-url; do
  gcloud secrets add-iam-policy-binding $SECRET \
    --member="serviceAccount:$SA" \
    --role="roles/secretmanager.secretAccessor"
done
```

---

## 7. Deploy the API / dashboard (port 8080)

```bash
gcloud run deploy cipher-shield-api \
  --image=$IMAGE \
  --region=$REGION \
  --port=8080 \
  --vpc-connector=cipher-connector \
  --vpc-egress=private-ranges-only \
  --set-env-vars="SHIELD_MODE=enforce" \
  --set-secrets="SHIELD_JWT_SECRET=cipher-jwt-secret:latest,SHIELD_PROXY_TOKEN=cipher-proxy-token:latest,DATABASE_URL=cipher-db-url:latest" \
  --allow-unauthenticated \
  --min-instances=1 \
  --max-instances=4

API_URL=$(gcloud run services describe cipher-shield-api \
  --region=$REGION --format='value(status.url)')
echo "API URL: $API_URL"
```

---

## 8. Deploy the package proxy (port 7070)

Cloud Run only exposes one port per service, so the proxy runs as a second service targeting port 7070. It uses the standalone `cipher-shield-proxy` binary from the same image — no direct database connection needed. It ships scan results to the API service over HTTPS.

```bash
gcloud run deploy cipher-shield-proxy \
  --image=$IMAGE \
  --region=$REGION \
  --port=7070 \
  --command=cipher-shield-proxy \
  --set-env-vars="SHIELD_MODE=enforce,SHIELD_SERVER_URL=${API_URL}" \
  --set-secrets="SHIELD_PROXY_TOKEN=cipher-proxy-token:latest" \
  --allow-unauthenticated \
  --min-instances=1 \
  --max-instances=4

PROXY_URL=$(gcloud run services describe cipher-shield-proxy \
  --region=$REGION --format='value(status.url)')
echo "Proxy URL: $PROXY_URL"
```

---

## 9. Verify

```bash
curl $API_URL/api/v1/health
# {"status":"ok","version":"0.1.4"}
```

---

## 10. Bootstrap the first admin user

```bash
ADMIN_PASSWORD=$(openssl rand -hex 12)
echo "Admin password: $ADMIN_PASSWORD — save this before proceeding"
curl -X POST $API_URL/api/v1/users \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"admin@yourcompany.com\",\"password\":\"${ADMIN_PASSWORD}\",\"role\":\"admin\"}"
```

This endpoint is open when the users table is empty; the first user is forced to `admin`.

---

## 11. Configure dev machines

**Option A — centralized proxy (no cipher-shield install required on each machine):**

Configure pip and npm to use the Cloud Run proxy URL directly. Cloud Run provides HTTPS by default.

```bash
# pip
pip config set global.index-url $PROXY_URL/simple/

# npm
npm config set registry $PROXY_URL/
```

All installs will be intercepted and scanned at the cloud proxy. Results appear in the dashboard at `$API_URL`.

**Option B — local proxy (cipher-shield installed on each developer's machine):**

```bash
export SHIELD_SERVER_URL=$API_URL
export SHIELD_PROXY_TOKEN=<PROXY_TOKEN from step 2>
cipher-shield proxy start
```

This starts a local proxy on `127.0.0.1:7070`, configures npm and pip automatically, and reports all results to the cloud server. If using this option, the proxy Cloud Run service (step 8) is optional.

---

## Scaling behavior

Both services scale 1–4 instances based on request concurrency. Set `--min-instances=0` to enable scale-to-zero. Keep the proxy at `--min-instances=1` if you don't want cold start delays on `npm install` / `pip install`.

```bash
gcloud run services update cipher-shield-api \
  --region=$REGION --min-instances=0 --max-instances=10
```

---

## Corporate proxies and secure web gateways

If your organization runs Cisco Umbrella, Zscaler, Netskope, or a similar SWG, see **[Network and corporate proxy requirements →](network.md)** for the one-time policy changes needed to allow cipher-shield traffic through.

---

## Teardown

```bash
gcloud run services delete cipher-shield-api  --region=$REGION -q
gcloud run services delete cipher-shield-proxy --region=$REGION -q
gcloud sql instances delete $SQL_INSTANCE -q
gcloud compute networks vpc-access connectors delete cipher-connector --region=$REGION -q
gcloud secrets delete cipher-jwt-secret -q
gcloud secrets delete cipher-proxy-token -q
gcloud secrets delete cipher-db-password -q
gcloud secrets delete cipher-db-url -q
```
