# Deploying cipher-shield on GCP

**Architecture:** Cloud Run + Cloud SQL PostgreSQL.  
Serverless containers — scales to zero when idle, auto-scales under load, fully managed.  
**Estimated cost:** ~$15–30/month (Cloud Run billing is per-request when scaled to zero).

---

## Prerequisites

- `gcloud` CLI installed and authenticated (`gcloud auth login`)
- A GCP project with billing enabled

```bash
gcloud services enable \
  run.googleapis.com \
  sqladmin.googleapis.com \
  secretmanager.googleapis.com \
  vpcaccess.googleapis.com
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

## 3. Create Cloud SQL PostgreSQL

```bash
gcloud sql instances create $SQL_INSTANCE \
  --database-version=POSTGRES_16 \
  --tier=db-f1-micro \
  --region=$REGION \
  --no-assign-ip \
  --network=default

gcloud sql databases create shield --instance=$SQL_INSTANCE
gcloud sql users create shield --instance=$SQL_INSTANCE --password="$DB_PASSWORD"

DB_PRIVATE_IP=$(gcloud sql instances describe $SQL_INSTANCE \
  --format='value(ipAddresses[0].ipAddress)')
echo "DB_PRIVATE_IP=$DB_PRIVATE_IP"
```

---

## 4. VPC connector

Cloud Run needs a VPC connector to reach the Cloud SQL private IP.

```bash
gcloud compute networks vpc-access connectors create cipher-connector \
  --region=$REGION \
  --network=default \
  --range=10.8.0.0/28
```

---

## 5. Grant Secret Manager access to Cloud Run

```bash
PROJECT_NUMBER=$(gcloud projects describe $PROJECT_ID --format='value(projectNumber)')
SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"

for SECRET in cipher-jwt-secret cipher-proxy-token cipher-db-password; do
  gcloud secrets add-iam-policy-binding $SECRET \
    --member="serviceAccount:$SA" \
    --role="roles/secretmanager.secretAccessor"
done
```

---

## 6. Deploy the API / dashboard (port 8080)

```bash
DB_URL="postgres://shield:${DB_PASSWORD}@${DB_PRIVATE_IP}:5432/shield?sslmode=require"

gcloud run deploy cipher-shield-api \
  --image=$IMAGE \
  --region=$REGION \
  --port=8080 \
  --vpc-connector=cipher-connector \
  --vpc-egress=private-ranges-only \
  --set-env-vars="SHIELD_MODE=enforce,DATABASE_URL=${DB_URL}" \
  --set-secrets="SHIELD_JWT_SECRET=cipher-jwt-secret:latest,SHIELD_PROXY_TOKEN=cipher-proxy-token:latest" \
  --allow-unauthenticated \
  --min-instances=1 \
  --max-instances=4

API_URL=$(gcloud run services describe cipher-shield-api \
  --region=$REGION --format='value(status.url)')
echo "API URL: $API_URL"
```

---

## 7. Deploy the package proxy (port 7070)

Cloud Run only exposes one port per service, so the proxy runs as a second service targeting port 7070. Both use the same image and share the same database.

```bash
gcloud run deploy cipher-shield-proxy \
  --image=$IMAGE \
  --region=$REGION \
  --port=7070 \
  --vpc-connector=cipher-connector \
  --vpc-egress=private-ranges-only \
  --set-env-vars="SHIELD_MODE=enforce,DATABASE_URL=${DB_URL}" \
  --set-secrets="SHIELD_JWT_SECRET=cipher-jwt-secret:latest,SHIELD_PROXY_TOKEN=cipher-proxy-token:latest" \
  --allow-unauthenticated \
  --min-instances=1 \
  --max-instances=4

PROXY_URL=$(gcloud run services describe cipher-shield-proxy \
  --region=$REGION --format='value(status.url)')
echo "Proxy URL: $PROXY_URL"
```

---

## 8. Verify

```bash
curl $API_URL/api/v1/health
# {"status":"ok","version":"0.1.0"}
```

---

## 9. Bootstrap the first admin user

```bash
curl -X POST $API_URL/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@yourcompany.com","password":"changeme","role":"admin"}'
```

This endpoint is open when the users table is empty; the first user is forced to `admin`.

---

## 10. Configure dev machines

Cloud Run provides HTTPS by default. Configure pip and npm to use the proxy service URL:

```bash
export SHIELD_SERVER_URL=$API_URL
export SHIELD_PROXY_TOKEN=<PROXY_TOKEN from step 2>
cipher-shield proxy start --proxy-url $PROXY_URL
```

Or configure pip/npm manually:

```bash
# pip
pip config set global.index-url $PROXY_URL/simple/

# npm
npm config set registry $PROXY_URL/
```

---

## Scaling behavior

Both services scale 1–4 instances based on request concurrency (Cloud Run default). Set `--min-instances=0` on either service to enable scale-to-zero. Keep the proxy at `--min-instances=1` if developers expect immediate installs without cold start delay.

```bash
gcloud run services update cipher-shield-api \
  --region=$REGION --min-instances=0 --max-instances=10
```

---

## Teardown

```bash
gcloud run services delete cipher-shield-api  --region=$REGION
gcloud run services delete cipher-shield-proxy --region=$REGION
gcloud sql instances delete $SQL_INSTANCE
gcloud compute networks vpc-access connectors delete cipher-connector --region=$REGION
gcloud secrets delete cipher-jwt-secret
gcloud secrets delete cipher-proxy-token
gcloud secrets delete cipher-db-password
```
