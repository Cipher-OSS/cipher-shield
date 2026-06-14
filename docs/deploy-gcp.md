# Deploying cipher-shield on GCP

**Architecture:** Cloud Run + Cloud SQL PostgreSQL + VPC connector.  
**Estimated cost:** ~$15–25/month (Cloud Run scales to zero when idle).

---

## Prerequisites

- `gcloud` CLI installed and authenticated (`gcloud auth login`)
- A GCP project with billing enabled
- APIs enabled: Cloud Run, Cloud SQL, Secret Manager, VPC Access

```bash
gcloud services enable \
  run.googleapis.com \
  sqladmin.googleapis.com \
  secretmanager.googleapis.com \
  vpcaccess.googleapis.com
```

---

## 1. Set project variables

```bash
export PROJECT_ID=$(gcloud config get-value project)
export REGION=us-central1
export INSTANCE_NAME=cipher-shield-db
```

---

## 2. Generate secrets

```bash
export JWT_SECRET=$(openssl rand -hex 32)
export PROXY_TOKEN=$(openssl rand -hex 32)
export DB_PASSWORD=$(openssl rand -hex 16)

echo "JWT_SECRET=$JWT_SECRET"
echo "PROXY_TOKEN=$PROXY_TOKEN"
echo "DB_PASSWORD=$DB_PASSWORD"
```

Store them in Secret Manager so they never appear in plain text in Cloud Run config:

```bash
echo -n "$JWT_SECRET"   | gcloud secrets create cipher-jwt-secret   --data-file=-
echo -n "$PROXY_TOKEN"  | gcloud secrets create cipher-proxy-token  --data-file=-
echo -n "$DB_PASSWORD"  | gcloud secrets create cipher-db-password  --data-file=-
```

---

## 3. Create Cloud SQL PostgreSQL instance

```bash
gcloud sql instances create $INSTANCE_NAME \
  --database-version=POSTGRES_16 \
  --tier=db-f1-micro \
  --region=$REGION \
  --no-assign-ip \
  --network=default

# Create database and user
gcloud sql databases create shield --instance=$INSTANCE_NAME

gcloud sql users create shield \
  --instance=$INSTANCE_NAME \
  --password="$DB_PASSWORD"

# Get the private IP
DB_PRIVATE_IP=$(gcloud sql instances describe $INSTANCE_NAME \
  --format='value(ipAddresses[0].ipAddress)')
echo "DB_PRIVATE_IP=$DB_PRIVATE_IP"
```

---

## 4. Create a VPC connector

Cloud Run needs a VPC connector to reach the Cloud SQL private IP.

```bash
gcloud compute networks vpc-access connectors create cipher-connector \
  --region=$REGION \
  --subnet-project=$PROJECT_ID \
  --network=default \
  --range=10.8.0.0/28
```

---

## 5. Grant Secret Manager access to Cloud Run

```bash
# Get the Cloud Run service account
PROJECT_NUMBER=$(gcloud projects describe $PROJECT_ID --format='value(projectNumber)')
CLOUD_RUN_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"

gcloud secrets add-iam-policy-binding cipher-jwt-secret \
  --member="serviceAccount:$CLOUD_RUN_SA" --role="roles/secretmanager.secretAccessor"

gcloud secrets add-iam-policy-binding cipher-proxy-token \
  --member="serviceAccount:$CLOUD_RUN_SA" --role="roles/secretmanager.secretAccessor"

gcloud secrets add-iam-policy-binding cipher-db-password \
  --member="serviceAccount:$CLOUD_RUN_SA" --role="roles/secretmanager.secretAccessor"
```

---

## 6. Deploy to Cloud Run

> **Note:** Cloud Run only exposes one port (8080 — the dashboard/API). The proxy port 7070 requires a separate deployment or a VM. See the note at the bottom.

```bash
gcloud run deploy cipher-shield \
  --image=ghcr.io/homes853/cipher-shield:latest \
  --region=$REGION \
  --platform=managed \
  --port=8080 \
  --vpc-connector=cipher-connector \
  --vpc-egress=private-ranges-only \
  --set-env-vars="SHIELD_MODE=enforce,DATABASE_URL=postgres://shield:${DB_PASSWORD}@${DB_PRIVATE_IP}:5432/shield?sslmode=require" \
  --set-secrets="SHIELD_JWT_SECRET=cipher-jwt-secret:latest,SHIELD_PROXY_TOKEN=cipher-proxy-token:latest" \
  --allow-unauthenticated \
  --min-instances=0 \
  --max-instances=2

# Get the service URL
SERVICE_URL=$(gcloud run services describe cipher-shield \
  --region=$REGION --format='value(status.url)')
echo "Service URL: $SERVICE_URL"
```

---

## 7. Verify

```bash
curl $SERVICE_URL/api/v1/health
# {"status":"ok","version":"0.1.0"}
```

---

## 8. Bootstrap the first admin user

```bash
curl -X POST $SERVICE_URL/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@yourcompany.com","password":"changeme","role":"admin"}'
```

---

## 9. Configure dev machines

```bash
export SHIELD_SERVER_URL=$SERVICE_URL
export SHIELD_PROXY_TOKEN=<your PROXY_TOKEN from step 2>

cipher-shield proxy start
```

---

## Proxy port (7070) on GCP

Cloud Run only supports a single HTTP port, so the registry proxy (7070) needs a separate VM if dev machines need to route `npm install` / `pip install` through it in real time.

**Option A — separate Compute Engine VM for the proxy:**

```bash
gcloud compute instances create cipher-proxy \
  --zone=${REGION}-a \
  --machine-type=e2-micro \
  --image-family=debian-12 \
  --image-project=debian-cloud \
  --tags=cipher-proxy

# SSH in and run the proxy container
gcloud compute ssh cipher-proxy -- \
  "sudo apt-get install -y docker.io && sudo docker run -d \
    --restart unless-stopped \
    -p 7070:7070 \
    -e SHIELD_JWT_SECRET=$JWT_SECRET \
    -e SHIELD_PROXY_TOKEN=$PROXY_TOKEN \
    -e SHIELD_MODE=enforce \
    -e DATABASE_URL=postgres://shield:${DB_PASSWORD}@${DB_PRIVATE_IP}:5432/shield?sslmode=require \
    ghcr.io/homes853/cipher-shield:latest"
```

**Option B — use Cloud Run for API/dashboard only, run proxy locally on each dev machine** (connects to Cloud Run to report results). This is the lowest-cost option.

---

## Teardown

```bash
gcloud run services delete cipher-shield --region=$REGION
gcloud sql instances delete $INSTANCE_NAME
gcloud compute networks vpc-access connectors delete cipher-connector --region=$REGION
gcloud secrets delete cipher-jwt-secret
gcloud secrets delete cipher-proxy-token
gcloud secrets delete cipher-db-password
```
