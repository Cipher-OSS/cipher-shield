# Deploying cipher-shield on Azure

**Architecture:** Azure Container Apps + Azure Database for PostgreSQL.  
Managed containers — no VMs to manage, scales to zero when idle, auto-restarts on crash.  
**Estimated cost:** ~$20–40/month at low traffic.

---

## Prerequisites

- Azure CLI installed and authenticated (`az login`)
- An Azure subscription with an active resource group

---

## 1. Set variables

```bash
export RG=cipher-shield-rg
export LOCATION=eastus
export DB_SERVER=cipher-shield-pg
export DB_NAME=shield
export DB_USER=shieldadmin
export ACA_ENV=cipher-shield-env
```

---

## 2. Create resource group

```bash
az group create --name $RG --location $LOCATION
```

---

## 3. Store secrets in Azure Key Vault

```bash
JWT_SECRET=$(openssl rand -hex 32)
PROXY_TOKEN=$(openssl rand -hex 32)
DB_PASSWORD=$(openssl rand -hex 16)

az keyvault create --name cipher-shield-kv \
  --resource-group $RG --location $LOCATION

az keyvault secret set --vault-name cipher-shield-kv \
  --name jwt-secret --value "$JWT_SECRET"
az keyvault secret set --vault-name cipher-shield-kv \
  --name proxy-token --value "$PROXY_TOKEN"
az keyvault secret set --vault-name cipher-shield-kv \
  --name db-password --value "$DB_PASSWORD"
```

---

## 4. Create Azure Database for PostgreSQL

```bash
az postgres flexible-server create \
  --resource-group $RG \
  --name $DB_SERVER \
  --location $LOCATION \
  --admin-user $DB_USER \
  --admin-password "$DB_PASSWORD" \
  --sku-name Standard_B1ms \
  --tier Burstable \
  --storage-size 32 \
  --version 16 \
  --public-access 0.0.0.0

az postgres flexible-server db create \
  --resource-group $RG \
  --server-name $DB_SERVER \
  --database-name $DB_NAME

DB_HOST=$(az postgres flexible-server show \
  --resource-group $RG --name $DB_SERVER \
  --query fullyQualifiedDomainName --output tsv)
echo "DB_HOST=$DB_HOST"
```

---

## 5. Create the Container Apps environment

```bash
az containerapp env create \
  --name $ACA_ENV \
  --resource-group $RG \
  --location $LOCATION
```

---

## 6. Deploy the API / dashboard (port 8080)

```bash
DB_URL="postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:5432/${DB_NAME}?sslmode=require"

az containerapp create \
  --name cipher-shield-api \
  --resource-group $RG \
  --environment $ACA_ENV \
  --image ghcr.io/cipher-oss/cipher-shield:latest \
  --target-port 8080 \
  --ingress external \
  --min-replicas 1 --max-replicas 4 \
  --scale-rule-name cpu-rule \
  --scale-rule-type cpu \
  --scale-rule-metadata type=Utilization value=60 \
  --env-vars \
    SHIELD_MODE=enforce \
    "DATABASE_URL=${DB_URL}" \
    "SHIELD_JWT_SECRET=${JWT_SECRET}" \
    "SHIELD_PROXY_TOKEN=${PROXY_TOKEN}"

API_URL=$(az containerapp show \
  --name cipher-shield-api --resource-group $RG \
  --query properties.configuration.ingress.fqdn --output tsv)
echo "API URL: https://$API_URL"
```

---

## 7. Deploy the package proxy (port 7070)

```bash
az containerapp create \
  --name cipher-shield-proxy \
  --resource-group $RG \
  --environment $ACA_ENV \
  --image ghcr.io/cipher-oss/cipher-shield:latest \
  --target-port 7070 \
  --ingress external \
  --transport http \
  --min-replicas 1 --max-replicas 4 \
  --scale-rule-name cpu-rule \
  --scale-rule-type cpu \
  --scale-rule-metadata type=Utilization value=60 \
  --env-vars \
    SHIELD_MODE=enforce \
    "DATABASE_URL=${DB_URL}" \
    "SHIELD_JWT_SECRET=${JWT_SECRET}" \
    "SHIELD_PROXY_TOKEN=${PROXY_TOKEN}"

PROXY_URL=$(az containerapp show \
  --name cipher-shield-proxy --resource-group $RG \
  --query properties.configuration.ingress.fqdn --output tsv)
echo "Proxy URL: https://$PROXY_URL"
```

---

## 8. Verify

```bash
curl https://$API_URL/api/v1/health
# {"status":"ok","version":"0.1.0"}
```

---

## 9. Bootstrap the first admin user

```bash
curl -X POST https://$API_URL/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@yourcompany.com","password":"changeme","role":"admin"}'
```

This endpoint is open when the users table is empty; the first user is forced to `admin`.

---

## 10. Configure dev machines

Azure Container Apps provides HTTPS by default. Configure pip and npm to use the proxy URL:

```bash
export SHIELD_SERVER_URL=https://$API_URL
export SHIELD_PROXY_TOKEN=<PROXY_TOKEN from step 3>
cipher-shield proxy start --proxy-url https://$PROXY_URL
```

Or configure pip/npm manually:

```bash
# pip
pip config set global.index-url https://$PROXY_URL/simple/

# npm
npm config set registry https://$PROXY_URL/
```

---

## Scaling behavior

Both Container Apps scale from 1 to 4 replicas based on CPU utilization (60% threshold). The API app scales independently of the proxy app. You can adjust `--min-replicas` and `--max-replicas` at any time:

```bash
az containerapp update \
  --name cipher-shield-api \
  --resource-group $RG \
  --min-replicas 0 \
  --max-replicas 10
```

Setting `--min-replicas 0` enables scale-to-zero for the API (useful for dev environments). Keep the proxy at `--min-replicas 1` so it's always ready to intercept installs.

---

## Teardown

```bash
az containerapp delete --name cipher-shield-api --resource-group $RG --yes
az containerapp delete --name cipher-shield-proxy --resource-group $RG --yes
az containerapp env delete --name $ACA_ENV --resource-group $RG --yes
az postgres flexible-server delete --resource-group $RG --name $DB_SERVER --yes
az keyvault delete --name cipher-shield-kv --resource-group $RG
az group delete --name $RG --yes
```
