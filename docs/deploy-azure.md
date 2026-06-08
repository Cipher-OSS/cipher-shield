# Deploying cipher-shield on Azure

**Architecture:** Azure Container Instances + Azure Database for PostgreSQL Flexible Server.  
**Estimated cost:** ~$25–40/month.

---

## Prerequisites

- Azure CLI installed and authenticated (`az login`)
- An Azure subscription
- A resource group (or create one below)

---

## 1. Set variables

```bash
export RESOURCE_GROUP=cipher-shield-rg
export LOCATION=eastus
export DB_SERVER=cipher-shield-pg
export DB_NAME=shield
export DB_USER=shieldadmin
export CONTAINER_GROUP=cipher-shield
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

---

## 3. Create resource group

```bash
az group create --name $RESOURCE_GROUP --location $LOCATION
```

---

## 4. Create Azure Database for PostgreSQL Flexible Server

```bash
az postgres flexible-server create \
  --resource-group $RESOURCE_GROUP \
  --name $DB_SERVER \
  --location $LOCATION \
  --admin-user $DB_USER \
  --admin-password "$DB_PASSWORD" \
  --sku-name Standard_B1ms \
  --tier Burstable \
  --storage-size 32 \
  --version 16 \
  --public-access None

# Create the database
az postgres flexible-server db create \
  --resource-group $RESOURCE_GROUP \
  --server-name $DB_SERVER \
  --database-name $DB_NAME

# Get the fully qualified domain name
DB_HOST=$(az postgres flexible-server show \
  --resource-group $RESOURCE_GROUP \
  --name $DB_SERVER \
  --query fullyQualifiedDomainName --output tsv)
echo "DB_HOST=$DB_HOST"
```

---

## 5. Configure firewall to allow the container

By default the Flexible Server has no public access. We'll allow the container's outbound IP. The simplest approach for a single container is to allow Azure services:

```bash
az postgres flexible-server firewall-rule create \
  --resource-group $RESOURCE_GROUP \
  --name $DB_SERVER \
  --rule-name allow-azure-services \
  --start-ip-address 0.0.0.0 \
  --end-ip-address 0.0.0.0
```

> For production, use VNet integration instead: inject the container into a VNet subnet and restrict Postgres to that subnet only.

---

## 6. Deploy Azure Container Instance

```bash
az container create \
  --resource-group $RESOURCE_GROUP \
  --name $CONTAINER_GROUP \
  --image ghcr.io/homes853/cipher-shield:latest \
  --cpu 1 \
  --memory 1 \
  --restart-policy Always \
  --ports 7070 8080 \
  --ip-address Public \
  --environment-variables \
    SHIELD_MODE=enforce \
    DATABASE_URL="postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:5432/${DB_NAME}?sslmode=require" \
    SHIELD_JWT_SECRET="$JWT_SECRET" \
    SHIELD_PROXY_TOKEN="$PROXY_TOKEN"

# Get the public IP
SERVER_IP=$(az container show \
  --resource-group $RESOURCE_GROUP \
  --name $CONTAINER_GROUP \
  --query ipAddress.ip --output tsv)
echo "Server IP: $SERVER_IP"
```

> **Security note:** The environment variables above are passed in plain text to the CLI. For production, use Azure Key Vault references with a managed identity instead.

---

## 7. Verify

```bash
curl http://$SERVER_IP:8080/api/v1/health
# {"status":"ok","version":"0.1.0"}
```

---

## 8. Bootstrap the first admin user

```bash
curl -X POST http://$SERVER_IP:8080/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@yourcompany.com","password":"changeme","role":"admin"}'
```

This endpoint requires no auth when the users table is empty. The first user is always created as admin.

---

## 9. Configure dev machines

On each developer's machine:

```bash
export SHIELD_SERVER_URL=http://$SERVER_IP:8080
export SHIELD_PROXY_TOKEN=<your PROXY_TOKEN from step 2>

cipher-shield proxy start
```

---

## (Optional) Use Azure Key Vault for secrets

```bash
# Create Key Vault
az keyvault create \
  --name cipher-shield-kv \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION

# Store secrets
az keyvault secret set --vault-name cipher-shield-kv --name jwt-secret   --value "$JWT_SECRET"
az keyvault secret set --vault-name cipher-shield-kv --name proxy-token  --value "$PROXY_TOKEN"
az keyvault secret set --vault-name cipher-shield-kv --name db-password  --value "$DB_PASSWORD"

# Assign a managed identity to the container and grant Key Vault access,
# then reference secrets via the identity at container startup.
# See: https://docs.microsoft.com/azure/container-instances/container-instances-managed-identity
```

---

## (Optional) Add HTTPS with Application Gateway

For production, put an Azure Application Gateway or Azure Front Door in front of port 8080 to terminate TLS. The proxy port 7070 can be exposed via an Azure Load Balancer or kept private and accessed over VPN.

---

## Teardown

```bash
az container delete --resource-group $RESOURCE_GROUP --name $CONTAINER_GROUP --yes
az postgres flexible-server delete --resource-group $RESOURCE_GROUP --name $DB_SERVER --yes
az group delete --name $RESOURCE_GROUP --yes
```
