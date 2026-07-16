terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.58"
    }
  }
}

provider "azurerm" {
  features {}
}

# ── Variables ─────────────────────────────────────────────────────────────────

variable "location" {
  default = "East US 2"
}

variable "domain" {
  description = "Base domain for cipher-shield (e.g. yourdomain.com) — shield.DOMAIN and proxy.DOMAIN will be created"
}

variable "db_admin_user" {
  default = "shieldadmin"
}

variable "db_password" {
  description = "PostgreSQL admin password"
  sensitive   = true
}

variable "jwt_secret" {
  description = "JWT signing secret (min 32 chars)"
  sensitive   = true
}

variable "proxy_token" {
  description = "Pre-shared token for proxy agent reporting"
  sensitive   = true
}

variable "anthropic_api_key" {
  description = "Anthropic API key (optional — enables Claude analysis)"
  default     = ""
  sensitive   = true
}

variable "image_tag" {
  description = "cipher-shield image tag to deploy"
  default     = "0.1.5"
}

# ── Resource Group ────────────────────────────────────────────────────────────

resource "azurerm_resource_group" "rg" {
  name     = "cipher-shield-rg"
  location = var.location
}

# ── VNet + Subnets ────────────────────────────────────────────────────────────

resource "azurerm_virtual_network" "vnet" {
  name                = "cipher-shield-vnet"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  address_space       = ["10.0.0.0/16"]
}

resource "azurerm_subnet" "pg" {
  name                 = "cipher-shield-pg-subnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.0.1.0/24"]

  delegation {
    name = "pg-delegation"
    service_delegation {
      name    = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

resource "azurerm_subnet" "aca" {
  name                 = "cipher-shield-aca-subnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.0.2.0/23"]

  delegation {
    name = "aca-delegation"
    service_delegation {
      name    = "Microsoft.App/environments"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

# ── Private DNS for PostgreSQL ────────────────────────────────────────────────

resource "azurerm_private_dns_zone" "pg" {
  name                = "cipher-shield-db.private.postgres.database.azure.com"
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_private_dns_zone_virtual_network_link" "pg" {
  name                  = "pg-dns-link"
  resource_group_name   = azurerm_resource_group.rg.name
  private_dns_zone_name = azurerm_private_dns_zone.pg.name
  virtual_network_id    = azurerm_virtual_network.vnet.id
}

# ── PostgreSQL Flexible Server ────────────────────────────────────────────────

resource "azurerm_postgresql_flexible_server" "pg" {
  name                          = "cipher-shield-db"
  resource_group_name           = azurerm_resource_group.rg.name
  location                      = azurerm_resource_group.rg.location
  version                       = "16"
  delegated_subnet_id           = azurerm_subnet.pg.id
  private_dns_zone_id           = azurerm_private_dns_zone.pg.id
  administrator_login           = var.db_admin_user
  administrator_password        = var.db_password
  sku_name                      = "B_Standard_B1ms"
  storage_mb                    = 32768
  public_network_access_enabled = false

  depends_on = [azurerm_private_dns_zone_virtual_network_link.pg]
}

resource "azurerm_postgresql_flexible_server_database" "shield" {
  name      = "shield"
  server_id = azurerm_postgresql_flexible_server.pg.id
  charset   = "UTF8"
  collation = "en_US.utf8"
}

# ── Log Analytics ─────────────────────────────────────────────────────────────

resource "azurerm_log_analytics_workspace" "logs" {
  name                = "cipher-shield-logs"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

# ── Container Apps Environment ────────────────────────────────────────────────

resource "azurerm_container_app_environment" "env" {
  name                       = "cipher-shield-env"
  location                   = azurerm_resource_group.rg.location
  resource_group_name        = azurerm_resource_group.rg.name
  log_analytics_workspace_id = azurerm_log_analytics_workspace.logs.id
  infrastructure_subnet_id   = azurerm_subnet.aca.id
}

# ── Locals ────────────────────────────────────────────────────────────────────

locals {
  db_url = "postgres://${var.db_admin_user}:${var.db_password}@${azurerm_postgresql_flexible_server.pg.fqdn}:5432/shield?sslmode=require"
  image  = "ghcr.io/cipher-oss/cipher-shield:${var.image_tag}"
}

# ── Container App — API + Dashboard (port 8080) ───────────────────────────────

resource "azurerm_container_app" "api" {
  name                         = "cipher-shield-api"
  container_app_environment_id = azurerm_container_app_environment.env.id
  resource_group_name          = azurerm_resource_group.rg.name
  revision_mode                = "Single"

  secret {
    name  = "jwt-secret"
    value = var.jwt_secret
  }
  secret {
    name  = "proxy-token"
    value = var.proxy_token
  }
  secret {
    name  = "db-url"
    value = local.db_url
  }
  dynamic "secret" {
    for_each = var.anthropic_api_key != "" ? [1] : []
    content {
      name  = "anthropic-api-key"
      value = var.anthropic_api_key
    }
  }

  template {
    min_replicas = 1
    max_replicas = 4

    container {
      name   = "cipher-shield-api"
      image  = local.image
      cpu    = 0.5
      memory = "1Gi"

      env { name = "SHIELD_MODE";        value = "enforce" }
      env { name = "SHIELD_CORS_ORIGIN"; value = "https://shield.${var.domain}" }
      env { name = "SHIELD_JWT_SECRET";  secret_name = "jwt-secret" }
      env { name = "SHIELD_PROXY_TOKEN"; secret_name = "proxy-token" }
      env { name = "DATABASE_URL";       secret_name = "db-url" }
      dynamic "env" {
        for_each = var.anthropic_api_key != "" ? [1] : []
        content {
          name        = "ANTHROPIC_API_KEY"
          secret_name = "anthropic-api-key"
        }
      }
    }
  }

  ingress {
    external_enabled = true
    target_port      = 8080
    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }
}

# ── Container App — Registry Proxy (port 7070) ────────────────────────────────

resource "azurerm_container_app" "proxy" {
  name                         = "cipher-shield-proxy"
  container_app_environment_id = azurerm_container_app_environment.env.id
  resource_group_name          = azurerm_resource_group.rg.name
  revision_mode                = "Single"

  secret {
    name  = "proxy-token"
    value = var.proxy_token
  }

  template {
    min_replicas = 1
    max_replicas = 4

    container {
      name    = "cipher-shield-proxy"
      image   = local.image
      command = ["cipher-shield-proxy"]
      cpu     = 0.5
      memory  = "1Gi"

      env { name = "SHIELD_MODE";       value = "enforce" }
      env { name = "SHIELD_SERVER_URL"; value = "https://shield.${var.domain}" }
      env { name = "SHIELD_PROXY_TOKEN"; secret_name = "proxy-token" }
    }
  }

  ingress {
    external_enabled = true
    target_port      = 7070
    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }
}

# ── Custom Domains + Managed Certificates ─────────────────────────────────────
# Azure provisions free Let's Encrypt certs via CNAME validation.
#
# Apply sequence:
#   1. terraform apply  (deploys infra, get FQDNs from outputs below)
#   2. Add CNAMEs in Cloudflare:
#        shield.YOURDOMAIN  →  cipher-shield-api.<env_default_domain>
#        proxy.YOURDOMAIN   →  cipher-shield-proxy.<env_default_domain>
#   3. terraform apply  (provisions managed certs, binds custom domains)

resource "azurerm_container_app_environment_managed_certificate" "shield" {
  name                         = "cert-shield"
  container_app_environment_id = azurerm_container_app_environment.env.id
  domain_name                  = "shield.${var.domain}"
  domain_validation_type       = "CNAME"
}

resource "azurerm_container_app_environment_managed_certificate" "proxy" {
  name                         = "cert-proxy"
  container_app_environment_id = azurerm_container_app_environment.env.id
  domain_name                  = "proxy.${var.domain}"
  domain_validation_type       = "CNAME"
}

resource "azurerm_container_app_custom_domain" "shield" {
  name                                             = "shield.${var.domain}"
  container_app_id                                 = azurerm_container_app.api.id
  container_app_environment_certificate_id         = azurerm_container_app_environment_managed_certificate.shield.id
  certificate_binding_type                         = "SniEnabled"
}

resource "azurerm_container_app_custom_domain" "proxy" {
  name                                             = "proxy.${var.domain}"
  container_app_id                                 = azurerm_container_app.proxy.id
  container_app_environment_certificate_id         = azurerm_container_app_environment_managed_certificate.proxy.id
  certificate_binding_type                         = "SniEnabled"
}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "env_default_domain" {
  value       = azurerm_container_app_environment.env.default_domain
  description = "Use this to build CNAME targets: cipher-shield-api.<this> and cipher-shield-proxy.<this>"
}

output "api_fqdn" {
  value       = "cipher-shield-api.${azurerm_container_app_environment.env.default_domain}"
  description = "Step 1: Add Cloudflare CNAME → shield.${var.domain} points here"
}

output "proxy_fqdn" {
  value       = "cipher-shield-proxy.${azurerm_container_app_environment.env.default_domain}"
  description = "Step 1: Add Cloudflare CNAME → proxy.${var.domain} points here"
}

output "api_url" {
  value       = "https://shield.${var.domain}"
  description = "cipher-shield dashboard + API (after custom domain is active)"
}

output "npm_config" {
  value       = "npm config set registry https://proxy.${var.domain}/"
  description = "Run on developer machines to point npm at cipher-shield"
}

output "pip_config" {
  value       = "pip config set global.index-url https://proxy.${var.domain}/simple/"
  description = "Run on developer machines to point pip at cipher-shield"
}
