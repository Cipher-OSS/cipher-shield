terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.gcp_project
  region  = var.gcp_region
}

# ── Variables ─────────────────────────────────────────────────────────────────

variable "gcp_project" {
  description = "GCP project ID"
}

variable "gcp_region" {
  default = "us-central1"
}

variable "domain" {
  description = "Base domain (e.g. yourdomain.com) — shield.DOMAIN and proxy.DOMAIN will be created"
}

variable "db_admin_user" {
  default = "shieldadmin"
}

variable "db_password" {
  description = "Cloud SQL PostgreSQL password — generate with: openssl rand -hex 32"
  sensitive   = true
}

variable "jwt_secret" {
  description = "JWT signing secret, minimum 32 characters — generate with: openssl rand -hex 32"
  sensitive   = true
}

variable "proxy_token" {
  description = "Pre-shared token for proxy-to-API authentication — generate with: openssl rand -hex 32"
  sensitive   = true
}

variable "anthropic_api_key" {
  description = "Anthropic API key (optional — enables Claude-powered package analysis)"
  default     = ""
  sensitive   = true
}

variable "image_tag" {
  # Check https://github.com/Cipher-OSS/cipher-shield/releases for the latest version before deploying.
  description = "cipher-shield image tag to deploy — pin to a specific semver for production"
  default     = "1.0.0"
}

# Protects the Cloud SQL instance from accidental deletion.
# Set to false in terraform.tfvars before running terraform destroy.
# See the Teardown section in deploy-gcp-terraform.md.
variable "deletion_protection" {
  type        = bool
  description = "Enable Cloud SQL deletion protection. Set to false before running terraform destroy."
  default     = true
}

# Controls enforcement behavior for both the API and proxy services.
# enforce — block malicious packages (production default)
# warn    — log findings but allow all installs through (useful for initial rollout)
#
# Note: cipher-shield is fail-open. If the scan pipeline is unreachable or times
# out (45s), the package is allowed through regardless of this setting. This is
# a deliberate tradeoff: fail-closed would block all installs during any API
# outage, making it unsuitable for developer workstations.
variable "shield_mode" {
  description = "Enforcement mode: 'enforce' blocks threats, 'warn' logs them. See fail-open note above."
  default     = "enforce"
}

# ── Enable required APIs ──────────────────────────────────────────────────────

resource "google_project_service" "compute" {
  service            = "compute.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "run" {
  service            = "run.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "sqladmin" {
  service            = "sqladmin.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "vpcaccess" {
  service            = "vpcaccess.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "servicenetworking" {
  service            = "servicenetworking.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "secretmanager" {
  service            = "secretmanager.googleapis.com"
  disable_on_destroy = false
}

# ── VPC ───────────────────────────────────────────────────────────────────────

resource "google_compute_network" "vpc" {
  name                    = "cipher-shield-vpc"
  auto_create_subnetworks = false
  depends_on              = [google_project_service.compute]
}

resource "google_compute_subnetwork" "subnet" {
  name          = "cipher-shield-subnet"
  ip_cidr_range = "10.0.1.0/24"
  region        = var.gcp_region
  network       = google_compute_network.vpc.id
}

# VPC connector gives Cloud Run egress into the VPC so it can reach Cloud SQL's
# private IP. Without this, Cloud Run has no path to the database.
resource "google_vpc_access_connector" "connector" {
  name          = "cipher-shield-connector"
  region        = var.gcp_region
  network       = google_compute_network.vpc.name
  ip_cidr_range = "10.8.0.0/28"

  depends_on = [google_project_service.vpcaccess]
}

# RFC 1918 address range peered into Cloud SQL's service network.
resource "google_compute_global_address" "sql_private_ip" {
  name          = "cipher-shield-sql-ip"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.vpc.id
}

# Service networking peering connects Cloud SQL to the VPC.
# On teardown: if terraform destroy fails here with "Producer services still
# using this connection", wait 2 minutes for Cloud SQL deletion to propagate,
# then run: terraform state rm google_service_networking_connection.sql_vpc
# followed by terraform destroy again.
resource "google_service_networking_connection" "sql_vpc" {
  network                 = google_compute_network.vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.sql_private_ip.name]
  depends_on              = [google_project_service.servicenetworking]
}

# ── Cloud SQL (PostgreSQL) ────────────────────────────────────────────────────

resource "google_sql_database_instance" "pg" {
  name             = "cipher-shield-db"
  database_version = "POSTGRES_16"
  region           = var.gcp_region

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      # Private IP only — the database has no public endpoint.
      # Cloud Run reaches it through the VPC connector above.
      ipv4_enabled    = false
      private_network = google_compute_network.vpc.id

      # Enforce TLS on all connections even within the VPC (defense in depth).
      # The application connection string also sets sslmode=require.
      # ssl_mode replaces the deprecated require_ssl in hashicorp/google 5.x.
      ssl_mode = "ENCRYPTED_ONLY"
    }
  }

  # Cloud SQL provisioning typically takes 10–15 minutes. These timeouts
  # prevent Terraform from marking the apply as failed too early.
  timeouts {
    create = "30m"
    update = "20m"
    delete = "20m"
  }

  # Set deletion_protection = false in terraform.tfvars before destroying.
  deletion_protection = var.deletion_protection

  depends_on = [google_service_networking_connection.sql_vpc]
}

resource "google_sql_database" "shield" {
  name     = "shield"
  instance = google_sql_database_instance.pg.name
}

resource "google_sql_user" "admin" {
  name     = var.db_admin_user
  instance = google_sql_database_instance.pg.name
  password = var.db_password
}

# ── Service Account for Cloud Run ─────────────────────────────────────────────

resource "google_service_account" "shield" {
  account_id   = "cipher-shield"
  display_name = "cipher-shield Cloud Run SA"
}

# Minimal IAM: only the permissions Cloud Run needs — Cloud SQL client access
# and per-secret read access below. No project-wide editor or owner roles.
resource "google_project_iam_member" "sql_client" {
  project = var.gcp_project
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.shield.email}"
}

# ── Locals ────────────────────────────────────────────────────────────────────

locals {
  image  = "ghcr.io/cipher-oss/cipher-shield:${var.image_tag}"
  db_url = "postgres://${var.db_admin_user}:${var.db_password}@${google_sql_database_instance.pg.private_ip_address}:5432/shield?sslmode=require"
}

# ── Secret Manager ────────────────────────────────────────────────────────────
# Secrets are injected into Cloud Run at runtime and never stored in image
# layers or plaintext environment variables. Each secret's IAM binding grants
# access only to the Cloud Run service account.

resource "google_secret_manager_secret" "db_url" {
  secret_id  = "cipher-db-url"
  project    = var.gcp_project
  replication {
    auto {}
  }
  depends_on = [google_project_service.secretmanager]
}

resource "google_secret_manager_secret_version" "db_url" {
  secret      = google_secret_manager_secret.db_url.id
  secret_data = local.db_url
}

resource "google_secret_manager_secret" "jwt_secret" {
  secret_id  = "cipher-jwt-secret"
  project    = var.gcp_project
  replication {
    auto {}
  }
  depends_on = [google_project_service.secretmanager]
}

resource "google_secret_manager_secret_version" "jwt_secret" {
  secret      = google_secret_manager_secret.jwt_secret.id
  secret_data = var.jwt_secret
}

resource "google_secret_manager_secret" "proxy_token" {
  secret_id  = "cipher-proxy-token"
  project    = var.gcp_project
  replication {
    auto {}
  }
  depends_on = [google_project_service.secretmanager]
}

resource "google_secret_manager_secret_version" "proxy_token" {
  secret      = google_secret_manager_secret.proxy_token.id
  secret_data = var.proxy_token
}

resource "google_secret_manager_secret" "anthropic_api_key" {
  count      = var.anthropic_api_key != "" ? 1 : 0
  secret_id  = "cipher-anthropic-key"
  project    = var.gcp_project
  replication {
    auto {}
  }
  depends_on = [google_project_service.secretmanager]
}

resource "google_secret_manager_secret_version" "anthropic_api_key" {
  count       = var.anthropic_api_key != "" ? 1 : 0
  secret      = google_secret_manager_secret.anthropic_api_key[0].id
  secret_data = var.anthropic_api_key
}

resource "google_secret_manager_secret_iam_member" "db_url" {
  project   = var.gcp_project
  secret_id = google_secret_manager_secret.db_url.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.shield.email}"
}

resource "google_secret_manager_secret_iam_member" "jwt_secret" {
  project   = var.gcp_project
  secret_id = google_secret_manager_secret.jwt_secret.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.shield.email}"
}

resource "google_secret_manager_secret_iam_member" "proxy_token" {
  project   = var.gcp_project
  secret_id = google_secret_manager_secret.proxy_token.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.shield.email}"
}

resource "google_secret_manager_secret_iam_member" "anthropic_api_key" {
  count     = var.anthropic_api_key != "" ? 1 : 0
  project   = var.gcp_project
  secret_id = google_secret_manager_secret.anthropic_api_key[0].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.shield.email}"
}

# ── Cloud Run — API + Dashboard (port 8080) ───────────────────────────────────

resource "google_cloud_run_v2_service" "api" {
  name     = "cipher-shield-api"
  location = var.gcp_region

  # Restricts inbound traffic to the Global HTTPS Load Balancer only.
  # Direct calls to the *.run.app URL are rejected at the Cloud Run ingress
  # layer, even though allUsers invoker is set below.
  ingress = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"

  template {
    service_account = google_service_account.shield.email

    vpc_access {
      connector = google_vpc_access_connector.connector.id
      # Route only private-range traffic through the VPC connector.
      # Public outbound traffic (OSV, registry APIs) exits directly.
      egress = "PRIVATE_RANGES_ONLY"
    }

    containers {
      image = local.image

      ports {
        container_port = 8080
      }

      env {
        name  = "SHIELD_MODE"
        value = var.shield_mode
      }
      env {
        name  = "SHIELD_CORS_ORIGIN"
        value = "https://shield.${var.domain}"
      }

      env {
        name = "DATABASE_URL"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.db_url.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "SHIELD_JWT_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.jwt_secret.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "SHIELD_PROXY_TOKEN"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.proxy_token.secret_id
            version = "latest"
          }
        }
      }

      # Splat [*] produces an empty list when count=0 and a single-element list
      # when count=1, so this block is only created when anthropic_api_key is set.
      dynamic "env" {
        for_each = google_secret_manager_secret.anthropic_api_key[*].secret_id
        content {
          name = "ANTHROPIC_API_KEY"
          value_source {
            secret_key_ref {
              secret  = env.value
              version = "latest"
            }
          }
        }
      }

      resources {
        limits = { cpu = "1", memory = "512Mi" }
      }
    }

    scaling {
      min_instance_count = 1
      max_instance_count = 4
    }
  }

  depends_on = [google_project_service.run]
}

# ── Cloud Run — Registry Proxy (port 7070) ────────────────────────────────────

resource "google_cloud_run_v2_service" "proxy" {
  name     = "cipher-shield-proxy"
  location = var.gcp_region
  ingress  = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"

  template {
    service_account = google_service_account.shield.email

    vpc_access {
      connector = google_vpc_access_connector.connector.id
      egress    = "PRIVATE_RANGES_ONLY"
    }

    containers {
      image   = local.image
      command = ["cipher-shield-proxy"]

      ports {
        container_port = 7070
      }

      env {
        name  = "SHIELD_MODE"
        value = var.shield_mode
      }
      env {
        # The proxy reports scan results back to the API service.
        name  = "SHIELD_SERVER_URL"
        value = "https://shield.${var.domain}"
      }

      env {
        name = "SHIELD_PROXY_TOKEN"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.proxy_token.secret_id
            version = "latest"
          }
        }
      }

      resources {
        limits = { cpu = "1", memory = "512Mi" }
      }
    }

    scaling {
      min_instance_count = 1
      max_instance_count = 4
    }
  }

  depends_on = [google_project_service.run]
}

# allUsers invoker is required for the Global LB to call Cloud Run without
# signing each request. This does not open the *.run.app URL to the internet —
# the ingress setting above blocks all traffic that doesn't come through the LB.
resource "google_cloud_run_v2_service_iam_member" "api_public" {
  project  = var.gcp_project
  location = var.gcp_region
  name     = google_cloud_run_v2_service.api.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

resource "google_cloud_run_v2_service_iam_member" "proxy_public" {
  project  = var.gcp_project
  location = var.gcp_region
  name     = google_cloud_run_v2_service.proxy.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# ── Global HTTPS Load Balancer ────────────────────────────────────────────────
# Single static IP, host-based routing, Google-managed TLS certificate.
#
# IMPORTANT — this is a two-stage apply. Unlike AWS (ALB hostnames + CNAMEs),
# GCP's Global LB assigns a static IP. You need A records, not CNAMEs.
# The Google-managed cert validates by resolving your domain to this IP over
# HTTP and HTTPS — if DNS isn't pointing here when the cert is created, it will
# get stuck in FAILED_NOT_VISIBLE and must be recreated.
#
# Stage 1: reserve the IP
#   terraform apply -target=google_compute_global_address.shield
#   terraform output lb_ip_address
#
# Stage 2: add DNS A records in your provider (Cloudflare, Route 53, etc.)
#   shield.yourdomain.com  →  A  →  <lb_ip_address>
#   proxy.yourdomain.com   →  A  →  <lb_ip_address>
#   Verify propagation: dig shield.yourdomain.com
#
# Stage 3: apply the full stack
#   terraform apply

resource "google_compute_global_address" "shield" {
  name       = "cipher-shield-ip"
  depends_on = [google_project_service.compute]
}

# Serverless NEGs connect the Global LB backends to each Cloud Run service.
resource "google_compute_region_network_endpoint_group" "api" {
  name                  = "cipher-shield-api-neg"
  network_endpoint_type = "SERVERLESS"
  region                = var.gcp_region

  cloud_run {
    service = google_cloud_run_v2_service.api.name
  }
}

resource "google_compute_region_network_endpoint_group" "proxy" {
  name                  = "cipher-shield-proxy-neg"
  network_endpoint_type = "SERVERLESS"
  region                = var.gcp_region

  cloud_run {
    service = google_cloud_run_v2_service.proxy.name
  }
}

resource "google_compute_backend_service" "api" {
  name                  = "cipher-shield-api-backend"
  load_balancing_scheme = "EXTERNAL"
  protocol              = "HTTPS"

  backend {
    group = google_compute_region_network_endpoint_group.api.id
  }
}

resource "google_compute_backend_service" "proxy" {
  name                  = "cipher-shield-proxy-backend"
  load_balancing_scheme = "EXTERNAL"
  protocol              = "HTTPS"

  backend {
    group = google_compute_region_network_endpoint_group.proxy.id
  }
}

# proxy.DOMAIN → proxy backend; all other hosts → API backend (shield.DOMAIN).
resource "google_compute_url_map" "shield" {
  name            = "cipher-shield-urlmap"
  default_service = google_compute_backend_service.api.id

  host_rule {
    hosts        = ["proxy.${var.domain}"]
    path_matcher = "proxy-matcher"
  }

  path_matcher {
    name            = "proxy-matcher"
    default_service = google_compute_backend_service.proxy.id
  }
}

# Google-managed cert provisions automatically once DNS A records resolve to
# the LB IP. Validation typically completes within 10–20 minutes of propagation.
# If it shows FAILED_NOT_VISIBLE, verify DNS with: dig shield.DOMAIN
resource "google_compute_managed_ssl_certificate" "shield" {
  name = "cipher-shield-cert"

  managed {
    domains = [
      "shield.${var.domain}",
      "proxy.${var.domain}",
    ]
  }
}

# Enforce TLS 1.2 minimum with a modern cipher suite.
# MODERN profile removes RC4, 3DES, and CBC-mode ciphers implicated in
# BEAST, POODLE, and SWEET32 attacks.
resource "google_compute_ssl_policy" "shield" {
  name            = "cipher-shield-ssl-policy"
  profile         = "MODERN"
  min_tls_version = "TLS_1_2"
}

resource "google_compute_target_https_proxy" "shield" {
  name             = "cipher-shield-https-proxy"
  url_map          = google_compute_url_map.shield.id
  ssl_certificates = [google_compute_managed_ssl_certificate.shield.id]
  ssl_policy       = google_compute_ssl_policy.shield.id
}

resource "google_compute_global_forwarding_rule" "shield" {
  name                  = "cipher-shield-https"
  target                = google_compute_target_https_proxy.shield.id
  port_range            = "443"
  ip_address            = google_compute_global_address.shield.address
  load_balancing_scheme = "EXTERNAL"
}

# Port 80 frontend redirects all HTTP traffic to HTTPS.
# Google's managed cert validation probes port 80 during provisioning —
# this frontend must exist for cert validation to succeed.
resource "google_compute_url_map" "redirect" {
  name = "cipher-shield-http-redirect"

  default_url_redirect {
    https_redirect         = true
    redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
    strip_query            = false
  }
}

resource "google_compute_target_http_proxy" "redirect" {
  name    = "cipher-shield-http-proxy"
  url_map = google_compute_url_map.redirect.id
}

resource "google_compute_global_forwarding_rule" "redirect" {
  name                  = "cipher-shield-http"
  target                = google_compute_target_http_proxy.redirect.id
  port_range            = "80"
  ip_address            = google_compute_global_address.shield.address
  load_balancing_scheme = "EXTERNAL"
}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "lb_ip_address" {
  value       = google_compute_global_address.shield.address
  description = "Add A records in your DNS provider: shield.<domain> and proxy.<domain> → this IP"
}

output "api_url" {
  value       = "https://shield.${var.domain}"
  description = "cipher-shield dashboard + API"
}

output "npm_config" {
  value       = "npm config set registry https://proxy.${var.domain}/"
  description = "Run on developer machines to point npm at cipher-shield"
}

output "pip_config" {
  value       = "pip config set global.index-url https://proxy.${var.domain}/simple/"
  description = "Run on developer machines to point pip at cipher-shield"
}
