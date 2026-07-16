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
  description = "Base domain for cipher-shield (e.g. yourdomain.com) — shield.DOMAIN and proxy.DOMAIN will be created"
}

variable "db_admin_user" {
  default = "shieldadmin"
}

variable "db_password" {
  description = "Cloud SQL PostgreSQL admin password"
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

# VPC connector so Cloud Run can reach Cloud SQL private IP
resource "google_vpc_access_connector" "connector" {
  name          = "cipher-shield-connector"
  region        = var.gcp_region
  network       = google_compute_network.vpc.name
  ip_cidr_range = "10.8.0.0/28"

  depends_on = [google_project_service.vpcaccess]
}

# Private IP range for Cloud SQL
resource "google_compute_global_address" "sql_private_ip" {
  name          = "cipher-shield-sql-ip"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.vpc.id
}

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
      ipv4_enabled    = false
      private_network = google_compute_network.vpc.id
    }
  }

  deletion_protection = true
  depends_on          = [google_service_networking_connection.sql_vpc]
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

resource "google_secret_manager_secret" "db_url" {
  secret_id  = "cipher-db-url"
  project    = var.gcp_project
  replication { auto {} }
  depends_on = [google_project_service.secretmanager]
}

resource "google_secret_manager_secret_version" "db_url" {
  secret      = google_secret_manager_secret.db_url.id
  secret_data = local.db_url
}

resource "google_secret_manager_secret" "jwt_secret" {
  secret_id  = "cipher-jwt-secret"
  project    = var.gcp_project
  replication { auto {} }
  depends_on = [google_project_service.secretmanager]
}

resource "google_secret_manager_secret_version" "jwt_secret" {
  secret      = google_secret_manager_secret.jwt_secret.id
  secret_data = var.jwt_secret
}

resource "google_secret_manager_secret" "proxy_token" {
  secret_id  = "cipher-proxy-token"
  project    = var.gcp_project
  replication { auto {} }
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
  replication { auto {} }
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
  ingress  = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"

  template {
    service_account = google_service_account.shield.email

    vpc_access {
      connector = google_vpc_access_connector.connector.id
      egress    = "PRIVATE_RANGES_ONLY"
    }

    containers {
      image = local.image

      ports {
        container_port = 8080
      }

      env { name = "SHIELD_MODE";        value = "enforce" }
      env { name = "SHIELD_CORS_ORIGIN"; value = "https://shield.${var.domain}" }

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

      dynamic "env" {
        for_each = var.anthropic_api_key != "" ? [1] : []
        content {
          name = "ANTHROPIC_API_KEY"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.anthropic_api_key[0].secret_id
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

      env { name = "SHIELD_MODE";       value = "enforce" }
      env { name = "SHIELD_SERVER_URL"; value = "https://shield.${var.domain}" }

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

# Allow unauthenticated access (Global LB is the public entry point)
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
# Mirrors the ALB pattern from AWS — single public IP, host-based routing,
# Google-managed TLS cert.
#
# Apply sequence:
#   1. terraform apply -target=google_compute_global_address.shield
#   2. terraform output lb_ip_address  →  add A records for shield/npm/pypi.${var.domain} in Cloudflare
#   3. terraform apply  (managed cert validates once DNS propagates)

resource "google_compute_global_address" "shield" {
  name       = "cipher-shield-ip"
  depends_on = [google_project_service.compute]
}

# Serverless NEGs connect the Global LB to each Cloud Run service
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

# URL map: proxy.* → proxy backend; everything else → API backend
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

# Google-managed cert — provisions automatically once DNS A records are in place
resource "google_compute_managed_ssl_certificate" "shield" {
  name = "cipher-shield-cert"

  managed {
    domains = [
      "shield.${var.domain}",
      "proxy.${var.domain}",
    ]
  }
}

resource "google_compute_target_https_proxy" "shield" {
  name             = "cipher-shield-https-proxy"
  url_map          = google_compute_url_map.shield.id
  ssl_certificates = [google_compute_managed_ssl_certificate.shield.id]
}

resource "google_compute_global_forwarding_rule" "shield" {
  name                  = "cipher-shield-https"
  target                = google_compute_target_https_proxy.shield.id
  port_range            = "443"
  ip_address            = google_compute_global_address.shield.address
  load_balancing_scheme = "EXTERNAL"
}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "lb_ip_address" {
  value       = google_compute_global_address.shield.address
  description = "Add A records in Cloudflare for shield.${var.domain} and proxy.${var.domain} pointing to this IP"
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
