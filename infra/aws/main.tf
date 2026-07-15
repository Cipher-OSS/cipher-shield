terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ── Variables ─────────────────────────────────────────────────────────────────

variable "aws_region" {
  default = "us-east-1"
}

variable "domain" {
  description = "Base domain for cipher-shield (e.g. yourdomain.com) — shield.DOMAIN and proxy.DOMAIN will be created"
}

variable "db_admin_user" {
  default = "shieldadmin"
}

variable "db_password" {
  description = "RDS PostgreSQL admin password"
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
  default     = "0.1.4"
}

# ── VPC ───────────────────────────────────────────────────────────────────────

resource "aws_vpc" "vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "cipher-shield-vpc" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id
  tags   = { Name = "cipher-shield-igw" }
}

# Public subnets (ALB)
resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true
  tags                    = { Name = "cipher-shield-public-a" }
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "${var.aws_region}b"
  map_public_ip_on_launch = true
  tags                    = { Name = "cipher-shield-public-b" }
}

# Private subnets (ECS + RDS)
resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = "${var.aws_region}a"
  tags              = { Name = "cipher-shield-private-a" }
}

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = "10.0.4.0/24"
  availability_zone = "${var.aws_region}b"
  tags              = { Name = "cipher-shield-private-b" }
}

# NAT Gateway (ECS in private subnets reaches npm/PyPI via this)
resource "aws_eip" "nat" {
  domain = "vpc"
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public_a.id
  tags          = { Name = "cipher-shield-nat" }
  depends_on    = [aws_internet_gateway.igw]
}

# Route tables
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = { Name = "cipher-shield-public-rt" }
}

resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.vpc.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }
  tags = { Name = "cipher-shield-private-rt" }
}

resource "aws_route_table_association" "private_a" {
  subnet_id      = aws_subnet.private_a.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_b" {
  subnet_id      = aws_subnet.private_b.id
  route_table_id = aws_route_table.private.id
}

# ── Security Groups ───────────────────────────────────────────────────────────

resource "aws_security_group" "alb" {
  name        = "cipher-shield-alb"
  description = "ALB — HTTPS only"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "cipher-shield-alb-sg" }
}

resource "aws_security_group" "ecs" {
  name        = "cipher-shield-ecs"
  description = "ECS tasks — reachable from ALB only"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  ingress {
    from_port       = 7070
    to_port         = 7070
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "cipher-shield-ecs-sg" }
}

resource "aws_security_group" "rds" {
  name        = "cipher-shield-rds"
  description = "RDS PostgreSQL"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
  }

  tags = { Name = "cipher-shield-rds-sg" }
}

# ── ACM Certificate ───────────────────────────────────────────────────────────
# Covers all three subdomains on a single cert.
#
# Apply sequence:
#   1. terraform apply -target=aws_acm_certificate.shield
#   2. terraform output acm_validation_records  →  add those CNAMEs to Cloudflare
#   3. terraform apply  (cert validates, listener + services come up)

resource "aws_acm_certificate" "shield" {
  domain_name       = "*.${var.domain}"
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_acm_certificate_validation" "shield" {
  certificate_arn         = aws_acm_certificate.shield.arn
  validation_record_fqdns = [for dvo in aws_acm_certificate.shield.domain_validation_options : dvo.resource_record_name]
}

# ── RDS PostgreSQL ────────────────────────────────────────────────────────────

resource "aws_db_subnet_group" "pg" {
  name       = "cipher-shield-pg"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]
  tags       = { Name = "cipher-shield-pg-subnet-group" }
}

resource "aws_db_instance" "pg" {
  identifier             = "cipher-shield-db"
  engine                 = "postgres"
  engine_version         = "16"
  instance_class         = "db.t4g.micro"
  allocated_storage      = 20
  db_name                = "shield"
  username               = var.db_admin_user
  password               = var.db_password
  db_subnet_group_name   = aws_db_subnet_group.pg.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  skip_final_snapshot    = true
  publicly_accessible    = false

  tags = { Name = "cipher-shield-db" }
}

# ── ECS ───────────────────────────────────────────────────────────────────────

resource "aws_ecs_cluster" "cluster" {
  name = "cipher-shield"
}

resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/ecs/cipher-shield"
  retention_in_days = 30
}

resource "aws_iam_role" "ecs_task_execution" {
  name = "cipher-shield-ecs-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution" {
  role       = aws_iam_role.ecs_task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "secrets_read" {
  name = "cipher-shield-secrets-read"
  role = aws_iam_role.ecs_task_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "secretsmanager:GetSecretValue"
      Resource = concat(
        [
          aws_secretsmanager_secret.db_url.arn,
          aws_secretsmanager_secret.jwt_secret.arn,
          aws_secretsmanager_secret.proxy_token.arn,
        ],
        aws_secretsmanager_secret.anthropic_api_key[*].arn
      )
    }]
  })
}

# ── Secrets Manager ───────────────────────────────────────────────────────────

resource "aws_secretsmanager_secret" "db_url" {
  name = "cipher-shield/db-url"
}

resource "aws_secretsmanager_secret_version" "db_url" {
  secret_id     = aws_secretsmanager_secret.db_url.id
  secret_string = local.db_url
}

resource "aws_secretsmanager_secret" "jwt_secret" {
  name = "cipher-shield/jwt-secret"
}

resource "aws_secretsmanager_secret_version" "jwt_secret" {
  secret_id     = aws_secretsmanager_secret.jwt_secret.id
  secret_string = var.jwt_secret
}

resource "aws_secretsmanager_secret" "proxy_token" {
  name = "cipher-shield/proxy-token"
}

resource "aws_secretsmanager_secret_version" "proxy_token" {
  secret_id     = aws_secretsmanager_secret.proxy_token.id
  secret_string = var.proxy_token
}

resource "aws_secretsmanager_secret" "anthropic_api_key" {
  count = var.anthropic_api_key != "" ? 1 : 0
  name  = "cipher-shield/anthropic-api-key"
}

resource "aws_secretsmanager_secret_version" "anthropic_api_key" {
  count         = var.anthropic_api_key != "" ? 1 : 0
  secret_id     = aws_secretsmanager_secret.anthropic_api_key[0].id
  secret_string = var.anthropic_api_key
}

# ── Locals ────────────────────────────────────────────────────────────────────

locals {
  image  = "ghcr.io/cipher-oss/cipher-shield:${var.image_tag}"
  db_url = "postgres://${var.db_admin_user}:${var.db_password}@${aws_db_instance.pg.address}:5432/shield?sslmode=require"

  api_secrets = concat(
    [
      { name = "DATABASE_URL",       valueFrom = aws_secretsmanager_secret.db_url.arn },
      { name = "SHIELD_JWT_SECRET",  valueFrom = aws_secretsmanager_secret.jwt_secret.arn },
      { name = "SHIELD_PROXY_TOKEN", valueFrom = aws_secretsmanager_secret.proxy_token.arn },
    ],
    [for arn in aws_secretsmanager_secret.anthropic_api_key[*].arn : { name = "ANTHROPIC_API_KEY", valueFrom = arn }]
  )

  proxy_secrets = [
    { name = "SHIELD_PROXY_TOKEN", valueFrom = aws_secretsmanager_secret.proxy_token.arn },
  ]
}

# API task — full server binary (API + dashboard)
resource "aws_ecs_task_definition" "api" {
  family                   = "cipher-shield-api"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn

  container_definitions = jsonencode([{
    name      = "cipher-shield-api"
    image     = local.image
    essential = true
    portMappings = [
      { containerPort = 8080, protocol = "tcp" }
    ]
    environment = [
      { name = "SHIELD_MODE", value = "enforce" }
    ]
    secrets = local.api_secrets
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.ecs.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "api"
      }
    }
  }])
}

# Proxy task — standalone cipher-shield-proxy binary, reports to API
resource "aws_ecs_task_definition" "proxy" {
  family                   = "cipher-shield-proxy"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn

  container_definitions = jsonencode([{
    name       = "cipher-shield-proxy"
    image      = local.image
    essential  = true
    entryPoint = ["cipher-shield-proxy"]
    portMappings = [
      { containerPort = 7070, protocol = "tcp" }
    ]
    environment = [
      { name = "SHIELD_MODE",       value = "enforce" },
      { name = "SHIELD_SERVER_URL", value = "https://shield.${var.domain}" }
    ]
    secrets = local.proxy_secrets
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.ecs.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "proxy"
      }
    }
  }])
}

# ── ALB ───────────────────────────────────────────────────────────────────────

resource "aws_lb" "alb" {
  name               = "cipher-shield-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = [aws_subnet.public_a.id, aws_subnet.public_b.id]
  tags               = { Name = "cipher-shield-alb" }
}

resource "aws_lb_target_group" "api" {
  name        = "cipher-shield-api"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = aws_vpc.vpc.id
  target_type = "ip"

  health_check {
    path                = "/api/v1/health"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_target_group" "proxy" {
  name        = "cipher-shield-proxy"
  port        = 7070
  protocol    = "HTTP"
  vpc_id      = aws_vpc.vpc.id
  target_type = "ip"

  health_check {
    path                = "/"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
    matcher             = "200,404"
  }
}

# Single HTTPS listener — host-based routing sends npm/pypi to proxy, default to API
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.alb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.shield.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }

  depends_on = [aws_acm_certificate_validation.shield]
}

resource "aws_lb_listener_rule" "proxy" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 10

  condition {
    host_header {
      values = ["proxy.${var.domain}"]
    }
  }

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.proxy.arn
  }
}

# ── ECS Services ──────────────────────────────────────────────────────────────

resource "aws_ecs_service" "api" {
  name            = "cipher-shield-api"
  cluster         = aws_ecs_cluster.cluster.id
  task_definition = aws_ecs_task_definition.api.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = [aws_subnet.private_a.id, aws_subnet.private_b.id]
    security_groups = [aws_security_group.ecs.id]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "cipher-shield-api"
    container_port   = 8080
  }

  depends_on = [aws_lb_listener.https]
}

resource "aws_ecs_service" "proxy" {
  name            = "cipher-shield-proxy"
  cluster         = aws_ecs_cluster.cluster.id
  task_definition = aws_ecs_task_definition.proxy.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = [aws_subnet.private_a.id, aws_subnet.private_b.id]
    security_groups = [aws_security_group.ecs.id]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.proxy.arn
    container_name   = "cipher-shield-proxy"
    container_port   = 7070
  }

  depends_on = [aws_lb_listener.https]
}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "acm_validation_records" {
  value       = aws_acm_certificate.shield.domain_validation_options
  description = "Step 1: Add these CNAME records to Cloudflare to validate the ACM certificate"
}

output "alb_dns_name" {
  value       = aws_lb.alb.dns_name
  description = "Step 2: Create CNAME records in Cloudflare for shield.${var.domain} and proxy.${var.domain} pointing to this"
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
