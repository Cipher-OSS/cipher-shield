# Deploying cipher-shield on AWS

**Architecture:** EC2 (t3.micro) + RDS PostgreSQL (db.t3.micro) inside a VPC.  
**Estimated cost:** ~$25–35/month.

---

## Prerequisites

- AWS CLI installed and configured (`aws configure`)
- An AWS account with permissions to create EC2, RDS, VPC, and security group resources
- A domain or IP to point your team at (or use the EC2 public IP directly)

---

## 1. Generate secrets

Run these locally and save the output — you'll need them in later steps.

```bash
export JWT_SECRET=$(openssl rand -hex 32)
export PROXY_TOKEN=$(openssl rand -hex 32)
export DB_PASSWORD=$(openssl rand -hex 16)

echo "JWT_SECRET=$JWT_SECRET"
echo "PROXY_TOKEN=$PROXY_TOKEN"
echo "DB_PASSWORD=$DB_PASSWORD"
```

---

## 2. Create a VPC and subnets

If you already have a VPC you want to use, skip to step 3.

```bash
# Create VPC
VPC_ID=$(aws ec2 create-vpc --cidr-block 10.0.0.0/16 \
  --query 'Vpc.VpcId' --output text)
aws ec2 modify-vpc-attribute --vpc-id $VPC_ID --enable-dns-hostnames

# Public subnet (EC2)
SUBNET_PUBLIC=$(aws ec2 create-subnet --vpc-id $VPC_ID \
  --cidr-block 10.0.1.0/24 --availability-zone us-east-1a \
  --query 'Subnet.SubnetId' --output text)

# Private subnets (RDS requires two AZs)
SUBNET_PRIV_A=$(aws ec2 create-subnet --vpc-id $VPC_ID \
  --cidr-block 10.0.2.0/24 --availability-zone us-east-1a \
  --query 'Subnet.SubnetId' --output text)
SUBNET_PRIV_B=$(aws ec2 create-subnet --vpc-id $VPC_ID \
  --cidr-block 10.0.3.0/24 --availability-zone us-east-1b \
  --query 'Subnet.SubnetId' --output text)

# Internet gateway
IGW=$(aws ec2 create-internet-gateway --query 'InternetGateway.InternetGatewayId' --output text)
aws ec2 attach-internet-gateway --vpc-id $VPC_ID --internet-gateway-id $IGW

# Route table for public subnet
RT=$(aws ec2 create-route-table --vpc-id $VPC_ID \
  --query 'RouteTable.RouteTableId' --output text)
aws ec2 create-route --route-table-id $RT --destination-cidr-block 0.0.0.0/0 --gateway-id $IGW
aws ec2 associate-route-table --route-table-id $RT --subnet-id $SUBNET_PUBLIC
```

---

## 3. Create security groups

```bash
# EC2 security group
SG_EC2=$(aws ec2 create-security-group \
  --group-name cipher-shield-ec2 \
  --description "cipher-shield server" \
  --vpc-id $VPC_ID \
  --query 'GroupId' --output text)

# SSH (restrict to your IP in production)
aws ec2 authorize-security-group-ingress --group-id $SG_EC2 \
  --protocol tcp --port 22 --cidr 0.0.0.0/0

# Dashboard + API — open to team (restrict to your office/VPN CIDR in production)
aws ec2 authorize-security-group-ingress --group-id $SG_EC2 \
  --protocol tcp --port 8080 --cidr 0.0.0.0/0

# Registry proxy — open to dev machines
aws ec2 authorize-security-group-ingress --group-id $SG_EC2 \
  --protocol tcp --port 7070 --cidr 0.0.0.0/0

# RDS security group (only reachable from EC2)
SG_RDS=$(aws ec2 create-security-group \
  --group-name cipher-shield-rds \
  --description "cipher-shield postgres" \
  --vpc-id $VPC_ID \
  --query 'GroupId' --output text)

aws ec2 authorize-security-group-ingress --group-id $SG_RDS \
  --protocol tcp --port 5432 --source-group $SG_EC2
```

---

## 4. Create RDS PostgreSQL instance

```bash
# Subnet group
aws rds create-db-subnet-group \
  --db-subnet-group-name cipher-shield-subnets \
  --db-subnet-group-description "cipher-shield" \
  --subnet-ids $SUBNET_PRIV_A $SUBNET_PRIV_B

# Database (takes ~5 minutes)
aws rds create-db-instance \
  --db-instance-identifier cipher-shield-db \
  --db-instance-class db.t3.micro \
  --engine postgres \
  --engine-version 16 \
  --master-username shield \
  --master-user-password "$DB_PASSWORD" \
  --db-name shield \
  --db-subnet-group-name cipher-shield-subnets \
  --vpc-security-group-ids $SG_RDS \
  --no-publicly-accessible \
  --storage-type gp2 \
  --allocated-storage 20

# Wait for it to be available
aws rds wait db-instance-available --db-instance-identifier cipher-shield-db

# Get the endpoint
DB_HOST=$(aws rds describe-db-instances \
  --db-instance-identifier cipher-shield-db \
  --query 'DBInstances[0].Endpoint.Address' --output text)
echo "DB_HOST=$DB_HOST"
```

---

## 5. Launch EC2 instance

```bash
# Get latest Amazon Linux 2023 AMI
AMI=$(aws ec2 describe-images \
  --owners amazon \
  --filters "Name=name,Values=al2023-ami-*-x86_64" \
            "Name=state,Values=available" \
  --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
  --output text)

# Create key pair (skip if you already have one)
aws ec2 create-key-pair --key-name cipher-shield \
  --query 'KeyMaterial' --output text > ~/.ssh/cipher-shield.pem
chmod 400 ~/.ssh/cipher-shield.pem

# User data script — installs Docker and starts cipher-shield
cat > /tmp/userdata.sh << USERDATA
#!/bin/bash
yum install -y docker
systemctl enable --now docker

docker run -d \
  --name cipher-shield \
  --restart unless-stopped \
  -p 7070:7070 \
  -p 8080:8080 \
  -e SHIELD_JWT_SECRET="${JWT_SECRET}" \
  -e SHIELD_PROXY_TOKEN="${PROXY_TOKEN}" \
  -e SHIELD_MODE=enforce \
  -e DATABASE_URL="postgres://shield:${DB_PASSWORD}@${DB_HOST}:5432/shield?sslmode=require" \
  ghcr.io/homes853/cipher-shield:latest
USERDATA

# Launch instance
INSTANCE_ID=$(aws ec2 run-instances \
  --image-id $AMI \
  --instance-type t3.micro \
  --key-name cipher-shield \
  --security-group-ids $SG_EC2 \
  --subnet-id $SUBNET_PUBLIC \
  --associate-public-ip-address \
  --user-data file:///tmp/userdata.sh \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=cipher-shield}]' \
  --query 'Instances[0].InstanceId' --output text)

aws ec2 wait instance-running --instance-ids $INSTANCE_ID

SERVER_IP=$(aws ec2 describe-instances \
  --instance-ids $INSTANCE_ID \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
echo "Server IP: $SERVER_IP"
```

---

## 6. Verify the server is running

```bash
# Wait ~60 seconds for Docker to pull and start the image, then:
curl http://$SERVER_IP:8080/api/v1/health
# {"status":"ok","version":"0.1.0"}
```

---

## 7. Bootstrap the first admin user

```bash
curl -X POST http://$SERVER_IP:8080/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@yourcompany.com","password":"changeme","role":"admin"}'
```

This endpoint requires no auth when the users table is empty. The first user is always created as admin. After this, `POST /api/v1/users` requires an admin JWT.

---

## 8. Configure dev machines

On each developer's machine, set these environment variables (add to `~/.zshrc` or `~/.bashrc`):

```bash
export SHIELD_SERVER_URL=http://$SERVER_IP:8080
export SHIELD_PROXY_TOKEN=<your PROXY_TOKEN from step 1>
```

Then start the proxy:

```bash
cipher-shield proxy start
```

---

## 9. (Optional) Put a load balancer in front

For HTTPS and a stable DNS name, add an Application Load Balancer:

```bash
# Create ALB targeting port 8080 (dashboard/API)
# The proxy port 7070 stays HTTP — use a NLB or VPN for that in production
```

Or use Amazon Certificate Manager (ACM) + Route 53 to give the server a proper domain with TLS.

---

## Teardown

```bash
aws ec2 terminate-instances --instance-ids $INSTANCE_ID
aws rds delete-db-instance --db-instance-identifier cipher-shield-db --skip-final-snapshot
aws ec2 delete-security-group --group-id $SG_EC2
aws ec2 delete-security-group --group-id $SG_RDS
```
