# Deploying cipher-shield on AWS

**Architecture:** ECS Fargate + RDS PostgreSQL.  
Managed containers — no EC2 to patch, auto-restarts on crash, scales 1–4 tasks at 60% CPU.  
**Estimated cost:** ~$35–60/month at low traffic.

---

## Prerequisites

- AWS CLI installed and authenticated (`aws configure`)
- Permissions to create ECS, RDS, IAM, Secrets Manager, and VPC resources

---

## 1. Set variables

```bash
export AWS_REGION=us-east-1
export APP=cipher-shield
export IMAGE=ghcr.io/cipher-oss/cipher-shield:latest
export DB_NAME=shield
export DB_USER=shieldadmin
```

---

## 2. Store secrets in Secrets Manager

```bash
JWT_SECRET=$(openssl rand -hex 32)
PROXY_TOKEN=$(openssl rand -hex 32)
DB_PASSWORD=$(openssl rand -hex 16)

aws secretsmanager create-secret --region $AWS_REGION \
  --name $APP/jwt-secret --secret-string "$JWT_SECRET"
aws secretsmanager create-secret --region $AWS_REGION \
  --name $APP/proxy-token --secret-string "$PROXY_TOKEN"
```

---

## 3. Networking — default VPC

```bash
VPC_ID=$(aws ec2 describe-vpcs --region $AWS_REGION \
  --filters Name=isDefault,Values=true \
  --query 'Vpcs[0].VpcId' --output text)

# Grab the first two public subnets
SUBNETS=$(aws ec2 describe-subnets --region $AWS_REGION \
  --filters Name=vpc-id,Values=$VPC_ID \
  --query 'Subnets[0:2].SubnetId' --output text | tr '\t' ',')
```

---

## 4. Security groups

```bash
# Task — accepts API (8080) and proxy (7070) traffic
TASK_SG=$(aws ec2 create-security-group --region $AWS_REGION \
  --group-name $APP-task --description "$APP Fargate task" \
  --vpc-id $VPC_ID --query GroupId --output text)
aws ec2 authorize-security-group-ingress --region $AWS_REGION \
  --group-id $TASK_SG --protocol tcp --port 8080 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --region $AWS_REGION \
  --group-id $TASK_SG --protocol tcp --port 7070 --cidr 0.0.0.0/0

# Database — only reachable from the Fargate task
DB_SG=$(aws ec2 create-security-group --region $AWS_REGION \
  --group-name $APP-db --description "$APP RDS" \
  --vpc-id $VPC_ID --query GroupId --output text)
aws ec2 authorize-security-group-ingress --region $AWS_REGION \
  --group-id $DB_SG --protocol tcp --port 5432 --source-group $TASK_SG
```

---

## 5. Create RDS PostgreSQL

```bash
aws rds create-db-subnet-group --region $AWS_REGION \
  --db-subnet-group-name $APP-subnets \
  --db-subnet-group-description "$APP DB subnets" \
  --subnet-ids $(echo $SUBNETS | tr ',' ' ')

aws rds create-db-instance --region $AWS_REGION \
  --db-instance-identifier $APP-pg \
  --db-instance-class db.t4g.micro \
  --engine postgres --engine-version 16.3 \
  --master-username $DB_USER \
  --master-user-password "$DB_PASSWORD" \
  --db-name $DB_NAME \
  --vpc-security-group-ids $DB_SG \
  --db-subnet-group-name $APP-subnets \
  --no-publicly-accessible \
  --allocated-storage 20

# ~5 minutes
aws rds wait db-instance-available --region $AWS_REGION \
  --db-instance-identifier $APP-pg

DB_HOST=$(aws rds describe-db-instances --region $AWS_REGION \
  --db-instance-identifier $APP-pg \
  --query 'DBInstances[0].Endpoint.Address' --output text)

aws secretsmanager create-secret --region $AWS_REGION \
  --name $APP/db-url \
  --secret-string "postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:5432/${DB_NAME}?sslmode=require"
```

---

## 6. IAM execution role

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

aws iam create-role --role-name $APP-exec-role \
  --assume-role-policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}]
  }'

aws iam attach-role-policy --role-name $APP-exec-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy

aws iam put-role-policy --role-name $APP-exec-role \
  --policy-name secrets-read \
  --policy-document "{
    \"Version\":\"2012-10-17\",
    \"Statement\":[{
      \"Effect\":\"Allow\",
      \"Action\":\"secretsmanager:GetSecretValue\",
      \"Resource\":\"arn:aws:secretsmanager:${AWS_REGION}:${ACCOUNT_ID}:secret:${APP}/*\"
    }]
  }"

ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${APP}-exec-role"
```

---

## 7. ECS cluster and task definition

```bash
aws ecs create-cluster --region $AWS_REGION --cluster-name $APP

aws logs create-log-group --region $AWS_REGION --log-group-name /ecs/$APP

cat > /tmp/task.json << EOF
{
  "family": "$APP",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512", "memory": "1024",
  "executionRoleArn": "${ROLE_ARN}",
  "taskRoleArn": "${ROLE_ARN}",
  "containerDefinitions": [{
    "name": "$APP",
    "image": "${IMAGE}",
    "portMappings": [
      {"containerPort": 8080},
      {"containerPort": 7070}
    ],
    "environment": [
      {"name": "SHIELD_MODE", "value": "enforce"}
    ],
    "secrets": [
      {"name": "SHIELD_JWT_SECRET",  "valueFrom": "arn:aws:secretsmanager:${AWS_REGION}:${ACCOUNT_ID}:secret:${APP}/jwt-secret"},
      {"name": "SHIELD_PROXY_TOKEN", "valueFrom": "arn:aws:secretsmanager:${AWS_REGION}:${ACCOUNT_ID}:secret:${APP}/proxy-token"},
      {"name": "DATABASE_URL",       "valueFrom": "arn:aws:secretsmanager:${AWS_REGION}:${ACCOUNT_ID}:secret:${APP}/db-url"}
    ],
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "/ecs/${APP}",
        "awslogs-region": "${AWS_REGION}",
        "awslogs-stream-prefix": "ecs"
      }
    }
  }]
}
EOF

aws ecs register-task-definition --region $AWS_REGION --cli-input-json file:///tmp/task.json
```

---

## 8. Deploy Fargate service with auto-scaling

```bash
aws ecs create-service --region $AWS_REGION \
  --cluster $APP --service-name $APP \
  --task-definition $APP --desired-count 1 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={
    subnets=[${SUBNETS}],
    securityGroups=[${TASK_SG}],
    assignPublicIp=ENABLED
  }"

# Scale 1–4 tasks; add a task when average CPU exceeds 60%
aws application-autoscaling register-scalable-target \
  --service-namespace ecs \
  --resource-id service/$APP/$APP \
  --scalable-dimension ecs:service:DesiredCount \
  --min-capacity 1 --max-capacity 4

aws application-autoscaling put-scaling-policy \
  --service-namespace ecs \
  --resource-id service/$APP/$APP \
  --scalable-dimension ecs:service:DesiredCount \
  --policy-name cpu-scaling \
  --policy-type TargetTrackingScaling \
  --target-tracking-scaling-policy-configuration '{
    "TargetValue": 60.0,
    "PredefinedMetricSpecification": {"PredefinedMetricType": "ECSServiceAverageCPUUtilization"},
    "ScaleInCooldown": 60,
    "ScaleOutCooldown": 30
  }'
```

---

## 9. Get the public IP and verify

```bash
# Wait until the service has a running task (image pull + startup, ~60–90s)
aws ecs wait services-stable --region $AWS_REGION --cluster $APP --services $APP

TASK_ARN=$(aws ecs list-tasks --region $AWS_REGION \
  --cluster $APP --service-name $APP \
  --query 'taskArns[0]' --output text)

ENI=$(aws ecs describe-tasks --region $AWS_REGION \
  --cluster $APP --tasks $TASK_ARN \
  --query 'tasks[0].attachments[0].details[?name==`networkInterfaceId`].value' \
  --output text)

SERVER_IP=$(aws ec2 describe-network-interfaces --region $AWS_REGION \
  --network-interface-ids $ENI \
  --query 'NetworkInterfaces[0].Association.PublicIp' --output text)

curl http://$SERVER_IP:8080/api/v1/health
# {"status":"ok","version":"0.1.0"}
```

---

## 10. Bootstrap the first admin user

```bash
curl -X POST http://$SERVER_IP:8080/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@yourcompany.com","password":"changeme","role":"admin"}'
```

This endpoint is open when the users table is empty; the first user is forced to `admin`. After that, it requires an admin JWT.

---

## 11. Configure dev machines

On each developer's machine:

```bash
export SHIELD_SERVER_URL=http://$SERVER_IP:8080
export SHIELD_PROXY_TOKEN=<PROXY_TOKEN from step 2>
cipher-shield proxy start
```

---

## Corporate proxies and secure web gateways

If your organization runs Cisco Umbrella, Zscaler, Netskope, or a similar SWG, see **[Network and corporate proxy requirements →](network.md)** for the one-time policy changes needed to allow cipher-shield traffic through.

---

## Teardown

```bash
aws ecs update-service --region $AWS_REGION --cluster $APP --service $APP --desired-count 0
aws ecs delete-service --region $AWS_REGION --cluster $APP --service $APP
aws ecs delete-cluster --region $AWS_REGION --cluster $APP
aws rds delete-db-instance --region $AWS_REGION \
  --db-instance-identifier $APP-pg --skip-final-snapshot
aws ec2 delete-security-group --region $AWS_REGION --group-id $TASK_SG
aws ec2 delete-security-group --region $AWS_REGION --group-id $DB_SG
```
