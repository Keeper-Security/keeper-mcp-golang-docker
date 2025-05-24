# KSM MCP Deployment Guide

## Overview

This guide covers various deployment options for the KSM MCP server, including Docker, Docker Compose, Kubernetes, and standalone deployments.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Docker Deployment](#docker-deployment)
- [Docker Compose Deployment](#docker-compose-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Standalone Deployment](#standalone-deployment)
- [Security Considerations](#security-considerations)
- [Monitoring and Logging](#monitoring-and-logging)
- [Troubleshooting](#troubleshooting)

## Prerequisites

- Docker 20.10+ (for containerized deployments)
- Docker Compose 2.0+ (for multi-container deployments)
- Go 1.21+ (for building from source)
- Valid KSM credentials (one-time token or config file)

## Docker Deployment

### Quick Start

1. **Pull the image** (or build locally):
```bash
# Build locally
docker build -t keeper-mcp:latest .

# Or pull from registry (when available)
# docker pull keeper/ksm-mcp:latest
```

2. **Create secrets**:
```bash
# Create directories
mkdir -p secrets config logs

# Add your KSM token
echo "YOUR_KSM_TOKEN" > secrets/ksm_token.txt

# Or add your config file
cp /path/to/config.json secrets/ksm_config.json

# Optional: Add master password
echo "YOUR_MASTER_PASSWORD" > secrets/master_password.txt
```

3. **Run the container**:
```bash
docker run -it --rm \
  -v $(pwd)/config:/home/keeper/.keeper/ksm-mcp \
  -v $(pwd)/logs:/var/log/ksm-mcp \
  -v $(pwd)/secrets:/run/secrets:ro \
  keeper-mcp:latest
```

### Production Docker Run

For production, use more restrictive settings:

```bash
docker run -d \
  --name ksm-mcp \
  --restart unless-stopped \
  --memory="512m" \
  --cpus="1.0" \
  --read-only \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  -v ksm-config:/home/keeper/.keeper/ksm-mcp \
  -v ksm-logs:/var/log/ksm-mcp \
  -v $(pwd)/secrets:/run/secrets:ro \
  --health-cmd "ksm-mcp test --profile docker" \
  --health-interval 30s \
  keeper-mcp:latest serve --batch --log-level warn
```

## Docker Compose Deployment

### Development Setup

1. **Clone the repository**:
```bash
git clone https://github.com/keeper-security/ksm-mcp.git
cd ksm-mcp
```

2. **Create secrets**:
```bash
mkdir -p secrets
echo "YOUR_KSM_TOKEN" > secrets/ksm_token.txt
```

3. **Start services**:
```bash
docker-compose up -d
```

4. **View logs**:
```bash
docker-compose logs -f ksm-mcp
```

### Production Setup

Use the production compose file:

```bash
# Create external secrets
echo "PROD_TOKEN" | docker secret create ksm_token_production -
echo "PROD_PASSWORD" | docker secret create ksm_master_password_production -

# Deploy stack
docker stack deploy -c docker-compose.prod.yml ksm-mcp-prod
```

## Kubernetes Deployment

### Using kubectl

1. **Create namespace**:
```bash
kubectl create namespace ksm-mcp
```

2. **Create secrets**:
```bash
# Create KSM token secret
kubectl create secret generic ksm-secrets \
  --from-literal=token=YOUR_KSM_TOKEN \
  -n ksm-mcp

# Create master password secret
kubectl create secret generic master-password \
  --from-literal=password=YOUR_MASTER_PASSWORD \
  -n ksm-mcp
```

3. **Deploy application**:
```yaml
# ksm-mcp-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ksm-mcp
  namespace: ksm-mcp
spec:
  replicas: 2
  selector:
    matchLabels:
      app: ksm-mcp
  template:
    metadata:
      labels:
        app: ksm-mcp
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: ksm-mcp
        image: keeper-mcp:latest
        imagePullPolicy: Always
        command: ["ksm-mcp", "serve", "--batch"]
        env:
        - name: KSM_MCP_PROFILE
          value: "kubernetes"
        - name: KSM_MCP_LOG_LEVEL
          value: "info"
        volumeMounts:
        - name: config
          mountPath: /home/keeper/.keeper/ksm-mcp
        - name: logs
          mountPath: /var/log/ksm-mcp
        - name: ksm-token
          mountPath: /run/secrets/ksm_token
          subPath: token
          readOnly: true
        - name: master-password
          mountPath: /run/secrets/master_password
          subPath: password
          readOnly: true
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          exec:
            command:
            - ksm-mcp
            - test
            - --profile
            - kubernetes
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          exec:
            command:
            - ksm-mcp
            - test
            - --profile
            - kubernetes
          initialDelaySeconds: 10
          periodSeconds: 10
      volumes:
      - name: config
        persistentVolumeClaim:
          claimName: ksm-config-pvc
      - name: logs
        emptyDir: {}
      - name: ksm-token
        secret:
          secretName: ksm-secrets
      - name: master-password
        secret:
          secretName: master-password
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: ksm-config-pvc
  namespace: ksm-mcp
spec:
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
```

4. **Apply deployment**:
```bash
kubectl apply -f ksm-mcp-deployment.yaml
```

### Using Helm

A Helm chart is planned for future releases. For now, use the kubectl method above.

## Standalone Deployment

### Building from Source

1. **Clone and build**:
```bash
git clone https://github.com/keeper-security/ksm-mcp.git
cd ksm-mcp
make build
```

2. **Install**:
```bash
sudo make install
```

3. **Configure**:
```bash
# Initialize configuration
ksm-mcp init

# Add a profile
ksm-mcp profiles add production
```

4. **Run as service** (systemd):

Create `/etc/systemd/system/ksm-mcp.service`:
```ini
[Unit]
Description=KSM MCP Server
After=network.target

[Service]
Type=simple
User=ksm-mcp
Group=ksm-mcp
WorkingDirectory=/var/lib/ksm-mcp
ExecStart=/usr/local/bin/ksm-mcp serve --batch --profile production
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ksm-mcp

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/ksm-mcp /var/log/ksm-mcp

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable ksm-mcp
sudo systemctl start ksm-mcp
sudo systemctl status ksm-mcp
```

## Security Considerations

### Docker Security

1. **Use secrets** instead of environment variables for sensitive data
2. **Run as non-root** user (default in our image)
3. **Use read-only** filesystem where possible
4. **Drop capabilities** not needed
5. **Enable security options**:
   ```yaml
   security_opt:
     - no-new-privileges:true
     - seccomp:unconfined
   ```

### Network Security

1. **Don't expose ports** unless necessary (MCP uses stdio)
2. **Use internal networks** in Docker Compose
3. **Enable TLS** for any exposed endpoints
4. **Implement firewall rules** for standalone deployments

### Access Control

1. **Use master password** for profile encryption
2. **Rotate KSM tokens** regularly
3. **Limit profile permissions** in KSM
4. **Enable audit logging**
5. **Monitor access logs**

## Monitoring and Logging

### Log Management

Logs are written to:
- **Container**: stdout/stderr (JSON format)
- **File**: `/var/log/ksm-mcp/audit.log`

Configure log aggregation:
```yaml
logging:
  driver: "fluentd"
  options:
    fluentd-address: "localhost:24224"
    tag: "ksm-mcp"
```

### Metrics

Future versions will support Prometheus metrics at `/metrics` endpoint.

### Health Checks

Use the built-in health check:
```bash
# Docker
docker exec ksm-mcp ksm-mcp test --profile docker

# Kubernetes
kubectl exec -n ksm-mcp deployment/ksm-mcp -- ksm-mcp test
```

## Troubleshooting

### Common Issues

1. **Container won't start**:
   - Check logs: `docker logs ksm-mcp`
   - Verify secrets are mounted correctly
   - Ensure config directory is writable

2. **Authentication fails**:
   - Verify token/config is valid
   - Check network connectivity to KSM
   - Ensure time sync (for TOTP)

3. **Permission denied**:
   - Check file ownership (should be UID 1000)
   - Verify volume permissions
   - Ensure SELinux contexts (if applicable)

### Debug Mode

Run with debug logging:
```bash
docker run -it --rm \
  -e KSM_MCP_LOG_LEVEL=debug \
  keeper-mcp:latest serve --log-level debug
```

### Support

For issues and support:
- GitHub Issues: https://github.com/keeper-security/ksm-mcp/issues
- Documentation: https://github.com/keeper-security/ksm-mcp/wiki