# KSM MCP - Keeper Secrets Manager Model Context Protocol Server

[![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)](https://golang.org)
[![MCP Protocol](https://img.shields.io/badge/MCP-1.0-green.svg)](https://modelcontextprotocol.io)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://hub.docker.com/r/keepersecurityinc/ksm-mcp-poc)

A secure Model Context Protocol (MCP) server for Keeper Secrets Manager (KSM) that enables AI agents to safely interact with secrets without direct credential exposure.

## 📋 Quick Start Guide

KSM MCP lets AI assistants manage your secrets securely:
- **What**: Bridge between AI (like Claude) and Keeper Secrets Manager
- **Why**: AI never sees your KSM credentials or master password
- **How**: Install → Initialize with base64 config → AI can now manage secrets safely
- **Security**: All sensitive operations require human confirmation

> **Note**: This guide uses base64-encoded configuration for the fastest setup. For production deployments, see [Advanced Configuration](#advanced-configuration).

## 🎯 Overview

KSM MCP acts as a secure intermediary between AI agents and Keeper Secrets Manager, implementing the Model Context Protocol to provide controlled access to secrets management capabilities. It ensures that sensitive credentials are never exposed to AI models while maintaining full auditability and security controls.

### Key Benefits

- **Zero Trust Architecture**: AI agents never see KSM credentials
- **Human-in-the-Loop**: Confirmation prompts for sensitive operations
- **Enterprise Ready**: Comprehensive audit logging and compliance features
- **Docker Native**: Easy deployment with container support
- **Multi-Platform**: Works on Linux, macOS, and Windows

## 🚀 Quick Start (Under 2 Minutes)

### Option 1: Docker (Recommended)

```bash
# Pull the image
docker pull keepersecurityinc/ksm-mcp-poc:latest

# Initialize with base64 config (get from KSM portal)
docker run -it --rm \
  keepersecurityinc/ksm-mcp-poc:latest \
  init --config "BASE64_CONFIG_STRING"

# Start the server
docker run -it --rm \
  -v ~/.keeper/ksm-mcp:/home/ksm/.keeper/ksm-mcp \
  keepersecurityinc/ksm-mcp-poc:latest serve
```

### Option 2: Binary Installation

```bash
# Download latest release (macOS/Linux)
curl -L https://github.com/Keeper-Security/ksm-mcp/releases/latest/download/ksm-mcp-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m | sed 's/x86_64/amd64/') -o ksm-mcp
chmod +x ksm-mcp

# Or download manually from: https://github.com/Keeper-Security/ksm-mcp/releases/latest

# Initialize with base64 config (get from KSM portal)
./ksm-mcp init --config "BASE64_CONFIG_STRING"

# Start the server
./ksm-mcp serve
```

### Option 3: Build from Source

```bash
# Clone and build
git clone https://github.com/keeper-security/ksm-mcp.git
cd ksm-mcp
make build

# Initialize with base64 config
./bin/ksm-mcp init --config "BASE64_CONFIG_STRING"
./bin/ksm-mcp serve
```

## 📝 Getting Your Base64 Config

1. Log into your [Keeper Secrets Manager Portal](https://keepersecurity.com/secrets-manager/)
2. Create or select an application
3. Generate a One-Time Token
4. Copy the **base64-encoded configuration string** (starts with `ewog...`)
5. Use this string in the `--config` parameter during initialization

> **Important**: The base64 config contains your KSM credentials. Keep it secure and never commit it to version control.

## 🔧 Configuration

### Claude Desktop Integration

Add to your Claude Desktop configuration:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`  
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`  
**Linux**: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "ksm": {
      "command": "/usr/local/bin/ksm-mcp",
      "args": ["serve"]
    }
  }
}
```

For Docker:
```json
{
  "mcpServers": {
    "ksm": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "~/.keeper/ksm-mcp:/home/ksm/.keeper/ksm-mcp",
        "keepersecurityinc/ksm-mcp-poc:latest",
        "serve"
      ]
    }
  }
}
```

### Advanced Configuration

For production deployments, consider:

1. **File-based configuration** (more secure than base64):
   ```bash
   ksm-mcp init --config /path/to/ksm-config.json
   ```

2. **Master password protection**:
   ```bash
   ksm-mcp init --config "BASE64_CONFIG" --master-password
   ```

3. **Multiple profiles** for different environments:
   ```bash
   ksm-mcp init --profile prod --config "PROD_CONFIG"
   ksm-mcp init --profile dev --config "DEV_CONFIG"
   ```

See the [Deployment Guide](docs/DEPLOYMENT.md) for detailed production setup.

## 📋 Available MCP Tools

### Secret Operations

| Tool | Description | Confirmation Required |
|------|-------------|-----------------------|
| `list_secrets` | List all accessible secrets | No |
| `get_secret` | Retrieve a specific secret (masked by default) | Yes (for unmasked) |
| `search_secrets` | Search secrets by title/notes/fields | No |
| `create_secret` | Create a new secret | Yes |
| `update_secret` | Update an existing secret | Yes |
| `delete_secret` | Delete a secret | Yes |

### File Management

| Tool | Description | Confirmation Required |
|------|-------------|-----------------------|
| `list_files` | List file attachments | No |
| `upload_file` | Upload file to secret | Yes |
| `download_file` | Download file from secret | Yes |
| `delete_file` | Delete file attachment | Yes |

### Utilities

| Tool | Description | Confirmation Required |
|------|-------------|-----------------------|
| `notation_query` | Execute KSM notation query | No |
| `generate_password` | Generate secure password | No |
| `get_totp_code` | Get current TOTP code | No |
| `health_check` | Check server health status | No |

## 🔐 Security Features

### Master Password Protection

All KSM credentials are encrypted with AES-256-GCM:

```bash
# Set master password on first use
ksm-mcp init --token "TOKEN"
Enter master password: ****
Confirm master password: ****

# Required on each server start
ksm-mcp serve
Enter master password: ****
```

### Confirmation Prompts

Sensitive operations require explicit approval:

```
🔒 Confirmation Required
Operation: create_secret
Title: Production Database
Type: databaseCredentials
Approve? (y/N): y
✅ Operation approved
```

### Audit Logging

All operations are logged with full context:

```json
{
  "timestamp": "2024-01-23T10:15:30Z",
  "event_id": "evt_123456",
  "session_id": "ses_789012",
  "event_type": "secret_accessed",
  "user": "ai_agent",
  "resource": "secret/prod-db",
  "action": "read",
  "result": "success",
  "ip_address": "127.0.0.1"
}
```

### ⚠️ Important Security Warning

**Password Exposure to AI Models**: When you unmask passwords or generate passwords without the `save_to_secret` parameter, the password values are exposed to the AI model. This defeats the security purpose of KSM MCP.

**Best Practices**:
- Always use `save_to_secret` when generating passwords: The password is saved directly without AI exposure
- Avoid unmasking passwords unless absolutely necessary (e.g., test/QA passwords)
- Use field notation to work with passwords without exposing them
- Let the AI work with secret UIDs rather than actual values

## 📚 Usage Examples

### Searching Secrets

The search functionality looks across multiple fields:

```json
// Search by title
{
  "tool": "search_secrets",
  "arguments": {
    "query": "production"
  }
}

// Search by URL/hostname
{
  "tool": "search_secrets", 
  "arguments": {
    "query": "api.example.com"
  }
}

// Search by username
{
  "tool": "search_secrets",
  "arguments": {
    "query": "admin@company.com"
  }
}
```

Search covers:
- Secret titles
- Notes/descriptions
- Record types (e.g., "PAM Machine", "login", "password")
- Login usernames
- URLs and hostnames
- Addresses
- File attachment names

### Password Generation with Security

```json
// Generate and save password (secure - AI never sees it)
{
  "tool": "generate_password",
  "arguments": {
    "length": 32,
    "save_to_secret": "New API Key"
  }
}
// Returns: {"message": "Password generated and saved to secret 'New API Key'", "uid": "xxx"}

// Generate password (exposed to AI - use only for test/QA)
{
  "tool": "generate_password",
  "arguments": {
    "length": 16,
    "digits": 4,
    "special": 2
  }
}
// Returns: {"password": "actual-password-here", "warning": "Password is exposed to AI model"}
```

### Working with UIDs

All list operations now prominently display UIDs:

```json
// List secrets response
{
  "secrets": [
    {
      "uid": "BkZU8qnwN0aBP8x2jDTSRA",
      "title": "Production Database",
      "type": "databaseCredentials",
      "folder": "shared/infrastructure"
    }
  ],
  "count": 1
}
```

## 🐳 Docker Deployment

### Docker Compose

```yaml
version: '3.8'
services:
  ksm-mcp:
    image: keeper/ksm-mcp:latest
    environment:
      - KSM_MCP_PROFILE=production
      - KSM_MCP_LOG_LEVEL=info
    volumes:
      - ./config:/home/keeper/.keeper/ksm-mcp
    secrets:
      - ksm_token
    stdin_open: true
    tty: true

secrets:
  ksm_token:
    file: ./secrets/ksm_token.txt
```

### Kubernetes

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: ksm-secrets
data:
  token: <base64-encoded-token>
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ksm-mcp
spec:
  replicas: 1
  template:
    spec:
      containers:
      - name: ksm-mcp
        image: keeper/ksm-mcp:latest
        env:
        - name: KSM_MCP_TOKEN
          valueFrom:
            secretKeyRef:
              name: ksm-secrets
              key: token
```

## 🛠️ Advanced Usage

### Batch Mode

For automated environments without user interaction:

```bash
# Auto-approve all operations (use with caution!)
ksm-mcp serve --batch --auto-approve

# With timeout for operations
ksm-mcp serve --batch --timeout 60s
```

### KSM Notation Examples

```bash
# Get specific field
keeper://record_uid/field/password

# Get by title
keeper://Database Login/field/password

# Complex notation
keeper://shared_folder/subfolder/record_title/field/username
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `KSM_MCP_CONFIG_DIR` | Configuration directory | `~/.keeper/ksm-mcp` |
| `KSM_MCP_PROFILE` | Default profile name | From config |
| `KSM_MCP_BATCH_MODE` | Enable batch mode | `false` |
| `KSM_MCP_LOG_LEVEL` | Logging level | `info` |
| `KSM_MCP_MASTER_PASSWORD` | Master password (not recommended) | - |

## 📊 Monitoring

### Health Check

```bash
# CLI health check
ksm-mcp test --profile production

# MCP tool
{"tool": "health_check"}

# Response
{
  "status": "healthy",
  "profile": "production",
  "uptime": "2h30m",
  "checks": {
    "storage": "ok",
    "ksm_connection": "ok",
    "rate_limiter": "ok"
  }
}
```

### Metrics (Coming Soon)

Prometheus metrics endpoint at `/metrics`:
- Request rates and latencies
- Error rates by operation
- Active sessions
- Rate limit statistics

## 🧪 Testing

```bash
# Run all tests
make test

# Run with coverage
make coverage

# Run E2E tests
make test-e2e

# Run security tests
go test ./... -run Security
```

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone repository
git clone https://github.com/keeper-security/ksm-mcp.git
cd ksm-mcp

# Install dependencies
make deps

# Run tests
make test

# Build binary
make build
```

## 📚 Documentation

- [Technical Architecture](docs/TECHNICAL.md) - System design and architecture
- [Security Guide](docs/SECURITY.md) - Security considerations and best practices
- [API Reference](docs/API.md) - Complete MCP tools documentation
- [User Guide](docs/USER_GUIDE.md) - Detailed usage instructions
- [Deployment Guide](docs/DEPLOYMENT.md) - Production deployment options

## 🐛 Troubleshooting

### Common Issues

**"Profile not found" error**
```bash
# List profiles
ksm-mcp profiles list

# Recreate profile
ksm-mcp init --profile myprofile --token "NEW_TOKEN"
```

**"Connection timeout" error**
```bash
# Test connectivity
ksm-mcp test --profile production --verbose

# Check KSM status
curl -I https://keepersecurity.com/api/rest/ping
```

**"Rate limit exceeded" error**
```bash
# Check current limits
ksm-mcp config get mcp.rate_limit

# Adjust limits
ksm-mcp config set mcp.rate_limit.requests_per_minute 120
```

## 📄 License

Copyright © 2024 Keeper Security, Inc.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## 🔗 Links

- **Homepage**: https://keepersecurity.com
- **Documentation**: https://docs.keeper.io/secrets-manager/
- **MCP Specification**: https://modelcontextprotocol.io
- **Support**: support@keepersecurity.com
- **Security**: security@keepersecurity.com

## 🙏 Acknowledgments

- [Model Context Protocol](https://modelcontextprotocol.io) - Protocol specification
- [Keeper Security](https://keepersecurity.com) - Secrets management platform
- [Anthropic](https://anthropic.com) - Claude AI and MCP ecosystem

---

Made with ❤️ by Keeper Security