# KSM MCP User Guide

This guide walks you through setting up and using the KSM MCP server with your AI agents.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Profile Setup](#profile-setup)
3. [Running the Server](#running-the-server)
4. [AI Agent Integration](#ai-agent-integration)
5. [Common Use Cases](#common-use-cases)
6. [Troubleshooting](#troubleshooting)

## Getting Started

### Prerequisites

Before you begin, ensure you have:

1. **Keeper Secrets Manager Account**
   - Active KSM subscription
   - API access enabled
   - Base64 configuration string from KSM portal

2. **System Requirements**
   - macOS, Linux, or Windows
   - Docker (optional but recommended)
   - 50MB free disk space
   - Terminal access

### Installation

#### Option 1: Docker (Easiest - Recommended)

```bash
# Pull the Docker image
docker pull keepersecurityinc/ksm-mcp-poc:latest

# Test installation
docker run --rm keepersecurityinc/ksm-mcp-poc:latest --version
```

#### Option 2: Download Binary

```bash
# macOS (Intel)
curl -LO https://github.com/Keeper-Security/ksm-mcp/releases/latest/download/ksm-mcp-darwin-amd64.tar.gz
tar -xzf ksm-mcp-darwin-amd64.tar.gz
sudo mv ksm-mcp-darwin-amd64 /usr/local/bin/ksm-mcp

# macOS (Apple Silicon)
curl -LO https://github.com/Keeper-Security/ksm-mcp/releases/latest/download/ksm-mcp-darwin-arm64.tar.gz
tar -xzf ksm-mcp-darwin-arm64.tar.gz
sudo mv ksm-mcp-darwin-arm64 /usr/local/bin/ksm-mcp

# Linux
curl -LO https://github.com/Keeper-Security/ksm-mcp/releases/latest/download/ksm-mcp-linux-amd64.tar.gz
tar -xzf ksm-mcp-linux-amd64.tar.gz
sudo mv ksm-mcp-linux-amd64 /usr/local/bin/ksm-mcp

# Windows
# Download ksm-mcp-windows-amd64.zip from:
# https://github.com/Keeper-Security/ksm-mcp/releases/latest
# Extract and add to PATH
```

#### Option 3: Build from Source

```bash
git clone https://github.com/Keeper-Security/ksm-mcp.git
cd ksm-mcp
make build
sudo mv bin/ksm-mcp /usr/local/bin/
```

### Verify Installation

```bash
ksm-mcp --version
# Output: ksm-mcp version 1.0.0
```

## Profile Setup

### Quick Setup (Recommended for Getting Started)

#### Step 1: Get Your Base64 Configuration

1. Log into [Keeper Secrets Manager Portal](https://keepersecurity.com/secrets-manager/)
2. Navigate to Applications
3. Create a new application or select existing
4. Generate a One-Time Token
5. Copy the **base64 configuration string** (starts with `ewog...`)

#### Step 2: Initialize KSM MCP

**Using Docker:**
```bash
# Initialize with base64 config (no master password for quick start)
docker run -it --rm \
  -v ~/.keeper/ksm-mcp:/home/ksm/.keeper/ksm-mcp \
  keepersecurityinc/ksm-mcp-poc:latest \
  init --config "YOUR_BASE64_CONFIG_STRING" --no-master-password

# Output:
✓ Successfully initialized KSM configuration
✓ Testing connection... Connected to Keeper Secrets Manager (42 secrets found)
✓ Profile 'default' created successfully
```

**Using Binary:**
```bash
# Initialize with base64 config
ksm-mcp init --config "YOUR_BASE64_CONFIG_STRING" --no-master-password
```

> **Note**: The `--no-master-password` flag skips master password setup for faster onboarding. For production use, omit this flag to add password protection.

### Production Setup (More Secure)

For production environments, use these more secure options:

#### Option 1: File-Based Configuration
```bash
# Save your KSM config to a file
echo '{"clientId":"...","privateKey":"..."}' > ~/keeper/ksm-config.json

# Initialize with file
ksm-mcp init --config ~/keeper/ksm-config.json
```

#### Option 2: With Master Password
```bash
# Initialize with master password protection
ksm-mcp init --config "BASE64_CONFIG_STRING"

# You'll be prompted:
Enter master password: ********
Confirm master password: ********
```

#### Option 3: Multiple Profiles
```bash
# Create profiles for different environments
ksm-mcp init --profile production --config "PROD_CONFIG"
ksm-mcp init --profile development --config "DEV_CONFIG"

# Set default profile
ksm-mcp profiles set-default production
```

### Managing Multiple Profiles

```bash
# List all profiles
ksm-mcp profiles list
PROFILE     DEFAULT
-------     -------
mycompany   ✓
production  
staging     

# Switch default profile
ksm-mcp profiles set-default production

# Show profile details
ksm-mcp profiles show production

# Delete old profile
ksm-mcp profiles delete staging
```

## Running the Server

### Quick Start

**Using Docker:**
```bash
# Run the server (after initialization)
docker run -it --rm \
  -v ~/.keeper/ksm-mcp:/home/ksm/.keeper/ksm-mcp \
  keepersecurityinc/ksm-mcp-poc:latest serve
```

**Using Binary:**
```bash
# Start with default profile
ksm-mcp serve
```

### Claude Desktop Integration

1. **Find your config file location:**
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`
   - Linux: `~/.config/Claude/claude_desktop_config.json`

2. **Add KSM MCP configuration:**

   **For Docker users:**
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

   **For binary users:**
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

3. **Restart Claude Desktop** to load the new configuration

### Server Modes

#### Interactive Mode (Default)
- Prompts for confirmations on sensitive operations
- Shows operation details
- Best for development and testing

```bash
ksm-mcp serve
```

#### Batch Mode
- No interactive prompts
- Operations timeout after 30s
- Good for automation

```bash
ksm-mcp serve --batch --timeout 30s
```

#### Auto-Approve Mode (Use with Caution!)
- Automatically approves all operations
- No confirmations required
- Only for trusted environments

```bash
ksm-mcp serve --auto-approve
```

### Understanding Confirmations

When the server asks for confirmation:

```
┌─────────────────────────────────────────┐
│ Confirmation Required                   │
├─────────────────────────────────────────┤
│ Reveal unmasked secret Production DB?   │
│                                         │
│ This will expose sensitive data.        │
│                                         │
│ Approve? (y/N):                        │
└─────────────────────────────────────────┘
```

- Type `y` or `yes` to approve
- Press Enter or type `n` to deny
- Default is deny for security

> **Note**: Confirmations work differently in Docker and MCP environments. For detailed information about confirmation modes and troubleshooting, see the [Confirmations Guide](CONFIRMATIONS.md).

## AI Agent Integration

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ksm": {
      "command": "ksm-mcp",
      "args": ["serve", "--profile", "mycompany"]
    }
  }
}
```

### Custom AI Integration

```python
import subprocess
import json

# Start MCP server
proc = subprocess.Popen(
    ["ksm-mcp", "serve", "--profile", "mycompany"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

# Send MCP request
request = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
        "name": "list_secrets",
        "arguments": {}
    }
}

proc.stdin.write(json.dumps(request) + "\n")
proc.stdin.flush()

# Read response
response = json.loads(proc.stdout.readline())
```

## Common Use Cases

### 1. Database Credential Management

```yaml
User: "I need to connect to our production database"
AI: "I'll retrieve the production database credentials for you."
    [Calls get_secret with UID for prod DB]
    
    Here are the connection details:
    - Host: db.example.com
    - Port: 5432
    - Username: app_user
    - Password: ******** (masked)
    - Database: production_db
    
    To reveal the password, I'll need your confirmation.
```

### 2. API Key Rotation

```yaml
User: "Generate a new API key for our payment service"
AI: "I'll generate a new secure API key and update the payment service secret."
    [Calls generate_password with high entropy settings]
    [Calls update_secret with new API key]
    
    ✓ Generated new 32-character API key
    ✓ Updated payment service secret
    The new API key has been saved securely.
```

### 3. Configuration File Management

```yaml
User: "Download the production config and update the database URL"
AI: "I'll download the current config, update it, and upload the new version."
    [Calls download_file to get config.json]
    [Modifies the file locally]
    [Calls upload_file with updated config]
    
    ✓ Downloaded current config.json
    ✓ Updated database URL to new endpoint
    ✓ Uploaded updated configuration
    The production configuration has been updated.
```

### 4. Secret Discovery

```yaml
User: "What AWS credentials do we have?"
AI: "I'll search for AWS-related secrets in your vault."
    [Calls search_secrets with query "AWS"]
    
    Found 3 AWS-related secrets:
    1. AWS Production (login) - Main account credentials
    2. AWS S3 Backup (login) - Backup bucket access
    3. AWS Lambda Keys (custom) - Lambda function credentials
    
    Would you like details on any of these?
```

### 5. TOTP Code Generation

```yaml
User: "I need the 2FA code for GitHub"
AI: "I'll get the current TOTP code for GitHub."
    [Calls get_totp_code with GitHub secret UID]
    
    Current GitHub 2FA code: 123456
    Valid for: 18 seconds
    
    Please use this code quickly as it will expire soon.
```

## Troubleshooting

### Common Issues

#### "Failed to unlock profile store"
```bash
# Wrong master password
# Solution: Enter correct password or reset profile
ksm-mcp profiles delete myprofile
ksm-mcp init --profile myprofile --token "US:NEW_TOKEN"
```

#### "Connection failed: context deadline exceeded"
```bash
# Network timeout
# Solution: Check internet connection and KSM status
ksm-mcp test --profile myprofile
```

#### "Rate limit exceeded"
```bash
# Too many requests
# Solution: Wait 60 seconds or increase limits
ksm-mcp serve --profile myprofile
# In config.yaml, increase rate_limit.requests_per_minute
```

### Debug Mode

Enable verbose logging:

```bash
# Show all operations
ksm-mcp serve --verbose

# Check specific profile
ksm-mcp test --profile myprofile --details
```

### Log Analysis

```bash
# View recent operations
tail -f ~/.keeper/ksm-mcp/logs/audit.log | jq

# Search for errors
grep ERROR ~/.keeper/ksm-mcp/logs/audit.log

# Find specific operations
grep "create_secret" ~/.keeper/ksm-mcp/logs/audit.log
```

### Getting Help

1. **Built-in Help**
   ```bash
   ksm-mcp --help
   ksm-mcp serve --help
   ```

2. **Configuration Check**
   ```bash
   cat ~/.keeper/ksm-mcp/config.yaml
   ```

3. **Profile Verification**
   ```bash
   ksm-mcp profiles list
   ksm-mcp test --profile myprofile
   ```

## Best Practices

### Security
1. Use unique master passwords
2. Enable confirmations for production
3. Regularly rotate credentials
4. Monitor audit logs
5. Limit profile permissions

### Performance
1. Use specific field requests
2. Implement caching where appropriate
3. Batch operations when possible
4. Set reasonable timeouts
5. Monitor rate limits

### Maintenance
1. Regular backups of profiles
2. Update server periodically
3. Clean old audit logs
4. Review access patterns
5. Test disaster recovery

## Advanced Configuration

### Custom Timeout Settings
```yaml
# ~/.keeper/ksm-mcp/config.yaml
mcp:
  timeout: 60s  # Increase for slow networks
  
security:
  confirmation_timeout: 45s  # More time for decisions
  session_timeout: 30m      # Longer sessions
```

### Rate Limit Adjustments
```yaml
mcp:
  rate_limit:
    requests_per_minute: 120  # Double the default
    requests_per_hour: 2000   # For heavy usage
```

### Logging Configuration
```yaml
logging:
  level: debug  # More detailed logs
  file: /var/log/ksm-mcp/audit.log  # Custom location
```