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
   - One-time access token

2. **System Requirements**
   - macOS, Linux, or Windows
   - Go 1.21+ (for building from source)
   - 50MB free disk space
   - Terminal access

### Installation

#### Option 1: Download Binary (Recommended)

```bash
# macOS
curl -LO https://github.com/keeper-security/ksm-mcp/releases/latest/download/ksm-mcp-darwin-amd64
chmod +x ksm-mcp-darwin-amd64
sudo mv ksm-mcp-darwin-amd64 /usr/local/bin/ksm-mcp

# Linux
curl -LO https://github.com/keeper-security/ksm-mcp/releases/latest/download/ksm-mcp-linux-amd64
chmod +x ksm-mcp-linux-amd64
sudo mv ksm-mcp-linux-amd64 /usr/local/bin/ksm-mcp

# Windows
# Download ksm-mcp-windows-amd64.exe from releases
# Add to PATH or move to C:\Windows\System32
```

#### Option 2: Build from Source

```bash
git clone https://github.com/keeper-security/ksm-mcp.git
cd ksm-mcp
go build -o ksm-mcp cmd/ksm-mcp/main.go
sudo mv ksm-mcp /usr/local/bin/
```

### Verify Installation

```bash
ksm-mcp --version
# Output: ksm-mcp version 1.0.0
```

## Profile Setup

### Getting a One-Time Token

1. Log into Keeper Secrets Manager
2. Navigate to Applications
3. Create a new application
4. Select "One-Time Access Token"
5. Set permissions (read/write as needed)
6. Generate token (format: `US:BASE64_TOKEN_DATA`)

### Creating Your First Profile

```bash
# Initialize profile with one-time token
ksm-mcp init --profile mycompany --token "US:YOUR_ONE_TIME_TOKEN"

# You'll be prompted to create a master password
Enter master password: ********
Confirm master password: ********

# Output:
✓ Successfully initialized KSM configuration
✓ Testing connection to Keeper Secrets Manager... (found 42 secrets)
✓ Profile 'mycompany' initialized successfully!
```

### Using Existing KSM Configuration

If you already have a KSM config file:

```bash
ksm-mcp init --profile existing --config ~/keeper/config.json
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

### Basic Usage

```bash
# Start with default profile
ksm-mcp serve

# Start with specific profile
ksm-mcp serve --profile production
```

### Server Modes

#### Interactive Mode (Default)
- Prompts for confirmations
- Shows operation details
- Best for development

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