# KSM MCP Use Cases and Examples

This document provides practical examples of using KSM MCP with AI agents.

## Basic Operations

### 1. Listing Secrets

**User Prompt:**
```
Show me all our database credentials
```

**AI Agent Actions:**
```json
{
  "tool": "list_secrets",
  "arguments": {
    "type": "login"
  }
}
```

**AI Response:**
```
I found 5 database credentials in your vault:

1. **Production PostgreSQL** (UID: NJ_xXSkk3xYI1h9ql5lAiQ)
   - Type: login
   - Folder: Production Systems

2. **Staging MySQL** (UID: aB_cDeFgHiJkLmNoPqRsT)
   - Type: login
   - Folder: Staging Environment

3. **Development MongoDB** (UID: uV_wXyZaBcDeFgHiJkLm)
   - Type: login
   - Folder: Development

4. **Analytics Redshift** (UID: No_PqRsTuVwXyZaBcDeF)
   - Type: login
   - Folder: Analytics

5. **Backup Database** (UID: gH_iJkLmNoPqRsTuVwXy)
   - Type: login
   - Folder: Backups

Would you like to see the details of any specific database?
```

### 2. Retrieving Specific Credentials

**User Prompt:**
```
I need the connection details for the production PostgreSQL database
```

**AI Agent Actions:**
```json
{
  "tool": "get_secret",
  "arguments": {
    "uid": "NJ_xXSkk3xYI1h9ql5lAiQ",
    "unmask": false
  }
}
```

**AI Response:**
```
Here are the Production PostgreSQL connection details:

- **Host**: prod-db.example.com
- **Port**: 5432
- **Database**: production_main
- **Username**: app_prod_user
- **Password**: ******** (masked for security)
- **Connection String**: postgresql://app_prod_user:********@prod-db.example.com:5432/production_main

The password is masked for security. Would you like me to reveal it?
```

### 3. Generating Secure Passwords

**User Prompt:**
```
Create a new strong password for our API service
```

**AI Agent Actions:**
```json
{
  "tool": "generate_password",
  "arguments": {
    "length": 32,
    "lowercase": 8,
    "uppercase": 8,
    "digits": 8,
    "special": 8,
    "special_set": "!@#$%^&*"
  }
}
```

**AI Response:**
```
I've generated a strong 32-character password for your API service:

- Length: 32 characters
- Contains: 8 lowercase, 8 uppercase, 8 digits, 8 special characters
- Special characters from: !@#$%^&*
- Entropy: ~190 bits (extremely strong)

The password has been generated. Would you like me to:
1. Create a new secret with this password?
2. Update an existing secret?
3. Display the password for manual use?
```

## Advanced Scenarios

### 4. Rotating Database Credentials

**User Prompt:**
```
We need to rotate the staging database password
```

**AI Agent Actions:**
```json
// Step 1: Generate new password
{
  "tool": "generate_password",
  "arguments": {
    "length": 24,
    "lowercase": 6,
    "uppercase": 6,
    "digits": 6,
    "special": 6
  }
}

// Step 2: Update the secret
{
  "tool": "update_secret",
  "arguments": {
    "uid": "aB_cDeFgHiJkLmNoPqRsT",
    "fields": {
      "password": "NewGeneratedPassword123!",
      "notes": "Password rotated on 2024-01-15 by automation"
    }
  }
}
```

**AI Response:**
```
I'll help you rotate the staging database password. Here's what I'll do:

1. ✓ Generated a new 24-character secure password
2. ⚠️ **Confirmation Required**: Update the staging database secret with the new password?

[After confirmation]

✓ Password successfully updated for Staging MySQL database

**Important Next Steps:**
1. Update the database user password in MySQL
2. Update application configuration files
3. Restart application services
4. Verify connectivity with new password

Would you like me to help with any of these steps?
```

### 5. Managing API Keys Across Environments

**User Prompt:**
```
Show me all Stripe API keys and check which environments they're for
```

**AI Agent Actions:**
```json
{
  "tool": "search_secrets",
  "arguments": {
    "query": "stripe"
  }
}

// For each result:
{
  "tool": "get_secret",
  "arguments": {
    "uid": "secret_uid_here",
    "fields": ["title", "notes", "url"],
    "unmask": false
  }
}
```

**AI Response:**
```
I found 3 Stripe API keys in your vault:

1. **Stripe Production API** 
   - Environment: Production
   - Key Type: Live/Production (based on 'live_' prefix)
   - Last Updated: 2024-01-10
   - Notes: "Production Stripe account - handle with care"

2. **Stripe Test API**
   - Environment: Development/Testing
   - Key Type: Test (based on 'test_' prefix)
   - Last Updated: 2023-12-15
   - Notes: "Safe for development - test mode only"

3. **Stripe Webhook Secret**
   - Environment: Production
   - Type: Webhook Endpoint Secret
   - Last Updated: 2024-01-05
   - Notes: "For webhook signature verification"

⚠️ **Security Notice**: Your production API key is masked. The test key can be revealed safely if needed for development.
```

### 6. Bulk Secret Export for Audit

**User Prompt:**
```
I need a security audit report of all secrets created in the last 30 days
```

**AI Agent Actions:**
```json
{
  "tool": "list_secrets",
  "arguments": {}
}

// For each secret, check creation date:
{
  "tool": "get_secret",
  "arguments": {
    "uid": "uid_here",
    "fields": ["created", "modified", "title", "type"],
    "unmask": false
  }
}
```

**AI Response:**
```
## Security Audit Report - Secrets Created in Last 30 Days

I found 8 secrets created since December 15, 2023:

### High Sensitivity (Production)
1. **AWS Production Keys** (Created: 2024-01-12)
   - Type: login
   - Contains: Access keys for production AWS account
   - Risk Level: Critical

2. **Database Master Password** (Created: 2024-01-08)
   - Type: login
   - Contains: RDS master user credentials
   - Risk Level: Critical

### Medium Sensitivity (Integration)
3. **SendGrid API Key** (Created: 2024-01-14)
   - Type: custom
   - Contains: Email service API key
   - Risk Level: Medium

4. **Datadog API Key** (Created: 2024-01-10)
   - Type: custom
   - Contains: Monitoring service credentials
   - Risk Level: Medium

### Low Sensitivity (Development)
5. **Local Dev Database** (Created: 2024-01-13)
   - Type: login
   - Contains: Local development credentials
   - Risk Level: Low

6. **Test SMTP Server** (Created: 2024-01-11)
   - Type: login
   - Contains: Test email server credentials
   - Risk Level: Low

### Recommendations:
- Ensure all production secrets have 2FA enabled
- Review access logs for critical secrets
- Consider rotating any shared credentials
- Implement secret scanning in CI/CD pipeline
```

### 7. Configuration File Management

**User Prompt:**
```
Download our app config, update the Redis connection, and upload it back
```

**AI Agent Actions:**
```json
// Step 1: Download current config
{
  "tool": "download_file",
  "arguments": {
    "uid": "config_secret_uid",
    "file_uid": "app-config.json",
    "save_path": "/tmp/app-config.json"
  }
}

// Step 2: After editing locally
{
  "tool": "upload_file",
  "arguments": {
    "uid": "config_secret_uid",
    "file_path": "/tmp/app-config-updated.json",
    "title": "app-config.json"
  }
}
```

**AI Response:**
```
I'll help you update the Redis connection in your app configuration:

1. ⚠️ **Confirmation Required**: Download app-config.json from the configuration secret?

[After confirmation]
✓ Downloaded app-config.json to temporary location

2. Current Redis configuration:
   ```json
   "redis": {
     "host": "redis.internal.example.com",
     "port": 6379,
     "database": 0
   }
   ```

3. What changes would you like to make to the Redis connection?

[After user provides new config]

4. Updated configuration:
   ```json
   "redis": {
     "host": "redis-cluster.internal.example.com",
     "port": 6380,
     "database": 0,
     "cluster": true
   }
   ```

5. ⚠️ **Confirmation Required**: Upload the updated configuration file?

[After confirmation]
✓ Successfully uploaded updated configuration
✓ Previous version backed up automatically

The configuration has been updated. You'll need to restart your application services to apply these changes.
```

### 8. Emergency Access Recovery

**User Prompt:**
```
We're locked out of our admin panel and need the recovery codes
```

**AI Agent Actions:**
```json
{
  "tool": "search_secrets",
  "arguments": {
    "query": "admin recovery"
  }
}

{
  "tool": "get_field",
  "arguments": {
    "notation": "admin_secret_uid/custom_field/recovery_codes",
    "unmask": true
  }
}
```

**AI Response:**
```
I understand this is an emergency situation. I'll help you retrieve the admin panel recovery codes.

Found: **Admin Panel - Emergency Access**

⚠️ **CRITICAL CONFIRMATION REQUIRED**: 
This will reveal sensitive recovery codes. Please confirm:
- Is this a legitimate emergency?
- Are you authorized to access these codes?
- Will you follow the recovery procedure?

Type 'yes' to proceed with revealing recovery codes.

[After confirmation]

✓ Admin Panel Recovery Codes:
```
1. EMRG-7K9L-4M2N-8P3Q
2. EMRG-2X5Y-9B4C-6D8F
3. EMRG-3H6J-5K8M-1N4P
4. EMRG-9Q2R-7S5T-3V8W
5. EMRG-4Z7A-2C5E-8G1J
```

**Important**:
- Each code can only be used once
- After use, generate new recovery codes
- This access has been logged for audit

Would you like me to guide you through the recovery process?
```

## Integration Examples

### 9. CI/CD Pipeline Integration

**Shell Script Example:**
```bash
#!/bin/bash
# deploy.sh - Deployment script using KSM MCP

# Start KSM MCP in batch mode
ksm_mcp_cmd() {
    echo "$1" | ksm-mcp serve --batch --profile production --timeout 10s
}

# Get database credentials
DB_CREDS=$(ksm_mcp_cmd '{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "get_field",
    "arguments": {
      "notation": "prod_db/field/connection_string",
      "unmask": true
    }
  }
}')

# Parse response and export
export DATABASE_URL=$(echo "$DB_CREDS" | jq -r '.result.value')

# Run deployment
./run-deployment.sh
```

### 10. Scheduled Secret Rotation

**Python Example:**
```python
import subprocess
import json
import schedule
import time

def rotate_api_keys():
    """Rotate API keys monthly"""
    
    # List all API keys
    secrets = call_ksm_tool("list_secrets", {"type": "custom"})
    
    for secret in secrets['result']['secrets']:
        if 'api' in secret['title'].lower():
            # Generate new key
            new_key = call_ksm_tool("generate_password", {
                "length": 32,
                "special": 0  # No special chars for API keys
            })
            
            # Update secret
            call_ksm_tool("update_secret", {
                "uid": secret['uid'],
                "fields": {
                    "api_key": new_key['result']['password']
                }
            })
            
            print(f"Rotated API key for: {secret['title']}")

def call_ksm_tool(tool_name, arguments):
    """Call KSM MCP tool"""
    # Implementation details...
    pass

# Schedule monthly rotation
schedule.every(30).days.do(rotate_api_keys)

while True:
    schedule.run_pending()
    time.sleep(86400)  # Check daily
```

## Best Practices in Examples

1. **Always mask first**: Get secrets with `unmask: false` initially
2. **Confirm sensitive operations**: Use confirmation prompts for changes
3. **Log important actions**: Keep audit trail of automated operations
4. **Handle errors gracefully**: Always have fallback procedures
5. **Test in non-production**: Verify scripts in safe environments first