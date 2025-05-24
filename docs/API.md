# KSM MCP API Documentation

This document describes the Model Context Protocol (MCP) tools exposed by the KSM MCP server.

## Protocol Overview

The KSM MCP server implements the Model Context Protocol using JSON-RPC 2.0 over stdio. All communication happens through newline-delimited JSON messages.

## Authentication

Authentication is handled at the profile level during server initialization. The AI agent does not need to provide credentials - they are securely stored in the encrypted profile.

## Available Tools

### list_secrets

List all secrets accessible in the vault.

**Parameters:**
```typescript
{
  folder_uid?: string  // Optional: Filter by folder UID
  type?: string       // Optional: Filter by secret type
}
```

**Returns:**
```typescript
{
  secrets: Array<{
    uid: string
    title: string
    type: string
    folder?: string
  }>
}
```

**Example:**
```json
{
  "tool": "list_secrets",
  "arguments": {
    "type": "login"
  }
}
```

### get_secret

Retrieve a specific secret by UID.

**Parameters:**
```typescript
{
  uid: string         // Required: Secret UID
  fields?: string[]   // Optional: Specific fields to retrieve
  unmask?: boolean    // Optional: Return unmasked values (requires confirmation)
}
```

**Returns:**
```typescript
{
  uid: string
  title: string
  type: string
  fields: Record<string, any>
  notes?: string
  files?: Array<{
    uid: string
    name: string
    size: number
    mime_type: string
  }>
}
```

**Example:**
```json
{
  "tool": "get_secret",
  "arguments": {
    "uid": "NJ_xXSkk3xYI1h9ql5lAiQ",
    "fields": ["login", "password"],
    "unmask": false
  }
}
```

### search_secrets

Search for secrets by query string.

**Parameters:**
```typescript
{
  query: string      // Required: Search query
  type?: string      // Optional: Filter by type
}
```

**Returns:**
```typescript
{
  results: Array<{
    uid: string
    title: string
    type: string
    folder?: string
  }>
}
```

**Example:**
```json
{
  "tool": "search_secrets",
  "arguments": {
    "query": "database",
    "type": "login"
  }
}
```

### get_field

Get a specific field value using KSM notation.

**Parameters:**
```typescript
{
  notation: string   // Required: KSM notation (e.g., "UID/field/password")
  unmask?: boolean   // Optional: Return unmasked value (requires confirmation)
}
```

**Returns:**
```typescript
{
  value: string | any
  field_type: string
}
```

**KSM Notation Examples:**
- `NJ_xXSkk3xYI1h9ql5lAiQ/field/password` - Password field
- `NJ_xXSkk3xYI1h9ql5lAiQ/custom_field/api_key` - Custom field
- `My Database/field/login` - Using title instead of UID
- `UID/file/config.json` - File reference

**Example:**
```json
{
  "tool": "get_field",
  "arguments": {
    "notation": "NJ_xXSkk3xYI1h9ql5lAiQ/field/password",
    "unmask": true
  }
}
```

### generate_password

Generate a secure password with specified requirements.

**Parameters:**
```typescript
{
  length?: number      // Optional: Length (default: 32)
  lowercase?: number   // Optional: Min lowercase chars
  uppercase?: number   // Optional: Min uppercase chars
  digits?: number      // Optional: Min digits
  special?: number     // Optional: Min special chars
  special_set?: string // Optional: Custom special char set
}
```

**Returns:**
```typescript
{
  password: string
}
```

**Example:**
```json
{
  "tool": "generate_password",
  "arguments": {
    "length": 20,
    "lowercase": 5,
    "uppercase": 5,
    "digits": 5,
    "special": 5
  }
}
```

### get_totp_code

Get the current TOTP code for a secret.

**Parameters:**
```typescript
{
  uid: string  // Required: Secret UID containing TOTP
}
```

**Returns:**
```typescript
{
  code: string     // Current TOTP code
  time_left: number // Seconds until expiry
}
```

**Example:**
```json
{
  "tool": "get_totp_code",
  "arguments": {
    "uid": "NJ_xXSkk3xYI1h9ql5lAiQ"
  }
}
```

### create_secret

Create a new secret (requires confirmation).

**Parameters:**
```typescript
{
  folder_uid: string             // Required: Target folder UID
  type: string                   // Required: Secret type
  title: string                  // Required: Secret title
  fields: Record<string, any>    // Required: Field values
  notes?: string                 // Optional: Notes
}
```

**Returns:**
```typescript
{
  uid: string      // New secret UID
  title: string
  type: string
}
```

**Example:**
```json
{
  "tool": "create_secret",
  "arguments": {
    "folder_uid": "hZA7V2E9S8qBNCm5lAeZ7A",
    "type": "login",
    "title": "Production Database",
    "fields": {
      "login": "admin",
      "password": "secure_password_here",
      "url": "https://db.example.com"
    },
    "notes": "Production PostgreSQL database"
  }
}
```

### update_secret

Update an existing secret (requires confirmation).

**Parameters:**
```typescript
{
  uid: string                    // Required: Secret UID
  title?: string                 // Optional: New title
  fields?: Record<string, any>   // Optional: Fields to update
  notes?: string                 // Optional: New notes
}
```

**Returns:**
```typescript
{
  uid: string
  title: string
  updated: boolean
}
```

**Example:**
```json
{
  "tool": "update_secret",
  "arguments": {
    "uid": "NJ_xXSkk3xYI1h9ql5lAiQ",
    "fields": {
      "password": "new_secure_password"
    }
  }
}
```

### delete_secret

Delete a secret (requires confirmation).

**Parameters:**
```typescript
{
  uid: string      // Required: Secret UID
  confirm: boolean // Required: Must be true
}
```

**Returns:**
```typescript
{
  deleted: boolean
}
```

**Example:**
```json
{
  "tool": "delete_secret",
  "arguments": {
    "uid": "NJ_xXSkk3xYI1h9ql5lAiQ",
    "confirm": true
  }
}
```

### upload_file

Upload a file attachment to a secret (requires confirmation).

**Parameters:**
```typescript
{
  uid: string       // Required: Secret UID
  file_path: string // Required: Local file path
  title?: string    // Optional: File title
}
```

**Returns:**
```typescript
{
  file_uid: string
  name: string
  size: number
  mime_type: string
}
```

**Example:**
```json
{
  "tool": "upload_file",
  "arguments": {
    "uid": "NJ_xXSkk3xYI1h9ql5lAiQ",
    "file_path": "/path/to/config.json",
    "title": "Application Config"
  }
}
```

### download_file

Download a file attachment from a secret (requires confirmation).

**Parameters:**
```typescript
{
  uid: string        // Required: Secret UID
  file_uid: string   // Required: File UID or name
  save_path?: string // Optional: Where to save (default: current dir)
}
```

**Returns:**
```typescript
{
  saved_path: string
  size: number
}
```

**Example:**
```json
{
  "tool": "download_file",
  "arguments": {
    "uid": "NJ_xXSkk3xYI1h9ql5lAiQ",
    "file_uid": "xP9k2mN4oQr6sT8u",
    "save_path": "/tmp/config.json"
  }
}
```

### list_folders

List all folders in the vault.

**Parameters:** None

**Returns:**
```typescript
{
  folders: Array<{
    uid: string
    name: string
    parent_uid?: string
  }>
}
```

**Example:**
```json
{
  "tool": "list_folders",
  "arguments": {}
}
```

### create_folder

Create a new folder (requires confirmation).

**Parameters:**
```typescript
{
  name: string        // Required: Folder name
  parent_uid: string  // Required: Parent folder UID (use "" for root)
}
```

**Returns:**
```typescript
{
  uid: string
  name: string
  parent_uid: string
}
```

**Example:**
```json
{
  "tool": "create_folder",
  "arguments": {
    "name": "Production Secrets",
    "parent_uid": ""
  }
}
```

### health_check

Check the health status of the MCP server.

**Parameters:** None

**Returns:**
```typescript
{
  status: "healthy" | "degraded" | "unhealthy"
  timestamp: string
  uptime: string
  profile: string
  checks?: {
    storage: {status: string, error?: string}
    profile: {status: string, error?: string}
    ksm_connection: {status: string, error?: string}
    audit_logger: {status: string, error?: string}
    rate_limiter: {status: string, error?: string}
  }
}
```

**Example:**
```json
{
  "tool": "health_check",
  "arguments": {}
}
```

**Response Example:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-23T10:15:30Z",
  "uptime": "2h15m30s",
  "profile": "production",
  "checks": {
    "storage": {"status": "ok"},
    "profile": {"status": "ok"},
    "ksm_connection": {"status": "ok"},
    "audit_logger": {"status": "ok"},
    "rate_limiter": {"status": "ok"}
  }
}
```

## Error Handling

All errors follow the JSON-RPC 2.0 error format:

```typescript
{
  code: number
  message: string
  data?: any
}
```

### Common Error Codes

- `-32700` - Parse error
- `-32600` - Invalid request
- `-32601` - Method not found
- `-32602` - Invalid params
- `-32603` - Internal error
- `-32000` - Server error
- `-32001` - Validation error
- `-32002` - Authentication error
- `-32003` - Authorization error
- `-32004` - Not found error
- `-32005` - Rate limit error

## Rate Limiting

The server implements rate limiting to prevent abuse:
- Default: 60 requests per minute
- Configurable in server options
- Returns error code `-32005` when exceeded

## Security Considerations

1. **Masked Values**: By default, sensitive fields are masked (e.g., `pass***`)
2. **Confirmation Prompts**: Sensitive operations require user confirmation
3. **Input Validation**: All inputs are validated against injection attacks
4. **Audit Logging**: Every operation is logged for security auditing
5. **Session Management**: Each connection has a unique session ID

## Best Practices

1. Always use specific field selection when possible to minimize data exposure
2. Avoid using `unmask: true` unless absolutely necessary
3. Use search instead of listing all secrets when looking for specific items
4. Handle errors gracefully and don't expose error details to end users
5. Implement retry logic with exponential backoff for transient errors

## Common Use Cases

### Database Connection String

```json
// Get database connection details
{
  "tool": "get_secret",
  "arguments": {
    "uid": "database_secret_uid",
    "fields": ["host", "port", "database", "username"],
    "unmask": false
  }
}

// Get password separately with confirmation
{
  "tool": "get_field",
  "arguments": {
    "notation": "database_secret_uid/field/password",
    "unmask": true
  }
}
```

### API Key Rotation

```json
// Generate new API key
{
  "tool": "generate_password",
  "arguments": {
    "length": 32,
    "special": 0,
    "lowercase": 16,
    "uppercase": 16
  }
}

// Update the secret
{
  "tool": "update_secret",
  "arguments": {
    "uid": "api_secret_uid",
    "fields": {
      "apiKey": "NEW_GENERATED_KEY",
      "lastRotated": "2024-01-23T10:00:00Z"
    },
    "notes": "Rotated via automation"
  }
}
```

### Multi-Factor Authentication

```json
// Get TOTP code for 2FA
{
  "tool": "get_totp_code",
  "arguments": {
    "uid": "service_2fa_secret"
  }
}
// Returns: {"code": "123456", "time_left": 15}
```

### Bulk Operations

```json
// List all production secrets
{
  "tool": "list_secrets",
  "arguments": {
    "folder_uid": "production_folder_uid"
  }
}

// Search for expired certificates
{
  "tool": "search_secrets",
  "arguments": {
    "query": "certificate expires:<=2024-02-01",
    "type": "sslCertificate"
  }
}
```

### File Management

```json
// Upload configuration file
{
  "tool": "upload_file",
  "arguments": {
    "uid": "app_config_secret",
    "file_path": "/tmp/app.config",
    "title": "Production Configuration v2.0"
  }
}

// Download for backup
{
  "tool": "download_file",
  "arguments": {
    "uid": "app_config_secret",
    "file_uid": "config_v2.0",
    "save_path": "/backup/configs/app.config.bak"
  }
}
```

## Advanced Features

### KSM Notation

The KSM notation provides powerful query capabilities:

```
// Basic notation
<UID>/field/<field_name>
<UID>/custom_field/<field_name>
<UID>/file/<file_name>

// Title-based notation
<Title>/field/<field_name>

// Folder navigation
<Folder>/<Subfolder>/<Title>/field/<field_name>

// Special prefixes
keeper://<path>  // Explicit KSM notation
```

### Field Types

Common field types and their handling:

| Field Type | Description | Example |
|------------|-------------|---------|
| `login` | Username/email | `user@example.com` |
| `password` | Secret password | `***` (masked) |
| `url` | Website URL | `https://example.com` |
| `oneTimeCode` | TOTP secret | `otpauth://totp/...` |
| `fileRef` | File reference | `{"uid": "...", "size": 1024}` |
| `host` | Hostname/IP | `db.example.com` |
| `port` | Port number | `5432` |
| `keyPair` | SSH/SSL keys | `{"privateKey": "***", "publicKey": "..."}` |

### Batch Processing

For efficient batch operations:

```javascript
// Pseudo-code for batch processing
const secrets = await mcp.call("list_secrets", {type: "login"});
const updates = [];

for (const secret of secrets.secrets) {
  // Check if password needs rotation
  const details = await mcp.call("get_secret", {
    uid: secret.uid,
    fields: ["lastModified"]
  });
  
  if (needsRotation(details.lastModified)) {
    const newPassword = await mcp.call("generate_password", {
      length: 24
    });
    
    updates.push({
      uid: secret.uid,
      password: newPassword.password
    });
  }
}

// Apply updates
for (const update of updates) {
  await mcp.call("update_secret", {
    uid: update.uid,
    fields: {password: update.password}
  });
}
```

## Performance Tips

1. **Caching**: The server caches decrypted profiles for performance
2. **Batch Reading**: Request multiple fields in one call
3. **Selective Fields**: Only request needed fields to reduce payload
4. **Connection Reuse**: Keep the MCP connection alive for multiple operations
5. **Rate Limit Awareness**: Implement backoff when approaching limits

## Troubleshooting

### Common Issues

**Tool not found**
```json
{
  "error": {
    "code": -32601,
    "message": "Method not found: unknown_tool"
  }
}
```

**Invalid parameters**
```json
{
  "error": {
    "code": -32602,
    "message": "Invalid params: uid is required"
  }
}
```

**Rate limited**
```json
{
  "error": {
    "code": -32005,
    "message": "Rate limit exceeded: retry after 60s"
  }
}
```

**Confirmation timeout**
```json
{
  "error": {
    "code": -32003,
    "message": "Operation cancelled: confirmation timeout"
  }
}
```

### Debug Information

Enable debug logging for troubleshooting:

```bash
# Start server with debug logging
ksm-mcp serve --log-level debug

# Check audit logs
tail -f ~/.keeper/ksm-mcp/logs/audit.log
```