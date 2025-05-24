# Technical Architecture

## Table of Contents

- [Overview](#overview)
- [System Architecture](#system-architecture)
- [Component Design](#component-design)
- [Security Architecture](#security-architecture)
- [MCP Protocol Implementation](#mcp-protocol-implementation)
- [Data Flow](#data-flow)
- [Performance Considerations](#performance-considerations)
- [Technology Stack](#technology-stack)

## Overview

KSM MCP is designed as a secure intermediary service that implements the Model Context Protocol (MCP) to enable AI agents to interact with Keeper Secrets Manager without exposing credentials. The architecture emphasizes security, modularity, and performance.

## System Architecture

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│                 │  stdio   │                 │  HTTPS  │                 │
│   AI Agent      │ ◄─────► │   KSM MCP       │ ◄─────► │   Keeper SM     │
│ (Claude, etc.)  │  JSON-   │    Server       │   API   │     Cloud       │
│                 │   RPC    │                 │         │                 │
└─────────────────┘         └─────────────────┘         └─────────────────┘
        │                            │                            │
        │                            │                            │
        ▼                            ▼                            ▼
   MCP Requests               Local Storage                 Secret Vault
                            (Encrypted Profiles)
```

### Core Principles

1. **Zero Trust**: AI agents never receive KSM credentials
2. **Layered Security**: Multiple security controls at each layer
3. **Modular Design**: Clear separation of concerns
4. **Audit Everything**: Comprehensive logging of all operations
5. **Performance**: Efficient caching and connection pooling

## Component Design

### 1. MCP Server (`internal/mcp/`)

The MCP server handles JSON-RPC communication over stdio:

```go
type Server struct {
    storage     *storage.ProfileStore
    profiles    map[string]*ksm.Client
    logger      *audit.Logger
    confirmer   *ui.Confirmer
    options     *ServerOptions
    mu          sync.RWMutex
    rateLimiter *RateLimiter
    sessionID   string
    startTime   time.Time
}
```

Key responsibilities:
- Message parsing and validation
- Tool routing and execution
- Session management
- Rate limiting
- Error handling

### 2. Storage Layer (`internal/storage/`)

Secure profile storage using AES-256-GCM encryption:

```go
type ProfileStore struct {
    configDir string
    encryptor *crypto.Encryptor
    profiles  map[string]*types.Profile
}

type Profile struct {
    Name      string
    Type      string  // "one-time-token" or "config-file"
    Config    map[string]interface{}
    CreatedAt time.Time
    UpdatedAt time.Time
}
```

Features:
- Master password protection
- Profile isolation
- Atomic operations
- Corruption detection

### 3. KSM Integration (`internal/ksm/`)

Wrapper around the official KSM Go SDK:

```go
type Client struct {
    sm           *secrets.SecretsManager
    profileName  string
    initialized  bool
    cache        *SecretCache
    mu           sync.RWMutex
}
```

Provides:
- Connection management
- Secret caching
- Notation parsing
- Error normalization
- Retry logic

### 4. Security Components

#### Input Validation (`internal/validation/`)

Multi-layer validation approach:

```go
type Validator struct {
    maxFieldLength int
    allowedChars   *regexp.Regexp
    sanitizers     []SanitizerFunc
}
```

Protects against:
- SQL/NoSQL injection
- Command injection
- Path traversal
- XSS attacks
- LDAP injection
- Unicode attacks

#### Encryption (`internal/crypto/`)

```go
type Encryptor struct {
    key        []byte  // Derived from master password
    salt       []byte  // Random per-profile
    iterations int     // PBKDF2 iterations (100,000)
}
```

Uses:
- AES-256-GCM for encryption
- PBKDF2 for key derivation
- Secure random for nonces
- Constant-time comparisons

#### Audit Logging (`internal/audit/`)

```go
type LogEntry struct {
    Timestamp    time.Time `json:"timestamp"`
    EventID      string    `json:"event_id"`
    SessionID    string    `json:"session_id"`
    EventType    string    `json:"event_type"`
    User         string    `json:"user"`
    Resource     string    `json:"resource"`
    Action       string    `json:"action"`
    Result       string    `json:"result"`
    ErrorDetails string    `json:"error_details,omitempty"`
    Metadata     M         `json:"metadata,omitempty"`
}
```

### 5. User Interface (`internal/ui/`)

Confirmation prompt system:

```go
type Confirmer struct {
    reader      io.Reader
    writer      io.Writer
    timeout     time.Duration
    autoApprove bool
    batchMode   bool
}
```

## Security Architecture

### Defense in Depth

1. **Network Layer**
   - No network exposure (stdio only)
   - TLS for KSM API communication

2. **Authentication**
   - Master password for local access
   - KSM credentials never exposed
   - Session timeout enforcement

3. **Authorization**
   - Per-operation confirmation
   - Profile-based access control
   - Rate limiting per session

4. **Data Protection**
   - At-rest encryption (AES-256-GCM)
   - In-transit encryption (TLS)
   - Memory protection (zeroing)

5. **Monitoring**
   - Comprehensive audit logs
   - Anomaly detection hooks
   - Failed attempt tracking

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Malicious AI agent | Confirmation prompts, rate limiting |
| Profile theft | Master password, encryption |
| Injection attacks | Input validation, sanitization |
| Memory dumps | Credential zeroing, minimal retention |
| Log tampering | Append-only logs, checksums |
| Replay attacks | Session IDs, request nonces |

## MCP Protocol Implementation

### Message Flow

```
AI Agent                    KSM MCP                     KSM API
    │                          │                           │
    ├──── initialize ─────────►│                           │
    │◄──── capabilities ───────┤                           │
    │                          │                           │
    ├──── tools/list ─────────►│                           │
    │◄──── tool list ──────────┤                           │
    │                          │                           │
    ├──── tools/call ─────────►│                           │
    │      (list_secrets)      ├──── GetSecrets ──────────►│
    │                          │◄──── Secret List ─────────┤
    │◄──── result ─────────────┤                           │
    │                          │                           │
```

### Tool Implementation

Each tool follows a consistent pattern:

```go
func (s *Server) executeToolName(client ksm.ClientInterface, args map[string]interface{}) (interface{}, error) {
    // 1. Validate inputs
    if err := s.validator.ValidateToolInputs(args); err != nil {
        return nil, err
    }
    
    // 2. Check permissions/confirmations
    if needsConfirmation {
        if !s.confirmer.Confirm(operation) {
            return nil, ErrOperationDenied
        }
    }
    
    // 3. Execute operation
    result, err := client.Operation(params)
    
    // 4. Audit log
    s.logger.Log(auditEntry)
    
    // 5. Format response
    return formatResponse(result), err
}
```

### Error Handling

Errors are mapped to appropriate JSON-RPC codes:

| Error Type | JSON-RPC Code | Description |
|------------|---------------|-------------|
| Invalid params | -32602 | Validation failed |
| Not found | -32001 | Resource not found |
| Permission denied | -32002 | Confirmation rejected |
| Rate limited | -32003 | Too many requests |
| Internal error | -32603 | Unexpected error |

## Data Flow

### Secret Retrieval Flow

```
1. AI requests secret via MCP tool
   └─► 2. MCP validates request
       └─► 3. Check rate limits
           └─► 4. Load profile (decrypt)
               └─► 5. Get KSM client
                   └─► 6. Fetch from KSM
                       └─► 7. Mask sensitive data
                           └─► 8. Audit log
                               └─► 9. Return to AI
```

### Secret Modification Flow

```
1. AI requests modification
   └─► 2. Validate inputs
       └─► 3. Show confirmation prompt
           └─► 4. User approves/denies
               └─► 5. If approved, execute
                   └─► 6. Update in KSM
                       └─► 7. Audit log
                           └─► 8. Return result
```

## Performance Considerations

### Caching Strategy

1. **Profile Cache**: Decrypted profiles cached in memory
2. **Secret Cache**: Time-limited cache with TTL
3. **Connection Pool**: Reuse KSM client connections
4. **Batch Operations**: Support bulk secret operations

### Resource Limits

```yaml
rate_limiting:
  requests_per_minute: 60
  requests_per_hour: 1000
  burst_size: 10

timeouts:
  operation_timeout: 30s
  confirmation_timeout: 30s
  session_timeout: 15m

memory:
  max_cache_size: 100MB
  max_log_size: 1GB
  max_profiles: 50
```

### Optimization Techniques

1. **Lazy Loading**: Profiles loaded on-demand
2. **Streaming**: Large file operations use streams
3. **Compression**: Log compression for storage
4. **Indexing**: Fast secret search using indices

## Technology Stack

### Core Technologies

- **Language**: Go 1.21+
- **Protocol**: JSON-RPC 2.0 over stdio
- **Encryption**: AES-256-GCM
- **Key Derivation**: PBKDF2
- **SDK**: Keeper Secrets Manager Go SDK

### Key Dependencies

```go
require (
    github.com/keeper-security/secrets-manager-go v1.6.3
    github.com/spf13/cobra v1.8.0
    github.com/spf13/viper v1.18.2
    github.com/google/uuid v1.5.0
    golang.org/x/crypto v0.19.0
    golang.org/x/term v0.17.0
)
```

### Development Tools

- **Build**: Make, Go modules
- **Testing**: Go test, testify
- **Linting**: golangci-lint
- **Security**: gosec, trivy
- **CI/CD**: GitHub Actions
- **Containerization**: Docker, Kubernetes

## Extension Points

### Adding New Tools

1. Define tool in `tools.go`:
```go
{
    Name:        "new_tool",
    Description: "Tool description",
    InputSchema: schema,
}
```

2. Add handler in `tool_handlers.go`:
```go
func (s *Server) executeNewTool(client ksm.ClientInterface, args map[string]interface{}) (interface{}, error) {
    // Implementation
}
```

3. Add case in `executeTool`:
```go
case "new_tool":
    return s.executeNewTool(client, args)
```

### Custom Validators

Implement the `Validator` interface:
```go
type CustomValidator struct{}

func (v *CustomValidator) Validate(input string) error {
    // Custom validation logic
    return nil
}
```

### Audit Plugins

Implement the `AuditLogger` interface:
```go
type CustomLogger struct{}

func (l *CustomLogger) Log(entry LogEntry) error {
    // Custom logging logic
    return nil
}
```

## Future Enhancements

1. **Metrics & Monitoring**
   - Prometheus metrics endpoint
   - OpenTelemetry tracing
   - Custom dashboards

2. **Advanced Features**
   - Secret rotation automation
   - Policy-based access control
   - Multi-factor authentication
   - Hardware security module support

3. **Integrations**
   - Vault transit backend
   - SIEM integration
   - Webhook notifications
   - External validators

4. **Performance**
   - Distributed caching
   - Connection multiplexing
   - Parallel operations
   - Query optimization