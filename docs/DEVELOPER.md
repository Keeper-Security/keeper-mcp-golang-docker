# Developer Guide

This guide is for developers who want to extend or contribute to the KSM MCP server.

## Architecture Overview

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   AI Agent      │────▶│   MCP Server    │────▶│      KSM        │
│  (Claude, etc)  │◀────│   (ksm-mcp)     │◀────│  (Keeper API)   │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                        │                        │
        │ JSON-RPC 2.0          │ Encrypted              │ HTTPS
        │ over stdio            │ Profiles               │ REST API
        ▼                        ▼                        ▼
```

## Project Structure

```
ksm-mcp/
├── cmd/ksm-mcp/              # CLI application
│   ├── main.go              # Entry point
│   └── commands/            # Cobra commands
│       ├── root.go         # Root command
│       ├── init.go         # Profile initialization
│       ├── serve.go        # MCP server
│       ├── profiles.go     # Profile management
│       └── test.go         # Connection testing
│
├── internal/                 # Private packages
│   ├── audit/               # Audit logging
│   │   ├── logger.go       # Structured logger
│   │   └── events.go       # Event definitions
│   │
│   ├── config/              # Configuration
│   │   └── config.go       # Config structures
│   │
│   ├── crypto/              # Encryption
│   │   ├── crypto.go       # AES-256-GCM
│   │   └── crypto_test.go  # Crypto tests
│   │
│   ├── ksm/                 # KSM integration
│   │   ├── client.go       # KSM client wrapper
│   │   └── notation.go     # KSM notation parser
│   │
│   ├── mcp/                 # MCP protocol
│   │   ├── server.go       # MCP server
│   │   ├── handlers.go     # Request handlers
│   │   ├── tools.go        # Tool definitions
│   │   └── tool_handlers.go # Tool implementations
│   │
│   ├── storage/             # Profile storage
│   │   └── profiles.go     # Encrypted storage
│   │
│   ├── ui/                  # User interaction
│   │   └── confirm.go      # Confirmation prompts
│   │
│   └── validation/          # Input validation
│       ├── validator.go    # Validation logic
│       └── security_test.go # Security tests
│
├── pkg/types/               # Public types
│   └── types.go            # Shared structures
│
├── docs/                    # Documentation
├── examples/                # Example configs
└── tests/                   # Integration tests
```

## Core Components

### 1. MCP Server (`internal/mcp/server.go`)

The heart of the system, handling JSON-RPC communication:

```go
type Server struct {
    storage     *storage.ProfileStore
    profiles    map[string]*ksm.Client
    logger      *audit.Logger
    confirmer   *ui.Confirmer
    options     *ServerOptions
    rateLimiter *RateLimiter
    sessionID   string
}

func (s *Server) Start(ctx context.Context) error {
    // 1. Initialize session
    // 2. Load profiles
    // 3. Start message loop
    // 4. Handle requests
}
```

### 2. KSM Client Wrapper (`internal/ksm/client.go`)

Wraps the Keeper SDK with additional validation:

```go
type Client struct {
    sm        *sm.SecretsManager
    profile   string
    validator *validation.Validator
    logger    *audit.Logger
}

func (c *Client) GetSecret(uid string, fields []string, unmask bool) (map[string]interface{}, error) {
    // 1. Validate input
    // 2. Log access attempt
    // 3. Retrieve from KSM
    // 4. Mask sensitive fields
    // 5. Return result
}
```

### 3. Profile Storage (`internal/storage/profiles.go`)

Encrypted profile management:

```go
type ProfileStore struct {
    configDir string
    encryptor *crypto.Encryptor
    profiles  map[string]*types.Profile
}

func (ps *ProfileStore) CreateProfile(name string, config map[string]string) error {
    // 1. Validate profile name
    // 2. Encrypt configuration
    // 3. Save to disk
    // 4. Update in-memory cache
}
```

## Adding New Tools

### Step 1: Define the Tool

Add to `internal/mcp/tools.go`:

```go
var shareSecretTool = types.MCPTool{
    Name:        "share_secret",
    Description: "Share a secret with another user",
    InputSchema: map[string]interface{}{
        "type": "object",
        "properties": map[string]interface{}{
            "uid": map[string]interface{}{
                "type":        "string",
                "description": "Secret UID to share",
            },
            "email": map[string]interface{}{
                "type":        "string",
                "description": "Email of user to share with",
            },
            "permissions": map[string]interface{}{
                "type":        "array",
                "description": "Permissions to grant",
                "items": map[string]interface{}{
                    "type": "string",
                    "enum": []string{"read", "write", "share"},
                },
            },
        },
        "required": []string{"uid", "email", "permissions"},
    },
}
```

### Step 2: Create Parameter Type

Add to `pkg/types/types.go`:

```go
type ShareSecretParams struct {
    UID         string   `json:"uid"`
    Email       string   `json:"email"`
    Permissions []string `json:"permissions"`
}
```

### Step 3: Implement Handler

Add to `internal/mcp/tool_handlers.go`:

```go
func (s *Server) handleShareSecret(params json.RawMessage) (interface{}, error) {
    var p types.ShareSecretParams
    if err := json.Unmarshal(params, &p); err != nil {
        return nil, fmt.Errorf("invalid parameters: %w", err)
    }

    // Validate inputs
    if err := s.validator.ValidateUID(p.UID); err != nil {
        return nil, err
    }
    
    if err := s.validator.ValidateEmail(p.Email); err != nil {
        return nil, err
    }

    // Require confirmation
    ctx := context.Background()
    result := s.confirmer.Confirm(ctx, 
        fmt.Sprintf("Share secret %s with %s?", p.UID, p.Email))
    if !result.Approved {
        return nil, fmt.Errorf("operation cancelled")
    }

    // Call KSM API
    client := s.getCurrentClient()
    if err := client.ShareSecret(p.UID, p.Email, p.Permissions); err != nil {
        return nil, err
    }

    // Log operation
    s.logger.LogSecretOperation(audit.EventSecretShared, p.UID, 
        "share_secret", s.currentProfile, true, map[string]interface{}{
            "shared_with": p.Email,
            "permissions": p.Permissions,
        })

    return map[string]interface{}{
        "shared": true,
        "email":  p.Email,
    }, nil
}
```

### Step 4: Register Handler

Add to `getToolHandler()` in `internal/mcp/handlers.go`:

```go
case "share_secret":
    return s.handleShareSecret(params)
```

### Step 5: Add Tests

Create `internal/mcp/tool_handlers_test.go`:

```go
func TestHandleShareSecret(t *testing.T) {
    // Test valid sharing
    // Test invalid email
    // Test missing permissions
    // Test confirmation denial
    // Test KSM API error
}
```

## Security Guidelines

### Input Validation

Always validate inputs using the validator:

```go
// DO THIS
if err := validator.ValidateUID(uid); err != nil {
    return nil, fmt.Errorf("invalid UID: %w", err)
}

// NOT THIS
if len(uid) < 16 {
    return nil, errors.New("UID too short")
}
```

### Sensitive Data Handling

```go
// Always clear sensitive data
defer func() {
    for i := range sensitiveData {
        sensitiveData[i] = 0
    }
}()

// Use constant-time comparison for secrets
if subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
    return errors.New("invalid secret")
}
```

### Error Messages

```go
// DO THIS - Generic error for clients
return nil, fmt.Errorf("operation failed")

// Log detailed error internally
s.logger.LogError("database connection failed", err, map[string]interface{}{
    "host": dbHost,
    "port": dbPort,
})
```

## Testing

### Unit Tests

```go
func TestValidator_ValidateEmail(t *testing.T) {
    tests := []struct {
        name    string
        email   string
        wantErr bool
    }{
        {"valid", "user@example.com", false},
        {"invalid", "not-an-email", true},
        {"injection", "user@example.com; DROP TABLE;", true},
    }
    
    v := NewValidator()
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := v.ValidateEmail(tt.email)
            if (err != nil) != tt.wantErr {
                t.Errorf("ValidateEmail() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
```

### Integration Tests

```go
func TestMCPServer_FullFlow(t *testing.T) {
    // 1. Create test server
    // 2. Initialize with test profile
    // 3. Send tool request
    // 4. Verify response
    // 5. Check audit logs
}
```

### Security Tests

```go
func TestSecurity_InjectionAttempts(t *testing.T) {
    attacks := []string{
        "'; DROP TABLE secrets; --",
        "$(rm -rf /)",
        "../../../etc/passwd",
        "<script>alert('xss')</script>",
    }
    
    for _, attack := range attacks {
        // Verify each attack is properly blocked
    }
}
```

## Building and Releasing

### Local Development

```bash
# Run tests
go test ./...

# Run with race detection
go test -race ./...

# Run security tests
go test ./internal/validation -run Security

# Build binary
go build -o ksm-mcp cmd/ksm-mcp/main.go

# Run locally
./ksm-mcp serve --verbose
```

### Cross-Platform Build

```bash
# Build for all platforms
make build-all

# Or manually:
GOOS=darwin GOARCH=amd64 go build -o ksm-mcp-darwin-amd64
GOOS=linux GOARCH=amd64 go build -o ksm-mcp-linux-amd64
GOOS=windows GOARCH=amd64 go build -o ksm-mcp-windows-amd64.exe
```

### Release Process

1. Update version in `cmd/ksm-mcp/commands/root.go`
2. Update CHANGELOG.md
3. Run all tests
4. Create git tag
5. Build binaries
6. Create GitHub release
7. Upload binaries

## Contributing

### Code Style

- Follow standard Go formatting (`gofmt`)
- Use meaningful variable names
- Add comments for exported functions
- Keep functions focused and small
- Write tests for new functionality

### Pull Request Process

1. Fork the repository
2. Create feature branch
3. Write tests
4. Implement feature
5. Run all tests
6. Submit PR with description

### Security Review

All PRs undergo security review for:
- Input validation
- Error handling
- Sensitive data exposure
- Injection vulnerabilities
- Resource exhaustion

## Debugging

### Enable Debug Logging

```go
// In development
logger, _ := audit.NewLogger(audit.Config{
    FilePath: "debug.log",
    Level:    "debug",
})
```

### Trace Execution

```go
func (s *Server) handleToolCall(tool string, params json.RawMessage) {
    s.logger.Debug("handleToolCall", map[string]interface{}{
        "tool":   tool,
        "params": params,
        "caller": getCaller(),
    })
    // ... rest of function
}
```

### Memory Profiling

```go
import _ "net/http/pprof"

func init() {
    go func() {
        log.Println(http.ListenAndServe("localhost:6060", nil))
    }()
}

// Profile: go tool pprof http://localhost:6060/debug/pprof/heap
```

## Support

- GitHub Issues: Bug reports and feature requests
- Security: security@keepersecurity.com
- Documentation: PRs welcome!