# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the **KSM MCP Server** implementation in Go - a secure Model Context Protocol server that acts as an intermediary between AI agents and Keeper Secrets Manager (KSM). The server prevents direct credential exposure while maintaining usability for AI-powered workflows.

## Project Structure

```
ksm-mcp/
├── cmd/ksm-mcp/             # CLI entry point
├── internal/
│   ├── config/              # Configuration management
│   ├── crypto/              # Encryption utilities (AES-256-GCM)
│   ├── ksm/                 # KSM client wrapper and notation parser
│   ├── mcp/                 # MCP protocol implementation
│   ├── storage/             # Profile storage (encrypted)
│   └── ui/                  # Terminal UI and confirmation system
├── pkg/types/               # Shared types
├── configs/                 # Example configurations
├── scripts/                 # Build and test scripts
├── test/integration/        # Integration tests
└── Dockerfile              # Multi-stage Docker build
```

## Key Architecture Components

### Security Model
- **Profile-based storage**: Multiple named KSM configurations stored encrypted with AES-256-GCM
- **Confirmation system**: Interactive prompts with timeout for sensitive operations
- **Batch mode support**: `--batch` and `--auto-approve` flags for automation
- **Masking by default**: Sensitive fields are masked unless explicitly unmasked
- **Audit logging**: All operations logged for security tracking

### KSM Integration
- Uses Keeper's Go SDK for all KSM operations
- Supports both one-time token and existing config initialization
- Full KSM notation support (all formats: UID/field/password, Title/field/password, etc.)
- TOTP code generation and password generation using KSM functions

### MCP Protocol
- Implements MCP server over stdio
- Phase 1 tools: list_secrets, get_secret, search_secrets, get_field, generate_password, get_totp_code
- Phase 2 tools: create_secret, update_secret, delete_secret, upload_file, download_file, list_folders, create_folder
- Rate limiting and request correlation IDs

## Common Commands

### Development
```bash
make build                   # Build binary
make test                    # Run all tests
make test-coverage          # Run tests with coverage
make docker-build           # Build Docker image
make clean                  # Clean build artifacts
```

### CLI Usage
```bash
# Initialize profile with one-time token
ksm-mcp init --profile prod --token "US:TOKEN"

# Initialize with existing config
ksm-mcp init --profile prod --config ./ksm-config.json

# Serve MCP (interactive mode)
ksm-mcp serve

# Serve in batch mode (no prompts)
ksm-mcp serve --batch --auto-approve

# Profile management
ksm-mcp profiles list
ksm-mcp profiles delete prod

# Test connection
ksm-mcp test --profile prod
```

### Testing
```bash
go test ./...                # Run unit tests
go test -v ./internal/...    # Verbose unit tests
go test ./test/integration/  # Integration tests
go test -race ./...          # Race condition testing
```

## Security Considerations

1. **Never commit secrets**: All KSM configs are encrypted and stored in `~/.keeper/ksm-mcp/`
2. **Use separate profiles**: Different environments (dev, staging, prod) should use separate profiles
3. **Review confirmations**: Always review what the AI is requesting before approving
4. **Batch mode security**: Only use `--auto-approve` in secure, automated environments
5. **Token rotation**: Rotate KSM tokens regularly

## Dependencies

- Go 1.21+
- Keeper Secrets Manager Go SDK
- Cobra (CLI framework)
- Standard crypto libraries (AES-256-GCM)
- JSON-RPC for MCP protocol

## Development Guidelines

- Aim for 80%+ test coverage
- All packages must have unit tests
- Security tests for input validation required
- Follow Go best practices and conventions
- Use the existing KSM Go SDK (do not reimplement)
- Always choose the more secure option when in doubt

## Implementation Status

### Completed Phases
- **Phase 1: Project Setup** ✓
  - Go module initialization with proper naming
  - Directory structure and dependencies
  - Makefile with build, test, and Docker targets
  
- **Phase 2: Core Security Implementation** ✓
  - AES-256-GCM encryption (crypto package)
  - Encrypted profile storage (storage package)
  - Input validation and sanitization (validation package)
  - Confirmation prompts with timeout (ui package)
  - Audit logging with sensitive data filtering
  - Test coverage: crypto (87.1%), storage (84.6%), validation (95.2%)

- **Phase 3: KSM Integration** ✓
  - KSM client wrapper with SDK integration
  - Full notation parser supporting all formats
  - SDK method adaptations for SecretsManager type
  - Proper handling of custom fields via RecordDict
  - Password generation with configurable parameters
  - TOTP code generation from custom fields
  - File operations using SDK's GetFileForUpload
  - Folder management with parent hierarchy
  - All tests passing (100% test success rate)

- **Phase 4: MCP Protocol Implementation** ✓
  - JSON-RPC message handling with stdio transport
  - Complete tool registration for all 13 tools
  - Tool dispatch with confirmation prompts
  - Session management with profile switching
  - Rate limiting (60 requests/minute default)
  - Error handling and proper JSON-RPC responses
  - All Phase 1 and Phase 2 tools implemented
  - Test coverage with passing tests

### In Progress
- **Phase 5: CLI Implementation**
  - Cobra CLI framework setup
  - Commands: init, serve, profiles, test

### Upcoming Phases
- Phase 5: CLI Implementation
- Phase 6: Session Management
- Phase 7: Enhanced Features
- Phase 8: Production Readiness

## Known Issues & Notes

1. **KSM SDK Specifics**:
   - Use `*sm.SecretsManager` not `SecretsManagerClient`
   - Access custom fields via `record.RecordDict["custom"]`
   - File operations use `GetFileForUpload()` for uploads
   - Password generation requires string counts, not booleans
   - Index -1 indicates "no array index" in notation parsing

2. **Testing Notes**:
   - Integration tests with real KSM require valid tokens
   - Mock tests use in-memory storage for SDK
   - Notation tests use Index: -1 for non-array fields

3. **Security Reminders**:
   - All sensitive operations require confirmation
   - Batch mode bypasses confirmations - use carefully
   - Profile configs are encrypted at rest
   - Audit logs filter sensitive data automatically