# Changelog

All notable changes to the KSM MCP project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2025-05-24

### Added
- Integration and E2E tests in CI workflow
- CI-specific docker-compose.ci.yml for testing without secrets
- Better error messages for configuration issues

### Changed
- Updated Go version from 1.21 to 1.23 to match go.mod requirements
- Improved README with simpler setup options prioritized
- Docker workflow now builds locally without pushing to Docker Hub in CI
- Updated deprecated GitHub Actions (upload-artifact v3 to v4)

### Fixed
- Fixed golangci-lint ineffassign errors
- Fixed gosec G304 security warnings with proper #nosec annotations
- Fixed TestPersistence test failure by using consistent passwords
- Fixed CreateProfile to copy config map instead of storing reference
- Fixed docker-compose command to use v2 syntax (docker compose)
- Fixed Docker buildx multi-platform export error

### Security
- Fixed potential issue where Close() could clear original config maps
- All security scans now passing (gosec, trivy)

## [1.0.0] - 2024-01-15

### Added
- Initial release of KSM MCP (Keeper Secrets Manager Model Context Protocol) server
- Full MCP protocol implementation with JSON-RPC 2.0 over stdio
- Secure profile management with AES-256-GCM encryption
- Master password protection for stored credentials
- 13 MCP tools for comprehensive secret management:
  - `list_secrets` - List all accessible secrets
  - `get_secret` - Retrieve specific secrets with masking
  - `search_secrets` - Search secrets by query
  - `get_field` - Get fields using KSM notation
  - `generate_password` - Generate secure passwords
  - `get_totp_code` - Get TOTP codes
  - `create_secret` - Create new secrets
  - `update_secret` - Update existing secrets
  - `delete_secret` - Delete secrets
  - `upload_file` - Upload file attachments
  - `download_file` - Download file attachments
  - `list_folders` - List vault folders
  - `create_folder` - Create new folders
- Confirmation prompts for sensitive operations
- Comprehensive audit logging with structured JSON format
- Rate limiting to prevent abuse (60 requests/minute default)
- Session management with unique session IDs
- CLI with Cobra framework:
  - `init` - Initialize profiles with one-time tokens
  - `serve` - Start MCP server
  - `profiles` - Manage profiles (list, show, delete, set-default)
  - `test` - Test KSM connections
- Batch mode for CI/CD environments
- Auto-approve mode for trusted environments
- Input validation against multiple attack vectors:
  - SQL injection
  - Command injection
  - Path traversal
  - XSS attacks
  - LDAP/NoSQL injection
  - Unicode attacks
  - Format string vulnerabilities
- Sensitive field masking by default
- Configurable timeouts and rate limits
- Multi-profile support for different environments
- Verbose logging for debugging
- Cross-platform support (macOS, Linux, Windows)

### Security
- AES-256-GCM encryption for stored profiles
- PBKDF2 with 100,000 iterations for key derivation
- Constant-time comparison for sensitive operations
- Secure memory handling with explicit clearing
- No credential exposure in logs or errors
- Comprehensive security test suite

### Documentation
- Complete API documentation
- User guide with examples
- Developer documentation
- Security architecture documentation
- Example configurations
- Use case scenarios

### Tests
- Unit tests for all components
- Integration tests for MCP protocol
- Security tests for injection protection
- Cryptographic property tests
- Concurrent operation tests
- Rate limiting tests

## [Unreleased]

### Planned
- Web UI for profile management
- Kubernetes operator for automated deployment
- HashiCorp Vault backend support
- AWS Secrets Manager integration
- Azure Key Vault integration
- Prometheus metrics endpoint
- OpenTelemetry tracing
- SAML/OIDC authentication
- Hardware security module (HSM) support
- Secret rotation automation
- Compliance reporting features
- Backup and restore functionality