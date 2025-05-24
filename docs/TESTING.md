# KSM MCP Testing Guide

## Overview

The KSM MCP project includes a comprehensive testing infrastructure with unit tests, integration tests, and end-to-end (E2E) tests. The testing framework supports both online testing with real KSM connections and offline testing using mock data.

## Test Structure

```
internal/testing/
├── mock/           # Mock KSM server and client
├── capture/        # Data capture system for fixtures
├── integration/    # Integration tests
├── e2e/           # End-to-end MCP tool tests
└── fixtures/      # Test data fixtures
```

## Running Tests

### Using the Test Script

The easiest way to run tests is using the provided test script:

```bash
# Run all tests
./scripts/test.sh

# Run only unit tests
./scripts/test.sh unit

# Run E2E tests with verbose output
./scripts/test.sh e2e -v

# Capture real KSM data for offline testing
./scripts/test.sh integration -c
```

### Using the CLI

You can also run tests directly through the CLI:

```bash
# Test KSM connection
ksm-mcp test

# Run test suites
ksm-mcp test --run-tests

# Run specific test mode
ksm-mcp test --run-tests --mode e2e

# Capture real data
ksm-mcp test --run-tests --mode integration --capture
```

## Test Modes

### Unit Tests
- Test individual components in isolation
- No external dependencies required
- Fast execution
- High code coverage

```bash
ksm-mcp test --run-tests --mode unit
```

### Integration Tests
- Test interaction with KSM SDK
- Can run with mock or real KSM backend
- Support data capture for offline testing

```bash
# Run with mock data
ksm-mcp test --run-tests --mode integration

# Capture real data (requires token)
export KSM_ONE_TIME_TOKEN="your-token-here"
export KSM_CONFIG_FILE="/path/to/config.base64"
ksm-mcp test --run-tests --mode integration --capture
```

### E2E Tests
- Test all 13 MCP tools
- Verify complete workflows
- Test file operations with large files (2MB+)
- Use mock server for offline testing

```bash
ksm-mcp test --run-tests --mode e2e
```

## Mock Server

The mock KSM server provides:
- 12 pre-configured test records matching the screenshot data
- Support for all KSM operations (CRUD, file operations)
- Data capture capability for recording API calls
- Export/import of test fixtures

### Test Data Structure

Based on the provided screenshots, the mock server includes:

**Development Folder:**
- Database Connection (databaseCredentials)
- SSH Key (sshKeys) with file attachment
- Development Server Login (login)
- GitLab Access Token (login)

**Production Folder:**
- Test API Credentials (login)
- Test Corporate Card (bankCard)
- AWS Production Credentials (login)
- Production SSL Certificate (sslCertificate)

**Testing Folder:**
- Test Database Login (databaseCredentials)
- Configuration Files (file) with 3 attachments:
  - app.config (2KB)
  - test.env (512B)
  - docker-compose.test.yml (1.5KB)
- Test SMTP Configuration (serverCredentials)

## Data Capture

To capture real KSM data for offline testing:

1. Set up environment:
```bash
export KSM_ONE_TIME_TOKEN="US:3J8QgphqMQjeEr_BHvELdfvbRwPNbqr9FgzSo6SqGaU"
export KSM_CONFIG_FILE="/Users/mustinov/Downloads/config.base64"
```

2. Run capture:
```bash
ksm-mcp test --run-tests --mode integration --capture
```

3. Check captured data:
```bash
ls -la fixtures/ksm-capture/
```

The capture system will:
- Download all records from your vault
- Save file attachments locally
- Record all API calls
- Generate fixture files for offline testing

## E2E Test Coverage

The E2E test suite covers all 13 MCP tools:

1. **list_secrets** - List and filter secrets
2. **get_secret** - Retrieve secret details
3. **search_secrets** - Search by keywords
4. **create_secret** - Create new secrets
5. **update_secret** - Update existing secrets
6. **delete_secret** - Delete secrets
7. **list_files** - List file attachments
8. **download_file** - Download files
9. **upload_file** - Upload files (2MB+ tested)
10. **delete_file** - Delete file attachments
11. **notation_query** - Keeper notation queries
12. **generate_password** - Generate secure passwords
13. **get_totp_code** - Get TOTP codes
14. **share_secret** - Share secrets with users

## File Operations Testing

The test suite includes comprehensive file operation tests:

- Large file uploads (2MB+ as requested)
- Multiple file attachments per record
- Various file types (JSON, CSV, YAML, PDF, images, etc.)
- Binary file handling
- File deletion

## Writing New Tests

### Unit Test Example

```go
func TestValidateInput(t *testing.T) {
    validator := validation.NewValidator()
    
    err := validator.ValidateRecordUID("valid-uid-123")
    assert.NoError(t, err)
    
    err = validator.ValidateRecordUID("../../etc/passwd")
    assert.Error(t, err)
}
```

### E2E Test Example

```go
func TestNewTool(t *testing.T) {
    h := NewTestHarness(t)
    
    response, err := h.SendRequest("tools/call", map[string]interface{}{
        "name": "new_tool",
        "arguments": map[string]interface{}{
            "param1": "value1",
        },
    })
    require.NoError(t, err)
    
    result := extractToolResult(t, response)
    assert.Contains(t, result, "expected output")
}
```

## Continuous Integration

The test suite is designed to run in CI environments:

```yaml
# Example GitHub Actions workflow
- name: Run Tests
  run: |
    go test -v -cover ./...
    
- name: Run E2E Tests
  run: |
    ./scripts/test.sh e2e -v
```

## Troubleshooting

### Tests Failing

1. Check Go version: `go version` (requires 1.21+)
2. Update dependencies: `go mod tidy`
3. Clear test cache: `go clean -testcache`

### Capture Not Working

1. Verify token is valid
2. Check config file path exists
3. Ensure network connectivity to KSM

### Mock Data Issues

1. Reset mock data: Delete `fixtures/` directory
2. Regenerate: `ksm-mcp test --run-tests --mode integration`

## Performance Benchmarks

The test suite includes performance validation:

- File uploads: 2MB in < 5 seconds
- List operations: < 100ms with mock server
- Search operations: < 200ms with mock server
- Concurrent operations: 10 parallel requests supported