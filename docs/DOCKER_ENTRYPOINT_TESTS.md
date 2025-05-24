# Docker Entrypoint Tests

This document describes the tests for the `docker-entrypoint.sh` script.

## Test Coverage

The tests verify the following behaviors:

1. **Batch Mode Output Redirection**
   - When `KSM_MCP_BATCH_MODE=true`, auto-initialization output goes to stderr
   - No output goes to stdout when in batch mode (except the final command output)
   - Initialization messages are suppressed in batch mode

2. **Normal Mode Output**
   - Initialization messages are visible on stderr
   - "Auto-initializing KSM MCP..." message appears
   - "Initialization complete." message appears

3. **Initialization Logic**
   - Auto-init only runs when `KSM_CONFIG_BASE64` is provided
   - Auto-init only runs when no `profiles.db` exists
   - Custom profile names are respected via `KSM_MCP_PROFILE`

4. **Command Execution**
   - The entrypoint properly executes the provided command
   - Command output is preserved correctly

## Running the Tests

### Shell Script Test
```bash
# Run the shell script test directly
./scripts/test-docker-entrypoint.sh

# Or run via the main test script (integration mode)
./scripts/test.sh integration
```

### Go Test
```bash
# Run the Go integration test
INTEGRATION_TEST=true go test ./internal/testing/docker_entrypoint_test.go -v
```

## Test Implementation

The tests are implemented in two ways:

1. **Shell Script Test** (`scripts/test-docker-entrypoint.sh`)
   - Standalone bash script that tests the entrypoint behavior
   - Creates mock `ksm-mcp` command to simulate initialization
   - Tests various environment configurations
   - Provides colored output for test results

2. **Go Integration Test** (`internal/testing/docker_entrypoint_test.go`)
   - Integrates with the existing Go test framework
   - More detailed output verification
   - Can be run as part of the full test suite

## Key Test Scenarios

### Batch Mode Scenario
```bash
KSM_CONFIG_BASE64='dGVzdA==' \
KSM_MCP_BATCH_MODE=true \
./docker-entrypoint.sh echo 'test'
```
Expected: 
- stdout: `test\n`
- stderr: Contains init command output, no user-facing messages

### Normal Mode Scenario
```bash
KSM_CONFIG_BASE64='dGVzdA==' \
./docker-entrypoint.sh echo 'test'
```
Expected:
- stdout: `test\n`
- stderr: Contains "Auto-initializing..." and "Initialization complete" messages

## Mock Implementation

The tests use a mock `ksm-mcp` executable that:
- Recognizes the `init` command
- Outputs to both stdout and stderr for testing
- Allows verification of output redirection behavior