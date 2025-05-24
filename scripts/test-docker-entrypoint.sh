#!/bin/bash

# Test script for docker-entrypoint.sh
# Verifies output behavior in batch mode vs normal mode

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counter
TESTS_RUN=0
TESTS_PASSED=0

# Create temporary directory for test environment
TEST_DIR=$(mktemp -d)
trap "rm -rf $TEST_DIR" EXIT

# Mock ksm-mcp command for testing
cat > "$TEST_DIR/ksm-mcp" << 'EOF'
#!/bin/sh
# Mock ksm-mcp that simulates init command
if [ "$1" = "init" ]; then
    echo "Mock init output to stdout"
    echo "Mock init error to stderr" >&2
    exit 0
fi
exec "$@"
EOF
chmod +x "$TEST_DIR/ksm-mcp"

# Copy docker-entrypoint.sh to test directory
cp docker-entrypoint.sh "$TEST_DIR/docker-entrypoint.sh"
chmod +x "$TEST_DIR/docker-entrypoint.sh"

# Change to test directory and add to PATH
cd "$TEST_DIR"
export PATH="$TEST_DIR:$PATH"

# Test function
run_test() {
    local test_name="$1"
    local test_cmd="$2"
    local expected_stdout="$3"
    local expected_stderr="$4"
    local should_contain_stdout="$5"
    local should_contain_stderr="$6"
    
    TESTS_RUN=$((TESTS_RUN + 1))
    
    echo -e "${BLUE}Running test: $test_name${NC}"
    
    # Run command and capture output
    stdout_file=$(mktemp)
    stderr_file=$(mktemp)
    
    eval "$test_cmd" > "$stdout_file" 2> "$stderr_file" || true
    
    stdout_content=$(cat "$stdout_file")
    stderr_content=$(cat "$stderr_file")
    
    rm -f "$stdout_file" "$stderr_file"
    
    # Check results
    local test_passed=true
    
    # Check stdout
    if [ "$expected_stdout" = "empty" ] && [ -n "$stdout_content" ]; then
        echo -e "  ${RED}✗ Expected empty stdout but got: $stdout_content${NC}"
        test_passed=false
    elif [ "$expected_stdout" = "not-empty" ] && [ -z "$stdout_content" ]; then
        echo -e "  ${RED}✗ Expected non-empty stdout but got nothing${NC}"
        test_passed=false
    fi
    
    # Check stderr
    if [ "$expected_stderr" = "empty" ] && [ -n "$stderr_content" ]; then
        echo -e "  ${RED}✗ Expected empty stderr but got: $stderr_content${NC}"
        test_passed=false
    elif [ "$expected_stderr" = "not-empty" ] && [ -z "$stderr_content" ]; then
        echo -e "  ${RED}✗ Expected non-empty stderr but got nothing${NC}"
        test_passed=false
    fi
    
    # Check for specific content in stdout
    if [ -n "$should_contain_stdout" ]; then
        if echo "$stdout_content" | grep -q "$should_contain_stdout"; then
            echo -e "  ${GREEN}✓ Stdout contains: $should_contain_stdout${NC}"
        else
            echo -e "  ${RED}✗ Stdout does not contain: $should_contain_stdout${NC}"
            echo -e "    Actual stdout: $stdout_content"
            test_passed=false
        fi
    fi
    
    # Check for specific content in stderr
    if [ -n "$should_contain_stderr" ]; then
        if echo "$stderr_content" | grep -q "$should_contain_stderr"; then
            echo -e "  ${GREEN}✓ Stderr contains: $should_contain_stderr${NC}"
        else
            echo -e "  ${RED}✗ Stderr does not contain: $should_contain_stderr${NC}"
            echo -e "    Actual stderr: $stderr_content"
            test_passed=false
        fi
    fi
    
    if [ "$test_passed" = true ]; then
        echo -e "  ${GREEN}✓ Test passed${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "  ${RED}✗ Test failed${NC}"
    fi
    
    echo ""
}

echo -e "${BLUE}Testing docker-entrypoint.sh${NC}"
echo "============================"
echo ""

# Test 1: Batch mode - auto-init output should go to stderr, nothing to stdout
run_test "Batch mode auto-init (stderr only)" \
    "KSM_CONFIG_BASE64='dGVzdA==' KSM_MCP_BATCH_MODE=true KSM_MCP_CONFIG_DIR='$TEST_DIR' ./docker-entrypoint.sh echo 'test command'" \
    "empty" \
    "not-empty" \
    "" \
    "Mock init"

# Test 2: Batch mode - no initialization messages
run_test "Batch mode no messages" \
    "KSM_CONFIG_BASE64='dGVzdA==' KSM_MCP_BATCH_MODE=true KSM_MCP_CONFIG_DIR='$TEST_DIR' ./docker-entrypoint.sh echo 'test command' 2>&1 | grep -v 'test command'" \
    "empty" \
    "" \
    "" \
    ""

# Test 3: Normal mode - auto-init messages visible
run_test "Normal mode auto-init messages" \
    "KSM_CONFIG_BASE64='dGVzdA==' KSM_MCP_CONFIG_DIR='$TEST_DIR' ./docker-entrypoint.sh echo 'test command' 2>&1" \
    "not-empty" \
    "" \
    "" \
    "Auto-initializing KSM MCP"

# Test 4: Normal mode - completion message visible
run_test "Normal mode completion message" \
    "KSM_CONFIG_BASE64='dGVzdA==' KSM_MCP_CONFIG_DIR='$TEST_DIR' ./docker-entrypoint.sh echo 'test command' 2>&1" \
    "not-empty" \
    "" \
    "" \
    "Initialization complete"

# Test 5: No init when profile exists
touch "$TEST_DIR/profiles.db"
run_test "No init when profile exists" \
    "KSM_CONFIG_BASE64='dGVzdA==' KSM_MCP_CONFIG_DIR='$TEST_DIR' ./docker-entrypoint.sh echo 'test command' 2>&1" \
    "not-empty" \
    "" \
    "test command" \
    ""

# Remove profiles.db for next tests
rm -f "$TEST_DIR/profiles.db"

# Test 6: No init without KSM_CONFIG_BASE64
run_test "No init without config" \
    "KSM_MCP_CONFIG_DIR='$TEST_DIR' ./docker-entrypoint.sh echo 'test command' 2>&1" \
    "not-empty" \
    "" \
    "test command" \
    ""

# Test 7: Command execution works
run_test "Command execution" \
    "./docker-entrypoint.sh echo 'hello world'" \
    "not-empty" \
    "" \
    "hello world" \
    ""

# Test 8: Batch mode with custom profile
run_test "Batch mode custom profile" \
    "KSM_CONFIG_BASE64='dGVzdA==' KSM_MCP_BATCH_MODE=true KSM_MCP_PROFILE='custom' KSM_MCP_CONFIG_DIR='$TEST_DIR' ./docker-entrypoint.sh echo 'test' 2>&1 | grep -E '(--profile custom|test$)'" \
    "not-empty" \
    "" \
    "" \
    ""

# Summary
echo "============================"
echo -e "${BLUE}Test Summary${NC}"
echo "Tests run: $TESTS_RUN"
echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests failed: ${RED}$((TESTS_RUN - TESTS_PASSED))${NC}"
echo ""

if [ $TESTS_PASSED -eq $TESTS_RUN ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    exit 1
fi