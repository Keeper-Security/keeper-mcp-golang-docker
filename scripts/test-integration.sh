#!/bin/bash

# Integration test script for KSM MCP
# Usage: ./scripts/test-integration.sh

set -e

echo "KSM MCP Integration Testing"
echo "=========================="
echo ""

# Check if token is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <KSM_TOKEN> [KSM_CONFIG_PATH]"
    echo ""
    echo "Examples:"
    echo "  $0 US:ONE_TIME_TOKEN"
    echo "  $0 US:ONE_TIME_TOKEN /path/to/config.json"
    echo ""
    echo "The token will be used to initialize KSM and capture response data."
    echo "If config path is provided, it will also test config-based initialization."
    exit 1
fi

# Set environment variables
export KSM_TEST_TOKEN="$1"

if [ ! -z "$2" ]; then
    export KSM_TEST_CONFIG="$2"
    echo "Using config file: $KSM_TEST_CONFIG"
fi

echo "Using token: ${KSM_TEST_TOKEN:0:10}..."
echo ""

# Change to project directory
cd "$(dirname "$0")/.."

# Run integration tests
echo "Running integration tests..."
go test -tags=integration ./internal/ksm -v -run TestRealKSM

echo ""
echo "Integration testing complete!"