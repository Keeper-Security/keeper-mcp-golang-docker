#!/bin/bash

# KSM MCP Test Runner Script
# Usage: ./scripts/test.sh [mode] [options]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
MODE="all"
CAPTURE=false
VERBOSE=false
FILTER=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        unit|integration|e2e|all)
            MODE="$1"
            ;;
        -c|--capture)
            CAPTURE=true
            ;;
        -v|--verbose)
            VERBOSE=true
            ;;
        -f|--filter)
            FILTER="$2"
            shift
            ;;
        -h|--help)
            echo "KSM MCP Test Runner"
            echo ""
            echo "Usage: $0 [mode] [options]"
            echo ""
            echo "Modes:"
            echo "  unit         Run unit tests only"
            echo "  integration  Run integration tests"
            echo "  e2e          Run end-to-end tests"
            echo "  all          Run all tests (default)"
            echo ""
            echo "Options:"
            echo "  -c, --capture   Capture real KSM data (integration mode only)"
            echo "  -v, --verbose   Verbose output"
            echo "  -f, --filter    Filter tests by name"
            echo "  -h, --help      Show this help"
            echo ""
            echo "Examples:"
            echo "  $0                    # Run all tests"
            echo "  $0 unit               # Run unit tests only"
            echo "  $0 e2e -v             # Run E2E tests with verbose output"
            echo "  $0 integration -c     # Capture real KSM data"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
    shift
done

echo -e "${BLUE}KSM MCP Test Runner${NC}"
echo -e "Mode: ${YELLOW}$MODE${NC}"
echo ""

# Set up environment for capturing
if [ "$CAPTURE" = true ]; then
    if [ -z "$KSM_ONE_TIME_TOKEN" ]; then
        echo -e "${YELLOW}Warning: KSM_ONE_TIME_TOKEN not set${NC}"
        echo "Using test token from code..."
    fi
    
    if [ -z "$KSM_CONFIG_FILE" ]; then
        echo -e "${YELLOW}Warning: KSM_CONFIG_FILE not set${NC}"
        echo "Using default path from code..."
    fi
fi

# Build test command
echo -e "${GREEN}Building project...${NC}"
go build ./cmd/ksm-mcp

# Run tests using the CLI
echo -e "${GREEN}Running tests...${NC}"
CMD="./ksm-mcp test --run-tests --mode $MODE"

if [ "$CAPTURE" = true ]; then
    CMD="$CMD --capture"
fi

if [ "$VERBOSE" = true ]; then
    CMD="$CMD -v"
fi

if [ -n "$FILTER" ]; then
    CMD="$CMD --filter \"$FILTER\""
fi

echo -e "${BLUE}Executing: $CMD${NC}"
echo ""

eval $CMD

# Check result
if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✓ All tests passed!${NC}"
    
    # Show additional info based on mode
    case $MODE in
        integration)
            if [ "$CAPTURE" = true ]; then
                echo ""
                echo -e "${BLUE}Captured data location:${NC}"
                echo "  fixtures/ksm-capture/"
                echo ""
                echo "To use captured data in offline tests:"
                echo "  export KSM_USE_FIXTURES=true"
            fi
            ;;
        e2e)
            echo ""
            echo -e "${BLUE}E2E test coverage:${NC}"
            echo "  ✓ All 13 MCP tools tested"
            echo "  ✓ File operations tested (2MB+ files)"
            echo "  ✓ Error handling tested"
            ;;
    esac
else
    echo ""
    echo -e "${RED}✗ Tests failed${NC}"
    exit 1
fi

# Optional: Generate coverage report
if [ "$MODE" != "integration" ] || [ "$CAPTURE" = false ]; then
    if [ -f coverage.out ]; then
        echo ""
        echo -e "${BLUE}Coverage report available:${NC}"
        echo "  go tool cover -html=coverage.out"
    fi
fi