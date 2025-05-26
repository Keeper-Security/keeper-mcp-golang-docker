#!/bin/sh
set -e

# Ensure config.yaml exists
if [ ! -f "$KSM_MCP_CONFIG_DIR/config.yaml" ]; then
    cp "$KSM_MCP_CONFIG_DIR/config.yaml.example" "$KSM_MCP_CONFIG_DIR/config.yaml" 2>/dev/null || true
fi

# Skip profile initialization when using direct config (no profile specified)
if [ -n "$KSM_CONFIG_BASE64" ] && [ -z "$KSM_MCP_PROFILE" ]; then
    if [ "$KSM_MCP_BATCH_MODE" != "true" ]; then
        echo "Using direct KSM configuration (no profile initialization needed)" >&2
    fi
fi

# Detect if we're running in MCP mode (serve command)
case "$*" in
    *serve*)
        # Set MCP mode to stdio when running serve command in Docker
        export KSM_MCP_MODE="stdio"
        ;;
esac

# Execute the command
# If the first argument doesn't start with ksm-mcp, prepend it
case "$1" in
    ksm-mcp*)
        exec "$@"
        ;;
    *)
        # Just prepend ksm-mcp, the environment variable KSM_MCP_CONFIG_DIR will be used
        exec ksm-mcp "$@"
        ;;
esac