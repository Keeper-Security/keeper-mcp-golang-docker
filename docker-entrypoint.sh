#!/bin/sh
set -e

# Auto-initialize if KSM_CONFIG_BASE64 is provided and no profile exists
if [ -n "$KSM_CONFIG_BASE64" ] && [ ! -f "$KSM_MCP_CONFIG_DIR/profiles.db" ]; then
    # Only show messages if not in batch mode
    if [ "$KSM_MCP_BATCH_MODE" != "true" ]; then
        echo "Auto-initializing KSM MCP with provided base64 config..." >&2
    fi
    
    # Redirect init output to stderr if in batch mode
    if [ "$KSM_MCP_BATCH_MODE" = "true" ]; then
        ksm-mcp init --profile "${KSM_MCP_PROFILE:-default}" --no-master-password 2>&1 >&2
    else
        ksm-mcp init --profile "${KSM_MCP_PROFILE:-default}" --no-master-password
    fi
    
    if [ "$KSM_MCP_BATCH_MODE" != "true" ]; then
        echo "Initialization complete." >&2
    fi
fi

# Execute the command
exec "$@"