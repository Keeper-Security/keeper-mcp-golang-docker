#!/bin/sh
set -e

# Auto-initialize if KSM_CONFIG_BASE64 is provided and no profile exists
if [ -n "$KSM_CONFIG_BASE64" ] && [ ! -f "$KSM_MCP_CONFIG_DIR/profiles.db" ]; then
    echo "Auto-initializing KSM MCP with provided base64 config..."
    ksm-mcp init --profile "${KSM_MCP_PROFILE:-default}" --no-master-password
    echo "Initialization complete."
fi

# Execute the command
exec "$@"