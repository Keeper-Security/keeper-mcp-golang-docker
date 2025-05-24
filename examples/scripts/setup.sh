#!/bin/bash

# KSM MCP Setup Script
# This script helps set up KSM MCP for first-time users

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
CONFIG_DIR="${HOME}/.keeper/ksm-mcp"
LOG_DIR="${CONFIG_DIR}/logs"

echo -e "${BLUE}KSM MCP Setup Script${NC}"
echo "===================="
echo

# Check if ksm-mcp is installed
if ! command -v ksm-mcp &> /dev/null; then
    echo -e "${RED}Error: ksm-mcp is not installed or not in PATH${NC}"
    echo "Please install ksm-mcp first:"
    echo "  - Download from: https://github.com/keeper-security/ksm-mcp/releases"
    echo "  - Or build from source: make build && sudo make install"
    exit 1
fi

# Create directories
echo -e "${GREEN}Creating configuration directories...${NC}"
mkdir -p "$CONFIG_DIR" "$LOG_DIR"
chmod 700 "$CONFIG_DIR"

# Check for existing configuration
if [ -f "$CONFIG_DIR/config.yaml" ]; then
    echo -e "${YELLOW}Configuration already exists at $CONFIG_DIR/config.yaml${NC}"
    echo -n "Do you want to backup and create a new configuration? (y/N): "
    read -r BACKUP
    
    if [ "$BACKUP" = "y" ] || [ "$BACKUP" = "Y" ]; then
        BACKUP_FILE="$CONFIG_DIR/config.yaml.backup.$(date +%Y%m%d_%H%M%S)"
        cp "$CONFIG_DIR/config.yaml" "$BACKUP_FILE"
        echo -e "${GREEN}Backed up to: $BACKUP_FILE${NC}"
    else
        echo "Keeping existing configuration."
        SKIP_CONFIG=true
    fi
fi

# Create default configuration
if [ -z "$SKIP_CONFIG" ]; then
    echo -e "${GREEN}Creating default configuration...${NC}"
    cat > "$CONFIG_DIR/config.yaml" << 'EOF'
# KSM MCP Configuration
server:
  host: "127.0.0.1"
  port: 8080
  timeout: 30s

mcp:
  rate_limit:
    requests_per_minute: 60
    requests_per_hour: 1000

security:
  enable_master_password: true
  confirmations:
    enabled: true
    timeout: 30s
  masking:
    enabled: true

logging:
  level: info
  format: json
  output: stderr

audit:
  enabled: true
  file: "~/.keeper/ksm-mcp/logs/audit.log"

profiles:
  default: ""
EOF
    echo -e "${GREEN}Configuration created at: $CONFIG_DIR/config.yaml${NC}"
fi

# Set up master password
echo
echo -e "${BLUE}Master Password Setup${NC}"
echo "A master password is required to encrypt your KSM credentials."
echo "This password will be required each time you start the MCP server."
echo

# Initialize first profile
echo
echo -e "${BLUE}Profile Setup${NC}"
echo "Let's create your first profile to connect to KSM."
echo

# Get profile name
echo -n "Enter profile name (default: 'default'): "
read -r PROFILE_NAME
PROFILE_NAME=${PROFILE_NAME:-default}

# Get initialization method
echo
echo "How would you like to initialize this profile?"
echo "1) One-time token (recommended)"
echo "2) Existing KSM config file"
echo -n "Select option (1-2): "
read -r INIT_METHOD

case $INIT_METHOD in
    1)
        echo
        echo "Please obtain a one-time token from Keeper Secrets Manager:"
        echo "1. Log in to your Keeper vault"
        echo "2. Go to Secrets Manager"
        echo "3. Create an application"
        echo "4. Generate a one-time token"
        echo
        echo -n "Enter your one-time token: "
        read -r TOKEN
        
        if [ -z "$TOKEN" ]; then
            echo -e "${RED}Error: Token cannot be empty${NC}"
            exit 1
        fi
        
        echo -e "${GREEN}Initializing profile with token...${NC}"
        ksm-mcp init --profile "$PROFILE_NAME" --token "$TOKEN"
        ;;
        
    2)
        echo
        echo -n "Enter path to KSM config file: "
        read -r CONFIG_FILE
        
        if [ ! -f "$CONFIG_FILE" ]; then
            echo -e "${RED}Error: Config file not found: $CONFIG_FILE${NC}"
            exit 1
        fi
        
        echo -e "${GREEN}Initializing profile with config file...${NC}"
        ksm-mcp init --profile "$PROFILE_NAME" --config "$CONFIG_FILE"
        ;;
        
    *)
        echo -e "${RED}Invalid option${NC}"
        exit 1
        ;;
esac

# Test the profile
echo
echo -e "${GREEN}Testing profile connection...${NC}"
if ksm-mcp test --profile "$PROFILE_NAME"; then
    echo -e "${GREEN}✓ Profile configured successfully!${NC}"
else
    echo -e "${RED}✗ Profile test failed${NC}"
    echo "Please check your credentials and try again."
    exit 1
fi

# Set as default if it's the first profile
PROFILE_COUNT=$(ksm-mcp profiles list 2>/dev/null | wc -l)
if [ "$PROFILE_COUNT" -eq 1 ]; then
    echo -e "${GREEN}Setting '$PROFILE_NAME' as default profile...${NC}"
    ksm-mcp profiles set-default "$PROFILE_NAME"
fi

# Create example Claude Desktop configuration
echo
echo -e "${BLUE}Claude Desktop Integration${NC}"
echo -n "Would you like to create a Claude Desktop configuration? (y/N): "
read -r CREATE_CLAUDE

if [ "$CREATE_CLAUDE" = "y" ] || [ "$CREATE_CLAUDE" = "Y" ]; then
    CLAUDE_CONFIG_FILE="$CONFIG_DIR/claude-desktop-config.json"
    cat > "$CLAUDE_CONFIG_FILE" << EOF
{
  "mcpServers": {
    "ksm": {
      "command": "ksm-mcp",
      "args": ["serve", "--profile", "$PROFILE_NAME"],
      "env": {
        "KSM_MCP_LOG_LEVEL": "info"
      }
    }
  }
}
EOF
    echo -e "${GREEN}Claude Desktop configuration created at:${NC}"
    echo "$CLAUDE_CONFIG_FILE"
    echo
    echo "To use with Claude Desktop:"
    echo "1. Copy this configuration to your Claude Desktop config"
    echo "2. Restart Claude Desktop"
fi

# Create convenience scripts
echo
echo -e "${BLUE}Creating convenience scripts...${NC}"

# Start script
cat > "$CONFIG_DIR/start-server.sh" << EOF
#!/bin/bash
# Start KSM MCP Server
echo "Starting KSM MCP server with profile: $PROFILE_NAME"
exec ksm-mcp serve --profile "$PROFILE_NAME"
EOF
chmod +x "$CONFIG_DIR/start-server.sh"

# Test script
cat > "$CONFIG_DIR/test-connection.sh" << EOF
#!/bin/bash
# Test KSM connection
echo "Testing KSM connection for profile: $PROFILE_NAME"
ksm-mcp test --profile "$PROFILE_NAME" --details
EOF
chmod +x "$CONFIG_DIR/test-connection.sh"

echo -e "${GREEN}Created convenience scripts:${NC}"
echo "  - Start server: $CONFIG_DIR/start-server.sh"
echo "  - Test connection: $CONFIG_DIR/test-connection.sh"

# Final instructions
echo
echo -e "${GREEN}✅ Setup complete!${NC}"
echo
echo "Next steps:"
echo "1. Start the MCP server:"
echo "   ${BLUE}ksm-mcp serve --profile $PROFILE_NAME${NC}"
echo
echo "2. Or use the convenience script:"
echo "   ${BLUE}$CONFIG_DIR/start-server.sh${NC}"
echo
echo "3. Configure your AI agent to connect to the MCP server"
echo
echo "For more information, see the documentation at:"
echo "https://github.com/keeper-security/ksm-mcp"