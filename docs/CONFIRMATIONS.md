# KSM MCP Confirmations Guide

This guide explains how confirmations work in KSM MCP and the various options available for different deployment scenarios.

## Understanding Confirmations

KSM MCP implements confirmations as a security feature to prevent accidental exposure of sensitive data to AI models. Certain operations require explicit user approval before proceeding.

### Operations Requiring Confirmation

1. **Revealing unmasked secrets** (`get_secret` with `unmask: true`)
2. **Creating new secrets** (`create_secret`)
3. **Updating existing secrets** (`update_secret`)
4. **Deleting secrets** (`delete_secret`)
5. **Uploading files** (`upload_file`)
6. **Creating folders** (`create_folder`)

## The Challenge with MCP and Docker

When running through Claude Desktop or other MCP clients, the server communicates over stdio (stdin/stdout). This creates a conflict:
- The MCP protocol uses stdin/stdout for communication
- Interactive confirmations also need stdin for user input
- Docker without TTY allocation (`-t` flag) doesn't provide `/dev/tty`
    
## Interactive Confirmations: Terminal vs. Visual UI

When `ksm-mcp` needs your approval for a sensitive operation (like creating a secret or unmasking a password), it aims to provide an interactive confirmation prompt. However, the way this prompt appears depends on how `ksm-mcp` is run, especially when used with an MCP client like Claude Desktop.

**Why Terminal Prompts?**

*   **CLI Origins:** `ksm-mcp` is fundamentally a Command-Line Interface (CLI) tool. Standard CLI applications request user input (like "yes/no") directly in the terminal.
*   **Direct Interaction with `/dev/tty`:** When you run `ksm-mcp` as a local binary (as configured in "Option 3: Local Binary Installation" below), it attempts to interact with your system's controlling terminal (often `/dev/tty` on Unix-like systems). This allows it to show a prompt and read your input even if its main standard input/output are being used for MCP communication with Claude.
*   **Universal Fallback:** The terminal is a universal interface available in most environments where CLI tools run.

**Why Not Visual Confirmations in the AI Agent's UI?**

Ideally, you might expect a pop-up dialog within the Claude Desktop interface asking for your confirmation. While this would be a smoother user experience, it's not the current standard for a few reasons:

*   **MCP Protocol Limitations:** The Model Context Protocol (MCP) is designed for tools to expose their functionality and data to AI models in a structured way (typically JSON). The core MCP specification does not currently include a standard mechanism for a tool to request the AI client (like Claude Desktop) to render a custom UI element (like a confirmation dialog) and return the user's interaction.
*   **Tool Independence:** `ksm-mcp` aims to be usable by any AI agent or system that speaks MCP, not all of which will have graphical user interfaces. Relying on terminal-based interaction ensures broader compatibility.
*   **Security and Trust:** The confirmation logic currently resides within `ksm-mcp` itself. Delegating the UI aspect of confirmation to the MCP client would involve a different trust model and require specific protocol support.

**Current User Experience:**

*   **With Local Binary:** If `/dev/tty` access is successful, you should see prompts like "Create new secret 'XYZ'? [Y/n]" in the terminal window associated with the `ksm-mcp` process (often the terminal where Claude Desktop was launched, or visible in its logs if `stderr` is captured). You'll need to respond in that terminal.
*   **With Docker (or if `/dev/tty` fails):** True interactive prompts are generally not feasible. This is why "Batch Mode" or "Auto-Approve Mode" are the primary solutions for Dockerized or non-interactive environments, as detailed below.

While terminal-based prompts for a local binary are functional, we acknowledge it's a step away from a fully integrated visual experience. Future enhancements in the MCP ecosystem or `ksm-mcp` itself might offer more streamlined UI-based confirmations.

## Available Solutions

### 1. Batch Mode (Recommended for Docker)

Enable batch mode to skip interactive confirmations and use default responses:

```json
{
  "mcpServers": {
    "ksm": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "KSM_CONFIG_BASE64=YOUR_CONFIG",
        "-e", "KSM_MCP_BATCH_MODE=true",
        "ksm-mcp-local:latest"
      ]
    }
  }
}
```

**Behavior in batch mode:**
- Operations use the default response (usually deny for sensitive operations)
- No interactive prompts
- Suitable for automated environments

### 2. Auto-Approve Mode (Use with Caution!)

Automatically approve all operations without confirmation:

```json
{
  "mcpServers": {
    "ksm": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "KSM_CONFIG_BASE64=YOUR_CONFIG",
        "ksm-mcp-local:latest",
        "serve", "--auto-approve"
      ]
    }
  }
}
```

⚠️ **WARNING**: This bypasses all security confirmations. Only use for testing or fully trusted environments.

### 3. Local Binary Installation

Install and run the binary directly for full interactive support:

```bash
# Download and install
curl -L https://github.com/keeper-security/ksm-mcp/releases/latest/download/ksm-mcp-darwin-arm64 -o ksm-mcp
chmod +x ksm-mcp
sudo mv ksm-mcp /usr/local/bin/

# Initialize profile
ksm-mcp init --profile myprofile --config "YOUR_BASE64_CONFIG"

# Configure Claude Desktop
```

```json
{
  "mcpServers": {
    "ksm": {
      "command": "ksm-mcp",
      "args": ["serve", "--profile", "myprofile"]
    }
  }
}
```

This provides full interactive confirmation support when running outside Docker.

### 4. Docker with TTY (Experimental)

If your MCP client supports it, you can try allocating a TTY:

```json
{
  "mcpServers": {
    "ksm": {
      "command": "docker",
      "args": [
        "run", "-it", "--rm",
        "-e", "KSM_CONFIG_BASE64=YOUR_CONFIG",
        "ksm-mcp-local:latest"
      ]
    }
  }
}
```

**Note**: This may not work with all MCP clients as the TTY can interfere with JSON parsing.

## Configuration Options

### Environment Variables

- `KSM_MCP_BATCH_MODE=true` - Enable batch mode
- `KSM_MCP_TIMEOUT=60s` - Set confirmation timeout
- `KSM_MCP_DEFAULT_DENY=true` - Default to denying operations in batch mode

### Command Line Flags

- `--batch` - Enable batch mode
- `--auto-approve` - Auto-approve all operations
- `--timeout 30s` - Set confirmation timeout

### Configuration File

Create `~/.keeper/ksm-mcp/config.yaml`:

```yaml
security:
  batch_mode: false
  auto_approve: false
  confirmation_timeout: 30s
  default_deny: true
```

## Best Practices

1. **Production Environments**: Use batch mode with `default_deny: true`
2. **Development**: Use local binary for interactive confirmations
3. **CI/CD**: Use batch mode or auto-approve with restricted access
4. **Testing**: Auto-approve is acceptable in isolated test environments

## Troubleshooting

### "Interactive confirmation not available in MCP stdio mode"

This error occurs when:
- Running in Docker without TTY
- MCP is using stdio for communication
- No batch mode or auto-approve is set

**Solution**: Add `-e KSM_MCP_BATCH_MODE=true` to your Docker configuration.

### Confirmations Timing Out

If confirmations are timing out too quickly:

1. Increase the timeout: `--timeout 60s`
2. Enable batch mode to skip confirmations
3. Check if the terminal is properly allocated

### Different Behavior in Docker vs Local

Docker containers without TTY allocation cannot provide interactive prompts. This is expected behavior. Use batch mode or install locally for consistency.

## Security Considerations

1. **Batch Mode**: Operations will proceed with default responses. Configure `default_deny` appropriately.
2. **Auto-Approve**: Completely bypasses security confirmations. Only use in trusted environments.
3. **Audit Logs**: All confirmation decisions are logged for security auditing.

## Examples

### Secure Production Setup

```json
{
  "mcpServers": {
    "ksm-prod": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "KSM_CONFIG_BASE64=PROD_CONFIG",
        "-e", "KSM_MCP_BATCH_MODE=true",
        "-e", "KSM_MCP_DEFAULT_DENY=true",
        "-e", "KSM_MCP_LOG_LEVEL=info",
        "-v", "ksm-mcp-prod:/home/ksm/.keeper/ksm-mcp",
        "ksm-mcp:latest"
      ]
    }
  }
}
```

### Development Setup with Confirmations

```bash
# Install locally
brew install ksm-mcp  # or download binary

# Initialize
ksm-mcp init --profile dev --token "YOUR_TOKEN"

# Configure Claude
{
  "mcpServers": {
    "ksm-dev": {
      "command": "ksm-mcp",
      "args": ["serve", "--profile", "dev", "--timeout", "60s"]
    }
  }
}
```

### Test Environment with Auto-Approve

```json
{
  "mcpServers": {
    "ksm-test": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "KSM_CONFIG_BASE64=TEST_CONFIG",
        "ksm-mcp:latest",
        "serve", "--auto-approve", "--timeout", "10s"
      ]
    }
  }
}
```

## Summary

- **Docker + MCP**: Use batch mode or auto-approve
- **Local Binary**: Full interactive confirmation support
- **Security**: Always use the most restrictive mode suitable for your environment
- **Logging**: All decisions are audited for compliance 