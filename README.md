# KSM MCP Server - Secure AI Access to Keeper Secrets

KSM MCP is a Model Context Protocol (MCP) server that acts as a secure intermediary between AI language models (like Claude) and Keeper Secrets Manager (KSM). It allows AI agents to manage your KSM secrets-such as listing, creating, retrieving, and deleting records and folders-while protecting your KSM application credentials. Sensitive operations require user confirmation, ensuring you maintain control over your data.

## Quick User Guide

### Option 1: Using Docker (Recommended)

1.  **Get KSM Base64 Configuration:**
    *   Log into the [Keeper Secrets Vault](https://keepersecurity.com/vault).
    *   Navigate to your Secrets Manager, Application, then to the "Devices" tab.
    *   Click "Add Device" and copy the **base64-encoded configuration string** provided (it usually starts with `ewog...`).
    > **Important**: The base64 config contains your KSM application's credentials. Keep it secure and never commit it to version control.

2.  **Configure Claude Desktop:**
    *   Open your Claude Desktop configuration file:
        *   macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
        *   Windows: `%APPDATA%\Claude\claude_desktop_config.json`
        *   Linux: `~/.config/Claude/claude_desktop_config.json`
    *   Add or update the `ksm` server entry as follows, replacing `YOUR_BASE64_CONFIG_STRING_HERE` with your actual base64 config:

    ```json
    {
      "mcpServers": {
        "ksm": {
          "command": "docker",
          "args": [
            "run", "-i", "--rm",
            "-e", "KSM_CONFIG_BASE64=YOUR_BASE64_CONFIG_STRING_HERE",
            "keepersecurityinc/ksm-mcp-poc:latest"
          ]
        }
        // You might have other servers like "memory" here, leave them as is.
      }
    }
    ```

3.  **Restart Claude Desktop:**
    *   The KSM server should now be available to Claude. The first time it connects, it will use the base64 config to start up.

### Option 2: Using a Pre-compiled Binary

1.  **Download the Binary:**
    *   Go to the [KSM MCP Releases Page](https://github.com/Keeper-Security/ksm-mcp/releases) and download the appropriate binary for your operating system (e.g., `ksm-mcp-darwin-amd64` for Intel Macs, `ksm-mcp-windows-amd64.exe` for Windows).
    *   Make the binary executable (e.g., `chmod +x ./ksm-mcp-darwin-amd64`) and place it in a directory included in your system's PATH, or note its full path.

2.  **Get KSM Base64 Configuration:** (See step 1 in the Docker guide above)
    > **Important**: The base64 config contains your KSM application's credentials. Keep it secure and never commit it to version control.

3.  **Initialize KSM MCP Profile:**
    *   Open your terminal and run the init command, replacing `YOUR_BASE64_CONFIG_STRING` and choosing a profile name (e.g., `default`):
        ```bash
        /path/to/ksm-mcp init --profile default --config "YOUR_BASE64_CONFIG_STRING"
        ```
    *   You will be prompted to set a protection password for your local profile store. Remember this password, as you'll need it if you restart the server manually or if it's configured to require it. For automated use with Claude, often the server is run in batch mode where this isn't prompted interactively.

4.  **Configure Claude Desktop:**
    *   Open your `claude_desktop_config.json` file (see paths in Docker guide).
    *   Add or update the `ksm` server entry, replacing `/path/to/ksm-mcp` with the actual path to your downloaded binary:
    ```json
    {
      "mcpServers": {
        "ksm": {
          "command": "/path/to/ksm-mcp",
          "args": ["serve", "--profile", "default"] // Use the profile name you initialized
        }
        // ... other servers ...
      }
    }
    ```

5.  **Restart Claude Desktop.**

## Capabilities (Available Tools)

The KSM MCP server provides the following tools to interact with Keeper Secrets Manager:

### Secret Operations
*   `list_secrets`: List all accessible secrets (metadata only).
*   `get_secret`: Retrieve a specific secret (sensitive fields masked by default; unmasking requires confirmation).
*   `search_secrets`: Search secrets by title, notes, or other field content.
*   `create_secret`: Create a new secret (requires confirmation).
*   `update_secret`: Update an existing secret (requires confirmation).
*   `delete_secret`: Delete a secret (requires confirmation).

### Folder Operations
*   `list_folders`: List all accessible folders.
*   `create_folder`: Create a new folder (requires confirmation; must specify a parent shared folder).
*   `delete_folder`: Delete a folder (requires confirmation; option to force delete non-empty folders).

### File Management (within Secrets)
*   `upload_file`: Upload a file attachment to a secret (requires confirmation).
*   `download_file`: Download a file attachment from a secret.

### Utilities
*   `generate_password`: Generate a secure password. Can optionally save directly to a new secret without exposing it to the AI.
*   `get_totp_code`: Get the current TOTP code for a secret that has TOTP configured.
*   `get_server_version`: Get the current version of the KSM MCP server.
*   `health_check`: Check the operational status of the MCP server and its connection to KSM.


## Sample Use Cases

Here are some examples of how you might instruct an AI agent (like Claude) to use the KSM MCP server:

*   **Create a new secret in a new folder:**
    *"Please create a new folder named 'Project Phoenix Shared' under our main 'KSM-MCP-TEST-RECORDS' shared folder. Then, inside 'Project Phoenix Shared', create a new login secret titled 'Phoenix Dev DB' with username 'phoenix_user', password 'ComplexP@$$wOrd123!', and URL 'db.phoenix.dev.internal'."*

*   **List secrets and retrieve one:**
    *"List all secrets in the 'API Keys' folder. Then, get the details for the secret titled 'Third-Party Analytics API Key', but keep the API key itself masked."*

*   **Delete a secret and then its folder (if empty):**
    *"Delete the secret named 'Old Staging Server Credentials'. Once that's done, if the 'Staging Environment' folder it was in is now empty, please delete that folder as well."*

*   **Upload a configuration file to an existing record:**
    *"I have a new Kubernetes config file for our production cluster at '~/Downloads/kubeconfig-prod.yaml'. Please upload this file to the KSM record titled 'Production K8s Cluster Access', and name the attachment 'kubeconfig-prod-cluster.yaml'."*

*   **Generate a secure password and save it to a new record:**
    *"Generate a very strong 32-character password with uppercase, lowercase, numbers, and special characters. Save it directly to a new login record titled 'Internal Audit Service Account' in the 'Service Accounts' folder. Do not show me the password."*

*   **Check configuration consistency across environments:**
    *"I have service configuration records organized in folders by environment (dev, qa) with subfolders for each AWS region. Please analyze these records and identify any inconsistencies between similar services across different environments. Pay particular attention to configuration values that should typically be the same across environments, such as logging levels, timeout settings, or feature flags."*

---

## Server Configuration Reference

The KSM MCP server can be instantiated in multiple ways with various configuration options. This section documents all available methods, flags, and environment variables.

### Configuration Methods

#### Method 1: Docker with Environment Variables (Recommended)

```json
{
  "mcpServers": {
    "ksm": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "KSM_CONFIG_BASE64=YOUR_BASE64_CONFIG_STRING",
        "keepersecurityinc/ksm-mcp-poc:latest"
      ]
    }
  }
}
```

#### Method 2: Pre-compiled Binary with Profile

```json
{
  "mcpServers": {
    "ksm": {
      "command": "/path/to/ksm-mcp",
      "args": ["serve", "--profile", "default"]
    }
  }
}
```

#### Method 3: Pre-compiled Binary with Base64 Config (CLI Flag)

```json
{
  "mcpServers": {
    "ksm": {
      "command": "/path/to/ksm-mcp",
      "args": [
        "serve",
        "--config-base64", "YOUR_BASE64_CONFIG_STRING"
      ]
    }
  }
}
```

#### Method 4: Pre-compiled Binary with Environment Variables

```json
{
  "mcpServers": {
    "ksm": {
      "command": "/path/to/ksm-mcp",
      "args": ["serve"],
      "env": {
        "KSM_CONFIG_BASE64": "YOUR_BASE64_CONFIG_STRING"
      }
    }
  }
}
```

#### Method 5: Silent Mode (No Local Logs)

For environments where you want to prevent any local file creation (including audit logs):

```json
{
  "mcpServers": {
    "ksm": {
      "command": "/path/to/ksm-mcp",
      "args": [
        "serve",
        "--no-logs",
        "--config-base64", "YOUR_BASE64_CONFIG_STRING"
      ]
    }
  }
}
```

The `--no-logs` flag completely disables audit logging, ensuring no local files are created. This is useful for:
- Compliance environments where local file creation must be avoided
- Containerized deployments where persistence isn't desired
- Temporary or testing scenarios
- Systems with read-only filesystems

### Command Line Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--profile` | string | `""` | Profile name to use from local storage |
| `--config-base64` | string | `""` | Base64-encoded KSM configuration string |
| `--batch` | boolean | `false` | Run in batch mode (no password prompts, suitable for automated environments) |
| `--auto-approve` | boolean | `false` | Auto-approve all destructive operations without user confirmation (dangerous) |
| `--timeout` | duration | `30s` | Request timeout duration |
| `--log-level` | string | `info` | Log level (debug, info, warn, error) |
| `--no-logs` | boolean | `false` | Disable audit logging (no local files created) |

#### Flag Details

**`--batch` (Non-Interactive Mode)**
- **Purpose**: Prevents the server from prompting for passwords or user input
- **When to use**: 
  - Automated environments (CI/CD, Docker containers)
  - When running as a service where no human interaction is possible
  - Claude Desktop integration (recommended)
- **What it does**: 
  - Skips password prompts when loading encrypted profiles
  - Uses environment variables or CLI flags for all configuration
  - Fails gracefully if required input is missing instead of hanging

**`--no-logs` (Silent Mode)**
- **Purpose**: Completely disables audit logging to prevent any local file creation
- **When to use**:
  - Compliance environments where local artifacts must be avoided
  - Containerized or ephemeral deployments
  - Read-only filesystem environments
  - Testing scenarios where cleanup is important
- **What it does**:
  - Prevents creation of `~/.keeper/ksm-mcp/logs/` directory
  - Disables all audit logging (access logs, error logs, system logs)
  - Maintains full MCP functionality without logging overhead
  - Safe operation with nil-check wrappers for all logging calls
- **Security**: High - no sensitive data written to local files

**`--auto-approve` (Dangerous)**
- **Purpose**: Bypasses user confirmation prompts for destructive operations
- **⚠️ Security Warning**: This is dangerous and should only be used in controlled environments
- **What operations normally require confirmation**:
  - `create_secret` - Creating new secrets
  - `update_secret` - Modifying existing secrets  
  - `delete_secret` - Deleting secrets
  - `create_folder` - Creating new folders
  - `delete_folder` - Deleting folders
  - `upload_file` - Uploading files to secrets
  - Unmasking sensitive data (passwords, API keys, etc.)
- **When you might use it**:
  - Automated testing environments
  - Trusted AI agents in controlled scenarios
  - Bulk operations where manual confirmation isn't practical
- **Recommended alternative**: Use the `ksm_execute_confirmed_action` tool for selective approval

### Environment Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `KSM_CONFIG_BASE64` | string | `""` | Base64-encoded KSM configuration string |
| `KSM_MCP_CONFIG_DIR` | string | `~/.keeper/ksm-mcp` | Directory for profiles and logs |
| `KSM_MCP_PROFILE` | string | `""` | Default profile name to use |

### Configuration Priority

The server uses the following priority order for configuration:

1. **CLI Flag `--config-base64`** (highest priority)
2. **Environment Variable `KSM_CONFIG_BASE64`**
3. **CLI Flag `--profile`** with local profile storage
4. **Environment Variable `KSM_MCP_PROFILE`** with local profile storage

### Profile Management Commands

#### Why Use Profiles?

Profiles provide a secure way to store and manage KSM configurations locally without exposing sensitive credentials:

- **Security**: Your base64 config contains sensitive KSM application credentials. Profiles encrypt and store these locally with password protection
- **Convenience**: Once initialized, you only need to reference the profile name instead of passing the full base64 config each time
- **Multiple Environments**: Manage different KSM applications (dev, staging, prod) with separate profiles
- **Credential Protection**: Keeps sensitive data out of command lines, environment variables, and configuration files
- **Persistent Storage**: Survives system restarts and doesn't require re-entering credentials

**When to use profiles vs. direct config:**
- **Use profiles for**: Local development, persistent setups, multiple environments
- **Use direct config for**: CI/CD, Docker containers, temporary usage, environments where local storage isn't desired

#### Initialize a New Profile

```bash
ksm-mcp init --profile PROFILE_NAME --config "BASE64_CONFIG_STRING"
```

This command:
1. Takes your base64 KSM configuration
2. Encrypts it with a password you provide
3. Stores it locally in `~/.keeper/ksm-mcp/profiles/`
4. Allows future use with just `--profile PROFILE_NAME`

#### List Available Profiles

```bash
ksm-mcp profiles list
```

#### Delete a Profile

```bash
ksm-mcp profiles delete --profile PROFILE_NAME
```

### Security Considerations

| Method | Security Level | Use Case |
|--------|---------------|----------|
| Docker with env vars | **High** | Production, CI/CD |
| Binary with profile | **High** | Local development, persistent setup |
| Binary with CLI flag | **Medium** | Testing, temporary usage |
| Binary with env vars | **High** | Production, containerized environments |
| Silent mode | **High** | Compliance, no local artifacts |

### Troubleshooting

#### Common Issues

1. **"No active session" error**: Ensure you have either:
   - A valid `--profile` flag pointing to an initialized profile
   - A valid `--config-base64` flag or `KSM_CONFIG_BASE64` environment variable

2. **"Failed to create log directory" warnings**: Use `--no-logs` flag to disable local logging

3. **Permission denied errors**: Ensure the binary has execute permissions and the config directory is writable

#### Debug Mode

Enable debug logging for troubleshooting:

```bash
ksm-mcp serve --log-level debug --profile your-profile
```

### Examples

#### Development Setup

```bash
# Initialize profile
ksm-mcp init --profile dev --config "ewogICJob3N0bmFtZSI6..."

# Run server
ksm-mcp serve --profile dev --log-level debug
```

#### Production Setup (Docker)

```bash
docker run -i --rm \
  -e KSM_CONFIG_BASE64="ewogICJob3N0bmFtZSI6..." \
  keepersecurityinc/ksm-mcp-poc:latest
```

#### CI/CD Setup (No Local Files)

```bash
export KSM_CONFIG_BASE64="ewogICJob3N0bmFtZSI6..."
ksm-mcp serve --no-logs --batch --timeout 60s
``` 
