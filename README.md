# KSM MCP Server - Secure AI Access to Keeper Secrets

KSM MCP is a Model Context Protocol (MCP) server that acts as a secure intermediary between AI language models (like Claude) and Keeper Secrets Manager (KSM). It allows AI agents to manage your KSM secrets—such as listing, creating, retrieving, and deleting records and folders—while protecting your KSM application credentials. Sensitive operations require user confirmation, ensuring you maintain control over your data.

## Quick User Guide

### Option 1: Using Docker (Recommended)

1.  **Get KSM Base64 Configuration:**
    *   Log into the [Keeper Secrets Manager Portal](https://keepersecurity.com/secrets-manager/).
    *   Navigate to your KSM Application, then to the "Devices" tab.
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

*(Note: Some tools like `get_field` or specific KSM notation queries might also be available but are considered more advanced.)*

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

--- 
