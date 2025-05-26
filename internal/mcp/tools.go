package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/keeper-security/ksm-mcp/internal/audit"
	"github.com/keeper-security/ksm-mcp/pkg/types"
)

// getAvailableTools returns the list of available MCP tools
func (s *Server) getAvailableTools() []types.MCPTool {
	return []types.MCPTool{
		// Phase 1 Tools
		{
			Name:        "list_secrets",
			Description: "List all secrets (metadata only, no sensitive data)",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"folder_uid": map[string]interface{}{
						"type":        "string",
						"description": "Filter by folder UID",
					},
				},
			},
		},
		{
			Name:        "get_secret",
			Description: "Get a secret by UID",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"uid": map[string]interface{}{
						"type":        "string",
						"description": "Secret UID",
					},
					"fields": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Fields to retrieve (default: all)",
					},
					"unmask": map[string]interface{}{
						"type":        "boolean",
						"description": "Show unmasked values (requires confirmation)",
					},
				},
				"required": []string{"uid"},
			},
		},
		{
			Name:        "search_secrets",
			Description: "Search secrets by title",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"query": map[string]interface{}{
						"type":        "string",
						"description": "Search query",
					},
				},
				"required": []string{"query"},
			},
		},
		{
			Name:        "get_field",
			Description: "Get a specific field using KSM notation",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"notation": map[string]interface{}{
						"type":        "string",
						"description": "KSM notation (e.g., UID/field/password, Title/field/url[0])",
					},
					"unmask": map[string]interface{}{
						"type":        "boolean",
						"description": "Show unmasked value (requires confirmation)",
					},
				},
				"required": []string{"notation"},
			},
		},
		{
			Name:        "generate_password",
			Description: "Generate a secure password",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"length": map[string]interface{}{
						"type":        "integer",
						"description": "Password length (default: 32)",
						"minimum":     8,
						"maximum":     100,
					},
					"lowercase": map[string]interface{}{
						"type":        "integer",
						"description": "Minimum lowercase characters",
						"minimum":     0,
					},
					"uppercase": map[string]interface{}{
						"type":        "integer",
						"description": "Minimum uppercase characters",
						"minimum":     0,
					},
					"digits": map[string]interface{}{
						"type":        "integer",
						"description": "Minimum digit characters",
						"minimum":     0,
					},
					"special": map[string]interface{}{
						"type":        "integer",
						"description": "Minimum special characters",
						"minimum":     0,
					},
					"special_set": map[string]interface{}{
						"type":        "string",
						"description": "Custom special character set",
					},
					"save_to_secret": map[string]interface{}{
						"type":        "string",
						"description": "If specified, saves password to a secret with this title (password not exposed to AI)",
					},
				},
			},
		},
		{
			Name:        "get_totp_code",
			Description: "Generate a TOTP code for a secret",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"uid": map[string]interface{}{
						"type":        "string",
						"description": "Secret UID containing TOTP",
					},
				},
				"required": []string{"uid"},
			},
		},
		// Phase 2 Tools
		{
			Name:        "create_secret",
			Description: "Create a new secret (requires confirmation)",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"folder_uid": map[string]interface{}{
						"type":        "string",
						"description": "Folder UID to create secret in",
					},
					"type": map[string]interface{}{
						"type":        "string",
						"description": "Secret type (e.g., login)",
					},
					"title": map[string]interface{}{
						"type":        "string",
						"description": "Secret title",
					},
					"fields": map[string]interface{}{
						"type":        "array",
						"description": "Field values array",
						"items": map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{
								"type": map[string]interface{}{
									"type":        "string",
									"description": "Field type (login, password, url, etc.)",
								},
								"value": map[string]interface{}{
									"type":        "array",
									"description": "Field value(s)",
									"items":       map[string]interface{}{"type": "string"},
								},
							},
							"required": []string{"type", "value"},
						},
					},
					"notes": map[string]interface{}{
						"type":        "string",
						"description": "Secret notes",
					},
				},
				"required": []string{"type", "title"},
			},
		},
		{
			Name:        "update_secret",
			Description: "Update an existing secret (requires confirmation)",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"uid": map[string]interface{}{
						"type":        "string",
						"description": "Secret UID to update",
					},
					"title": map[string]interface{}{
						"type":        "string",
						"description": "New title",
					},
					"fields": map[string]interface{}{
						"type":        "array",
						"description": "Field values to update",
						"items": map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{
								"type": map[string]interface{}{
									"type":        "string",
									"description": "Field type (login, password, url, etc.)",
								},
								"value": map[string]interface{}{
									"type":        "array",
									"description": "Field value(s)",
									"items":       map[string]interface{}{"type": "string"},
								},
							},
							"required": []string{"type", "value"},
						},
					},
					"notes": map[string]interface{}{
						"type":        "string",
						"description": "New notes",
					},
				},
				"required": []string{"uid"},
			},
		},
		{
			Name:        "delete_secret",
			Description: "Delete a secret (requires confirmation)",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"uid": map[string]interface{}{
						"type":        "string",
						"description": "Secret UID to delete",
					},
				},
				"required": []string{"uid"},
			},
		},
		{
			Name:        "upload_file",
			Description: "Upload a file to a secret (requires confirmation)",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"uid": map[string]interface{}{
						"type":        "string",
						"description": "Secret UID",
					},
					"file_path": map[string]interface{}{
						"type":        "string",
						"description": "Path to file to upload",
					},
					"title": map[string]interface{}{
						"type":        "string",
						"description": "File title in KSM",
					},
				},
				"required": []string{"uid", "file_path", "title"},
			},
		},
		{
			Name:        "download_file",
			Description: "Download a file from a secret",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"uid": map[string]interface{}{
						"type":        "string",
						"description": "Secret UID",
					},
					"file_uid": map[string]interface{}{
						"type":        "string",
						"description": "File UID or name",
					},
					"save_path": map[string]interface{}{
						"type":        "string",
						"description": "Path to save file",
					},
				},
				"required": []string{"uid", "file_uid"},
			},
		},
		{
			Name:        "list_folders",
			Description: "List all folders",
			InputSchema: map[string]interface{}{
				"type": "object",
			},
		},
		{
			Name:        "create_folder",
			Description: "Create a new folder (requires confirmation)",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"name": map[string]interface{}{
						"type":        "string",
						"description": "Folder name",
					},
					"parent_uid": map[string]interface{}{
						"type":        "string",
						"description": "Parent folder UID",
					},
				},
				"required": []string{"name"},
			},
		},
		{
			Name:        "health_check",
			Description: "Check the health status of the MCP server",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
	}
}

// executeTool executes a tool with the given arguments
func (s *Server) executeTool(toolName string, args json.RawMessage) (interface{}, error) {
	// Get current client
	client, err := s.getCurrentClient()
	if err != nil {
		return nil, fmt.Errorf("no active session: %w", err)
	}

	// Log tool execution
	s.logger.LogSystem(audit.EventAccess, "Tool called", map[string]interface{}{
		"tool":    toolName,
		"profile": s.currentProfile,
	})

	// Route to appropriate tool handler
	switch toolName {
	// Phase 1 Tools
	case "list_secrets":
		return s.executeListSecrets(client, args)
	case "get_secret":
		return s.executeGetSecret(client, args)
	case "search_secrets":
		return s.executeSearchSecrets(client, args)
	case "get_field":
		return s.executeGetField(client, args)
	case "generate_password":
		return s.executeGeneratePassword(client, args)
	case "get_totp_code":
		return s.executeGetTOTPCode(client, args)

	// Phase 2 Tools
	case "create_secret":
		return s.executeCreateSecret(client, args)
	case "update_secret":
		return s.executeUpdateSecret(client, args)
	case "delete_secret":
		return s.executeDeleteSecret(client, args)
	case "upload_file":
		return s.executeUploadFile(client, args)
	case "download_file":
		return s.executeDownloadFile(client, args)
	case "list_folders":
		return s.executeListFolders(client, args)
	case "create_folder":
		return s.executeCreateFolder(client, args)
	case "health_check":
		return s.handleHealthCheck(context.Background(), args)

	default:
		return nil, fmt.Errorf("unknown tool: %s", toolName)
	}
}
