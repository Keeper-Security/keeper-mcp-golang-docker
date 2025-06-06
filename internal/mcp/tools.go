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
			Description: "List all secrets (metadata only, no sensitive data). Supports filtering by single folder or multiple folders.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"folder_uid": map[string]interface{}{
						"type":        "string",
						"description": "Filter by single folder UID (for backward compatibility)",
					},
					"folder_uids": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Filter by multiple folder UIDs (uses KSM SDK folder filtering for better performance)",
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
						"description": "If specified, saves password to a new secret with this title (password not exposed to AI).",
					},
					"folder_uid": map[string]interface{}{
						"type":        "string",
						"description": "UID of the shared folder to save the new secret in. Required if save_to_secret is used.",
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
			Description: "Create a new KSM secret. Fields are specified in a flattened format. Examples: 'login', 'password', 'bankAccount.accountType', 'phone.type', 'name.first', 'passkey.credentialId', 'passkey.privateKey' (as JSON string of JWK). For enum-like fields (e.g., phone.type), use TitleCase values (e.g., 'Mobile'). Requires confirmation.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"folder_uid": map[string]interface{}{
						"type":        "string",
						"description": "(Optional) Folder UID to create the secret in. If omitted, AI will be prompted to select or confirm a folder.",
					},
					"type": map[string]interface{}{
						"type":        "string",
						"description": "Secret type (e.g., login, bankAccount, contact). This determines the overall template.",
					},
					"title": map[string]interface{}{
						"type":        "string",
						"description": "Secret title.",
					},
					"fields": map[string]interface{}{
						"type":        "array",
						"description": "Array of field objects. Use flattened dot notation for complex fields (e.g., bankAccount.routingNumber). Each field value must be an array with a single string element, e.g., {type: \"login\", value: [\"user\"]}, {type: \"bankAccount.accountType\", value: [\"Checking\"]}.",
						"items": map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{
								"type": map[string]interface{}{
									"type":        "string",
									"description": "Field type, using dot notation for sub-fields (e.g., login, bankAccount.accountType, address.street1).",
								},
								"value": map[string]interface{}{
									"type":        "array",
									"description": "Field value, as a single-element array (e.g., [\"the_value\"] ). For enum-like sub-fields (e.g. phone.type), use TitleCase values (e.g. [\"Mobile\"]). For passkey.privateKey, value should be a JSON string representing the JsonWebKey. Example complex fields: bankAccount:[{accountType,routingNumber,accountNumber}], name:[{first,middle,last}], passkey:[{privateKey (JSON string),credentialId,signCount,userId,relyingParty,username,createdDate}], appFiller:[{applicationTitle,contentFilter,macroSequence}], script:[{command,fileRef,recordRef (comma-sep UIDs)}], pamResources:[{controllerUid,folderUid,resourceRef (comma-sep UIDs)}]",
									"items":       map[string]interface{}{"type": "string"},
									"minItems":    1,
									"maxItems":    1,
								},
							},
							"required": []string{"type", "value"},
						},
					},
					"notes": map[string]interface{}{
						"type":        "string",
						"description": "(Optional) Secret notes.",
					},
				},
				"required": []string{"type", "title", "fields"},
			},
		},
		{
			Name:        "update_secret",
			Description: "Update an existing KSM secret. Fields are specified in a flattened format. Examples: 'login', 'password', 'bankAccount.accountType', 'phone.type', 'name.first', 'passkey.credentialId', 'passkey.privateKey' (as JSON string of JWK). For enum-like fields (e.g., phone.type), use TitleCase values (e.g., 'Mobile'). Requires confirmation.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"uid": map[string]interface{}{
						"type":        "string",
						"description": "UID of the secret to update.",
					},
					"title": map[string]interface{}{
						"type":        "string",
						"description": "(Optional) New title for the secret.",
					},
					"fields": map[string]interface{}{
						"type":        "array",
						"description": "Array of field objects to update or add. Use flattened dot notation for complex fields (e.g., bankAccount.routingNumber). Each field value must be an array with a single string element, e.g., {type: \"login\", value: [\"user\"]}, {type: \"bankAccount.accountType\", value: [\"Checking\"]}. If a field type is provided that already exists, its value will be replaced. If it doesn't exist, it will be added.",
						"items": map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{
								"type": map[string]interface{}{
									"type":        "string",
									"description": "Field type, using dot notation for sub-fields (e.g., login, bankAccount.accountType, address.street1).",
								},
								"value": map[string]interface{}{
									"type":        "array",
									"description": "Field value, as a single-element array (e.g., [\"the_value\"] ). For enum-like sub-fields (e.g. phone.type), use TitleCase values (e.g. [\"Mobile\"]). For passkey.privateKey, value should be a JSON string representing the JsonWebKey. Example complex fields: bankAccount:[{accountType,routingNumber,accountNumber}], name:[{first,middle,last}], passkey:[{privateKey (JSON string),credentialId,signCount,userId,relyingParty,username,createdDate}], appFiller:[{applicationTitle,contentFilter,macroSequence}], script:[{command,fileRef,recordRef (comma-sep UIDs)}], pamResources:[{controllerUid,folderUid,resourceRef (comma-sep UIDs)}]",
									"items":       map[string]interface{}{"type": "string"},
									"minItems":    1,
									"maxItems":    1,
								},
							},
							"required": []string{"type", "value"},
						},
					},
					"notes": map[string]interface{}{
						"type":        "string",
						"description": "(Optional) New notes for the secret. If provided, this will replace existing notes.",
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
		{
			Name:        "get_server_version",
			Description: "Get the current version of the KSM MCP server",
			InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
		},
		{
			Name:        "delete_folder",
			Description: "Delete a folder (requires confirmation). Optionally force delete if not empty.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"folder_uid": map[string]interface{}{
						"type":        "string",
						"description": "UID of the folder to delete",
					},
					"force": map[string]interface{}{
						"type":        "boolean",
						"description": "If true, delete the folder even if it is not empty. This is a destructive operation.",
						"default":     false,
					},
				},
				"required": []string{"folder_uid"},
			},
		},
		// New tool for handling confirmed actions
		{
			Name:        "ksm_execute_confirmed_action",
			Description: "Executes an action that has been previously confirmed by the user via a prompt.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"original_tool_name": map[string]interface{}{
						"type":        "string",
						"description": "The name of the original tool that required confirmation (e.g., 'create_secret').",
					},
					"original_tool_args_json": map[string]interface{}{
						"type":        "string",
						"description": "The JSON string of arguments originally passed to the tool.",
					},
					"user_decision": map[string]interface{}{
						"type":        "boolean",
						"description": "User's decision: true if approved, false if denied.",
					},
					"confirmation_context": map[string]interface{}{
						"type":        "string",
						"description": "Optional context from the confirmation prompt.",
						"nullable":    true,
					},
				},
				"required": []string{"original_tool_name", "original_tool_args_json", "user_decision"},
			},
		},
		{
			Name:        "get_all_secrets_unmasked",
			Description: "Get all secrets with complete unmasked data (passwords, custom fields, etc.) in a single operation (requires confirmation)",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"folder_uid": map[string]interface{}{
						"type":        "string",
						"description": "Optional: Filter by folder UID",
					},
					"fields": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Fields to retrieve for each secret (default: all fields including passwords, login, URL, notes, custom fields)",
					},
				},
			},
		},
		{
			Name:        "get_record_type_schema",
			Description: "Get the schema for a specific KSM record type, detailing all its fields, sub-fields, types, and if they are required. Use this to understand how to structure a create_secret or update_secret call.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"type": map[string]interface{}{
						"type":        "string",
						"description": "The KSM record type name (e.g., bankAccount, pamMachine, login).",
					},
				},
				"required": []string{"type"},
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
	s.logSystem(audit.EventAccess, "Tool called", map[string]interface{}{
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
		// Health check doesn't strictly need a KSM client, but other tools might.
		// We pass nil for now as handleHealthCheck might not use it.
		// If other execute handlers require a client, this dispatch needs to fetch it.
		return s.handleHealthCheck(context.Background(), args)
	case "get_server_version":
		// GetServerVersion does not need a KSM client.
		// The executeGetServerVersion handler expects one for signature consistency.
		// We can pass nil as it won't be used.
		client, _ := s.getCurrentClient() // Get client, ignore error for this specific case or handle if critical
		return s.executeGetServerVersion(client, args)
	case "delete_folder":
		return s.executeDeleteFolder(client, args)
	case "ksm_execute_confirmed_action":
		return s.executeKsmExecuteConfirmedAction(args)
	case "get_all_secrets_unmasked":
		return s.executeGetAllSecretsUnmasked(client, args)
	case "get_record_type_schema":
		return s.executeGetRecordTypeSchema(client, args)

	default:
		return nil, fmt.Errorf("unknown tool: %s", toolName)
	}
}

// New handler for ksm_execute_confirmed_action
func (s *Server) executeKsmExecuteConfirmedAction(args json.RawMessage) (interface{}, error) {
	var params struct {
		OriginalToolName     string `json:"original_tool_name"`
		OriginalToolArgsJSON string `json:"original_tool_args_json"`
		UserDecision         bool   `json:"user_decision"`
		ConfirmationContext  string `json:"confirmation_context,omitempty"`
	}

	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters for ksm_execute_confirmed_action: %w", err)
	}

	s.logSystem(audit.EventAccess, "ksm_execute_confirmed_action called", map[string]interface{}{
		"original_tool": params.OriginalToolName,
		"decision":      params.UserDecision,
		"profile":       s.currentProfile,
	})

	if !params.UserDecision {
		return map[string]interface{}{"status": "operation_denied", "message": "User denied the operation."}, nil
	}

	// Get current client - this might be redundant if the client is passed around or re-fetched in actual tool handlers
	client, err := s.getCurrentClient()
	if err != nil {
		return nil, fmt.Errorf("no active session for confirmed action: %w", err)
	}

	// Convert JSON string args back to json.RawMessage for the original tool
	var originalToolArgs json.RawMessage
	if params.OriginalToolArgsJSON != "" {
		originalToolArgs = json.RawMessage(params.OriginalToolArgsJSON)
	} else {
		originalToolArgs = json.RawMessage("{}") // Empty JSON object if no args
	}

	// IMPORTANT: The actual execution logic for each tool needs to be refactored
	// so it can be called here *without* its own confirmation step.
	// This is a placeholder for that dispatch logic.
	switch params.OriginalToolName {
	case "create_secret":
		// Call a refactored version: e.g., s.executeCreateSecretInternal(client, originalToolArgs, true /*isConfirmed*/)
		return s.executeCreateSecretConfirmed(client, originalToolArgs)
	case "get_secret": // Assuming this is for unmasking
		// Call a refactored version: e.g., s.executeGetSecretInternal(client, originalToolArgs, true /*isConfirmed*/)
		return s.executeGetSecretConfirmed(client, originalToolArgs)
	case "update_secret":
		return s.executeUpdateSecretConfirmed(client, originalToolArgs)
	case "delete_secret":
		return s.executeDeleteSecretConfirmed(client, originalToolArgs)
	case "upload_file":
		return s.executeUploadFileConfirmed(client, originalToolArgs)
	case "download_file":
		return s.executeDownloadFileConfirmed(client, originalToolArgs)
	case "create_folder":
		return s.executeCreateFolderConfirmed(client, originalToolArgs)
	case "delete_folder":
		return s.executeDeleteFolderConfirmed(client, originalToolArgs)
	case "get_all_secrets_unmasked":
		return s.executeGetAllSecretsUnmaskedConfirmed(client, originalToolArgs)

	// Add other sensitive tools here
	default:
		return nil, fmt.Errorf("cannot execute unhandled confirmed original tool: %s", params.OriginalToolName)
	}
}
