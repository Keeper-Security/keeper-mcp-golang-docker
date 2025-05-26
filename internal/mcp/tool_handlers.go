package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/keeper-security/ksm-mcp/internal/audit"
	"github.com/keeper-security/ksm-mcp/pkg/types"
)

// Phase 1 Tool Implementations

// executeListSecrets handles the list_secrets tool
func (s *Server) executeListSecrets(client KSMClient, args json.RawMessage) (interface{}, error) {
	var params struct {
		FolderUID string `json:"folder_uid,omitempty"`
	}

	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}

	secrets, err := client.ListSecrets(params.FolderUID)
	if err != nil {
		return nil, err
	}

	// Enhance output to always include UIDs
	enhancedSecrets := make([]map[string]interface{}, len(secrets))
	for i, secret := range secrets {
		enhancedSecrets[i] = map[string]interface{}{
			"uid":    secret.UID,
			"title":  secret.Title,
			"type":   secret.Type,
			"folder": secret.Folder,
			// TODO: Add created/modified dates when KSM SDK exposes them
			// The SDK has CreatedDate field but it's not exposed via public methods
		}
	}

	return map[string]interface{}{
		"secrets": enhancedSecrets,
		"count":   len(secrets),
	}, nil
}

// executeGetSecret handles the get_secret tool
func (s *Server) executeGetSecret(client KSMClient, args json.RawMessage) (interface{}, error) {
	var params struct {
		UID    string   `json:"uid"`
		Fields []string `json:"fields,omitempty"`
		Unmask bool     `json:"unmask,omitempty"`
	}

	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters for get_secret: %w", err)
	}

	if !params.Unmask || s.options.BatchMode || s.options.AutoApprove {
		if params.Unmask {
			s.logger.LogSystem(audit.EventAccess, "GetSecret (Unmask): Batch/AutoApprove mode, executing directly", map[string]interface{}{
				"profile": s.currentProfile,
				"uid":     params.UID,
			})
			return s.executeGetSecretConfirmed(client, args)
		} else {
			s.logger.LogSystem(audit.EventAccess, "GetSecret (Masked): Executing directly", map[string]interface{}{
				"profile": s.currentProfile,
				"uid":     params.UID,
			})
			secret, err := client.GetSecret(params.UID, params.Fields, false)
			if err != nil {
				return nil, err
			}
			return secret, nil
		}
	}

	// Confirmation is required for unmasking
	// Attempt to get secret title for a more descriptive message, ignore error if not found
	secretTitle := params.UID                                    // Default to UID if title can't be fetched
	meta, err := client.GetSecret(params.UID, []string{}, false) // Get metadata (title) without unmasking
	if err == nil {
		if title, ok := meta["title"].(string); ok && title != "" {
			secretTitle = fmt.Sprintf("'%s' (UID: %s)", title, params.UID)
		}
	}

	actionDescription := fmt.Sprintf("Reveal unmasked secret %s", secretTitle)
	warningMessage := "This will expose all requested fields of the secret, including the password if present, directly TO THE AI MODEL and its context. This information could be logged or stored by the AI service."
	originalToolArgsJSON := string(args)

	confirmationDetails := map[string]interface{}{
		"prompt_name": "ksm_confirm_action",
		"prompt_arguments": map[string]interface{}{
			"action_description":      actionDescription,
			"warning_message":         warningMessage,
			"original_tool_name":      "get_secret",
			"original_tool_args_json": originalToolArgsJSON,
		},
	}

	s.logger.LogSystem(audit.EventAccess, "GetSecret (Unmask): Confirmation required", map[string]interface{}{
		"profile": s.currentProfile,
		"uid":     params.UID,
	})

	return map[string]interface{}{
		"status":               "confirmation_required",
		"message":              fmt.Sprintf("Confirmation required to %s. Use the 'ksm_confirm_action' prompt.", actionDescription),
		"confirmation_details": confirmationDetails,
	}, nil
}

// executeSearchSecrets handles the search_secrets tool
func (s *Server) executeSearchSecrets(client KSMClient, args json.RawMessage) (interface{}, error) {
	var params struct {
		Query string `json:"query"`
	}

	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}

	results, err := client.SearchSecrets(params.Query)
	if err != nil {
		return nil, err
	}

	// Enhance output to always include UIDs
	enhancedResults := make([]map[string]interface{}, len(results))
	for i, result := range results {
		enhancedResults[i] = map[string]interface{}{
			"uid":    result.UID,
			"title":  result.Title,
			"type":   result.Type,
			"folder": result.Folder,
		}
	}

	return map[string]interface{}{
		"results": enhancedResults,
		"count":   len(results),
	}, nil
}

// executeGetField handles the get_field tool
func (s *Server) executeGetField(client KSMClient, args json.RawMessage) (interface{}, error) {
	var params struct {
		Notation string `json:"notation"`
		Unmask   bool   `json:"unmask,omitempty"`
	}

	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}

	// Confirm if unmasking
	if params.Unmask {
		ctx := context.Background()
		result := s.confirmer.Confirm(ctx, fmt.Sprintf("Reveal unmasked field %s?", params.Notation))
		if result.Error != nil {
			return nil, fmt.Errorf("confirmation failed: %w", result.Error)
		}
		if !result.Approved {
			return nil, fmt.Errorf("operation cancelled by user")
		}
	}

	value, err := client.GetField(params.Notation, params.Unmask)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"value":    value,
		"notation": params.Notation,
	}, nil
}

// executeGeneratePassword handles the generate_password tool
func (s *Server) executeGeneratePassword(client KSMClient, args json.RawMessage) (interface{}, error) {
	var params types.GeneratePasswordParams

	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}

	// Check if save_to_secret is specified
	if params.SaveToSecret != "" {
		// Generate password
		password, err := client.GeneratePassword(params)
		if err != nil {
			return nil, err
		}

		// Create or update the secret with the generated password
		secretParams := types.CreateSecretParams{
			Title: params.SaveToSecret,
			Type:  "login",
			Fields: []types.SecretField{
				{
					Type:  "password",
					Value: []interface{}{password},
				},
			},
		}

		// Try to create the secret
		uid, err := client.CreateSecret(secretParams)
		if err != nil {
			// If creation fails, it might already exist - try updating
			// First, search for the secret
			results, searchErr := client.SearchSecrets(params.SaveToSecret)
			if searchErr != nil {
				return nil, fmt.Errorf("failed to save password: %w", err)
			}

			if len(results) > 0 {
				// Update existing secret
				updateParams := types.UpdateSecretParams{
					UID: results[0].UID,
					Fields: []types.SecretField{
						{
							Type:  "password",
							Value: []interface{}{password},
						},
					},
				}
				if updateErr := client.UpdateSecret(updateParams); err != nil {
					return nil, fmt.Errorf("failed to update secret with password: %w", updateErr)
				}
				uid = results[0].UID
			} else {
				return nil, fmt.Errorf("failed to save password: %w", err)
			}
		}

		// Return confirmation without exposing the password
		return map[string]interface{}{
			"message": fmt.Sprintf("Password generated and saved to secret '%s' (UID: %s)", params.SaveToSecret, uid),
			"uid":     uid,
			"length":  params.Length,
		}, nil
	}

	// Standard behavior - return password (with warning this exposes to AI)
	password, err := client.GeneratePassword(params)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"password": password,
		"length":   len(password),
		"warning":  "Password is exposed to AI model. Consider using save_to_secret parameter.",
	}, nil
}

// executeGetTOTPCode handles the get_totp_code tool
func (s *Server) executeGetTOTPCode(client KSMClient, args json.RawMessage) (interface{}, error) {
	var params struct {
		UID string `json:"uid"`
	}

	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}

	totp, err := client.GetTOTPCode(params.UID)
	if err != nil {
		return nil, err
	}

	return totp, nil
}

// Phase 2 Tool Implementations

// executeCreateSecret handles the create_secret tool
func (s *Server) executeCreateSecret(client KSMClient, args json.RawMessage) (interface{}, error) {
	// For batch or auto-approve mode, the new ksm_execute_confirmed_action tool will handle it directly.
	// So, if we are here, it means interactive confirmation *would* have been needed.
	// We now return a structured response indicating confirmation is required via a prompt.

	// First, parse the arguments to get necessary details for the confirmation message,
	// like the title. We don't need the full KSMClient here yet.
	var paramsForDesc types.CreateSecretParams // Use the existing struct for easy parsing of title, etc.
	if err := json.Unmarshal(args, &paramsForDesc); err != nil {
		// If basic parsing fails, it's an invalid request anyway.
		return nil, fmt.Errorf("invalid parameters for create_secret: %w", err)
	}

	// Check if server is in batch or auto-approve mode via its options
	if s.options.BatchMode || s.options.AutoApprove {
		// If in batch or auto-approve, proceed to execute directly.
		// This reuses the logic now in executeCreateSecretConfirmed.
		// This path assumes the AI client understands not to expect a prompt workflow
		// if the server is in batch/auto-approve (though ideally, client checks server capabilities).
		// Alternatively, even in batch mode, we could return the prompt structure,
		// and ksm_execute_confirmed_action would respect batch mode from its call.
		// For simplicity now: direct execution if batch/auto-approve.
		s.logger.LogSystem(audit.EventAccess, "CreateSecret: Batch/AutoApprove mode, executing directly", map[string]interface{}{
			"profile": s.currentProfile,
			"title":   paramsForDesc.Title,
		})
		return s.executeCreateSecretConfirmed(client, args)
	}

	actionDescription := fmt.Sprintf("Create new KSM secret titled '%s' of type '%s'", paramsForDesc.Title, paramsForDesc.Type)
	warningMessage := "This will create a new entry in your Keeper vault."

	originalToolArgsJSON := string(args)

	confirmationDetails := map[string]interface{}{
		"prompt_name": "ksm_confirm_action",
		"prompt_arguments": map[string]interface{}{
			"action_description":      actionDescription,
			"warning_message":         warningMessage,
			"original_tool_name":      "create_secret",
			"original_tool_args_json": originalToolArgsJSON,
		},
	}

	s.logger.LogSystem(audit.EventAccess, "CreateSecret: Confirmation required", map[string]interface{}{
		"profile": s.currentProfile,
		"title":   paramsForDesc.Title,
	})

	return map[string]interface{}{
		"status":               "confirmation_required",
		"message":              fmt.Sprintf("Confirmation required to %s. Use the 'ksm_confirm_action' prompt.", actionDescription),
		"confirmation_details": confirmationDetails,
	}, nil
}

// executeUpdateSecret handles the update_secret tool
func (s *Server) executeUpdateSecret(client KSMClient, args json.RawMessage) (interface{}, error) {
	var paramsForDesc types.UpdateSecretParams // Use for parsing UID for messages
	if err := json.Unmarshal(args, &paramsForDesc); err != nil {
		return nil, fmt.Errorf("invalid parameters for update_secret: %w", err)
	}

	if s.options.BatchMode || s.options.AutoApprove {
		s.logger.LogSystem(audit.EventAccess, "UpdateSecret: Batch/AutoApprove mode, executing directly", map[string]interface{}{
			"profile": s.currentProfile,
			"uid":     paramsForDesc.UID,
		})
		return s.executeUpdateSecretConfirmed(client, args)
	}

	actionDescription := fmt.Sprintf("Update KSM secret (UID: %s)", paramsForDesc.UID)
	if paramsForDesc.Title != "" {
		actionDescription = fmt.Sprintf("Update KSM secret '%s' (UID: %s)", paramsForDesc.Title, paramsForDesc.UID)
	}
	warningMessage := "This will modify an existing entry in your Keeper vault."
	originalToolArgsJSON := string(args)

	confirmationDetails := map[string]interface{}{
		"prompt_name": "ksm_confirm_action",
		"prompt_arguments": map[string]interface{}{
			"action_description":      actionDescription,
			"warning_message":         warningMessage,
			"original_tool_name":      "update_secret",
			"original_tool_args_json": originalToolArgsJSON,
		},
	}

	s.logger.LogSystem(audit.EventAccess, "UpdateSecret: Confirmation required", map[string]interface{}{
		"profile": s.currentProfile,
		"uid":     paramsForDesc.UID,
	})

	return map[string]interface{}{
		"status":               "confirmation_required",
		"message":              fmt.Sprintf("Confirmation required to %s. Use the 'ksm_confirm_action' prompt.", actionDescription),
		"confirmation_details": confirmationDetails,
	}, nil
}

// executeDeleteSecret handles the delete_secret tool
func (s *Server) executeDeleteSecret(client KSMClient, args json.RawMessage) (interface{}, error) {
	var paramsForDesc struct { // Use for parsing UID for messages
		UID string `json:"uid"`
	}
	if err := json.Unmarshal(args, &paramsForDesc); err != nil {
		return nil, fmt.Errorf("invalid parameters for delete_secret: %w", err)
	}

	if s.options.BatchMode || s.options.AutoApprove {
		s.logger.LogSystem(audit.EventAccess, "DeleteSecret: Batch/AutoApprove mode, executing directly", map[string]interface{}{
			"profile": s.currentProfile,
			"uid":     paramsForDesc.UID,
		})
		return s.executeDeleteSecretConfirmed(client, args)
	}

	actionDescription := fmt.Sprintf("Permanently delete KSM secret (UID: %s)", paramsForDesc.UID)
	warningMessage := "This action CANNOT BE UNDONE. The secret will be permanently removed from your Keeper vault."
	originalToolArgsJSON := string(args)

	confirmationDetails := map[string]interface{}{
		"prompt_name": "ksm_confirm_action",
		"prompt_arguments": map[string]interface{}{
			"action_description":      actionDescription,
			"warning_message":         warningMessage,
			"original_tool_name":      "delete_secret",
			"original_tool_args_json": originalToolArgsJSON,
		},
	}

	s.logger.LogSystem(audit.EventAccess, "DeleteSecret: Confirmation required", map[string]interface{}{
		"profile": s.currentProfile,
		"uid":     paramsForDesc.UID,
	})

	return map[string]interface{}{
		"status":               "confirmation_required",
		"message":              fmt.Sprintf("Confirmation required to %s. Use the 'ksm_confirm_action' prompt.", actionDescription),
		"confirmation_details": confirmationDetails,
	}, nil
}

// executeUploadFile handles the upload_file tool
func (s *Server) executeUploadFile(client KSMClient, args json.RawMessage) (interface{}, error) {
	var paramsForDesc struct { // Use for parsing details for messages
		UID      string `json:"uid"`
		FilePath string `json:"file_path"`
		Title    string `json:"title"`
	}
	if err := json.Unmarshal(args, &paramsForDesc); err != nil {
		return nil, fmt.Errorf("invalid parameters for upload_file: %w", err)
	}

	if s.options.BatchMode || s.options.AutoApprove {
		s.logger.LogSystem(audit.EventAccess, "UploadFile: Batch/AutoApprove mode, executing directly", map[string]interface{}{
			"profile": s.currentProfile,
			"uid":     paramsForDesc.UID,
			"file":    paramsForDesc.Title,
		})
		return s.executeUploadFileConfirmed(client, args)
	}

	actionDescription := fmt.Sprintf("Upload file '%s' (as title '%s') to KSM secret (UID: %s)", paramsForDesc.FilePath, paramsForDesc.Title, paramsForDesc.UID)
	warningMessage := "This will add a file attachment to an existing secret in your Keeper vault."
	originalToolArgsJSON := string(args)

	confirmationDetails := map[string]interface{}{
		"prompt_name": "ksm_confirm_action",
		"prompt_arguments": map[string]interface{}{
			"action_description":      actionDescription,
			"warning_message":         warningMessage,
			"original_tool_name":      "upload_file",
			"original_tool_args_json": originalToolArgsJSON,
		},
	}

	s.logger.LogSystem(audit.EventAccess, "UploadFile: Confirmation required", map[string]interface{}{
		"profile":  s.currentProfile,
		"uid":      paramsForDesc.UID,
		"filePath": paramsForDesc.FilePath,
	})

	return map[string]interface{}{
		"status":               "confirmation_required",
		"message":              fmt.Sprintf("Confirmation required to %s. Use the 'ksm_confirm_action' prompt.", actionDescription),
		"confirmation_details": confirmationDetails,
	}, nil
}

// executeDownloadFile handles the download_file tool
func (s *Server) executeDownloadFile(client KSMClient, args json.RawMessage) (interface{}, error) {
	var params struct {
		UID      string `json:"uid"`
		FileUID  string `json:"file_uid"`
		SavePath string `json:"save_path,omitempty"`
	}

	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}

	// DownloadFile expects (uid, fileUID, savePath)
	if err := client.DownloadFile(params.UID, params.FileUID, params.SavePath); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"uid":      params.UID,
		"file_uid": params.FileUID,
		"path":     params.SavePath,
		"message":  "File downloaded successfully",
	}, nil
}

// executeListFolders handles the list_folders tool
func (s *Server) executeListFolders(client KSMClient, args json.RawMessage) (interface{}, error) {
	folders, err := client.ListFolders()
	if err != nil {
		return nil, err
	}

	// Ensure UIDs are prominent in output
	return map[string]interface{}{
		"folders": folders.Folders,
		"count":   len(folders.Folders),
	}, nil
}

// executeCreateFolder handles the create_folder tool
func (s *Server) executeCreateFolder(client KSMClient, args json.RawMessage) (interface{}, error) {
	var paramsForDesc struct { // Use for parsing details for messages
		Name      string `json:"name"`
		ParentUID string `json:"parent_uid,omitempty"`
	}
	if err := json.Unmarshal(args, &paramsForDesc); err != nil {
		return nil, fmt.Errorf("invalid parameters for create_folder: %w", err)
	}

	if s.options.BatchMode || s.options.AutoApprove {
		s.logger.LogSystem(audit.EventAccess, "CreateFolder: Batch/AutoApprove mode, executing directly", map[string]interface{}{
			"profile": s.currentProfile,
			"name":    paramsForDesc.Name,
		})
		return s.executeCreateFolderConfirmed(client, args)
	}

	actionDescription := fmt.Sprintf("Create new KSM folder titled '%s'", paramsForDesc.Name)
	if paramsForDesc.ParentUID != "" {
		actionDescription += fmt.Sprintf(" inside folder UID %s", paramsForDesc.ParentUID)
	}
	warningMessage := "This will create a new folder in your Keeper vault."
	originalToolArgsJSON := string(args)

	confirmationDetails := map[string]interface{}{
		"prompt_name": "ksm_confirm_action",
		"prompt_arguments": map[string]interface{}{
			"action_description":      actionDescription,
			"warning_message":         warningMessage,
			"original_tool_name":      "create_folder",
			"original_tool_args_json": originalToolArgsJSON,
		},
	}

	s.logger.LogSystem(audit.EventAccess, "CreateFolder: Confirmation required", map[string]interface{}{
		"profile": s.currentProfile,
		"name":    paramsForDesc.Name,
	})

	return map[string]interface{}{
		"status":               "confirmation_required",
		"message":              fmt.Sprintf("Confirmation required to %s. Use the 'ksm_confirm_action' prompt.", actionDescription),
		"confirmation_details": confirmationDetails,
	}, nil
}
