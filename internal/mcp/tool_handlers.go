package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

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
			s.logSystem(audit.EventAccess, "GetSecret (Unmask): Batch/AutoApprove mode, executing directly", map[string]interface{}{
				"profile": s.currentProfile,
				"uid":     params.UID,
			})
			return s.executeGetSecretConfirmed(client, args)
		} else {
			s.logSystem(audit.EventAccess, "GetSecret (Masked): Executing directly", map[string]interface{}{
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

	secretTitle := params.UID
	meta, err := client.GetSecret(params.UID, []string{}, false)
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

	s.logSystem(audit.EventAccess, "GetSecret (Unmask): Confirmation required", map[string]interface{}{
		"profile": s.currentProfile,
		"uid":     params.UID,
	})

	return map[string]interface{}{
		"status":               "confirmation_required",
		"message":              fmt.Sprintf("Keeper Secrets Manager requires confirmation to %s. Use the 'ksm_confirm_action' prompt.", actionDescription),
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

	if params.SaveToSecret != "" {
		password, err := client.GeneratePassword(params)
		if err != nil {
			return nil, err
		}

		if params.FolderUID == "" {
			return nil, fmt.Errorf("folder_uid is required when using save_to_secret to ensure record is saved to a shared folder")
		}
		folderUID := params.FolderUID

		secretParams := types.CreateSecretParams{
			Title:     params.SaveToSecret,
			Type:      "login",
			FolderUID: folderUID,
			Fields: []types.SecretField{
				{
					Type:  "password",
					Value: []interface{}{password},
				},
			},
		}

		uid, err := client.CreateSecret(secretParams)
		if err != nil {
			results, searchErr := client.SearchSecrets(params.SaveToSecret)
			if searchErr != nil {
				return nil, fmt.Errorf("failed to save password (search failed): %w", err)
			}

			if len(results) > 0 {
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
				return nil, fmt.Errorf("failed to save password (create failed and secret not found to update): %w", err)
			}
		}

		return map[string]interface{}{
			"message": fmt.Sprintf("Password generated and saved to secret '%s' (UID: %s)", params.SaveToSecret, uid),
			"uid":     uid,
			"length":  params.Length,
		}, nil
	}

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

// executeGetAllSecretsUnmasked handles the get_all_secrets_unmasked tool
func (s *Server) executeGetAllSecretsUnmasked(client KSMClient, args json.RawMessage) (interface{}, error) {
	var params struct {
		FolderUID string   `json:"folder_uid,omitempty"`
		Fields    []string `json:"fields,omitempty"`
	}

	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters for get_all_secrets_unmasked: %w", err)
	}

	if s.options.BatchMode || s.options.AutoApprove {
		s.logSystem(audit.EventAccess, "GetAllSecretsUnmasked: Batch/AutoApprove mode, executing directly", map[string]interface{}{
			"profile":    s.currentProfile,
			"folder_uid": params.FolderUID,
		})
		return s.executeGetAllSecretsUnmaskedConfirmed(client, args)
	}

	actionDescription := "Retrieve all secrets with complete unmasked data (passwords, custom fields, etc.)"
	if params.FolderUID != "" {
		actionDescription = fmt.Sprintf("Retrieve all secrets with unmasked data from folder %s", params.FolderUID)
	}
	warningMessage := "This will expose ALL PASSWORDS and sensitive data from your secrets directly TO THE AI MODEL. This is a bulk operation that could expose a large amount of sensitive information."
	originalToolArgsJSON := string(args)

	confirmationDetails := map[string]interface{}{
		"prompt_name": "ksm_confirm_action",
		"prompt_arguments": map[string]interface{}{
			"action_description":      actionDescription,
			"warning_message":         warningMessage,
			"original_tool_name":      "get_all_secrets_unmasked",
			"original_tool_args_json": originalToolArgsJSON,
		},
	}

	s.logSystem(audit.EventAccess, "GetAllSecretsUnmasked: Confirmation required", map[string]interface{}{
		"profile":    s.currentProfile,
		"folder_uid": params.FolderUID,
	})

	return map[string]interface{}{
		"status":               "confirmation_required",
		"message":              fmt.Sprintf("Keeper Secrets Manager requires confirmation to %s. Use the 'ksm_confirm_action' prompt.", actionDescription),
		"confirmation_details": confirmationDetails,
	}, nil
}

// Phase 2 Tool Implementations

// executeCreateSecret handles the create_secret tool
func (s *Server) executeCreateSecret(client KSMClient, args json.RawMessage) (interface{}, error) {
	var paramsForDesc types.CreateSecretParams
	if err := json.Unmarshal(args, &paramsForDesc); err != nil {
		return nil, fmt.Errorf("invalid parameters for create_secret: %w", err)
	}

	if s.options.BatchMode || s.options.AutoApprove {
		s.logSystem(audit.EventAccess, "CreateSecret: Batch/AutoApprove mode, executing directly", map[string]interface{}{
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

	s.logSystem(audit.EventAccess, "CreateSecret: Confirmation required", map[string]interface{}{
		"profile": s.currentProfile,
		"title":   paramsForDesc.Title,
	})

	return map[string]interface{}{
		"status":               "confirmation_required",
		"message":              fmt.Sprintf("Keeper Secrets Manager requires confirmation to %s. Use the 'ksm_confirm_action' prompt.", actionDescription),
		"confirmation_details": confirmationDetails,
	}, nil
}

// executeUpdateSecret handles the update_secret tool
func (s *Server) executeUpdateSecret(client KSMClient, args json.RawMessage) (interface{}, error) {
	var paramsForDesc types.UpdateSecretParams
	if err := json.Unmarshal(args, &paramsForDesc); err != nil {
		return nil, fmt.Errorf("invalid parameters for update_secret: %w", err)
	}

	if s.options.BatchMode || s.options.AutoApprove {
		s.logSystem(audit.EventAccess, "UpdateSecret: Batch/AutoApprove mode, executing directly", map[string]interface{}{
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

	s.logSystem(audit.EventAccess, "UpdateSecret: Confirmation required", map[string]interface{}{
		"profile": s.currentProfile,
		"uid":     paramsForDesc.UID,
	})

	return map[string]interface{}{
		"status":               "confirmation_required",
		"message":              fmt.Sprintf("Keeper Secrets Manager requires confirmation to %s. Use the 'ksm_confirm_action' prompt.", actionDescription),
		"confirmation_details": confirmationDetails,
	}, nil
}

// executeDeleteSecret handles the delete_secret tool
func (s *Server) executeDeleteSecret(client KSMClient, args json.RawMessage) (interface{}, error) {
	var paramsForDesc struct {
		UID string `json:"uid"`
	}
	if err := json.Unmarshal(args, &paramsForDesc); err != nil {
		return nil, fmt.Errorf("invalid parameters for delete_secret: %w", err)
	}

	if s.options.BatchMode || s.options.AutoApprove {
		s.logSystem(audit.EventAccess, "DeleteSecret: Batch/AutoApprove mode, executing directly", map[string]interface{}{
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

	s.logSystem(audit.EventAccess, "DeleteSecret: Confirmation required", map[string]interface{}{
		"profile": s.currentProfile,
		"uid":     paramsForDesc.UID,
	})

	return map[string]interface{}{
		"status":               "confirmation_required",
		"message":              fmt.Sprintf("Keeper Secrets Manager requires confirmation to %s. Use the 'ksm_confirm_action' prompt.", actionDescription),
		"confirmation_details": confirmationDetails,
	}, nil
}

// executeUploadFile handles the upload_file tool
func (s *Server) executeUploadFile(client KSMClient, args json.RawMessage) (interface{}, error) {
	var paramsForDesc struct {
		UID      string `json:"uid"`
		FilePath string `json:"file_path"`
		Title    string `json:"title"`
	}
	if err := json.Unmarshal(args, &paramsForDesc); err != nil {
		return nil, fmt.Errorf("invalid parameters for upload_file: %w", err)
	}

	if s.options.BatchMode || s.options.AutoApprove {
		s.logSystem(audit.EventAccess, "UploadFile: Batch/AutoApprove mode, executing directly", map[string]interface{}{
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

	s.logSystem(audit.EventAccess, "UploadFile: Confirmation required", map[string]interface{}{
		"profile":  s.currentProfile,
		"uid":      paramsForDesc.UID,
		"filePath": paramsForDesc.FilePath,
	})

	return map[string]interface{}{
		"status":               "confirmation_required",
		"message":              fmt.Sprintf("Keeper Secrets Manager requires confirmation to %s. Use the 'ksm_confirm_action' prompt.", actionDescription),
		"confirmation_details": confirmationDetails,
	}, nil
}

// executeDownloadFile handles the download_file tool
func (s *Server) executeDownloadFile(client KSMClient, args json.RawMessage) (interface{}, error) {
	var paramsForDesc struct {
		UID      string `json:"uid"`
		FileUID  string `json:"file_uid"`
		SavePath string `json:"save_path,omitempty"`
	}
	if err := json.Unmarshal(args, &paramsForDesc); err != nil {
		return nil, fmt.Errorf("invalid parameters for download_file: %w", err)
	}

	if s.options.BatchMode || s.options.AutoApprove {
		s.logSystem(audit.EventAccess, "DownloadFile: Batch/AutoApprove mode, executing directly", map[string]interface{}{
			"profile":  s.currentProfile,
			"uid":      paramsForDesc.UID,
			"file_uid": paramsForDesc.FileUID,
		})
		return s.executeDownloadFileConfirmed(client, args)
	}

	actionDescription := fmt.Sprintf("Download file '%s' from KSM secret (UID: %s)", paramsForDesc.FileUID, paramsForDesc.UID)
	if paramsForDesc.SavePath != "" {
		actionDescription += fmt.Sprintf(" to '%s'", paramsForDesc.SavePath)
	}
	warningMessage := "This will download a file from your Keeper vault to your local system."
	originalToolArgsJSON := string(args)

	confirmationDetails := map[string]interface{}{
		"prompt_name": "ksm_confirm_action",
		"prompt_arguments": map[string]interface{}{
			"action_description":      actionDescription,
			"warning_message":         warningMessage,
			"original_tool_name":      "download_file",
			"original_tool_args_json": originalToolArgsJSON,
		},
	}

	s.logSystem(audit.EventAccess, "DownloadFile: Confirmation required", map[string]interface{}{
		"profile":  s.currentProfile,
		"uid":      paramsForDesc.UID,
		"file_uid": paramsForDesc.FileUID,
	})

	return map[string]interface{}{
		"status":               "confirmation_required",
		"message":              fmt.Sprintf("Keeper Secrets Manager requires confirmation to %s. Use the 'ksm_confirm_action' prompt.", actionDescription),
		"confirmation_details": confirmationDetails,
	}, nil
}

// executeListFolders handles the list_folders tool
func (s *Server) executeListFolders(client KSMClient, args json.RawMessage) (interface{}, error) {
	folders, err := client.ListFolders()
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"folders": folders.Folders,
		"count":   len(folders.Folders),
	}, nil
}

// executeCreateFolder handles the create_folder tool
func (s *Server) executeCreateFolder(client KSMClient, args json.RawMessage) (interface{}, error) {
	var paramsForDesc struct {
		Name      string `json:"name"`
		ParentUID string `json:"parent_uid,omitempty"`
	}
	if err := json.Unmarshal(args, &paramsForDesc); err != nil {
		return nil, fmt.Errorf("invalid parameters for create_folder: %w", err)
	}

	if s.options.BatchMode || s.options.AutoApprove {
		s.logSystem(audit.EventAccess, "CreateFolder: Batch/AutoApprove mode, executing directly", map[string]interface{}{
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

	s.logSystem(audit.EventAccess, "CreateFolder: Confirmation required", map[string]interface{}{
		"profile": s.currentProfile,
		"name":    paramsForDesc.Name,
	})

	return map[string]interface{}{
		"status":               "confirmation_required",
		"message":              fmt.Sprintf("Keeper Secrets Manager requires confirmation to %s. Use the 'ksm_confirm_action' prompt.", actionDescription),
		"confirmation_details": confirmationDetails,
	}, nil
}

// executeGetServerVersion handles the get_server_version tool
func (s *Server) executeGetServerVersion(client KSMClient, args json.RawMessage) (interface{}, error) {
	if s.options == nil || s.options.Version == "" {
		return map[string]interface{}{"version": "unknown"}, nil
	}
	return map[string]interface{}{"version": s.options.Version}, nil
}

// Confirmed action handlers
func (s *Server) executeCreateSecretConfirmed(client KSMClient, args json.RawMessage) (interface{}, error) {
	var params types.CreateSecretParams
	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters for confirmed create_secret: %w", err)
	}

	// Validate and warn about multiple values in standard fields
	standardFields := map[string]bool{
		"password":      true,
		"login":         true,
		"email":         true,
		"oneTimeCode":   true,
		"licenseNumber": true,
		"accountNumber": true,
		"pinCode":       true,
		"securityCode":  true,
		"cardNumber":    true,
		"routingNumber": true,
	}

	// Fields that require complex structures (arrays with maps) should be excluded
	complexFields := map[string]bool{
		"securityQuestion": true, // Requires [{question: "", answer: ""}]
		"paymentCard":      true, // Requires complex structure
		"address":          true, // Requires complex structure
		"phone":            true, // Requires complex structure
		"bankAccount":      true, // Requires complex structure
		"keyPair":          true, // Requires complex structure
		"host":             true, // Can be complex
		"name":             true, // Can be complex
		"pamHostname":      true, // Complex structure
		"pamResources":     true, // Complex structure
		"script":           true, // Complex structure
		"passkey":          true, // Complex structure
	}

	var warnings []string
	for i := range params.Fields {
		field := &params.Fields[i]
		// Skip complex fields that need structured data
		if complexFields[field.Type] {
			continue
		}

		if standardFields[field.Type] && len(field.Value) > 1 {
			warnings = append(warnings, fmt.Sprintf("Field '%s' has %d values but standard practice is to use only one value", field.Type, len(field.Value)))
			// Keep only the first value for standard fields
			field.Value = field.Value[:1]
		}
	}

	uid, err := client.CreateSecret(params)
	if err != nil {
		if strings.Contains(err.Error(), "folder uid=") && strings.Contains(err.Error(), "was not retrieved") {
			originalErrMessage := err.Error() // Capture original KSM error message part

			if params.FolderUID == "" {
				// Case 1: No folder_uid was provided in the initial request
				s.logSystem(audit.EventAccess, "CreateSecret: No folder_uid provided. Requesting clarification.", map[string]interface{}{
					"profile": s.currentProfile,
					"title":   params.Title,
				})
				allFolders, listFoldersErr := client.ListFolders()
				if listFoldersErr != nil {
					s.logError("mcp", listFoldersErr, map[string]interface{}{
						"operation": "executeCreateSecretConfirmed_listFolders_for_clarification",
						"profile":   s.currentProfile,
					})
					// Fallback to a generic error if we can't even list folders
					return nil, fmt.Errorf("failed to create secret (KSM error: %s). A folder is required. Additionally, failed to retrieve folder list: %w", originalErrMessage, listFoldersErr)
				}

				var candidateFolders []types.FolderInfo
				if allFolders != nil {
					for _, f := range allFolders.Folders {
						if f.ParentUID == "" {
							candidateFolders = append(candidateFolders, f)
						}
					}
					if len(candidateFolders) == 0 && len(allFolders.Folders) > 0 {
						s.logSystem(audit.EventAccess, "CreateSecret: No top-level folders found, preparing all folders for selection suggestion.", map[string]interface{}{})
						candidateFolders = allFolders.Folders // Use all folders if no top-level ones specifically
					}
				}

				clarificationMessage := fmt.Sprintf("Failed to create secret '%s' (KSM error: %s). No folder was specified.", params.Title, originalErrMessage)

				switch len(candidateFolders) {
				case 0:
					clarificationMessage += " No folders are available to create the secret in. Please create a folder first."
				case 1:
					f := candidateFolders[0]
					clarificationMessage += fmt.Sprintf(" The only available folder is '%s' (UID: %s). Would you like to use this folder?", f.Name, f.UID)
				case 2, 3, 4, 5: // List a few folders directly in the message
					var folderStrings []string
					for _, f := range candidateFolders {
						folderStrings = append(folderStrings, fmt.Sprintf("'%s' (UID: %s)", f.Name, f.UID))
					}
					clarificationMessage += fmt.Sprintf(" Please choose from the following folders: %s.", strings.Join(folderStrings, ", "))
				default: // More than 5 folders
					clarificationMessage += " Please choose a folder. Refer to the 'available_folders' list for names and UIDs."
				}

				return map[string]interface{}{
					"status":                  "folder_required_clarification",
					"message":                 clarificationMessage,
					"available_folders":       candidateFolders,
					"original_tool_args_json": string(args),
				}, nil

			} else {
				// Case 2: A specific folder_uid was provided, but it's likely empty (existing logic)
				s.logSystem(audit.EventAccess, fmt.Sprintf("CreateSecret: Target folder %s empty or invalid, attempting to find suitable parent.", params.FolderUID), map[string]interface{}{
					"profile":       s.currentProfile,
					"title":         params.Title,
					"target_folder": params.FolderUID,
				})

				allFolders, listFoldersErr := client.ListFolders()
				if listFoldersErr != nil {
					s.logError("mcp", listFoldersErr, map[string]interface{}{
						"operation": "executeCreateSecretConfirmed_listFolders_for_parent_check",
						"profile":   s.currentProfile,
					})
					// Fall through to original error if we can't list folders for parent check
				} else {
					var currentFolderInfo *types.FolderInfo
					for _, f := range allFolders.Folders {
						if f.UID == params.FolderUID {
							tempF := f
							currentFolderInfo = &tempF
							break
						}
					}

					if currentFolderInfo != nil && currentFolderInfo.ParentUID != "" {
						var parentFolderInfo *types.FolderInfo
						for _, f := range allFolders.Folders {
							if f.UID == currentFolderInfo.ParentUID {
								tempF := f
								parentFolderInfo = &tempF
								break
							}
						}

						if parentFolderInfo != nil {
							parentSecrets, listSecretsErr := client.ListSecrets(parentFolderInfo.UID)
							if listSecretsErr != nil {
								s.logError("mcp", listSecretsErr, map[string]interface{}{
									"operation":     "executeCreateSecretConfirmed_listSecrets_parent",
									"profile":       s.currentProfile,
									"parent_folder": parentFolderInfo.UID,
								})
								// Fall through to original error
							} else if len(parentSecrets) > 0 {
								s.logSystem(audit.EventAccess, fmt.Sprintf("CreateSecret: Recommending parent folder %s for secret %s", parentFolderInfo.UID, params.Title), map[string]interface{}{
									"profile":                 s.currentProfile,
									"title":                   params.Title,
									"original_folder_uid":     params.FolderUID,
									"recommended_folder_uid":  parentFolderInfo.UID,
									"recommended_folder_name": parentFolderInfo.Name,
								})
								return map[string]interface{}{
									"status":                  "parent_folder_recommended",
									"message":                 fmt.Sprintf("The target folder '%s' (UID: %s) is empty or cannot be directly used for new records. It's recommended to use the parent shared folder '%s' (UID: %s) which contains existing records.", currentFolderInfo.Name, params.FolderUID, parentFolderInfo.Name, parentFolderInfo.UID),
									"original_folder_uid":     params.FolderUID,
									"original_folder_name":    currentFolderInfo.Name,
									"recommended_folder_uid":  parentFolderInfo.UID,
									"recommended_folder_name": parentFolderInfo.Name,
									"original_tool_args_json": string(args),
								}, nil
							} else {
								s.logSystem(audit.EventAccess, fmt.Sprintf("CreateSecret: Parent folder %s (for target %s) is also empty or unsuitable.", parentFolderInfo.UID, params.FolderUID), map[string]interface{}{"profile": s.currentProfile})
							}
						}
					}
				}
				// Fallback for Case 2: if no suitable parent found or other issue with the specified folder
				return nil, fmt.Errorf("failed to create secret '%s' in folder '%s' (KSM error: %s). Hint: This can occur if the target shared folder is empty or not properly initialized for API record creation. Please ensure at least one record exists in the folder, or try its parent folder if applicable.", params.Title, params.FolderUID, originalErrMessage)
			}
		}
		// Generic KSM error not related to "folder uid was not retrieved"
		return nil, fmt.Errorf("failed to create secret '%s': %w", params.Title, err)
	}
	// Success
	response := map[string]interface{}{
		"uid":     uid,
		"title":   params.Title,
		"message": "Secret created successfully (confirmed).",
	}

	// Add warnings if any
	if len(warnings) > 0 {
		response["warnings"] = warnings
		response["message"] = "Secret created successfully (confirmed). Note: Multiple values were provided for standard fields but only the first value was used."
	}

	return response, nil
}

func (s *Server) executeGetSecretConfirmed(client KSMClient, args json.RawMessage) (interface{}, error) {
	var params struct {
		UID    string   `json:"uid"`
		Fields []string `json:"fields,omitempty"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters for confirmed get_secret: %w", err)
	}
	s.logSystem(audit.EventAccess, "GetSecret (Unmask): Executing confirmed/batched action", map[string]interface{}{
		"profile": s.currentProfile,
		"uid":     params.UID,
	})
	secret, err := client.GetSecret(params.UID, params.Fields, true) // unmask is explicitly true here
	if err != nil {
		return nil, err
	}
	return secret, nil
}

func (s *Server) executeGetAllSecretsUnmaskedConfirmed(client KSMClient, args json.RawMessage) (interface{}, error) {
	var params struct {
		FolderUID string   `json:"folder_uid,omitempty"`
		Fields    []string `json:"fields,omitempty"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters for confirmed get_all_secrets_unmasked: %w", err)
	}

	s.logSystem(audit.EventAccess, "GetAllSecretsUnmasked: Executing confirmed/batched action", map[string]interface{}{
		"profile":    s.currentProfile,
		"folder_uid": params.FolderUID,
	})

	// Get list of secrets first
	secrets, err := client.ListSecrets(params.FolderUID)
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	// Get full details for each secret with passwords unmasked
	var allSecrets []map[string]interface{}
	for _, secretMeta := range secrets {
		secret, err := client.GetSecret(secretMeta.UID, params.Fields, true) // unmask is true
		if err != nil {
			// Log error but continue with other secrets
			s.logError("mcp", err, map[string]interface{}{
				"operation": "get_all_secrets_unmasked",
				"uid":       secretMeta.UID,
				"title":     secretMeta.Title,
			})
			// Add error info to result
			secret = map[string]interface{}{
				"uid":   secretMeta.UID,
				"title": secretMeta.Title,
				"error": fmt.Sprintf("Failed to retrieve: %v", err),
			}
		}
		allSecrets = append(allSecrets, secret)
	}

	return map[string]interface{}{
		"secrets": allSecrets,
		"count":   len(allSecrets),
		"message": fmt.Sprintf("Retrieved %d secrets with complete unmasked data", len(allSecrets)),
	}, nil
}

func (s *Server) executeUpdateSecretConfirmed(client KSMClient, args json.RawMessage) (interface{}, error) {
	var params types.UpdateSecretParams
	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters for confirmed update_secret: %w", err)
	}

	// Validate and warn about multiple values in standard fields
	standardFields := map[string]bool{
		"password":      true,
		"login":         true,
		"email":         true,
		"oneTimeCode":   true,
		"licenseNumber": true,
		"accountNumber": true,
		"pinCode":       true,
		"securityCode":  true,
		"cardNumber":    true,
		"routingNumber": true,
	}

	// Fields that require complex structures (arrays with maps) should be excluded
	complexFields := map[string]bool{
		"securityQuestion": true, // Requires [{question: "", answer: ""}]
		"paymentCard":      true, // Requires complex structure
		"address":          true, // Requires complex structure
		"phone":            true, // Requires complex structure
		"bankAccount":      true, // Requires complex structure
		"keyPair":          true, // Requires complex structure
		"host":             true, // Can be complex
		"name":             true, // Can be complex
		"pamHostname":      true, // Complex structure
		"pamResources":     true, // Complex structure
		"script":           true, // Complex structure
		"passkey":          true, // Complex structure
	}

	var warnings []string
	for i := range params.Fields {
		field := &params.Fields[i]
		// Skip complex fields that need structured data
		if complexFields[field.Type] {
			continue
		}

		if standardFields[field.Type] && len(field.Value) > 1 {
			warnings = append(warnings, fmt.Sprintf("Field '%s' has %d values but standard practice is to use only one value", field.Type, len(field.Value)))
			// Keep only the first value for standard fields
			field.Value = field.Value[:1]
		}
	}

	if err := client.UpdateSecret(params); err != nil {
		return nil, err
	}

	response := map[string]interface{}{
		"uid":     params.UID,
		"message": "Secret updated successfully (confirmed).",
	}

	// Add warnings if any
	if len(warnings) > 0 {
		response["warnings"] = warnings
		response["message"] = "Secret updated successfully (confirmed). Note: Multiple values were provided for standard fields but only the first value was used."
	}

	return response, nil
}

func (s *Server) executeDeleteSecretConfirmed(client KSMClient, args json.RawMessage) (interface{}, error) {
	var paramsForDesc struct {
		UID string `json:"uid"`
	}
	if err := json.Unmarshal(args, &paramsForDesc); err != nil {
		return nil, fmt.Errorf("invalid parameters for confirmed delete_secret: %w", err)
	}
	if err := client.DeleteSecret(paramsForDesc.UID, true); err != nil {
		return nil, err
	}
	return map[string]interface{}{"uid": paramsForDesc.UID, "message": "Secret deleted successfully (confirmed)."}, nil
}

func (s *Server) executeUploadFileConfirmed(client KSMClient, args json.RawMessage) (interface{}, error) {
	var paramsForDesc struct {
		UID      string `json:"uid"`
		FilePath string `json:"file_path"`
		Title    string `json:"title"`
	}
	if err := json.Unmarshal(args, &paramsForDesc); err != nil {
		return nil, fmt.Errorf("invalid parameters for confirmed upload_file: %w", err)
	}
	if err := client.UploadFile(paramsForDesc.UID, paramsForDesc.FilePath, paramsForDesc.Title); err != nil {
		return nil, err
	}
	return map[string]interface{}{"uid": paramsForDesc.UID, "file": paramsForDesc.Title, "message": "File uploaded successfully (confirmed)."}, nil
}

func (s *Server) executeDownloadFileConfirmed(client KSMClient, args json.RawMessage) (interface{}, error) {
	var params struct {
		UID      string `json:"uid"`
		FileUID  string `json:"file_uid"`
		SavePath string `json:"save_path,omitempty"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters for confirmed download_file: %w", err)
	}

	s.logSystem(audit.EventAccess, "DownloadFile: Executing confirmed/batched action", map[string]interface{}{
		"profile":  s.currentProfile,
		"uid":      params.UID,
		"file_uid": params.FileUID,
	})

	if err := client.DownloadFile(params.UID, params.FileUID, params.SavePath); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"uid":      params.UID,
		"file_uid": params.FileUID,
		"path":     params.SavePath,
		"message":  "File downloaded successfully (confirmed).",
	}, nil
}

func (s *Server) executeCreateFolderConfirmed(client KSMClient, args json.RawMessage) (interface{}, error) {
	var params struct {
		Name      string `json:"name"`
		ParentUID string `json:"parent_uid,omitempty"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters for confirmed create_folder: %w", err)
	}

	if params.Name == "" {
		return nil, fmt.Errorf("folder name is required")
	}

	// If ParentUID is not provided, guide the AI to select one.
	if params.ParentUID == "" {
		s.logSystem(audit.EventAccess, "CreateFolder: No parent_uid provided. Requesting clarification.", map[string]interface{}{
			"profile": s.currentProfile,
			"name":    params.Name,
		})
		allFoldersResponse, listFoldersErr := client.ListFolders()
		if listFoldersErr != nil {
			s.logError("mcp", listFoldersErr, map[string]interface{}{
				"operation": "executeCreateFolderConfirmed_listFolders_for_parent_clarification",
				"profile":   s.currentProfile,
			})
			// Fallback to a generic error if we can't list folders
			return nil, fmt.Errorf("failed to create folder '%s': a parent_uid is required. Additionally, failed to retrieve folder list to offer suggestions: %w", params.Name, listFoldersErr)
		}

		var suitableParentFolders []types.FolderInfo
		if allFoldersResponse != nil {
			for _, f := range allFoldersResponse.Folders {
				// Heuristic: Top-level folders are potential shared folder targets for new folders.
				// A more robust check for "isShared" might be needed if SDK/API provides it.
				if f.ParentUID == "" {
					suitableParentFolders = append(suitableParentFolders, f)
				}
			}
			if len(suitableParentFolders) == 0 && len(allFoldersResponse.Folders) > 0 {
				// If no top-level, but other folders exist, offer all as potential parents.
				// This might guide user to pick an appropriate shared folder even if nested.
				s.logSystem(audit.EventAccess, "CreateFolder: No top-level folders found, providing all folders as potential parents for selection.", map[string]interface{}{})
				suitableParentFolders = allFoldersResponse.Folders
			}
		}

		clarificationMessage := fmt.Sprintf("Failed to create folder '%s': A parent folder UID (parent_uid) is required by KSM.", params.Name)
		switch len(suitableParentFolders) {
		case 0:
			clarificationMessage += " No suitable parent folders found to suggest. Please ensure a shared folder exists and is accessible."
		case 1:
			f := suitableParentFolders[0]
			clarificationMessage += fmt.Sprintf(" The folder '%s' (UID: %s) is available. Would you like to create the new folder under this one?", f.Name, f.UID)
		case 2, 3, 4, 5:
			var folderStrings []string
			for _, f := range suitableParentFolders {
				folderStrings = append(folderStrings, fmt.Sprintf("'%s' (UID: %s)", f.Name, f.UID))
			}
			clarificationMessage += fmt.Sprintf(" Please choose a parent folder from: %s.", strings.Join(folderStrings, ", "))
		default: // More than 5 folders
			clarificationMessage += " Please choose a parent folder. Refer to the 'available_parent_folders' list for names and UIDs."
		}

		return map[string]interface{}{
			"status":                   "parent_uid_required_clarification",
			"message":                  clarificationMessage,
			"available_parent_folders": suitableParentFolders,
			"original_tool_args_json":  string(args),
		}, nil
	}

	// If ParentUID is provided, proceed with creation attempt.
	uid, err := client.CreateFolder(params.Name, params.ParentUID)
	if err != nil {
		return nil, err // Error already formatted by client.CreateFolder
	}
	return map[string]interface{}{"uid": uid, "name": params.Name, "message": "Folder created successfully (confirmed)."}, nil
}

// executeDeleteFolder handles the delete_folder tool (confirmation step)
func (s *Server) executeDeleteFolder(client KSMClient, args json.RawMessage) (interface{}, error) {
	var params struct {
		FolderUID string `json:"folder_uid"`
		Force     bool   `json:"force,omitempty"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters for delete_folder: %w", err)
	}

	if params.FolderUID == "" {
		return nil, fmt.Errorf("folder_uid is required to delete a folder")
	}

	// Get folder name for a more descriptive confirmation message
	var folderName = params.FolderUID // Default to UID if name lookup fails
	if client != nil {                // KSMClient might be nil if called without an active profile (should not happen for this tool)
		foldersResponse, err := client.ListFolders()
		if err == nil && foldersResponse != nil {
			for _, f := range foldersResponse.Folders {
				if f.UID == params.FolderUID {
					folderName = f.Name
					break
				}
			}
		}
	}

	actionDescription := fmt.Sprintf("Permanently delete KSM folder '%s' (UID: %s)", folderName, params.FolderUID)
	warningMessage := "This action CANNOT BE UNDONE."
	if params.Force {
		warningMessage += " The folder and ALL ITS CONTENTS (secrets and subfolders) will be permanently removed."
	} else {
		warningMessage += " The folder must be empty to be deleted."
	}

	// Check if auto-approving
	if s.options.BatchMode || s.options.AutoApprove {
		s.logSystem(audit.EventAccess, "DeleteFolder: Batch/AutoApprove mode, executing directly", map[string]interface{}{
			"profile":    s.currentProfile,
			"folder_uid": params.FolderUID,
			"force":      params.Force,
		})
		return s.executeDeleteFolderConfirmed(client, args)
	}

	confirmationDetails := map[string]interface{}{
		"prompt_name": "ksm_confirm_action",
		"prompt_arguments": map[string]interface{}{
			"action_description":      actionDescription,
			"warning_message":         warningMessage,
			"original_tool_name":      "delete_folder",
			"original_tool_args_json": string(args),
		},
	}

	s.logSystem(audit.EventAccess, "DeleteFolder: Confirmation required", map[string]interface{}{
		"profile":    s.currentProfile,
		"folder_uid": params.FolderUID,
		"force":      params.Force,
	})

	return map[string]interface{}{
		"status":               "confirmation_required",
		"message":              fmt.Sprintf("Keeper Secrets Manager requires confirmation to %s. Use the 'ksm_confirm_action' prompt.", actionDescription),
		"confirmation_details": confirmationDetails,
	}, nil
}

// executeDeleteFolderConfirmed handles the confirmed deletion of a folder
func (s *Server) executeDeleteFolderConfirmed(client KSMClient, args json.RawMessage) (interface{}, error) {
	var params struct {
		FolderUID string `json:"folder_uid"`
		Force     bool   `json:"force,omitempty"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters for confirmed delete_folder: %w", err)
	}

	if params.FolderUID == "" {
		return nil, fmt.Errorf("folder_uid is required for confirmed delete_folder")
	}

	if client == nil {
		return nil, fmt.Errorf("KSM client not available for confirmed delete_folder")
	}

	if err := client.DeleteFolder(params.FolderUID, params.Force); err != nil {
		// Specific error for non-empty folder if not using force, based on typical SDK behavior
		if !params.Force && strings.Contains(strings.ToLower(err.Error()), "folder is not empty") {
			return nil, fmt.Errorf("failed to delete folder '%s': folder is not empty. Use 'force: true' to delete a non-empty folder. Original error: %w", params.FolderUID, err)
		}
		return nil, err // Error should be formatted by client.DeleteFolder
	}

	return map[string]interface{}{"folder_uid": params.FolderUID, "message": "Folder deleted successfully (confirmed)."}, nil
}
