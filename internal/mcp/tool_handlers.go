package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/keeper-security/ksm-mcp/internal/audit"
	"github.com/keeper-security/ksm-mcp/internal/recordtemplates"
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
	var paramsForDesc types.CreateSecretParams // Used for descriptions and initial checks
	if err := json.Unmarshal(args, &paramsForDesc); err != nil {
		return nil, fmt.Errorf("invalid parameters for create_secret: %w", err)
	}

	// ==== BEGIN FOLDER UID CHECK (Moved to pre-confirmation) ====
	if paramsForDesc.FolderUID == "" {
		s.logSystem(audit.EventAccess, "CreateSecret: No folder_uid provided by AI. Requesting clarification before confirmation.", map[string]interface{}{
			"profile": s.currentProfile,
			"title":   paramsForDesc.Title,
		})
		allFolders, listFoldersErr := client.ListFolders()
		if listFoldersErr != nil {
			s.logError("mcp", listFoldersErr, map[string]interface{}{
				"operation": "executeCreateSecret_listFolders_for_clarification",
				"profile":   s.currentProfile,
			})
			return nil, fmt.Errorf("failed to process create_secret for '%s': folder_uid is required. Additionally, failed to retrieve folder list: %w", paramsForDesc.Title, listFoldersErr)
		}

		var candidateFolders []types.FolderInfo
		if allFolders != nil {
			for _, f := range allFolders.Folders {
				if f.ParentUID == "" { // Suggest top-level folders
					candidateFolders = append(candidateFolders, f)
				}
			}
			if len(candidateFolders) == 0 && len(allFolders.Folders) > 0 {
				candidateFolders = allFolders.Folders
			}
		}

		clarificationMessage := fmt.Sprintf("Folder UID (folder_uid) is required to create secret '%s'.", paramsForDesc.Title)
		switch len(candidateFolders) {
		case 0:
			clarificationMessage += " No suitable folders are available. Please create a shared folder first or specify a valid folder_uid."
		case 1:
			f := candidateFolders[0]
			clarificationMessage += fmt.Sprintf(" The folder '%s' (UID: %s) is available. Please re-run create_secret with this folder_uid.", f.Name, f.UID)
		default:
			clarificationMessage += " Please choose a folder from the list_folders tool and re-run create_secret with a folder_uid."
		}

		return map[string]interface{}{
			"status":                  "folder_required_clarification",
			"message":                 clarificationMessage,
			"available_folders":       candidateFolders,
			"original_tool_args_json": string(args), // Allow AI to easily retry with folder_uid added
		}, nil
	}
	// ==== END FOLDER UID CHECK ====

	// If folder_uid is present, proceed to normal confirmation or direct execution
	if s.options.BatchMode || s.options.AutoApprove {
		s.logSystem(audit.EventAccess, "CreateSecret: Batch/AutoApprove mode, folder_uid present, executing directly", map[string]interface{}{
			"profile":    s.currentProfile,
			"title":      paramsForDesc.Title,
			"folder_uid": paramsForDesc.FolderUID,
		})
		return s.executeCreateSecretConfirmed(client, args) // args already contain folder_uid
	}

	// Standard confirmation flow (folder_uid is present)
	actionDescription := fmt.Sprintf("Create new KSM secret titled '%s' of type '%s' in folder '%s'", paramsForDesc.Title, paramsForDesc.Type, paramsForDesc.FolderUID)
	// Potentially fetch folder name for a friendlier message if FolderUID is just an ID
	// For now, using UID is clear enough for confirmation.
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

	s.logSystem(audit.EventAccess, "CreateSecret: Confirmation required (folder_uid present)", map[string]interface{}{
		"profile":    s.currentProfile,
		"title":      paramsForDesc.Title,
		"folder_uid": paramsForDesc.FolderUID,
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

// executeGetRecordTypeSchema handles the get_record_type_schema tool
func (s *Server) executeGetRecordTypeSchema(client KSMClient, args json.RawMessage) (interface{}, error) {
	var params struct {
		RecordType string `json:"type"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters for get_record_type_schema: %w", err)
	}

	if params.RecordType == "" {
		return nil, fmt.Errorf("record type (type) parameter is required for get_record_type_schema")
	}

	s.logSystem(audit.EventAccess, "GetRecordTypeSchema called", map[string]interface{}{
		"profile":     s.currentProfile, // Though schema is profile-agnostic, good to log context
		"record_type": params.RecordType,
	})

	schema, err := recordtemplates.GetSchema(params.RecordType)
	if err != nil {
		// Log the error more visibly as well, as this indicates a problem with template loading or lookup
		s.logError("mcp", fmt.Errorf("get_record_type_schema: error from recordtemplates.GetSchema for type '%s': %w", params.RecordType, err), nil)
		return nil, fmt.Errorf("failed to get schema for record type '%s': %w. Ensure templates are loaded correctly and the type exists.", params.RecordType, err)
	}

	return schema, nil
}

// Confirmed action handlers
func (s *Server) executeCreateSecretConfirmed(client KSMClient, args json.RawMessage) (interface{}, error) {
	var params types.CreateSecretParams
	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters for confirmed create_secret (initial unmarshal): %w", err)
	}

	// FolderUID check is now done in executeCreateSecret before confirmation.
	// So, here we assume params.FolderUID is present and valid for KSM API call.

	// Process the flattened fields into the structure the SDK expects
	reconstructedFields, processingWarnings, err := processFieldsForSDK(params.Fields)
	if err != nil {
		return nil, fmt.Errorf("error processing fields for SDK structure: %w", err)
	}
	params.Fields = reconstructedFields // Replace original fields with processed ones

	uid, err := client.CreateSecret(params)
	if err != nil {
		// The specific KSM error "folder uid= was not retrieved" might still occur if the provided
		// folder_uid is for a non-shared folder or an empty shared folder (depending on KSM API rules).
		// The previous complex logic for suggesting parent folders can remain here if that specific error occurs.
		if strings.Contains(err.Error(), "folder uid=") && strings.Contains(err.Error(), "was not retrieved") {
			originalErrMessage := err.Error()
			// ... [The existing logic for suggesting parent folder can be kept or simplified] ...
			// For now, let's return a more direct error if this happens post-confirmation with a folder_uid.
			return nil, fmt.Errorf("failed to create secret '%s' in folder '%s' (KSM API error: %s). Ensure the folder is a shared folder and accessible.", params.Title, params.FolderUID, originalErrMessage)
		}
		// Generic KSM error
		return nil, fmt.Errorf("failed to create secret '%s': %w", params.Title, err)
	}

	// Success
	response := map[string]interface{}{
		"uid":     uid,
		"title":   params.Title,
		"message": "Secret created successfully (confirmed).",
	}

	allWarnings := append(processingWarnings)

	if len(allWarnings) > 0 {
		response["warnings"] = allWarnings
		currentMsg := response["message"].(string)
		response["message"] = fmt.Sprintf("%s Some fields were processed or adjusted; see warnings.", currentMsg)
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
		return nil, fmt.Errorf("invalid parameters for confirmed update_secret (initial unmarshal): %w", err)
	}

	reconstructedFields, processingWarnings, err := processFieldsForSDK(params.Fields)
	if err != nil {
		return nil, fmt.Errorf("error processing fields for SDK structure during update: %w", err)
	}
	params.Fields = reconstructedFields

	if err := client.UpdateSecret(params); err != nil {
		return nil, err
	}

	response := map[string]interface{}{
		"uid":     params.UID,
		"message": "Secret updated successfully (confirmed).",
	}

	allWarnings := append(processingWarnings)

	if len(allWarnings) > 0 {
		response["warnings"] = allWarnings
		currentMsg := response["message"].(string)
		response["message"] = fmt.Sprintf("%s Some fields were processed or adjusted; see warnings.", currentMsg)
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
		default:
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

// processFieldsForSDK reconstructs complex fields from a flattened list
// and enforces single values for simple fields.
func processFieldsForSDK(inputFields []types.SecretField) ([]types.SecretField, []string, error) {
	processedFields := make([]types.SecretField, 0)
	tempComplexFields := make(map[string]map[string]interface{}) // Stores parts of complex fields, e.g., tempComplexFields["bankAccount_0"]["routingNumber"] = "123"
	complexFieldOrder := make(map[string][]string)               // Maintains order of elements for a complex field instance
	warnings := make([]string, 0)

	// Define simple fields that should strictly have only one value
	singleValueSimpleFields := map[string]bool{
		"password":      true,
		"login":         true,
		"email":         true,
		"oneTimeCode":   true,
		"licenseNumber": true,
		// "accountNumber" is part of bankAccount, but can also be standalone. If standalone, it's simple.
		// This logic assumes if "accountNumber" appears alone, it's simple.
		// If it appears as "bankAccount.accountNumber", it's handled by complex logic.
		"pinCode":        true,
		"url":            true,
		"text":           true,
		"multiline":      true,
		"secret":         true,
		"note":           true,
		"date":           true,
		"birthDate":      true,
		"expirationDate": true,
		// Fields like fileRef, cardRef, addressRef, recordRef are simple string UIDs
		"fileRef":        true,
		"cardRef":        true,
		"addressRef":     true,
		"recordRef":      true,
		"title":          true, // Though usually top-level, can be a field
		"company":        true,
		"groupNumber":    true,
		"isSSIDHidden":   true, // checkbox, effectively boolean but SDK might take string "true"/"false"
		"wifiEncryption": true, // dropdown
		"directoryType":  true, // dropdown
		"databaseType":   true, // dropdown
		"rbiUrl":         true, // text
		"key":            true, // often used for API keys, simple text
		"securityCode":   true, // Simple text, like a CVV if not part of paymentCard
		"cardNumber":     true, // Simple text, if not part of paymentCard
		"routingNumber":  true, // Simple text, if not part of bankAccount
	}

	// Define complex fields and their expected sub-fields based on record-templates/field-types.json
	// This map helps identify and parse flattened complex fields.
	// The value is a map of the sub-field name to its type (not strictly enforced here but good for reference)
	complexFieldDefinitions := map[string]map[string]string{
		"name":             {"firstName": "string", "lastName": "string", "fullName": "string"}, // Corrected to match field-types.json elements
		"phone":            {"region": "string", "number": "string", "ext": "string", "type": "string"},
		"address":          {"street1": "string", "street2": "string", "city": "string", "state": "string", "zip": "string", "country": "string"},
		"host":             {"hostName": "string", "port": "string"},
		"securityQuestion": {"question": "string", "answer": "string"},
		"paymentCard":      {"cardNumber": "string", "cardExpirationDate": "string", "cardSecurityCode": "string"},
		"bankAccount":      {"accountType": "string", "routingNumber": "string", "accountNumber": "string", "otherType": "string"},
		"keyPair":          {"publicKey": "string", "privateKey": "string"},
		"pamHostname":      {"hostName": "string", "port": "string"},
		"passkey":          {"privateKey": "string", "credentialId": "string", "signCount": "string", "userId": "string", "relyingParty": "string", "username": "string", "createdDate": "string"}, // Values will be strings from AI, SDK handles conversion for int64
		"appFiller":        {"applicationTitle": "string", "contentFilter": "string", "macroSequence": "string"},
		"pamResources":     {"controllerUid": "string", "folderUid": "string", "resourceRef": "string"}, // resourceRef is string array, AI sends as comma-sep string?
		"script":           {"command": "string", "fileRef": "string", "recordRef": "string"},           // recordRef is string array, AI sends as comma-sep string?
	}

	for _, field := range inputFields {
		parts := strings.SplitN(field.Type, ".", 2)
		baseType := parts[0]
		subField := ""
		if len(parts) > 1 {
			subField = parts[1]
		}

		definition, isComplex := complexFieldDefinitions[baseType]

		if isComplex && subField != "" {
			if _, ok := definition[subField]; !ok {
				// This subField is not defined for this complex type, treat baseType as simple
				// Or it could be an error / unexpected field. For now, log a warning or error.
				warnings = append(warnings, fmt.Sprintf("Warning: Field '%s' contains an unrecognized sub-field '%s'. Treating '%s' as a simple field.", field.Type, subField, baseType))
				// Fallback to treating the original field.Type as simple if sub-field is not recognized
				if singleValueSimpleFields[field.Type] && len(field.Value) > 1 {
					warnings = append(warnings, fmt.Sprintf("Field '%s' (treated as simple) has %d values; using only the first.", field.Type, len(field.Value)))
					field.Value = field.Value[:1]
				}
				processedFields = append(processedFields, field)
				continue
			}

			// For complex fields, the SDK usually expects ONE structured object in the field's "value" array.
			// We use "baseType_0" as a key to group sub-fields for the *first* instance of this complex type.
			// Supporting multiple instances of the same complex type (e.g. two phone numbers) would require indexing (phone_0, phone_1).
			// For now, assuming only one instance of each complex field type per secret for simplicity with this flattened approach.
			instanceKey := baseType + "_0"
			if _, ok := tempComplexFields[instanceKey]; !ok {
				tempComplexFields[instanceKey] = make(map[string]interface{})
				complexFieldOrder[instanceKey] = make([]string, 0) // Store order of subfields
			}
			if len(field.Value) > 0 {
				// Take the first element from the value array, as per our single-value principle for the flattened representation
				tempComplexFields[instanceKey][subField] = field.Value[0]
				complexFieldOrder[instanceKey] = append(complexFieldOrder[instanceKey], subField)
			} else {
				// Handle cases where a sub-field might be present but have an empty value array
				tempComplexFields[instanceKey][subField] = "" // Or an appropriate default
			}

		} else { // Simple field or a complex field that wasn't split (e.g. "otp", "file", or user provided "bankAccount" without ".subfield")
			if singleValueSimpleFields[field.Type] && len(field.Value) > 1 {
				warnings = append(warnings, fmt.Sprintf("Field '%s' has %d values; using only the first.", field.Type, len(field.Value)))
				field.Value = field.Value[:1] // Enforce single value
			}
			// Special handling for fields that are complex by nature but might be passed without sub-fields initially
			// e.g. a raw "securityQuestion" field before it's broken down.
			// If it's a known complex type but passed without sub-field, it might be an error or needs default handling.
			// For now, just add it as is, KSM SDK might reject it if structure is wrong.
			processedFields = append(processedFields, field)
		}
	}

	// Reconstruct complex fields
	for instanceKey, subFieldsMap := range tempComplexFields {
		baseType := strings.SplitN(instanceKey, "_", 2)[0]

		// The KSM Go SDK expects specific struct types for complex fields,
		// not just map[string]interface{}. We need to marshal to the correct type.
		// This requires knowing the target struct for each baseType.

		// Example for 'name' based on record-templates (firstName, lastName, fullName)
		// but KSM SDK for 'name' field type expects {first, middle, last}.
		// This is a mismatch we need to handle.
		// For 'bankAccount', KSM SDK expects {accountType, routingNumber, accountNumber, otherType}
		// For 'host', KSM SDK expects {hostName, port}
		// For 'securityQuestion', KSM SDK expects {question, answer}

		var complexValue interface{}
		switch baseType {
		case "name":
			nameMap := make(map[string]interface{})
			// Values from AI will use keys "firstName", "lastName", "fullName"
			// We map them to SDK's expected JSON keys "first", "middle", "last"
			if val, ok := subFieldsMap["firstName"].(string); ok {
				nameMap["first"] = val
			}
			if val, ok := subFieldsMap["lastName"].(string); ok {
				nameMap["last"] = val
			}
			// If fullName is provided, and first/last are also given, middle is ambiguous.
			// If only fullName is given, it might be used for first or split.
			// For simplicity with KSM SDK expecting distinct parts, we'll prioritize first/last.
			// Middle name is often optional. If template had a "middleName" element, we'd map it.
			if val, ok := subFieldsMap["fullName"].(string); ok {
				// If first and last are empty, attempt to use fullName for first.
				if nameMap["first"] == nil && nameMap["last"] == nil && val != "" {
					nameMap["first"] = val // Or try to split it intelligently if desired
				} else if nameMap["first"] != nil && nameMap["last"] != nil && val != "" {
					// If first and last are set, maybe fullName goes to middle? Or just log a warning.
					nameMap["middle"] = val // This is an assumption
					warnings = append(warnings, fmt.Sprintf("Warning: For field '%s', 'fullName' was provided alongside 'firstName' and 'lastName'. 'fullName' mapped to 'middle'.", instanceKey))
				} else if val != "" && nameMap["first"] == nil {
					nameMap["first"] = val // if only fullname is there, set it to first.
				}
			}
			// Ensure keys expected by SDK are present, even if empty, if that's how SDK handles it.
			if _, ok := nameMap["first"]; !ok {
				nameMap["first"] = ""
			}
			if _, ok := nameMap["middle"]; !ok {
				nameMap["middle"] = ""
			}
			if _, ok := nameMap["last"]; !ok {
				nameMap["last"] = ""
			}
			complexValue = nameMap
		case "phone":
			phoneMap := make(map[string]interface{})
			if r, ok := subFieldsMap["region"].(string); ok {
				phoneMap["region"] = r
			}
			if n, ok := subFieldsMap["number"].(string); ok {
				phoneMap["number"] = n
			}
			if e, ok := subFieldsMap["ext"].(string); ok {
				phoneMap["ext"] = e
			}
			if t, ok := subFieldsMap["type"].(string); ok {
				phoneMap["type"] = t
			}
			complexValue = phoneMap
		case "address":
			addressMap := make(map[string]interface{})
			if s1, ok := subFieldsMap["street1"].(string); ok {
				addressMap["street1"] = s1
			}
			if s2, ok := subFieldsMap["street2"].(string); ok {
				addressMap["street2"] = s2
			}
			if city, ok := subFieldsMap["city"].(string); ok {
				addressMap["city"] = city
			}
			if st, ok := subFieldsMap["state"].(string); ok {
				addressMap["state"] = st
			}
			if z, ok := subFieldsMap["zip"].(string); ok {
				addressMap["zip"] = z
			}
			if co, ok := subFieldsMap["country"].(string); ok {
				addressMap["country"] = co
			}
			complexValue = addressMap
		case "host", "pamHostname":
			hostMap := make(map[string]interface{})
			if hn, ok := subFieldsMap["hostName"].(string); ok {
				hostMap["hostName"] = hn
			}
			if p, ok := subFieldsMap["port"].(string); ok {
				hostMap["port"] = p
			}
			complexValue = hostMap
		case "securityQuestion":
			sqMap := make(map[string]interface{})
			if q, ok := subFieldsMap["question"].(string); ok {
				sqMap["question"] = q
			}
			if a, ok := subFieldsMap["answer"].(string); ok {
				sqMap["answer"] = a
			}
			complexValue = sqMap
		case "paymentCard":
			cardMap := make(map[string]interface{})
			if cn, ok := subFieldsMap["cardNumber"].(string); ok {
				cardMap["cardNumber"] = cn
			}
			if ced, ok := subFieldsMap["cardExpirationDate"].(string); ok {
				cardMap["cardExpirationDate"] = ced
			}
			if csc, ok := subFieldsMap["cardSecurityCode"].(string); ok {
				cardMap["cardSecurityCode"] = csc
			}
			complexValue = cardMap
		case "bankAccount":
			bankMap := make(map[string]interface{})
			if at, ok := subFieldsMap["accountType"].(string); ok {
				bankMap["accountType"] = at
			}
			if rn, ok := subFieldsMap["routingNumber"].(string); ok {
				bankMap["routingNumber"] = rn
			}
			if an, ok := subFieldsMap["accountNumber"].(string); ok {
				bankMap["accountNumber"] = an
			}
			if ot, ok := subFieldsMap["otherType"].(string); ok {
				bankMap["otherType"] = ot
			}
			complexValue = bankMap
		case "keyPair":
			keyPairMap := make(map[string]interface{})
			if pub, ok := subFieldsMap["publicKey"].(string); ok {
				keyPairMap["publicKey"] = pub
			}
			if priv, ok := subFieldsMap["privateKey"].(string); ok {
				keyPairMap["privateKey"] = priv
			}
			complexValue = keyPairMap
			processedFields = append(processedFields, types.SecretField{
				Type:  "privateKey",
				Value: []interface{}{complexValue},
			})
			continue
		case "passkey":
			passkeyMap := make(map[string]interface{})
			if pkStr, okPkStr := subFieldsMap["privateKey"].(string); okPkStr {
				var jwk map[string]interface{}
				if err := json.Unmarshal([]byte(pkStr), &jwk); err == nil {
					passkeyMap["privateKey"] = jwk // Store as unmarshalled map
				} else {
					warnings = append(warnings, fmt.Sprintf("Warning: Could not parse passkey.privateKey JSON string '%s' for field '%s'. Using raw string.", pkStr, instanceKey))
					passkeyMap["privateKey"] = pkStr // Fallback to raw string
				}
			} else if pkMap, okPkMap := subFieldsMap["privateKey"].(map[string]interface{}); okPkMap {
				// AI might have pre-structured it if very capable, though unlikely with current flattened approach
				passkeyMap["privateKey"] = pkMap
			}

			if cid, ok := subFieldsMap["credentialId"].(string); ok {
				passkeyMap["credentialId"] = cid
			}
			if scStr, okSc := subFieldsMap["signCount"].(string); okSc {
				if sc, err := strconv.ParseInt(scStr, 10, 64); err == nil {
					passkeyMap["signCount"] = sc
				} else {
					warnings = append(warnings, fmt.Sprintf("Warning: Could not parse passkey.signCount '%s' as integer for field '%s'. Using string value.", scStr, instanceKey))
					passkeyMap["signCount"] = scStr // Fallback to string if parse fails
				}
			}
			if uid, ok := subFieldsMap["userId"].(string); ok {
				passkeyMap["userId"] = uid
			}
			if rp, ok := subFieldsMap["relyingParty"].(string); ok {
				passkeyMap["relyingParty"] = rp
			}
			if un, ok := subFieldsMap["username"].(string); ok {
				passkeyMap["username"] = un
			}
			if cdStr, okCd := subFieldsMap["createdDate"].(string); okCd {
				if cd, err := strconv.ParseInt(cdStr, 10, 64); err == nil {
					passkeyMap["createdDate"] = cd
				} else {
					warnings = append(warnings, fmt.Sprintf("Warning: Could not parse passkey.createdDate '%s' as integer for field '%s'. Using string value.", cdStr, instanceKey))
					passkeyMap["createdDate"] = cdStr // Fallback to string
				}
			}
			complexValue = passkeyMap
		case "appFiller":
			appFillerMap := make(map[string]interface{})
			if at, ok := subFieldsMap["applicationTitle"].(string); ok {
				appFillerMap["applicationTitle"] = at
			}
			if cf, ok := subFieldsMap["contentFilter"].(string); ok {
				appFillerMap["contentFilter"] = cf
			}
			if ms, ok := subFieldsMap["macroSequence"].(string); ok {
				appFillerMap["macroSequence"] = ms
			}
			complexValue = appFillerMap
		case "pamResources":
			pamResourcesMap := make(map[string]interface{})
			if cuid, ok := subFieldsMap["controllerUid"].(string); ok {
				pamResourcesMap["controllerUid"] = cuid
			}
			if fuid, ok := subFieldsMap["folderUid"].(string); ok {
				pamResourcesMap["folderUid"] = fuid
			}
			if rr, ok := subFieldsMap["resourceRef"].(string); ok { // Assuming AI sends comma-separated string for array
				pamResourcesMap["resourceRef"] = strings.Split(rr, ",")
			} else {
				pamResourcesMap["resourceRef"] = []string{} // Default to empty array
			}
			complexValue = pamResourcesMap
		case "script":
			scriptMap := make(map[string]interface{})
			if cmd, ok := subFieldsMap["command"].(string); ok {
				scriptMap["command"] = cmd
			}
			if fr, ok := subFieldsMap["fileRef"].(string); ok {
				scriptMap["fileRef"] = fr
			}
			if rr, ok := subFieldsMap["recordRef"].(string); ok { // Assuming AI sends comma-separated string for array
				scriptMap["recordRef"] = strings.Split(rr, ",")
			} else {
				scriptMap["recordRef"] = []string{}
			}
			complexValue = scriptMap
		default:
			// For other complex types not explicitly handled, pass as map[string]interface{}
			// KSM SDK might handle it if the structure matches, or reject it.
			// This is a fallback and might lead to issues if SDK strictly needs typed structs.
			complexValue = subFieldsMap
			warnings = append(warnings, fmt.Sprintf("Warning: Complex field type '%s' is using a generic map structure. SDK compatibility not guaranteed.", baseType))
		}

		processedFields = append(processedFields, types.SecretField{
			Type:  baseType, // Use the original base type for the reconstructed field
			Value: []interface{}{complexValue},
		})
	}
	return processedFields, warnings, nil
}
