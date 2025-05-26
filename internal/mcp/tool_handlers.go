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

// Phase 2 Tool Implementations

// executeCreateSecret handles the create_secret tool
func (s *Server) executeCreateSecret(client KSMClient, args json.RawMessage) (interface{}, error) {
	var paramsForDesc types.CreateSecretParams
	if err := json.Unmarshal(args, &paramsForDesc); err != nil {
		return nil, fmt.Errorf("invalid parameters for create_secret: %w", err)
	}

	if s.options.BatchMode || s.options.AutoApprove {
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
	var paramsForDesc types.UpdateSecretParams
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
	var paramsForDesc struct {
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
	var paramsForDesc struct {
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

// Confirmed action handlers
func (s *Server) executeCreateSecretConfirmed(client KSMClient, args json.RawMessage) (interface{}, error) {
	var params types.CreateSecretParams
	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters for confirmed create_secret: %w", err)
	}
	uid, err := client.CreateSecret(params)
	if err != nil {
		if strings.Contains(err.Error(), "folder uid=") && strings.Contains(err.Error(), "was not retrieved") {
			originalErrMessage := err.Error() // Capture original KSM error message part

			if params.FolderUID == "" {
				// Case 1: No folder_uid was provided in the initial request
				s.logger.LogSystem(audit.EventAccess, "CreateSecret: No folder_uid provided. Requesting clarification.", map[string]interface{}{
					"profile": s.currentProfile,
					"title":   params.Title,
				})
				allFolders, listFoldersErr := client.ListFolders()
				if listFoldersErr != nil {
					s.logger.LogError("mcp", listFoldersErr, map[string]interface{}{
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
						s.logger.LogSystem(audit.EventAccess, "CreateSecret: No top-level folders found, preparing all folders for selection suggestion.", map[string]interface{}{})
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
				s.logger.LogSystem(audit.EventAccess, fmt.Sprintf("CreateSecret: Target folder %s empty or invalid, attempting to find suitable parent.", params.FolderUID), map[string]interface{}{
					"profile":       s.currentProfile,
					"title":         params.Title,
					"target_folder": params.FolderUID,
				})

				allFolders, listFoldersErr := client.ListFolders()
				if listFoldersErr != nil {
					s.logger.LogError("mcp", listFoldersErr, map[string]interface{}{
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
								s.logger.LogError("mcp", listSecretsErr, map[string]interface{}{
									"operation":     "executeCreateSecretConfirmed_listSecrets_parent",
									"profile":       s.currentProfile,
									"parent_folder": parentFolderInfo.UID,
								})
								// Fall through to original error
							} else if len(parentSecrets) > 0 {
								s.logger.LogSystem(audit.EventAccess, fmt.Sprintf("CreateSecret: Recommending parent folder %s for secret %s", parentFolderInfo.UID, params.Title), map[string]interface{}{
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
								s.logger.LogSystem(audit.EventAccess, fmt.Sprintf("CreateSecret: Parent folder %s (for target %s) is also empty or unsuitable.", parentFolderInfo.UID, params.FolderUID), map[string]interface{}{"profile": s.currentProfile})
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
	return map[string]interface{}{"uid": uid, "title": params.Title, "message": "Secret created successfully (confirmed)."}, nil
}

func (s *Server) executeGetSecretConfirmed(client KSMClient, args json.RawMessage) (interface{}, error) {
	var params struct {
		UID    string   `json:"uid"`
		Fields []string `json:"fields,omitempty"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters for confirmed get_secret: %w", err)
	}
	s.logger.LogSystem(audit.EventAccess, "GetSecret (Unmask): Executing confirmed/batched action", map[string]interface{}{
		"profile": s.currentProfile,
		"uid":     params.UID,
	})
	secret, err := client.GetSecret(params.UID, params.Fields, true) // unmask is explicitly true here
	if err != nil {
		return nil, err
	}
	return secret, nil
}

func (s *Server) executeUpdateSecretConfirmed(client KSMClient, args json.RawMessage) (interface{}, error) {
	var params types.UpdateSecretParams
	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters for confirmed update_secret: %w", err)
	}
	if err := client.UpdateSecret(params); err != nil {
		return nil, err
	}
	return map[string]interface{}{"uid": params.UID, "message": "Secret updated successfully (confirmed)."}, nil
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

func (s *Server) executeCreateFolderConfirmed(client KSMClient, args json.RawMessage) (interface{}, error) {
	var paramsForDesc struct {
		Name      string `json:"name"`
		ParentUID string `json:"parent_uid,omitempty"`
	}
	if err := json.Unmarshal(args, &paramsForDesc); err != nil {
		return nil, fmt.Errorf("invalid parameters for confirmed create_folder: %w", err)
	}
	uid, err := client.CreateFolder(paramsForDesc.Name, paramsForDesc.ParentUID)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"uid": uid, "name": paramsForDesc.Name, "message": "Folder created successfully (confirmed)."}, nil
}
