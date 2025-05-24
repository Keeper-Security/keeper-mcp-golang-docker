package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/keeper-security/ksm-mcp/internal/ksm"
	"github.com/keeper-security/ksm-mcp/pkg/types"
)

// Phase 1 Tool Implementations

// executeListSecrets handles the list_secrets tool
func (s *Server) executeListSecrets(client *ksm.Client, args json.RawMessage) (interface{}, error) {
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
func (s *Server) executeGetSecret(client *ksm.Client, args json.RawMessage) (interface{}, error) {
	var params struct {
		UID    string   `json:"uid"`
		Fields []string `json:"fields,omitempty"`
		Unmask bool     `json:"unmask,omitempty"`
	}

	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}

	// Confirm if unmasking
	if params.Unmask {
		ctx := context.Background()
		result := s.confirmer.Confirm(ctx, fmt.Sprintf("Reveal unmasked secret %s?", params.UID))
		if result.Error != nil {
			return nil, fmt.Errorf("confirmation failed: %w", result.Error)
		}
		if !result.Approved {
			return nil, fmt.Errorf("operation cancelled by user")
		}
	}

	secret, err := client.GetSecret(params.UID, params.Fields, params.Unmask)
	if err != nil {
		return nil, err
	}

	return secret, nil
}

// executeSearchSecrets handles the search_secrets tool
func (s *Server) executeSearchSecrets(client *ksm.Client, args json.RawMessage) (interface{}, error) {
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
func (s *Server) executeGetField(client *ksm.Client, args json.RawMessage) (interface{}, error) {
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
func (s *Server) executeGeneratePassword(client *ksm.Client, args json.RawMessage) (interface{}, error) {
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
func (s *Server) executeGetTOTPCode(client *ksm.Client, args json.RawMessage) (interface{}, error) {
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
func (s *Server) executeCreateSecret(client *ksm.Client, args json.RawMessage) (interface{}, error) {
	var params types.CreateSecretParams

	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}

	// Confirm creation
	ctx := context.Background()
	result := s.confirmer.Confirm(ctx, fmt.Sprintf("Create new secret '%s'?", params.Title))
	if result.Error != nil {
		return nil, fmt.Errorf("confirmation failed: %w", result.Error)
	}
	if !result.Approved {
		return nil, fmt.Errorf("operation cancelled by user")
	}

	uid, err := client.CreateSecret(params)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"uid":     uid,
		"title":   params.Title,
		"message": "Secret created successfully",
	}, nil
}

// executeUpdateSecret handles the update_secret tool
func (s *Server) executeUpdateSecret(client *ksm.Client, args json.RawMessage) (interface{}, error) {
	var params types.UpdateSecretParams

	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}

	// Confirm update
	ctx := context.Background()
	result := s.confirmer.Confirm(ctx, fmt.Sprintf("Update secret %s?", params.UID))
	if result.Error != nil {
		return nil, fmt.Errorf("confirmation failed: %w", result.Error)
	}
	if !result.Approved {
		return nil, fmt.Errorf("operation cancelled by user")
	}

	if err := client.UpdateSecret(params); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"uid":     params.UID,
		"message": "Secret updated successfully",
	}, nil
}

// executeDeleteSecret handles the delete_secret tool
func (s *Server) executeDeleteSecret(client *ksm.Client, args json.RawMessage) (interface{}, error) {
	var params struct {
		UID string `json:"uid"`
	}

	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}

	// Double confirm deletion
	ctx := context.Background()
	result := s.confirmer.Confirm(ctx, fmt.Sprintf("Delete secret %s? This cannot be undone!", params.UID))
	if result.Error != nil {
		return nil, fmt.Errorf("confirmation failed: %w", result.Error)
	}
	if !result.Approved {
		return nil, fmt.Errorf("operation cancelled by user")
	}

	// Second confirmation for safety
	result = s.confirmer.Confirm(ctx, "Are you absolutely sure? Type 'yes' to confirm deletion.")
	if result.Error != nil {
		return nil, fmt.Errorf("confirmation failed: %w", result.Error)
	}
	if !result.Approved {
		return nil, fmt.Errorf("operation cancelled by user")
	}

	if err := client.DeleteSecret(params.UID, true); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"uid":     params.UID,
		"message": "Secret deleted successfully",
	}, nil
}

// executeUploadFile handles the upload_file tool
func (s *Server) executeUploadFile(client *ksm.Client, args json.RawMessage) (interface{}, error) {
	var params struct {
		UID      string `json:"uid"`
		FilePath string `json:"file_path"`
		Title    string `json:"title"`
	}

	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}

	// Confirm upload
	ctx := context.Background()
	result := s.confirmer.Confirm(ctx, fmt.Sprintf("Upload file %s to secret %s?", params.FilePath, params.UID))
	if result.Error != nil {
		return nil, fmt.Errorf("confirmation failed: %w", result.Error)
	}
	if !result.Approved {
		return nil, fmt.Errorf("operation cancelled by user")
	}

	if err := client.UploadFile(params.UID, params.FilePath, params.Title); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"uid":      params.UID,
		"file":     params.Title,
		"message":  "File uploaded successfully",
	}, nil
}

// executeDownloadFile handles the download_file tool
func (s *Server) executeDownloadFile(client *ksm.Client, args json.RawMessage) (interface{}, error) {
	var params struct {
		UID      string `json:"uid"`
		FileUID  string `json:"file_uid"`
		SavePath string `json:"save_path,omitempty"`
	}

	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}

	err := client.DownloadFile(params.UID, params.FileUID, params.SavePath)
	if err != nil {
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
func (s *Server) executeListFolders(client *ksm.Client, args json.RawMessage) (interface{}, error) {
	folders, err := client.ListFolders()
	if err != nil {
		return nil, err
	}

	// Ensure UIDs are prominent in output
	return map[string]interface{}{
		"folders": folders,
		"count":   len(folders.Folders),
	}, nil
}

// executeCreateFolder handles the create_folder tool
func (s *Server) executeCreateFolder(client *ksm.Client, args json.RawMessage) (interface{}, error) {
	var params struct {
		Name      string `json:"name"`
		ParentUID string `json:"parent_uid,omitempty"`
	}

	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}

	// Confirm creation
	ctx := context.Background()
	result := s.confirmer.Confirm(ctx, fmt.Sprintf("Create folder '%s'?", params.Name))
	if result.Error != nil {
		return nil, fmt.Errorf("confirmation failed: %w", result.Error)
	}
	if !result.Approved {
		return nil, fmt.Errorf("operation cancelled by user")
	}

	uid, err := client.CreateFolder(params.Name, params.ParentUID)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"uid":     uid,
		"name":    params.Name,
		"message": "Folder created successfully",
	}, nil
}