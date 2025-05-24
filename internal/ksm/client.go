package ksm

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	sm "github.com/keeper-security/secrets-manager-go/core"
	"github.com/keeper-security/ksm-mcp/internal/audit"
	"github.com/keeper-security/ksm-mcp/internal/validation"
	"github.com/keeper-security/ksm-mcp/pkg/types"
)

// Client wraps the KSM SDK client
type Client struct {
	sm        *sm.SecretsManager
	profile   string
	validator *validation.Validator
	logger    *audit.Logger
}

// NewClient creates a new KSM client with the provided configuration
func NewClient(profile *types.Profile, logger *audit.Logger) (*Client, error) {
	if profile == nil {
		return nil, errors.New("profile cannot be nil")
	}

	// Create memory storage from profile config
	storage := sm.NewMemoryKeyValueStorage(profile.Config)

	// Create client options
	options := &sm.ClientOptions{
		Config: storage,
	}

	// Create secrets manager client
	smClient := sm.NewSecretsManager(options)
	if smClient == nil {
		return nil, errors.New("failed to create secrets manager client")
	}

	return &Client{
		sm:        smClient,
		profile:   profile.Name,
		validator: validation.NewValidator(),
		logger:    logger,
	}, nil
}

// InitializeWithToken initializes a new KSM configuration with a one-time token
func InitializeWithToken(token string) (map[string]string, error) {
	validator := validation.NewValidator()
	if err := validator.ValidateToken(token); err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	// Initialize with one-time token
	storage := sm.NewMemoryKeyValueStorage()
	options := &sm.ClientOptions{
		Token:  token,
		Config: storage,
	}

	client := sm.NewSecretsManager(options)
	if client == nil {
		return nil, errors.New("failed to create secrets manager client")
	}

	// Initialize client to exchange token for config
	if _, err := client.GetSecrets([]string{}); err != nil {
		return nil, fmt.Errorf("failed to initialize with token: %w", err)
	}

	// Extract configuration
	config := make(map[string]string)
	keys := []string{"clientId", "privateKey", "appKey", "hostname"}
	
	// Get storage data and extract fields
	storageData := storage.ReadStorage()
	for _, key := range keys {
		if value, exists := storageData[key]; exists {
			if strValue, ok := value.(string); ok {
				config[key] = strValue
			}
		}
	}

	if len(config) == 0 {
		return nil, errors.New("failed to retrieve configuration from token")
	}

	return config, nil
}

// InitializeWithConfig validates an existing KSM configuration
func InitializeWithConfig(configData []byte) (map[string]string, error) {
	var config map[string]string
	if err := json.Unmarshal(configData, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Validate required fields
	requiredFields := []string{"clientId", "privateKey", "appKey"}
	for _, field := range requiredFields {
		if _, exists := config[field]; !exists {
			return nil, fmt.Errorf("missing required field: %s", field)
		}
	}

	// Test configuration by creating a client
	storage := sm.NewMemoryKeyValueStorage(config)
	options := &sm.ClientOptions{
		Config: storage,
	}

	testClient := sm.NewSecretsManager(options)
	if testClient == nil {
		return nil, errors.New("failed to create client with provided config")
	}

	return config, nil
}

// ListSecrets returns metadata for all secrets
func (c *Client) ListSecrets(folderUID string) ([]*types.SecretMetadata, error) {
	// Log access attempt
	c.logger.LogAccess("secrets", "list", "", c.profile, true, map[string]interface{}{
		"folder": folderUID,
	})

	// Get all secrets
	records, err := c.sm.GetSecrets([]string{})
	if err != nil {
		c.logger.LogError("ksm", err, map[string]interface{}{
			"operation": "list_secrets",
		})
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	// Convert to metadata
	var metadata []*types.SecretMetadata
	for _, record := range records {
		// Filter by folder if specified
		if folderUID != "" && record.FolderUid() != folderUID {
			continue
		}

		metadata = append(metadata, &types.SecretMetadata{
			UID:    record.Uid,
			Title:  record.Title(),
			Type:   record.Type(),
			Folder: record.FolderUid(),
		})
	}

	return metadata, nil
}

// GetSecret retrieves a secret by UID
func (c *Client) GetSecret(uid string, fields []string, unmask bool) (map[string]interface{}, error) {
	// Validate UID
	if err := c.validator.ValidateUID(uid); err != nil {
		return nil, fmt.Errorf("invalid UID: %w", err)
	}

	// Log access attempt
	c.logger.LogSecretOperation(audit.EventSecretAccess, uid, "", c.profile, true, map[string]interface{}{
		"fields": fields,
		"masked": !unmask,
	})

	// Get secret
	records, err := c.sm.GetSecrets([]string{uid})
	if err != nil {
		c.logger.LogError("ksm", err, map[string]interface{}{
			"operation": "get_secret",
			"uid":       uid,
		})
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	if len(records) == 0 {
		return nil, errors.New("secret not found")
	}

	record := records[0]
	result := make(map[string]interface{})

	// Add basic metadata
	result["uid"] = record.Uid
	result["title"] = record.Title()
	result["type"] = record.Type()

	// Add requested fields
	if len(fields) == 0 {
		// Return all fields
		fields = []string{"login", "password", "url", "notes", "custom"}
	}

	for _, field := range fields {
		switch field {
		case "login":
			if values := record.GetFieldValuesByType("login"); len(values) > 0 {
				result["login"] = values[0]
			}
		case "password":
			if password := record.Password(); password != "" {
				if unmask {
					result["password"] = password
				} else {
					result["password"] = maskValue(password)
				}
			}
		case "url":
			if values := record.GetFieldValuesByType("url"); len(values) > 0 {
				result["url"] = values[0]
			}
		case "notes":
			if notes := record.Notes(); notes != "" {
				result["notes"] = notes
			}
		case "custom":
			// Handle custom fields
			customFields := make(map[string]interface{})
			// Try to get custom fields - the SDK might expose them differently
			// We'll use the raw record dictionary
			if recordDict := record.RecordDict; recordDict != nil {
				if customFieldsData, exists := recordDict["custom"]; exists {
					if customFieldsList, ok := customFieldsData.([]interface{}); ok {
						for _, field := range customFieldsList {
							if fieldMap, ok := field.(map[string]interface{}); ok {
								if label, hasLabel := fieldMap["label"].(string); hasLabel {
									if value, hasValue := fieldMap["value"]; hasValue {
										customFields[label] = value
									}
								}
							}
						}
					}
				}
			}
			if len(customFields) > 0 {
				result["custom_fields"] = customFields
			}
		}
	}

	return result, nil
}

// SearchSecrets searches for secrets by query
func (c *Client) SearchSecrets(query string) ([]*types.SecretMetadata, error) {
	// Validate query
	if err := c.validator.ValidateSearchQuery(query); err != nil {
		return nil, fmt.Errorf("invalid search query: %w", err)
	}

	// Log search
	c.logger.LogAccess("secrets", "search", "", c.profile, true, map[string]interface{}{
		"query_length": len(query),
	})

	// Get all secrets and filter
	records, err := c.sm.GetSecrets([]string{})
	if err != nil {
		return nil, fmt.Errorf("failed to search secrets: %w", err)
	}

	queryLower := strings.ToLower(query)
	var results []*types.SecretMetadata

	for _, record := range records {
		found := false
		
		// Search in title
		if strings.Contains(strings.ToLower(record.Title()), queryLower) {
			found = true
		}
		
		// Search in notes if not already found
		if !found && record.Notes() != "" {
			if strings.Contains(strings.ToLower(record.Notes()), queryLower) {
				found = true
			}
		}
		
		// Search in record type if not already found
		if !found && strings.Contains(strings.ToLower(record.Type()), queryLower) {
			found = true
		}
		
		// Search in field values if not already found
		if !found {
			// Check standard fields
			fieldTypes := []string{"login", "url", "hostname", "address"}
			for _, fieldType := range fieldTypes {
				if fieldValue := record.GetFieldValueByType(fieldType); fieldValue != "" {
					if strings.Contains(strings.ToLower(fieldValue), queryLower) {
						found = true
						break
					}
				}
			}
			
			// Check file attachments
			if !found && record.Files != nil {
				for _, file := range record.Files {
					if file.Name != "" && strings.Contains(strings.ToLower(file.Name), queryLower) {
						found = true
						break
					}
					if file.Title != "" && strings.Contains(strings.ToLower(file.Title), queryLower) {
						found = true
						break
					}
				}
			}
			
			// TODO: Add custom field search when SDK provides access
			// Currently the SDK doesn't expose a method to iterate custom fields
		}
		
		if found {
			results = append(results, &types.SecretMetadata{
				UID:    record.Uid,
				Title:  record.Title(),
				Type:   record.Type(),
				Folder: record.FolderUid(),
			})
		}
	}

	return results, nil
}

// GetField retrieves a specific field using KSM notation
func (c *Client) GetField(notation string, unmask bool) (interface{}, error) {
	// Validate notation
	if err := c.validator.ValidateKSMNotation(notation); err != nil {
		return nil, fmt.Errorf("invalid notation: %w", err)
	}

	// Parse notation
	parsedNotation, err := ParseNotation(notation)
	if err != nil {
		return nil, fmt.Errorf("failed to parse notation: %w", err)
	}

	// Log access
	c.logger.LogAccess("field", "get", notation, c.profile, true, map[string]interface{}{
		"masked": !unmask,
	})

	// Use SDK's notation support
	results, err := c.sm.GetNotation(notation)
	if err != nil {
		c.logger.LogError("ksm", err, map[string]interface{}{
			"operation": "get_field",
			"notation":  notation,
		})
		return nil, fmt.Errorf("failed to get field: %w", err)
	}

	// Process results based on type
	if len(results) > 0 {
		// For single values, return the first result
		if len(results) == 1 {
			value := results[0]
			if str, ok := value.(string); ok && !unmask && isSensitiveField(parsedNotation.Field) {
				return maskValue(str), nil
			}
			return value, nil
		}
		
		// For multiple values, mask if needed
		if !unmask && isSensitiveField(parsedNotation.Field) {
			maskedResults := make([]interface{}, len(results))
			for i, result := range results {
				if str, ok := result.(string); ok {
					maskedResults[i] = maskValue(str)
				} else {
					maskedResults[i] = result
				}
			}
			return maskedResults, nil
		}
		
		return results, nil
	}

	return nil, errors.New("field not found")
}

// GeneratePassword generates a secure password using KSM
func (c *Client) GeneratePassword(params types.GeneratePasswordParams) (string, error) {
	// Set defaults
	if params.Length == 0 {
		params.Length = 32
	}

	// Log password generation
	c.logger.LogSystem(audit.EventAccess, "Password generated", map[string]interface{}{
		"length": params.Length,
	})

	// Use SDK's password generation
	// Convert int params to string counts
	var lowercase, uppercase, digits, special string
	if params.Lowercase > 0 {
		lowercase = fmt.Sprintf("%d", params.Lowercase)
	} else {
		lowercase = "0"
	}
	if params.Uppercase > 0 {
		uppercase = fmt.Sprintf("%d", params.Uppercase)
	} else {
		uppercase = "0"
	}
	if params.Digits > 0 {
		digits = fmt.Sprintf("%d", params.Digits)
	} else {
		digits = "0"
	}
	if params.Special > 0 {
		special = fmt.Sprintf("%d", params.Special)
	} else {
		special = "0"
	}
	
	password, err := sm.GeneratePassword(
		params.Length,
		lowercase,
		uppercase,
		digits,
		special,
		params.SpecialSet, // Use custom special character set if provided
	)
	if err != nil {
		return "", fmt.Errorf("failed to generate password: %w", err)
	}

	if password == "" {
		return "", errors.New("failed to generate password")
	}

	return password, nil
}

// GetTOTPCode generates a TOTP code for a secret
func (c *Client) GetTOTPCode(uid string) (*types.TOTPResponse, error) {
	// Validate UID
	if err := c.validator.ValidateUID(uid); err != nil {
		return nil, fmt.Errorf("invalid UID: %w", err)
	}

	// Log TOTP access
	c.logger.LogSecretOperation(audit.EventSecretAccess, uid, "", c.profile, true, map[string]interface{}{
		"field": "totp",
	})

	// Get secret
	records, err := c.sm.GetSecrets([]string{uid})
	if err != nil || len(records) == 0 {
		return nil, errors.New("secret not found")
	}

	record := records[0]

	// Look for TOTP field
	// Try different field names where TOTP might be stored
	var totpURL string
	
	// Check standard fields
	if record.Password() != "" && strings.HasPrefix(record.Password(), "otpauth://") {
		totpURL = record.Password()
	}

	// Check custom fields for TOTP using the raw record dictionary
	if totpURL == "" && record.RecordDict != nil {
		if customFieldsData, exists := record.RecordDict["custom"]; exists {
			if customFieldsList, ok := customFieldsData.([]interface{}); ok {
				for _, field := range customFieldsList {
					if fieldMap, ok := field.(map[string]interface{}); ok {
						if fieldType, hasType := fieldMap["type"].(string); hasType && fieldType == "oneTimeCode" {
							if value, hasValue := fieldMap["value"]; hasValue {
								if values, ok := value.([]interface{}); ok && len(values) > 0 {
									if url, ok := values[0].(string); ok {
									totpURL = url
									break
								}
							}
						}
					}
				}
			}
		}
	}
	}

	if totpURL == "" {
		// Try using notation to get TOTP field
		totpNotation := fmt.Sprintf("%s/custom_field/oneTimeCode", uid)
		if results, err := c.sm.GetNotation(totpNotation); err == nil && len(results) > 0 {
			if url, ok := results[0].(string); ok {
				totpURL = url
			}
		}
	}

	if totpURL == "" {
		return nil, errors.New("no TOTP field found in secret")
	}

	// Generate TOTP code
	totpCode, err := sm.GetTotpCode(totpURL)
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP: %w", err)
	}

	return &types.TOTPResponse{
		Code:     totpCode.Code,
		TimeLeft: totpCode.TimeLeft,
	}, nil
}

// CreateSecret creates a new secret
func (c *Client) CreateSecret(params types.CreateSecretParams) (string, error) {
	// Validate parameters
	if params.Title == "" {
		return "", errors.New("title is required")
	}

	// Log creation attempt
	c.logger.LogSecretOperation(audit.EventSecretCreate, "", "", c.profile, true, map[string]interface{}{
		"title":  params.Title,
		"type":   params.Type,
		"folder": params.FolderUID,
	})

	// Create new record data
	recordData := sm.NewRecordCreate(params.Type, params.Title)
	
	// Set notes
	if params.Notes != "" {
		recordData.Notes = params.Notes
	}
	
	// Add fields from params
	var fields []interface{}
	for _, field := range params.Fields {
		fields = append(fields, map[string]interface{}{
			"type": field.Type,
			"value": field.Value,
		})
	}
	recordData.Fields = fields

	// Create the record
	uid, err := c.sm.CreateSecretWithRecordData("", params.FolderUID, recordData)
	if err != nil {
		c.logger.LogError("ksm", err, map[string]interface{}{
			"operation": "create_secret",
		})
		return "", fmt.Errorf("failed to create secret: %w", err)
	}

	return uid, nil
}

// UpdateSecret updates an existing secret
func (c *Client) UpdateSecret(params types.UpdateSecretParams) error {
	// Validate UID
	if err := c.validator.ValidateUID(params.UID); err != nil {
		return fmt.Errorf("invalid UID: %w", err)
	}

	// Log update attempt
	c.logger.LogSecretOperation(audit.EventSecretUpdate, params.UID, "", c.profile, true, nil)

	// Get existing record
	records, err := c.sm.GetSecrets([]string{params.UID})
	if err != nil || len(records) == 0 {
		return errors.New("secret not found")
	}

	record := records[0]

	// Update fields
	if params.Title != "" {
		record.SetTitle(params.Title)
	}
	for _, field := range params.Fields {
		if field.Type == "password" && len(field.Value) > 0 {
			if password, ok := field.Value[0].(string); ok {
				record.SetPassword(password)
			}
		} else if len(field.Value) > 0 {
			if value, ok := field.Value[0].(string); ok {
				record.SetFieldValueSingle(field.Type, value)
			}
		}
	}
	if params.Notes != "" {
		record.SetNotes(params.Notes)
	}

	// Save the record
	if err := c.sm.Save(record); err != nil {
		c.logger.LogError("ksm", err, map[string]interface{}{
			"operation": "update_secret",
			"uid":       params.UID,
		})
		return fmt.Errorf("failed to update secret: %w", err)
	}

	return nil
}

// DeleteSecret deletes a secret
func (c *Client) DeleteSecret(uid string, confirm bool) error {
	if !confirm {
		return errors.New("deletion must be confirmed")
	}

	// Validate UID
	if err := c.validator.ValidateUID(uid); err != nil {
		return fmt.Errorf("invalid UID: %w", err)
	}

	// Log deletion attempt
	c.logger.LogSecretOperation(audit.EventSecretDelete, uid, "", c.profile, true, nil)

	// Delete the record
	statuses, err := c.sm.DeleteSecrets([]string{uid})
	if err != nil {
		c.logger.LogError("ksm", err, map[string]interface{}{
			"operation": "delete_secret",
			"uid":       uid,
		})
		return fmt.Errorf("failed to delete secret: %w", err)
	}
	
	// Check if deletion was successful
	if status, exists := statuses[uid]; exists && status != "success" {
		return fmt.Errorf("failed to delete secret: %s", status)
	}

	return nil
}

// UploadFile uploads a file to a secret
func (c *Client) UploadFile(uid, filePath, title string) error {
	// Validate inputs
	if err := c.validator.ValidateUID(uid); err != nil {
		return fmt.Errorf("invalid UID: %w", err)
	}
	if err := c.validator.ValidateFilePath(filePath); err != nil {
		return fmt.Errorf("invalid file path: %w", err)
	}

	// Log upload attempt
	c.logger.LogAccess("file", "upload", uid, c.profile, true, map[string]interface{}{
		"file": filePath,
	})

	// Get the record
	records, err := c.sm.GetSecrets([]string{uid})
	if err != nil || len(records) == 0 {
		return errors.New("secret not found")
	}

	record := records[0]

	// Create file upload using the SDK function
	file, err := sm.GetFileForUpload(filePath, filePath, title, "")
	if err != nil {
		return fmt.Errorf("failed to prepare file for upload: %w", err)
	}
	
	// Upload the file
	fileUID, err := c.sm.UploadFile(record, file)
	if err != nil {
		c.logger.LogError("ksm", err, map[string]interface{}{
			"operation": "upload_file",
			"uid":       uid,
		})
		return fmt.Errorf("failed to upload file: %w", err)
	}
	
	_ = fileUID // File UID is available if needed

	return nil
}

// DownloadFile downloads a file from a secret
func (c *Client) DownloadFile(uid, fileUID, savePath string) error {
	// Validate inputs
	if err := c.validator.ValidateUID(uid); err != nil {
		return fmt.Errorf("invalid UID: %w", err)
	}

	// Log download attempt
	c.logger.LogAccess("file", "download", uid, c.profile, true, map[string]interface{}{
		"file_uid": fileUID,
	})

	// Get the record
	records, err := c.sm.GetSecrets([]string{uid})
	if err != nil || len(records) == 0 {
		return errors.New("secret not found")
	}

	record := records[0]

	// Find the file
	var targetFile *sm.KeeperFile
	
	for _, file := range record.Files {
		if file.Uid == fileUID || file.Title == fileUID {
			targetFile = file
			break
		}
	}

	if targetFile == nil {
		return errors.New("file not found")
	}

	// Download the file
	success := record.DownloadFile(targetFile.Uid, savePath)
	if !success {
		return errors.New("failed to download file")
	}

	return nil
}

// ListFolders lists all folders
func (c *Client) ListFolders() (*types.ListFoldersResponse, error) {
	// Log access
	c.logger.LogAccess("folders", "list", "", c.profile, true, nil)

	// Get folders from SDK
	folders, err := c.sm.GetFolders()
	if err != nil {
		return nil, fmt.Errorf("failed to list folders: %w", err)
	}

	// Convert to response format
	folderList := make([]types.FolderInfo, 0, len(folders))
	for _, folder := range folders {
		folderList = append(folderList, types.FolderInfo{
			UID:       folder.FolderUid,
			Name:      folder.Name,
			ParentUID: folder.ParentUid,
		})
	}

	return &types.ListFoldersResponse{
		Folders: folderList,
	}, nil
}

// CreateFolder creates a new folder
func (c *Client) CreateFolder(name, parentUID string) (string, error) {
	// Log creation attempt
	c.logger.LogAccess("folder", "create", "", c.profile, true, map[string]interface{}{
		"name":   name,
		"parent": parentUID,
	})

	// Get existing folders for parent validation
	folders, err := c.sm.GetFolders()
	if err != nil {
		return "", fmt.Errorf("failed to get folders: %w", err)
	}

	// Create folder
	options := sm.CreateOptions{
		FolderUid: parentUID,
	}

	folderUID, err := c.sm.CreateFolder(options, name, folders)
	if err != nil {
		c.logger.LogError("ksm", err, map[string]interface{}{
			"operation": "create_folder",
			"name":      name,
		})
		return "", fmt.Errorf("failed to create folder: %w", err)
	}

	return folderUID, nil
}

// TestConnection tests the KSM connection
func (c *Client) TestConnection() error {
	// Try to get secrets to test connection
	_, err := c.sm.GetSecrets([]string{})
	if err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}
	
	return nil
}

// Helper functions

// maskValue masks sensitive values
func maskValue(value string) string {
	if len(value) <= 6 {
		return "******"
	}
	return value[:3] + "***" + value[len(value)-3:]
}

// isSensitiveField checks if a field name is sensitive
func isSensitiveField(field string) bool {
	sensitiveFields := []string{
		"password", "secret", "key", "token", "privateKey",
		"cardNumber", "cardSecurityCode", "accountNumber",
		"pin", "passphrase", "auth",
	}
	
	fieldLower := strings.ToLower(field)
	for _, sensitive := range sensitiveFields {
		if strings.Contains(fieldLower, strings.ToLower(sensitive)) {
			return true
		}
	}
	return false
}