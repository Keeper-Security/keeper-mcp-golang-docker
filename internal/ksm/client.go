package ksm

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/keeper-security/ksm-mcp/internal/audit"
	"github.com/keeper-security/ksm-mcp/internal/validation"
	"github.com/keeper-security/ksm-mcp/pkg/types"
	sm "github.com/keeper-security/secrets-manager-go/core"
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
	if c.logger != nil {
		c.logAccess("secrets", "list", "", c.profile, true, map[string]interface{}{
			"folder": folderUID,
		})
	}

	// Get all secrets
	records, err := c.sm.GetSecrets([]string{})
	if err != nil {
		if c.logger != nil {
			c.logError("ksm", err, map[string]interface{}{
				"operation": "list_secrets",
			})
		}
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
	if c.logger != nil {
		c.logSecretOperation(audit.EventSecretAccess, uid, "", c.profile, true, map[string]interface{}{
			"fields": fields,
			"masked": !unmask,
		})
	}

	// Get secret
	records, err := c.sm.GetSecrets([]string{uid})
	if err != nil {
		c.logError("ksm", err, map[string]interface{}{
			"operation": "get_secret",
			"uid":       uid,
		})
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	if len(records) == 0 {
		return nil, errors.New("secret not found")
	}

	// Handle duplicates - just use the first one since they're the same record
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
			// First try the standard Password() method
			if password := record.Password(); password != "" {
				if unmask {
					result["password"] = password
				} else {
					result["password"] = maskValue(password)
				}
			} else {
				// For database credentials and other types, check field values
				if values := record.GetFieldValuesByType("password"); len(values) > 0 {
					if unmask {
						result["password"] = values[0]
					} else {
						result["password"] = maskValue(values[0])
					}
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
	if c.logger != nil {
		c.logAccess("secrets", "search", "", c.profile, true, map[string]interface{}{
			"query_length": len(query),
		})
	}

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
	if c.logger != nil {
		c.logAccess("field", "get", notation, c.profile, true, map[string]interface{}{
			"masked": !unmask,
		})
	}

	// Try to use SDK's notation support first
	results, err := c.sm.GetNotation(notation)
	if err != nil {
		// Check if it's a duplicate record error
		if strings.Contains(err.Error(), "multiple records") || strings.Contains(err.Error(), "found multiple records") {
			// Handle duplicates by getting records manually
			return c.getFieldFromDuplicates(parsedNotation, unmask)
		}

		if c.logger != nil {
			c.logError("ksm", err, map[string]interface{}{
				"operation": "get_field",
				"notation":  notation,
			})
		}
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

// getFieldFromDuplicates handles getting field from duplicate records
func (c *Client) getFieldFromDuplicates(parsedNotation *types.NotationResult, unmask bool) (interface{}, error) {
	// Get all records
	records, err := c.sm.GetSecrets([]string{})
	if err != nil {
		return nil, fmt.Errorf("failed to get records: %w", err)
	}

	// Find matching records by UID or title
	var matchingRecords []*sm.Record
	for _, record := range records {
		if parsedNotation.UID != "" && record.Uid == parsedNotation.UID {
			matchingRecords = append(matchingRecords, record)
		} else if parsedNotation.Title != "" && record.Title() == parsedNotation.Title {
			matchingRecords = append(matchingRecords, record)
		}
	}

	if len(matchingRecords) == 0 {
		return nil, errors.New("record not found")
	}

	// Use the first matching record (they're all the same)
	record := matchingRecords[0]

	// Extract the field value
	var indexPtr *int
	if parsedNotation.Index > 0 {
		indexPtr = &parsedNotation.Index
	}
	fieldValue, err := c.extractFieldValue(record, parsedNotation.Field, indexPtr)
	if err != nil {
		return nil, err
	}

	// Handle masking
	if !unmask && isSensitiveField(parsedNotation.Field) {
		if str, ok := fieldValue.(string); ok {
			return maskValue(str), nil
		}
	}

	return fieldValue, nil
}

// extractFieldValue extracts a specific field value from a record
func (c *Client) extractFieldValue(record *sm.Record, field string, index *int) (interface{}, error) {
	switch field {
	case "password":
		// First try the standard Password() method
		if password := record.Password(); password != "" {
			return password, nil
		}
		// For database credentials and other types, check field values
		values := record.GetFieldValuesByType("password")
		if len(values) > 0 {
			if index != nil && *index < len(values) {
				return values[*index], nil
			}
			return values[0], nil
		}
		return "", nil
	case "login":
		values := record.GetFieldValuesByType("login")
		if len(values) > 0 {
			if index != nil && *index < len(values) {
				return values[*index], nil
			}
			return values[0], nil
		}
	case "url":
		values := record.GetFieldValuesByType("url")
		if len(values) > 0 {
			if index != nil && *index < len(values) {
				return values[*index], nil
			}
			return values[0], nil
		}
	case "notes":
		return record.Notes(), nil
	default:
		// Try custom fields
		if record.RecordDict != nil {
			if customFieldsData, exists := record.RecordDict["custom"]; exists {
				if customFieldsList, ok := customFieldsData.([]interface{}); ok {
					for _, fieldData := range customFieldsList {
						if fieldMap, ok := fieldData.(map[string]interface{}); ok {
							if label, hasLabel := fieldMap["label"].(string); hasLabel && label == field {
								if value, hasValue := fieldMap["value"]; hasValue {
									return value, nil
								}
							}
						}
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("field '%s' not found", field)
}

// GeneratePassword generates a secure password using KSM
func (c *Client) GeneratePassword(params types.GeneratePasswordParams) (string, error) {
	// Set defaults
	if params.Length == 0 {
		params.Length = 32
	}

	// Log password generation
	c.logSystem(audit.EventAccess, "Password generated", map[string]interface{}{
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
	c.logSecretOperation(audit.EventSecretAccess, uid, "", c.profile, true, map[string]interface{}{
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
	if params.FolderUID == "" {
		// This case should ideally be caught by the MCP handler before calling the client method,
		// or the handler should determine a default folder UID.
		// If it reaches here, it means no folder was specified by the caller of this client method.
		return "", errors.New("folderUID is required to create a secret")
	}

	c.logSecretOperation(audit.EventSecretCreate, "", "", c.profile, true, map[string]interface{}{
		"title":  params.Title,
		"type":   params.Type,
		"folder": params.FolderUID, // This is the target folder where user wants the secret
	})

	// Prepare record data
	recordData := sm.NewRecordCreate(params.Type, params.Title)
	if params.Notes != "" {
		recordData.Notes = params.Notes
	}
	var fields []interface{}
	for _, field := range params.Fields {
		fields = append(fields, map[string]interface{}{
			"type":  field.Type,
			"value": field.Value,
		})
	}
	recordData.Fields = fields

	// Get all folders for context and to determine shared parent for SDK options
	allKeeperFolders, err := c.sm.GetFolders() // SDK type: []*sm.KeeperFolder
	if err != nil {
		c.logError("ksm", err, map[string]interface{}{
			"operation": "CreateSecret_GetFolders",
			"title":     params.Title,
		})
		return "", fmt.Errorf("failed to list folders while preparing to create secret '%s': %w", params.Title, err)
	}

	// Determine SDK CreateOptions based on the target params.FolderUID
	sdkCreateOptions := sm.CreateOptions{}
	foundTargetFolder := false

	for _, kf := range allKeeperFolders {
		if kf.FolderUid == params.FolderUID {
			foundTargetFolder = true
			if kf.ParentUid != "" { // Our target folder has a parent
				sdkCreateOptions.FolderUid = kf.ParentUid        // The direct parent becomes the main FolderUid for CreateOptions
				sdkCreateOptions.SubFolderUid = params.FolderUID // Our target is the SubFolderUid
			} else { // Our target folder is a root folder (no parent UID)
				sdkCreateOptions.FolderUid = params.FolderUID // Target itself is the main FolderUid
				sdkCreateOptions.SubFolderUid = ""            // No sub-folder in this context for the SDK call
			}
			break
		}
	}

	// If targetFolderUID was not found in allKeeperFolders, it implies it might be a shared folder itself that wasn't listed as a sub-folder of anything.
	// Or it's an invalid FolderUID. The SDK call will ultimately determine validity.
	if !foundTargetFolder {
		c.logSystem(audit.EventAccess, fmt.Sprintf("Target folder %s not found in GetFolders list; assuming it is the main shared folder for SDK CreateOptions or will be handled by SDK.", params.FolderUID), map[string]interface{}{"profile": c.profile, "target_folder_uid": params.FolderUID})
		sdkCreateOptions.FolderUid = params.FolderUID // Assume user-provided UID is the main shared folder context
		sdkCreateOptions.SubFolderUid = ""            // If it's the main shared folder, SubFolderUid is empty for the SDK.
	}

	c.logSystem(audit.EventAccess, "Attempting CreateSecretWithRecordDataAndOptions", map[string]interface{}{
		"title":              params.Title,
		"sdk_folder_uid":     sdkCreateOptions.FolderUid,
		"sdk_sub_folder_uid": sdkCreateOptions.SubFolderUid,
		"profile":            c.profile,
	})

	// Create the record using the more specific SDK call
	// The SDK expects a pointer to CreateOptions
	uid, err := c.sm.CreateSecretWithRecordDataAndOptions(&sdkCreateOptions, recordData, allKeeperFolders)
	if err != nil {
		c.logError("ksm", err, map[string]interface{}{
			"operation":          "CreateSecretWithRecordDataAndOptions",
			"title":              params.Title,
			"target_folder_uid":  params.FolderUID, // User's intended folder
			"sdk_folder_uid":     sdkCreateOptions.FolderUid,
			"sdk_sub_folder_uid": sdkCreateOptions.SubFolderUid,
		})
		return "", fmt.Errorf("failed to create secret '%s' using CreateSecretWithRecordDataAndOptions: %w", params.Title, err)
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
	c.logSecretOperation(audit.EventSecretUpdate, params.UID, "", c.profile, true, nil)

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
		c.logError("ksm", err, map[string]interface{}{
			"operation": "update_secret",
			"uid":       params.UID,
		})
		return fmt.Errorf("failed to update secret: %w", err)
	}

	return nil
}

// DeleteSecret deletes a secret
func (c *Client) DeleteSecret(uid string, permanent bool) error { // KSM SDK permanent is 'force'
	// Note: The 'permanent' flag is for MCP layer consistency.
	// The underlying KSM SDK DeleteSecrets call used here does not explicitly take a 'force' boolean
	// in its most basic documented form. Deletion is generally permanent.
	if !permanent {
		c.logSystem(audit.EventAccess, "DeleteSecret called with permanent=false by handler; KSM SDK delete is typically permanent.", map[string]interface{}{
			"uid": uid,
		})
	}

	// Validate UID
	if err := c.validator.ValidateUID(uid); err != nil {
		return fmt.Errorf("invalid UID: %w", err)
	}

	// Log deletion attempt
	c.logSecretOperation(audit.EventSecretDelete, uid, "", c.profile, true, nil)

	// Delete the record
	statuses, err := c.sm.DeleteSecrets([]string{uid}) // Basic call, assuming no direct force flag here or handled by SDK default
	if err != nil {
		c.logError("ksm", err, map[string]interface{}{
			"operation": "delete_secret",
			"uid":       uid,
		})
		return fmt.Errorf("failed to delete secret during SDK call for UID %s: %w", uid, err)
	}

	// Check if deletion was successful for the specific UID
	status, exists := statuses[uid]
	if !exists {
		c.logSystem(audit.EventAccess, fmt.Sprintf("DeleteSecret status for UID %s not found in SDK response, though SDK call had no error.", uid), map[string]interface{}{
			"uid": uid, "statuses_map": statuses,
		})
		return fmt.Errorf("failed to confirm delete secret status for UID %s (not found in status map: %v)", uid, statuses)
	}

	// Treat "success" and "ok" as successful deletion statuses.
	if status != "success" && status != "ok" {
		c.logSystem(audit.EventError, fmt.Sprintf("DeleteSecret status for UID %s was '%s', not 'success' or 'ok'.", uid, status), map[string]interface{}{
			"uid": uid, "status": status,
		})
		return fmt.Errorf("failed to delete secret: KSM reported status '%s' for UID %s", status, uid)
	}

	c.logSystem(audit.EventAccess, fmt.Sprintf("DeleteSecret successful for UID %s with KSM status '%s'", uid, status), map[string]interface{}{
		"uid": uid, "status": status,
	})
	return nil // Success
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
	c.logAccess("file", "upload", uid, c.profile, true, map[string]interface{}{
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
		c.logError("ksm", err, map[string]interface{}{
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
	c.logAccess("file", "download", uid, c.profile, true, map[string]interface{}{
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
	c.logAccess("folders", "list", "", c.profile, true, nil)

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
	c.logAccess("folder", "create", "", c.profile, true, map[string]interface{}{
		"name":   name,
		"parent": parentUID,
	})

	// Get existing folders for context and validation (SDK might use this)
	allKeeperFolders, err := c.sm.GetFolders()
	if err != nil {
		return "", fmt.Errorf("failed to get folders prior to creating folder '%s': %w", name, err)
	}

	if parentUID == "" {
		c.logSystem(audit.EventError, "CreateFolder: parentUID is empty. KSM API requires a parent shared folder UID for folder creation.", map[string]interface{}{"name": name, "profile": c.profile})
		return "", fmt.Errorf("failed to create folder '%s': a parent folder UID (parent_uid) is required by KSM. This usually needs to be a Shared Folder UID", name)
	}

	options := sm.CreateOptions{
		FolderUid:    parentUID, // The UID of the folder under which the new folder will be created.
		SubFolderUid: "",        // If creating directly under FolderUid, SubFolderUid is empty for this SDK call.
	}

	folderUID, err := c.sm.CreateFolder(options, name, allKeeperFolders) // Pass allKeeperFolders
	if err != nil {
		c.logError("ksm", err, map[string]interface{}{
			"operation":  "create_folder",
			"name":       name,
			"parent_uid": parentUID,
			"profile":    c.profile,
		})
		return "", fmt.Errorf("failed to create folder '%s' under parent '%s': %w", name, parentUID, err)
	}

	// The KSM SDK for Go might return an empty string for folderUID even on success in some cases (e.g. if the folder already exists with the same name in the same location).
	// However, for a truly new folder, a UID is expected.
	if folderUID == "" {
		// Let's try to find the folder by name under the parent to confirm if it was indeed created or already existed.
		// This is a workaround for SDK potentially not returning UID consistently on create if it behaves like an upsert.
		var foundExistingByName = false
		updatedFolders, listErr := c.sm.GetFolders()
		if listErr == nil {
			for _, kf := range updatedFolders {
				if kf.Name == name && kf.ParentUid == parentUID {
					folderUID = kf.FolderUid // Found it, use its UID.
					foundExistingByName = true
					c.logSystem(audit.EventAccess, fmt.Sprintf("CreateFolder: KSM SDK returned empty UID for folder '%s', but found existing/newly created folder by name with UID %s.", name, folderUID), map[string]interface{}{})
					break
				}
			}
		}

		if !foundExistingByName {
			c.logSystem(audit.EventError, "CreateFolder: KSM SDK returned empty folderUID without an error, and folder was not found by name.", map[string]interface{}{"name": name, "parent_uid": parentUID, "profile": c.profile})
			return "", fmt.Errorf("KSM SDK returned an empty UID for new folder '%s' and it could not be subsequently found by name", name)
		}
	}

	c.logSystem(audit.EventAccess, fmt.Sprintf("Folder '%s' (UID: %s) (operation successful or folder already existed) under parent %s", name, folderUID, parentUID), map[string]interface{}{"profile": c.profile})
	return folderUID, nil
}

// DeleteFolder deletes a folder by UID, optionally forcing if non-empty.
func (c *Client) DeleteFolder(uid string, force bool) error {
	c.logAccess("folder", "delete", uid, c.profile, true, map[string]interface{}{
		"force": force,
	})

	if err := c.validator.ValidateUID(uid); err != nil {
		return fmt.Errorf("invalid folder UID for delete: %w", err)
	}

	statuses, err := c.sm.DeleteFolder([]string{uid}, force)
	if err != nil {
		c.logError("ksm", err, map[string]interface{}{
			"operation":  "delete_folder_sdk_call",
			"folder_uid": uid,
			"force":      force,
			"profile":    c.profile,
		})
		return fmt.Errorf("KSM SDK failed to delete folder '%s': %w", uid, err)
	}

	// Check status for the specific UID
	status, exists := statuses[uid]
	if !exists {
		c.logSystem(audit.EventError, fmt.Sprintf("DeleteFolder status for UID %s not found in SDK response.", uid), map[string]interface{}{
			"folder_uid":   uid,
			"force":        force,
			"statuses_map": statuses,
			"profile":      c.profile,
		})
		return fmt.Errorf("failed to confirm delete status for folder '%s', UID not in status map: %v", uid, statuses)
	}

	// Based on DeleteSecret, "success" or "ok" should be fine. SDK might also return empty status on success.
	if status != "success" && status != "ok" && status != "" {
		c.logSystem(audit.EventError, fmt.Sprintf("DeleteFolder status for UID %s was '%s'.", uid, status), map[string]interface{}{
			"folder_uid": uid,
			"force":      force,
			"status":     status,
			"profile":    c.profile,
		})
		return fmt.Errorf("failed to delete folder '%s': KSM reported status '%s'", uid, status)
	}

	c.logSystem(audit.EventAccess, fmt.Sprintf("Folder '%s' deleted successfully with status '%s'.", uid, status), map[string]interface{}{
		"folder_uid": uid,
		"status":     status,
		"profile":    c.profile,
	})
	return nil
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

// Helper logging methods that handle nil logger checks
func (c *Client) logAccess(resource, action, notation, profile string, allowed bool, details map[string]interface{}) {
	if c.logger != nil {
		c.logger.LogAccess(resource, action, notation, profile, allowed, details)
	}
}

func (c *Client) logSecretOperation(operation audit.EventType, uid, user, profile string, success bool, details map[string]interface{}) {
	if c.logger != nil {
		c.logger.LogSecretOperation(operation, uid, user, profile, success, details)
	}
}

func (c *Client) logError(source string, err error, details map[string]interface{}) {
	if c.logger != nil {
		c.logger.LogError(source, err, details)
	}
}

func (c *Client) logSystem(eventType audit.EventType, message string, details map[string]interface{}) {
	if c.logger != nil {
		c.logger.LogSystem(eventType, message, details)
	}
}
