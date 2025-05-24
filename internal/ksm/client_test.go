package ksm

import (
	"testing"
	"time"

	"github.com/keeper-security/ksm-mcp/internal/audit"
	"github.com/keeper-security/ksm-mcp/pkg/types"
)

func TestMaskValue(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{"short value", "123", "******"},
		{"exact 6 chars", "123456", "******"},
		{"long value", "password123", "pas***123"},
		{"very long", "thisIsAVeryLongPassword123!", "thi***23!"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskValue(tt.value)
			if result != tt.expected {
				t.Errorf("maskValue(%s) = %s, want %s", tt.value, result, tt.expected)
			}
		})
	}
}

func TestIsSensitiveField(t *testing.T) {
	tests := []struct {
		name      string
		field     string
		sensitive bool
	}{
		{"password field", "password", true},
		{"secret field", "secret", true},
		{"api key", "apiKey", true},
		{"token", "accessToken", true},
		{"private key", "privateKey", true},
		{"card number", "cardNumber", true},
		{"pin", "pin", true},
		{"passphrase", "passphrase", true},

		{"username", "username", false},
		{"email", "email", false},
		{"title", "title", false},
		{"url", "url", false},
		{"notes", "notes", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSensitiveField(tt.field)
			if result != tt.sensitive {
				t.Errorf("isSensitiveField(%s) = %v, want %v", tt.field, result, tt.sensitive)
			}
		})
	}
}

func TestInitializeWithToken(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{"valid US token", "US:abcdef123456789012345678901234567890", false},
		{"valid EU token", "EU:abcdef123456789012345678901234567890", false},
		{"invalid token", "invalid", true},
		{"empty token", "", true},
		{"no region", "abcdef123456789012345678901234567890", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: This test will fail without a real KSM backend
			// In production, we'd use a mock or test server
			config, err := InitializeWithToken(tt.token)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				// Skip success case as it requires real KSM
				t.Skip("Requires real KSM connection")
			}

			_ = config // Suppress unused variable warning
		})
	}
}

func TestInitializeWithConfig(t *testing.T) {
	tests := []struct {
		name       string
		configJSON string
		wantErr    bool
	}{
		{
			"valid config",
			`{"clientId": "test123", "privateKey": "key123", "appKey": "app123"}`,
			false,
		},
		{
			"missing clientId",
			`{"privateKey": "key123", "appKey": "app123"}`,
			true,
		},
		{
			"invalid json",
			`{invalid json}`,
			true,
		},
		{
			"empty config",
			`{}`,
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := InitializeWithConfig([]byte(tt.configJSON))

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if config == nil {
					t.Error("Expected config but got nil")
				}
			}
		})
	}
}

func TestGeneratePasswordParams(t *testing.T) {
	// Test default values
	params := types.GeneratePasswordParams{}
	if params.Length != 0 {
		t.Errorf("Expected default length 0, got %d", params.Length)
	}

	// Test with values
	params = types.GeneratePasswordParams{
		Length:     16,
		Lowercase:  4,
		Uppercase:  4,
		Digits:     4,
		Special:    4,
		SpecialSet: "!@#$",
	}

	if params.Length != 16 {
		t.Errorf("Expected length 16, got %d", params.Length)
	}
}

func TestNewClient(t *testing.T) {
	// Create test logger
	logConfig := audit.Config{
		FilePath: t.TempDir() + "/test.log",
		MaxSize:  1024,
		MaxAge:   time.Hour,
	}
	logger, err := audit.NewLogger(logConfig)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	tests := []struct {
		name    string
		profile *types.Profile
		wantErr bool
	}{
		{
			"valid profile",
			&types.Profile{
				Name: "test",
				Config: map[string]string{
					"clientId":   "test123",
					"privateKey": "key123",
					"appKey":     "app123",
				},
			},
			false,
		},
		{
			"nil profile",
			nil,
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.profile, logger)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				// Skip success case as it may fail without real KSM
				if err != nil {
					t.Logf("Client creation failed (expected without real KSM): %v", err)
				}
				if client != nil && client.profile != tt.profile.Name {
					t.Errorf("Expected profile name %s, got %s", tt.profile.Name, client.profile)
				}
			}
		})
	}
}

func TestTOTPResponse(t *testing.T) {
	resp := &types.TOTPResponse{
		Code:     "123456",
		TimeLeft: 30,
	}

	if resp.Code != "123456" {
		t.Errorf("Expected code 123456, got %s", resp.Code)
	}

	if resp.TimeLeft != 30 {
		t.Errorf("Expected time left 30, got %d", resp.TimeLeft)
	}
}

func TestSecretMetadata(t *testing.T) {
	metadata := &types.SecretMetadata{
		UID:    "test-uid-123",
		Title:  "Test Secret",
		Type:   "login",
		Folder: "folder-123",
	}

	if metadata.UID != "test-uid-123" {
		t.Errorf("Expected UID test-uid-123, got %s", metadata.UID)
	}
}

func TestCreateSecretParams(t *testing.T) {
	params := types.CreateSecretParams{
		FolderUID: "folder-123",
		Type:      "login",
		Title:     "New Secret",
		Fields: []types.SecretField{
			{
				Type:  "login",
				Value: []interface{}{"user@example.com"},
			},
			{
				Type:  "password",
				Value: []interface{}{"secret123"},
			},
			{
				Type:  "url",
				Value: []interface{}{"https://example.com"},
			},
		},
		Notes: "Test notes",
	}

	if params.Title != "New Secret" {
		t.Errorf("Expected title 'New Secret', got %s", params.Title)
	}

	// Check login field
	found := false
	for _, field := range params.Fields {
		if field.Type == "login" && len(field.Value) > 0 {
			if login, ok := field.Value[0].(string); ok && login == "user@example.com" {
				found = true
				break
			}
		}
	}
	if !found {
		t.Error("Login field mismatch")
	}
}

func TestUpdateSecretParams(t *testing.T) {
	params := types.UpdateSecretParams{
		UID:   "test-uid-123",
		Title: "Updated Secret",
		Fields: []types.SecretField{
			{
				Type:  "password",
				Value: []interface{}{"newpassword123"},
			},
		},
		Notes: "Updated notes",
	}

	if params.UID != "test-uid-123" {
		t.Errorf("Expected UID test-uid-123, got %s", params.UID)
	}

	if params.Title != "Updated Secret" {
		t.Errorf("Expected title 'Updated Secret', got %s", params.Title)
	}
}

func TestDeleteSecretParams(t *testing.T) {
	// Test without confirmation
	params := types.DeleteSecretParams{
		UID:     "test-uid-123",
		Confirm: false,
	}

	if params.Confirm {
		t.Error("Expected confirm to be false")
	}

	// Test with confirmation
	params.Confirm = true
	if !params.Confirm {
		t.Error("Expected confirm to be true")
	}
}

func TestFileOperationParams(t *testing.T) {
	// Upload params
	uploadParams := types.UploadFileParams{
		UID:      "test-uid-123",
		FilePath: "/path/to/file.pdf",
		Title:    "Important Document",
	}

	if uploadParams.UID != "test-uid-123" {
		t.Errorf("Expected UID test-uid-123, got %s", uploadParams.UID)
	}

	// Download params
	downloadParams := types.DownloadFileParams{
		UID:      "test-uid-123",
		FileUID:  "file-uid-456",
		SavePath: "/path/to/save/",
	}

	if downloadParams.FileUID != "file-uid-456" {
		t.Errorf("Expected file UID file-uid-456, got %s", downloadParams.FileUID)
	}
}

func TestFolderOperations(t *testing.T) {
	// Folder info
	folder := types.FolderInfo{
		UID:       "folder-123",
		Name:      "Work",
		ParentUID: "parent-456",
	}

	if folder.Name != "Work" {
		t.Errorf("Expected folder name 'Work', got %s", folder.Name)
	}

	// List folders response
	response := types.ListFoldersResponse{
		Folders: []types.FolderInfo{folder},
	}

	if len(response.Folders) != 1 {
		t.Errorf("Expected 1 folder, got %d", len(response.Folders))
	}

	// Create folder params
	createParams := types.CreateFolderParams{
		Name:      "New Folder",
		ParentUID: "parent-123",
	}

	if createParams.Name != "New Folder" {
		t.Errorf("Expected folder name 'New Folder', got %s", createParams.Name)
	}
}
