package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/keeper-security/ksm-mcp/internal/audit"
	"github.com/keeper-security/ksm-mcp/internal/ksm"
	"github.com/keeper-security/ksm-mcp/internal/ui"
	"github.com/keeper-security/ksm-mcp/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock KSM Client
type mockKSMClient struct {
	mock.Mock
}

func (m *mockKSMClient) ListSecrets(folderUID string) ([]*types.SecretMetadata, error) {
	args := m.Called(folderUID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*types.SecretMetadata), args.Error(1)
}

func (m *mockKSMClient) GetSecret(uid string, fields []string, unmask bool) (map[string]interface{}, error) {
	args := m.Called(uid, fields, unmask)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *mockKSMClient) SearchSecrets(query string) ([]*types.SecretMetadata, error) {
	args := m.Called(query)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*types.SecretMetadata), args.Error(1)
}

func (m *mockKSMClient) CreateSecret(params types.CreateSecretParams) (string, error) {
	args := m.Called(params)
	return args.String(0), args.Error(1)
}

func (m *mockKSMClient) UpdateSecret(params types.UpdateSecretParams) error {
	args := m.Called(params)
	return args.Error(0)
}

func (m *mockKSMClient) DeleteSecret(uid string, permanent bool) error {
	args := m.Called(uid, permanent)
	return args.Error(0)
}

func (m *mockKSMClient) GeneratePassword(params types.GeneratePasswordParams) (string, error) {
	args := m.Called(params)
	return args.String(0), args.Error(1)
}

// Mock Confirmer
type mockConfirmer struct {
	mock.Mock
}

func (m *mockConfirmer) Confirm(ctx context.Context, message string) ui.ConfirmationResult {
	args := m.Called(ctx, message)
	return args.Get(0).(ui.ConfirmationResult)
}

func (m *mockConfirmer) ConfirmSensitiveOperation(ctx context.Context, operation, resource string) ui.ConfirmationResult {
	args := m.Called(ctx, operation, resource)
	return args.Get(0).(ui.ConfirmationResult)
}

// Test CREATE operation
func TestExecuteCreateSecret(t *testing.T) {
	tests := []struct {
		name        string
		args        json.RawMessage
		confirm     bool
		expectError bool
		mockSetup   func(*mockKSMClient, *mockConfirmer)
	}{
		{
			name:        "successful create",
			args:        json.RawMessage(`{"type":"login","title":"Test Secret","fields":[]}`),
			confirm:     true,
			expectError: false,
			mockSetup: func(client *mockKSMClient, confirmer *mockConfirmer) {
				confirmer.On("Confirm", mock.Anything, "Create new secret 'Test Secret'?").
					Return(ui.ConfirmationResult{Approved: true})
				client.On("CreateSecret", mock.MatchedBy(func(p types.CreateSecretParams) bool {
					return p.Title == "Test Secret" && p.Type == "login"
				})).Return("test-uid-123", nil)
			},
		},
		{
			name:        "user denies confirmation",
			args:        json.RawMessage(`{"type":"login","title":"Test Secret","fields":[]}`),
			confirm:     false,
			expectError: true,
			mockSetup: func(client *mockKSMClient, confirmer *mockConfirmer) {
				confirmer.On("Confirm", mock.Anything, "Create new secret 'Test Secret'?").
					Return(ui.ConfirmationResult{Approved: false})
			},
		},
		{
			name:        "invalid JSON parameters",
			args:        json.RawMessage(`{"invalid json`),
			expectError: true,
			mockSetup:   func(client *mockKSMClient, confirmer *mockConfirmer) {},
		},
		{
			name:        "KSM client error",
			args:        json.RawMessage(`{"type":"login","title":"Test Secret","fields":[]}`),
			confirm:     true,
			expectError: true,
			mockSetup: func(client *mockKSMClient, confirmer *mockConfirmer) {
				confirmer.On("Confirm", mock.Anything, "Create new secret 'Test Secret'?").
					Return(ui.ConfirmationResult{Approved: true})
				client.On("CreateSecret", mock.Anything).Return("", errors.New("KSM error"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := new(mockKSMClient)
			mockConfirmer := new(mockConfirmer)
			
			server := &Server{
				confirmer: mockConfirmer,
				logger:    audit.NewLogger("test", "test"),
			}

			tt.mockSetup(mockClient, mockConfirmer)

			result, err := server.executeCreateSecret(mockClient, tt.args)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				resultMap := result.(map[string]interface{})
				assert.Equal(t, "test-uid-123", resultMap["uid"])
				assert.Equal(t, "Test Secret", resultMap["title"])
			}

			mockClient.AssertExpectations(t)
			mockConfirmer.AssertExpectations(t)
		})
	}
}

// Test READ operations (list and get)
func TestExecuteListSecrets(t *testing.T) {
	tests := []struct {
		name        string
		args        json.RawMessage
		expectError bool
		mockSetup   func(*mockKSMClient)
		validate    func(*testing.T, interface{})
	}{
		{
			name:        "successful list all secrets",
			args:        json.RawMessage(`{}`),
			expectError: false,
			mockSetup: func(client *mockKSMClient) {
				client.On("ListSecrets", "").Return([]*types.SecretMetadata{
					{UID: "uid1", Title: "Secret 1", Type: "login"},
					{UID: "uid2", Title: "Secret 2", Type: "password"},
				}, nil)
			},
			validate: func(t *testing.T, result interface{}) {
				resultMap := result.(map[string]interface{})
				assert.Equal(t, 2, resultMap["count"])
				secrets := resultMap["secrets"].([]map[string]interface{})
				assert.Len(t, secrets, 2)
				assert.Equal(t, "uid1", secrets[0]["uid"])
				assert.Equal(t, "Secret 1", secrets[0]["title"])
			},
		},
		{
			name:        "list with folder filter",
			args:        json.RawMessage(`{"folder_uid":"folder123"}`),
			expectError: false,
			mockSetup: func(client *mockKSMClient) {
				client.On("ListSecrets", "folder123").Return([]*types.SecretMetadata{
					{UID: "uid1", Title: "Secret 1", Type: "login", Folder: "folder123"},
				}, nil)
			},
			validate: func(t *testing.T, result interface{}) {
				resultMap := result.(map[string]interface{})
				assert.Equal(t, 1, resultMap["count"])
			},
		},
		{
			name:        "KSM client error",
			args:        json.RawMessage(`{}`),
			expectError: true,
			mockSetup: func(client *mockKSMClient) {
				client.On("ListSecrets", "").Return(nil, errors.New("KSM error"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := new(mockKSMClient)
			server := &Server{
				logger: audit.NewLogger("test", "test"),
			}

			tt.mockSetup(mockClient)

			result, err := server.executeListSecrets(mockClient, tt.args)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, result)
				}
			}

			mockClient.AssertExpectations(t)
		})
	}
}

func TestExecuteGetSecret(t *testing.T) {
	tests := []struct {
		name        string
		args        json.RawMessage
		expectError bool
		mockSetup   func(*mockKSMClient, *mockConfirmer)
	}{
		{
			name:        "get secret masked",
			args:        json.RawMessage(`{"uid":"test-uid","unmask":false}`),
			expectError: false,
			mockSetup: func(client *mockKSMClient, confirmer *mockConfirmer) {
				client.On("GetSecret", "test-uid", []string(nil), false).Return(map[string]interface{}{
					"uid":   "test-uid",
					"title": "Test Secret",
					"type":  "login",
				}, nil)
			},
		},
		{
			name:        "get secret unmasked with confirmation",
			args:        json.RawMessage(`{"uid":"test-uid","unmask":true}`),
			expectError: false,
			mockSetup: func(client *mockKSMClient, confirmer *mockConfirmer) {
				confirmer.On("Confirm", mock.Anything, "Reveal unmasked secret test-uid?").
					Return(ui.ConfirmationResult{Approved: true})
				client.On("GetSecret", "test-uid", []string(nil), true).Return(map[string]interface{}{
					"uid":      "test-uid",
					"title":    "Test Secret",
					"password": "actual-password",
				}, nil)
			},
		},
		{
			name:        "get secret unmasked denied",
			args:        json.RawMessage(`{"uid":"test-uid","unmask":true}`),
			expectError: true,
			mockSetup: func(client *mockKSMClient, confirmer *mockConfirmer) {
				confirmer.On("Confirm", mock.Anything, "Reveal unmasked secret test-uid?").
					Return(ui.ConfirmationResult{Approved: false})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := new(mockKSMClient)
			mockConfirmer := new(mockConfirmer)
			server := &Server{
				confirmer: mockConfirmer,
				logger:    audit.NewLogger("test", "test"),
			}

			tt.mockSetup(mockClient, mockConfirmer)

			result, err := server.executeGetSecret(mockClient, tt.args)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}

			mockClient.AssertExpectations(t)
			mockConfirmer.AssertExpectations(t)
		})
	}
}

// Test UPDATE operation
func TestExecuteUpdateSecret(t *testing.T) {
	tests := []struct {
		name        string
		args        json.RawMessage
		expectError bool
		mockSetup   func(*mockKSMClient, *mockConfirmer)
	}{
		{
			name:        "successful update",
			args:        json.RawMessage(`{"uid":"test-uid","title":"Updated Title","fields":[]}`),
			expectError: false,
			mockSetup: func(client *mockKSMClient, confirmer *mockConfirmer) {
				confirmer.On("Confirm", mock.Anything, "Update secret test-uid?").
					Return(ui.ConfirmationResult{Approved: true})
				client.On("UpdateSecret", mock.MatchedBy(func(p types.UpdateSecretParams) bool {
					return p.UID == "test-uid" && p.Title == "Updated Title"
				})).Return(nil)
			},
		},
		{
			name:        "update denied by user",
			args:        json.RawMessage(`{"uid":"test-uid","title":"Updated Title"}`),
			expectError: true,
			mockSetup: func(client *mockKSMClient, confirmer *mockConfirmer) {
				confirmer.On("Confirm", mock.Anything, "Update secret test-uid?").
					Return(ui.ConfirmationResult{Approved: false})
			},
		},
		{
			name:        "KSM update error",
			args:        json.RawMessage(`{"uid":"test-uid","title":"Updated Title"}`),
			expectError: true,
			mockSetup: func(client *mockKSMClient, confirmer *mockConfirmer) {
				confirmer.On("Confirm", mock.Anything, "Update secret test-uid?").
					Return(ui.ConfirmationResult{Approved: true})
				client.On("UpdateSecret", mock.Anything).Return(errors.New("update failed"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := new(mockKSMClient)
			mockConfirmer := new(mockConfirmer)
			server := &Server{
				confirmer: mockConfirmer,
				logger:    audit.NewLogger("test", "test"),
			}

			tt.mockSetup(mockClient, mockConfirmer)

			result, err := server.executeUpdateSecret(mockClient, tt.args)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				resultMap := result.(map[string]interface{})
				assert.Equal(t, "test-uid", resultMap["uid"])
				assert.Equal(t, "Secret updated successfully", resultMap["message"])
			}

			mockClient.AssertExpectations(t)
			mockConfirmer.AssertExpectations(t)
		})
	}
}

// Test DELETE operation
func TestExecuteDeleteSecret(t *testing.T) {
	tests := []struct {
		name        string
		args        json.RawMessage
		expectError bool
		mockSetup   func(*mockKSMClient, *mockConfirmer)
	}{
		{
			name:        "successful delete with double confirmation",
			args:        json.RawMessage(`{"uid":"test-uid"}`),
			expectError: false,
			mockSetup: func(client *mockKSMClient, confirmer *mockConfirmer) {
				confirmer.On("Confirm", mock.Anything, "Delete secret test-uid? This cannot be undone!").
					Return(ui.ConfirmationResult{Approved: true})
				confirmer.On("Confirm", mock.Anything, "Are you absolutely sure? Type 'yes' to confirm deletion.").
					Return(ui.ConfirmationResult{Approved: true})
				client.On("DeleteSecret", "test-uid", true).Return(nil)
			},
		},
		{
			name:        "delete denied on first confirmation",
			args:        json.RawMessage(`{"uid":"test-uid"}`),
			expectError: true,
			mockSetup: func(client *mockKSMClient, confirmer *mockConfirmer) {
				confirmer.On("Confirm", mock.Anything, "Delete secret test-uid? This cannot be undone!").
					Return(ui.ConfirmationResult{Approved: false})
			},
		},
		{
			name:        "delete denied on second confirmation",
			args:        json.RawMessage(`{"uid":"test-uid"}`),
			expectError: true,
			mockSetup: func(client *mockKSMClient, confirmer *mockConfirmer) {
				confirmer.On("Confirm", mock.Anything, "Delete secret test-uid? This cannot be undone!").
					Return(ui.ConfirmationResult{Approved: true})
				confirmer.On("Confirm", mock.Anything, "Are you absolutely sure? Type 'yes' to confirm deletion.").
					Return(ui.ConfirmationResult{Approved: false})
			},
		},
		{
			name:        "KSM delete error",
			args:        json.RawMessage(`{"uid":"test-uid"}`),
			expectError: true,
			mockSetup: func(client *mockKSMClient, confirmer *mockConfirmer) {
				confirmer.On("Confirm", mock.Anything, mock.Anything).
					Return(ui.ConfirmationResult{Approved: true})
				client.On("DeleteSecret", "test-uid", true).Return(errors.New("delete failed"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := new(mockKSMClient)
			mockConfirmer := new(mockConfirmer)
			server := &Server{
				confirmer: mockConfirmer,
				logger:    audit.NewLogger("test", "test"),
			}

			tt.mockSetup(mockClient, mockConfirmer)

			result, err := server.executeDeleteSecret(mockClient, tt.args)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				resultMap := result.(map[string]interface{})
				assert.Equal(t, "test-uid", resultMap["uid"])
				assert.Equal(t, "Secret deleted successfully", resultMap["message"])
			}

			mockClient.AssertExpectations(t)
			mockConfirmer.AssertExpectations(t)
		})
	}
}

// Test Search operation
func TestExecuteSearchSecrets(t *testing.T) {
	tests := []struct {
		name        string
		args        json.RawMessage
		expectError bool
		mockSetup   func(*mockKSMClient)
		validate    func(*testing.T, interface{})
	}{
		{
			name:        "successful search",
			args:        json.RawMessage(`{"query":"password"}`),
			expectError: false,
			mockSetup: func(client *mockKSMClient) {
				client.On("SearchSecrets", "password").Return([]*types.SecretMetadata{
					{UID: "uid1", Title: "Admin Password", Type: "password"},
					{UID: "uid2", Title: "DB Password", Type: "password"},
				}, nil)
			},
			validate: func(t *testing.T, result interface{}) {
				resultMap := result.(map[string]interface{})
				assert.Equal(t, 2, resultMap["count"])
				results := resultMap["results"].([]map[string]interface{})
				assert.Len(t, results, 2)
				assert.Equal(t, "uid1", results[0]["uid"])
			},
		},
		{
			name:        "empty search results",
			args:        json.RawMessage(`{"query":"nonexistent"}`),
			expectError: false,
			mockSetup: func(client *mockKSMClient) {
				client.On("SearchSecrets", "nonexistent").Return([]*types.SecretMetadata{}, nil)
			},
			validate: func(t *testing.T, result interface{}) {
				resultMap := result.(map[string]interface{})
				assert.Equal(t, 0, resultMap["count"])
			},
		},
		{
			name:        "search error",
			args:        json.RawMessage(`{"query":"test"}`),
			expectError: true,
			mockSetup: func(client *mockKSMClient) {
				client.On("SearchSecrets", "test").Return(nil, errors.New("search failed"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := new(mockKSMClient)
			server := &Server{
				logger: audit.NewLogger("test", "test"),
			}

			tt.mockSetup(mockClient)

			result, err := server.executeSearchSecrets(mockClient, tt.args)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, result)
				}
			}

			mockClient.AssertExpectations(t)
		})
	}
}