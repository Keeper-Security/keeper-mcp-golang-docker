package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/keeper-security/ksm-mcp/internal/audit"
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

func (m *mockKSMClient) GetField(notation string, unmask bool) (interface{}, error) {
	args := m.Called(notation, unmask)
	return args.Get(0), args.Error(1)
}

func (m *mockKSMClient) GetTOTPCode(uid string) (*types.TOTPResponse, error) {
	args := m.Called(uid)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*types.TOTPResponse), args.Error(1)
}

func (m *mockKSMClient) UploadFile(uid, filePath, title string) error {
	args := m.Called(uid, filePath, title)
	return args.Error(0)
}

func (m *mockKSMClient) DownloadFile(uid, fileUID, savePath string) error {
	args := m.Called(uid, fileUID, savePath)
	return args.Error(0)
}

func (m *mockKSMClient) ListFolders() (*types.ListFoldersResponse, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*types.ListFoldersResponse), args.Error(1)
}

func (m *mockKSMClient) CreateFolder(name string, parentUID string) (string, error) {
	args := m.Called(name, parentUID)
	return args.String(0), args.Error(1)
}

func (m *mockKSMClient) TestConnection() error {
	args := m.Called()
	return args.Error(0)
}

// Mock Confirmer
type mockConfirmer struct {
	mock.Mock
}

func (m *mockConfirmer) Confirm(ctx context.Context, message string) *ui.ConfirmationResult {
	args := m.Called(ctx, message)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*ui.ConfirmationResult)
}

func (m *mockConfirmer) ConfirmOperation(ctx context.Context, operation, resource string, details map[string]interface{}) *ui.ConfirmationResult {
	args := m.Called(ctx, operation, resource, details)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*ui.ConfirmationResult)
}

// Test CREATE operation
func TestExecuteCreateSecret(t *testing.T) {
	tests := []struct {
		name          string
		args          json.RawMessage
		serverOptions *ServerOptions
		expectError   bool
		mockSetup     func(*mockKSMClient, *mockConfirmer)
		validate      func(*testing.T, interface{})
	}{
		{
			name:          "successful create - confirmation path",
			args:          json.RawMessage(`{"type":"login","title":"Test Secret C","fields":[]}`),
			serverOptions: &ServerOptions{BatchMode: false, AutoApprove: false},
			expectError:   false,
			mockSetup:     func(client *mockKSMClient, confirmer *mockConfirmer) {},
			validate: func(t *testing.T, result interface{}) {
				resultMap := result.(map[string]interface{})
				assert.Equal(t, "confirmation_required", resultMap["status"])
				assert.Contains(t, resultMap["message"].(string), "Confirmation required to Create new KSM secret titled 'Test Secret C'")
				details, ok := resultMap["confirmation_details"].(map[string]interface{})
				assert.True(t, ok)
				assert.Equal(t, "ksm_confirm_action", details["prompt_name"])
				promptArgs, _ := details["prompt_arguments"].(map[string]interface{})
				assert.Equal(t, "create_secret", promptArgs["original_tool_name"])
			},
		},
		{
			name:          "successful create - batch mode",
			args:          json.RawMessage(`{"type":"login","title":"Test Secret B","fields":[]}`),
			serverOptions: &ServerOptions{BatchMode: true, AutoApprove: false},
			expectError:   false,
			mockSetup: func(client *mockKSMClient, confirmer *mockConfirmer) {
				client.On("CreateSecret", mock.AnythingOfType("types.CreateSecretParams")).Return("test-uid-batch", nil)
			},
			validate: func(t *testing.T, result interface{}) {
				resultMap := result.(map[string]interface{})
				assert.Equal(t, "test-uid-batch", resultMap["uid"])
				assert.Equal(t, "Secret created successfully (confirmed).", resultMap["message"])
			},
		},
		{
			name:          "invalid JSON parameters",
			args:          json.RawMessage(`{"invalid json`),
			serverOptions: &ServerOptions{BatchMode: false, AutoApprove: false},
			expectError:   true,
			mockSetup:     func(client *mockKSMClient, confirmer *mockConfirmer) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := new(mockKSMClient)
			mockConfirmer := new(mockConfirmer)

			logger, _ := audit.NewLogger(audit.Config{
				FilePath: "/tmp/test-audit.log",
			})

			server := &Server{
				confirmer: mockConfirmer,
				logger:    logger,
				options:   tt.serverOptions,
			}
			server.getCurrentClient = server.defaultGetCurrentClientImpl

			if tt.mockSetup != nil {
				tt.mockSetup(mockClient, mockConfirmer)
			}

			if tt.serverOptions.BatchMode || tt.serverOptions.AutoApprove {
				server.getCurrentClient = func() (KSMClient, error) {
					return mockClient, nil
				}
			}

			result, err := server.executeCreateSecret(mockClient, tt.args)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				if tt.validate != nil {
					tt.validate(t, result)
				}
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
			logger, _ := audit.NewLogger(audit.Config{
				FilePath: "/tmp/test-audit.log",
			})
			server := &Server{
				logger: logger,
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
		name          string
		args          json.RawMessage
		serverOptions *ServerOptions
		expectError   bool
		mockSetup     func(*mockKSMClient, *mockConfirmer)
		validate      func(*testing.T, interface{})
	}{
		{
			name:          "get secret masked",
			args:          json.RawMessage(`{"uid":"test-uid","unmask":false}`),
			serverOptions: &ServerOptions{BatchMode: false, AutoApprove: false},
			expectError:   false,
			mockSetup: func(client *mockKSMClient, confirmer *mockConfirmer) {
				client.On("GetSecret", "test-uid", []string(nil), false).Return(map[string]interface{}{
					"uid":   "test-uid",
					"title": "Test Secret",
					"type":  "login",
				}, nil)
			},
			validate: func(t *testing.T, result interface{}) {
				resultMap := result.(map[string]interface{})
				assert.Equal(t, "test-uid", resultMap["uid"])
			},
		},
		{
			name:          "get secret unmasked - confirmation path",
			args:          json.RawMessage(`{"uid":"test-uid","unmask":true}`),
			serverOptions: &ServerOptions{BatchMode: false, AutoApprove: false},
			expectError:   false,
			mockSetup: func(client *mockKSMClient, confirmer *mockConfirmer) {
				client.On("GetSecret", "test-uid", []string{}, false).Return(map[string]interface{}{"title": "Test Unmask"}, nil).Once()
			},
			validate: func(t *testing.T, result interface{}) {
				resultMap := result.(map[string]interface{})
				assert.Equal(t, "confirmation_required", resultMap["status"])
				assert.Contains(t, resultMap["message"].(string), "Reveal unmasked secret 'Test Unmask' (UID: test-uid)")
			},
		},
		{
			name:          "get secret unmasked - batch mode",
			args:          json.RawMessage(`{"uid":"test-uid-batch","unmask":true}`),
			serverOptions: &ServerOptions{BatchMode: true, AutoApprove: false},
			expectError:   false,
			mockSetup: func(client *mockKSMClient, confirmer *mockConfirmer) {
				client.On("GetSecret", "test-uid-batch", []string(nil), true).Return(map[string]interface{}{"password": "pass"}, nil)
			},
			validate: func(t *testing.T, result interface{}) {
				resultMap := result.(map[string]interface{})
				assert.Equal(t, "pass", resultMap["password"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := new(mockKSMClient)
			mockConfirmer := new(mockConfirmer)
			logger, _ := audit.NewLogger(audit.Config{FilePath: "/tmp/test-audit.log"})
			server := &Server{
				confirmer: mockConfirmer,
				logger:    logger,
				options:   tt.serverOptions,
			}
			server.getCurrentClient = server.defaultGetCurrentClientImpl
			if tt.mockSetup != nil {
				tt.mockSetup(mockClient, mockConfirmer)
			}

			if tt.serverOptions.BatchMode || tt.serverOptions.AutoApprove {
				if tt.name == "get secret unmasked - batch mode" {
					server.getCurrentClient = func() (KSMClient, error) { return mockClient, nil }
				}
			}
			result, err := server.executeGetSecret(mockClient, tt.args)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				if tt.validate != nil {
					tt.validate(t, result)
				}
			}
			mockClient.AssertExpectations(t)
			mockConfirmer.AssertExpectations(t)
		})
	}
}

// Test UPDATE operation
func TestExecuteUpdateSecret(t *testing.T) {
	tests := []struct {
		name          string
		args          json.RawMessage
		serverOptions *ServerOptions
		expectError   bool
		mockSetup     func(*mockKSMClient, *mockConfirmer)
		validate      func(*testing.T, interface{})
	}{
		{
			name:          "successful update - batch mode",
			args:          json.RawMessage(`{"uid":"test-uid","title":"Updated Title"}`),
			serverOptions: &ServerOptions{BatchMode: true},
			expectError:   false,
			mockSetup: func(client *mockKSMClient, confirmer *mockConfirmer) {
				client.On("UpdateSecret", mock.MatchedBy(func(p types.UpdateSecretParams) bool {
					return p.UID == "test-uid" && p.Title == "Updated Title"
				})).Return(nil)
			},
			validate: func(t *testing.T, result interface{}) {
				resultMap := result.(map[string]interface{})
				assert.Equal(t, "test-uid", resultMap["uid"])
				assert.Equal(t, "Secret updated successfully (confirmed).", resultMap["message"])
			},
		},
		{
			name:          "update - confirmation path",
			args:          json.RawMessage(`{"uid":"test-uid-conf","title":"Confirm Update"}`),
			serverOptions: &ServerOptions{BatchMode: false, AutoApprove: false},
			expectError:   false,
			mockSetup:     func(client *mockKSMClient, confirmer *mockConfirmer) {},
			validate: func(t *testing.T, result interface{}) {
				resultMap := result.(map[string]interface{})
				assert.Equal(t, "confirmation_required", resultMap["status"])
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := new(mockKSMClient)
			mockConfirmer := new(mockConfirmer)
			logger, _ := audit.NewLogger(audit.Config{FilePath: "/tmp/test-audit.log"})
			server := &Server{
				confirmer: mockConfirmer,
				logger:    logger,
				options:   tt.serverOptions,
			}
			server.getCurrentClient = server.defaultGetCurrentClientImpl
			if tt.mockSetup != nil {
				tt.mockSetup(mockClient, mockConfirmer)
			}
			if tt.serverOptions.BatchMode || tt.serverOptions.AutoApprove {
				server.getCurrentClient = func() (KSMClient, error) { return mockClient, nil }
			}
			result, err := server.executeUpdateSecret(mockClient, tt.args)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, result)
				}
			}
			mockClient.AssertExpectations(t)
			mockConfirmer.AssertExpectations(t)
		})
	}
}

// Test DELETE operation
func TestExecuteDeleteSecret(t *testing.T) {
	tests := []struct {
		name          string
		args          json.RawMessage
		serverOptions *ServerOptions
		expectError   bool
		mockSetup     func(*mockKSMClient, *mockConfirmer)
		validate      func(*testing.T, interface{})
	}{
		{
			name:          "successful delete - batch mode",
			args:          json.RawMessage(`{"uid":"test-uid-del"}`),
			serverOptions: &ServerOptions{BatchMode: true},
			expectError:   false,
			mockSetup: func(client *mockKSMClient, confirmer *mockConfirmer) {
				client.On("DeleteSecret", "test-uid-del", true).Return(nil)
			},
			validate: func(t *testing.T, result interface{}) {
				resultMap := result.(map[string]interface{})
				assert.Equal(t, "test-uid-del", resultMap["uid"])
				assert.Equal(t, "Secret deleted successfully (confirmed).", resultMap["message"])
			},
		},
		{
			name:          "delete - confirmation path",
			args:          json.RawMessage(`{"uid":"test-uid-del-conf"}`),
			serverOptions: &ServerOptions{BatchMode: false, AutoApprove: false},
			expectError:   false,
			mockSetup:     func(client *mockKSMClient, confirmer *mockConfirmer) {},
			validate: func(t *testing.T, result interface{}) {
				resultMap := result.(map[string]interface{})
				assert.Equal(t, "confirmation_required", resultMap["status"])
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := new(mockKSMClient)
			mockConfirmer := new(mockConfirmer)
			logger, _ := audit.NewLogger(audit.Config{FilePath: "/tmp/test-audit.log"})
			server := &Server{
				confirmer: mockConfirmer,
				logger:    logger,
				options:   tt.serverOptions,
			}
			server.getCurrentClient = server.defaultGetCurrentClientImpl
			if tt.mockSetup != nil {
				tt.mockSetup(mockClient, mockConfirmer)
			}
			if tt.serverOptions.BatchMode || tt.serverOptions.AutoApprove {
				server.getCurrentClient = func() (KSMClient, error) { return mockClient, nil }
			}
			result, err := server.executeDeleteSecret(mockClient, tt.args)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, result)
				}
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
			logger, _ := audit.NewLogger(audit.Config{
				FilePath: "/tmp/test-audit.log",
			})
			server := &Server{
				logger: logger,
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

// Test ksm_execute_confirmed_action tool
func TestExecuteKsmExecuteConfirmedAction(t *testing.T) {
	tests := []struct {
		name            string
		args            json.RawMessage
		expectError     bool
		mockClientSetup func(*mockKSMClient)
		validateResult  func(*testing.T, interface{})
		expectedStatus  string
		expectedMessage string
	}{
		{
			name: "approve create_secret",
			args: json.RawMessage(`{
				"original_tool_name": "create_secret",
				"original_tool_args_json": "{\"type\":\"login\",\"title\":\"Confirmed Secret\"}",
				"user_decision": true
			}`),
			expectError: false,
			mockClientSetup: func(client *mockKSMClient) {
				client.On("CreateSecret", mock.MatchedBy(func(p types.CreateSecretParams) bool {
					return p.Title == "Confirmed Secret"
				})).Return("confirmed-uid", nil)
			},
			validateResult: func(t *testing.T, result interface{}) {
				resultMap := result.(map[string]interface{})
				assert.Equal(t, "confirmed-uid", resultMap["uid"])
				assert.Contains(t, resultMap["message"].(string), "Secret created successfully (confirmed)")
			},
		},
		{
			name: "deny create_secret",
			args: json.RawMessage(`{
				"original_tool_name": "create_secret",
				"original_tool_args_json": "{\"type\":\"login\",\"title\":\"Denied Secret\"}",
				"user_decision": false
			}`),
			expectError: false,
			mockClientSetup: func(client *mockKSMClient) {
			},
			validateResult: func(t *testing.T, result interface{}) {
				resultMap := result.(map[string]interface{})
				assert.Equal(t, "operation_denied", resultMap["status"])
				assert.Equal(t, "User denied the operation.", resultMap["message"])
			},
		},
		{
			name: "approve get_secret unmask",
			args: json.RawMessage(`{
				"original_tool_name": "get_secret",
				"original_tool_args_json": "{\"uid\":\"unmask-this\", \"unmask\":true}",
				"user_decision": true
			}`),
			expectError: false,
			mockClientSetup: func(client *mockKSMClient) {
				client.On("GetSecret", "unmask-this", []string(nil), true).Return(map[string]interface{}{"password": "secret_value"}, nil)
			},
			validateResult: func(t *testing.T, result interface{}) {
				resultMap := result.(map[string]interface{})
				assert.Equal(t, "secret_value", resultMap["password"])
			},
		},
		{
			name: "unknown original_tool_name",
			args: json.RawMessage(`{
				"original_tool_name": "non_existent_tool",
				"original_tool_args_json": "{}",
				"user_decision": true
			}`),
			expectError: true,
			mockClientSetup: func(client *mockKSMClient) {
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := new(mockKSMClient)
			logger, _ := audit.NewLogger(audit.Config{FilePath: "/tmp/test-audit-confirmed.log"})
			server := &Server{
				logger:  logger,
				options: &ServerOptions{},
			}
			server.getCurrentClient = func() (KSMClient, error) {
				return mockClient, nil
			}

			if tt.mockClientSetup != nil {
				tt.mockClientSetup(mockClient)
			}

			result, err := server.executeKsmExecuteConfirmedAction(tt.args)

			if tt.expectError {
				assert.Error(t, err)
				if tt.expectedMessage != "" {
					assert.Contains(t, err.Error(), tt.expectedMessage)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				if tt.validateResult != nil {
					tt.validateResult(t, result)
				}
			}
			mockClient.AssertExpectations(t)
		})
	}
}
