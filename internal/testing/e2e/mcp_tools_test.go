package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourusername/ksm-mcp/internal/mcp"
	"github.com/yourusername/ksm-mcp/internal/storage"
	"github.com/yourusername/ksm-mcp/internal/testing/mock"
	"github.com/yourusername/ksm-mcp/internal/ui"
)

type TestHarness struct {
	server       *mcp.Server
	mockClient   *mock.MockClient
	input        *bytes.Buffer
	output       *bytes.Buffer
	confirmer    *ui.Confirmer
	responseChan chan interface{}
}

func NewTestHarness(t *testing.T) *TestHarness {
	// Create mock client
	mockClient := mock.NewMockClient()
	
	// Create test IO
	input := &bytes.Buffer{}
	output := &bytes.Buffer{}
	
	// Create confirmer with auto-confirm for testing
	confirmer := &ui.Confirmer{
		AutoConfirm: true,
	}
	
	// Create test storage
	store := storage.NewMemoryProfileStore()
	store.AddProfile("test", mockClient)
	
	// Create server options
	options := &mcp.ServerOptions{
		Storage:   store,
		Confirmer: confirmer,
		Timeout:   30 * time.Second,
	}
	
	// Create server
	server := mcp.NewServer(options)
	
	return &TestHarness{
		server:       server,
		mockClient:   mockClient,
		input:        input,
		output:       output,
		confirmer:    confirmer,
		responseChan: make(chan interface{}, 10),
	}
}

func (h *TestHarness) SendRequest(method string, params interface{}) (interface{}, error) {
	request := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      1,
	}
	
	requestData, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	
	// Send request
	h.input.Write(requestData)
	h.input.WriteByte('\n')
	
	// Process request
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	go func() {
		// Simulate server processing
		// In real implementation, this would be the server's message loop
		var req map[string]interface{}
		decoder := json.NewDecoder(h.input)
		if err := decoder.Decode(&req); err == nil {
			// Process through server
			response := h.server.HandleRequest(ctx, req)
			h.responseChan <- response
		}
	}()
	
	select {
	case response := <-h.responseChan:
		return response, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("request timeout")
	}
}

func TestListSecretsTool(t *testing.T) {
	h := NewTestHarness(t)
	
	// Test 1: List all secrets
	t.Run("ListAllSecrets", func(t *testing.T) {
		response, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "list_secrets",
			"arguments": map[string]interface{}{},
		})
		require.NoError(t, err)
		
		result := extractToolResult(t, response)
		assert.Contains(t, result, "Found 12 secrets")
		assert.Contains(t, result, "Database Connection")
		assert.Contains(t, result, "SSH Key")
		assert.Contains(t, result, "Test API Credentials")
	})
	
	// Test 2: List by folder
	t.Run("ListByFolder", func(t *testing.T) {
		response, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "list_secrets",
			"arguments": map[string]interface{}{
				"folder": "Development",
			},
		})
		require.NoError(t, err)
		
		result := extractToolResult(t, response)
		assert.Contains(t, result, "Development")
		assert.Contains(t, result, "Database Connection")
		assert.Contains(t, result, "SSH Key")
		assert.NotContains(t, result, "Test Corporate Card") // In Production folder
	})
	
	// Test 3: List by type
	t.Run("ListByType", func(t *testing.T) {
		response, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "list_secrets",
			"arguments": map[string]interface{}{
				"record_type": "login",
			},
		})
		require.NoError(t, err)
		
		result := extractToolResult(t, response)
		assert.Contains(t, result, "Test API Credentials")
		assert.Contains(t, result, "Development Server Login")
		assert.NotContains(t, result, "SSH Key") // Different type
	})
}

func TestGetSecretTool(t *testing.T) {
	h := NewTestHarness(t)
	
	// Test 1: Get by UID
	t.Run("GetByUID", func(t *testing.T) {
		response, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "get_secret",
			"arguments": map[string]interface{}{
				"uid": "dev-db-conn",
			},
		})
		require.NoError(t, err)
		
		result := extractToolResult(t, response)
		assert.Contains(t, result, "Database Connection")
		assert.Contains(t, result, "dev-db.example.com")
		assert.Contains(t, result, "dev_user")
		assert.Contains(t, result, "DevPass123!")
	})
	
	// Test 2: Get by title
	t.Run("GetByTitle", func(t *testing.T) {
		response, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "get_secret",
			"arguments": map[string]interface{}{
				"title": "SSH Key",
			},
		})
		require.NoError(t, err)
		
		result := extractToolResult(t, response)
		assert.Contains(t, result, "SSH Key")
		assert.Contains(t, result, "dev-server.example.com")
		assert.Contains(t, result, "BEGIN RSA PRIVATE KEY")
	})
	
	// Test 3: Get with field filter
	t.Run("GetWithFieldFilter", func(t *testing.T) {
		response, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "get_secret",
			"arguments": map[string]interface{}{
				"uid": "prod-api-creds",
				"field": "password",
			},
		})
		require.NoError(t, err)
		
		result := extractToolResult(t, response)
		assert.Contains(t, result, "ProdSecret789!")
		assert.NotContains(t, result, "prod-api-key-123456") // Other field
	})
}

func TestSearchSecretsTool(t *testing.T) {
	h := NewTestHarness(t)
	
	// Test search functionality
	t.Run("SearchByTerm", func(t *testing.T) {
		response, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "search_secrets",
			"arguments": map[string]interface{}{
				"search_term": "Database",
			},
		})
		require.NoError(t, err)
		
		result := extractToolResult(t, response)
		assert.Contains(t, result, "Database Connection")
		assert.Contains(t, result, "Test Database Login")
		assert.NotContains(t, result, "SSH Key")
	})
}

func TestCreateSecretTool(t *testing.T) {
	h := NewTestHarness(t)
	
	// Enable capture mode
	h.mockClient.SetCaptureMode(true)
	
	t.Run("CreateNewSecret", func(t *testing.T) {
		response, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "create_secret",
			"arguments": map[string]interface{}{
				"title": "New Test Secret",
				"record_type": "login",
				"fields": map[string]interface{}{
					"login": "new_user",
					"password": "NewPass123!",
					"url": "https://new.example.com",
				},
				"notes": "Created by E2E test",
				"folder": "Testing",
			},
		})
		require.NoError(t, err)
		
		result := extractToolResult(t, response)
		assert.Contains(t, result, "Secret created successfully")
		assert.Contains(t, result, "New Test Secret")
		
		// Verify capture
		captures := h.mockClient.GetCaptures()
		assert.Greater(t, len(captures), 0)
		lastCapture := captures[len(captures)-1]
		assert.Equal(t, "Save", lastCapture.Method)
	})
}

func TestUpdateSecretTool(t *testing.T) {
	h := NewTestHarness(t)
	
	t.Run("UpdateExistingSecret", func(t *testing.T) {
		response, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "update_secret",
			"arguments": map[string]interface{}{
				"uid": "test-db-login",
				"fields": map[string]interface{}{
					"password": "UpdatedPass456!",
				},
				"notes": "Password updated by E2E test",
			},
		})
		require.NoError(t, err)
		
		result := extractToolResult(t, response)
		assert.Contains(t, result, "Secret updated successfully")
		
		// Verify update
		getResponse, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "get_secret",
			"arguments": map[string]interface{}{
				"uid": "test-db-login",
			},
		})
		require.NoError(t, err)
		
		getResult := extractToolResult(t, getResponse)
		assert.Contains(t, getResult, "UpdatedPass456!")
		assert.Contains(t, getResult, "Password updated by E2E test")
	})
}

func TestDeleteSecretTool(t *testing.T) {
	h := NewTestHarness(t)
	
	// Create a test secret first
	h.mockClient.GetServer().CreateSecret("test-to-delete", "Secret to Delete", "login", map[string]interface{}{
		"login": "temp_user",
		"password": "TempPass123!",
	})
	
	t.Run("DeleteSecret", func(t *testing.T) {
		// Confirm it exists
		getResponse, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "get_secret",
			"arguments": map[string]interface{}{
				"uid": "test-to-delete",
			},
		})
		require.NoError(t, err)
		assert.Contains(t, extractToolResult(t, getResponse), "Secret to Delete")
		
		// Delete it
		response, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "delete_secret",
			"arguments": map[string]interface{}{
				"uid": "test-to-delete",
			},
		})
		require.NoError(t, err)
		
		result := extractToolResult(t, response)
		assert.Contains(t, result, "deleted successfully")
		
		// Confirm it's gone
		getResponse2, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "get_secret",
			"arguments": map[string]interface{}{
				"uid": "test-to-delete",
			},
		})
		require.NoError(t, err)
		assert.Contains(t, extractToolResult(t, getResponse2), "not found")
	})
}

func TestFileTool(t *testing.T) {
	h := NewTestHarness(t)
	
	// Test list files
	t.Run("ListFiles", func(t *testing.T) {
		response, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "list_files",
			"arguments": map[string]interface{}{
				"uid": "test-config-files",
			},
		})
		require.NoError(t, err)
		
		result := extractToolResult(t, response)
		assert.Contains(t, result, "app.config")
		assert.Contains(t, result, "test.env")
		assert.Contains(t, result, "docker-compose.test.yml")
		assert.Contains(t, result, "3 files")
	})
	
	// Test download file
	t.Run("DownloadFile", func(t *testing.T) {
		response, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "download_file",
			"arguments": map[string]interface{}{
				"uid": "test-config-files",
				"file_name": "app.config",
				"output_path": "/tmp/test_app.config",
			},
		})
		require.NoError(t, err)
		
		result := extractToolResult(t, response)
		assert.Contains(t, result, "File downloaded successfully")
		assert.Contains(t, result, "2048 bytes")
	})
	
	// Test upload file
	t.Run("UploadFile", func(t *testing.T) {
		h.mockClient.SetCaptureMode(true)
		
		response, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "upload_file",
			"arguments": map[string]interface{}{
				"uid": "dev-db-conn",
				"file_path": "/tmp/test_upload.txt",
				"file_type": "text/plain",
			},
		})
		require.NoError(t, err)
		
		result := extractToolResult(t, response)
		assert.Contains(t, result, "File uploaded successfully")
		
		// Verify capture
		captures := h.mockClient.GetCaptures()
		assert.Greater(t, len(captures), 0)
		lastCapture := captures[len(captures)-1]
		assert.Equal(t, "UploadFile", lastCapture.Method)
	})
}

func TestNotationQueryTool(t *testing.T) {
	h := NewTestHarness(t)
	
	t.Run("QueryByType", func(t *testing.T) {
		response, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "notation_query",
			"arguments": map[string]interface{}{
				"query": "type:login",
			},
		})
		require.NoError(t, err)
		
		result := extractToolResult(t, response)
		assert.Contains(t, result, "Found")
		assert.Contains(t, result, "login records")
	})
}

func TestPasswordGeneratorTool(t *testing.T) {
	h := NewTestHarness(t)
	
	t.Run("GeneratePassword", func(t *testing.T) {
		response, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "generate_password",
			"arguments": map[string]interface{}{
				"length": 20,
				"include_symbols": true,
				"include_numbers": true,
				"include_uppercase": true,
				"include_lowercase": true,
			},
		})
		require.NoError(t, err)
		
		result := extractToolResult(t, response)
		assert.Contains(t, result, "Generated password:")
		// Extract password from result
		// Should be 20 characters long
	})
}

func TestTOTPTool(t *testing.T) {
	h := NewTestHarness(t)
	
	// First create a record with TOTP
	h.mockClient.GetServer().CreateSecret("test-totp", "Test TOTP", "login", map[string]interface{}{
		"login": "totp_user",
		"password": "TOTPPass123!",
		"oneTimeCode": "JBSWY3DPEHPK3PXP", // Example TOTP secret
	})
	
	t.Run("GetTOTPCode", func(t *testing.T) {
		response, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "get_totp_code",
			"arguments": map[string]interface{}{
				"uid": "test-totp",
			},
		})
		require.NoError(t, err)
		
		result := extractToolResult(t, response)
		assert.Contains(t, result, "TOTP Code:")
		// Code should be 6 digits
	})
}

func TestShareSecretTool(t *testing.T) {
	h := NewTestHarness(t)
	
	t.Run("ShareSecret", func(t *testing.T) {
		response, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "share_secret",
			"arguments": map[string]interface{}{
				"uid": "dev-db-conn",
				"users": []string{"test@example.com"},
				"expiration": "24h",
			},
		})
		require.NoError(t, err)
		
		result := extractToolResult(t, response)
		assert.Contains(t, result, "shared successfully")
		assert.Contains(t, result, "test@example.com")
	})
}

// Helper function to extract tool result from response
func extractToolResult(t *testing.T, response interface{}) string {
	respMap, ok := response.(map[string]interface{})
	require.True(t, ok, "Response should be a map")
	
	result, ok := respMap["result"]
	if !ok {
		// Check for error
		if err, ok := respMap["error"]; ok {
			t.Fatalf("Tool returned error: %v", err)
		}
		t.Fatal("No result in response")
	}
	
	// Convert result to string
	switch v := result.(type) {
	case string:
		return v
	case map[string]interface{}:
		data, _ := json.MarshalIndent(v, "", "  ")
		return string(data)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// TestE2EScenario tests a complete workflow
func TestE2EScenario(t *testing.T) {
	h := NewTestHarness(t)
	
	t.Run("CompleteWorkflow", func(t *testing.T) {
		// 1. List all secrets
		listResp, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "list_secrets",
			"arguments": map[string]interface{}{},
		})
		require.NoError(t, err)
		assert.Contains(t, extractToolResult(t, listResp), "12 secrets")
		
		// 2. Create a new secret
		createResp, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "create_secret",
			"arguments": map[string]interface{}{
				"title": "E2E Test Secret",
				"record_type": "login",
				"fields": map[string]interface{}{
					"login": "e2e_user",
					"password": "E2EPass123!",
					"url": "https://e2e.test.com",
				},
			},
		})
		require.NoError(t, err)
		assert.Contains(t, extractToolResult(t, createResp), "created successfully")
		
		// 3. Search for it
		searchResp, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "search_secrets",
			"arguments": map[string]interface{}{
				"search_term": "E2E",
			},
		})
		require.NoError(t, err)
		assert.Contains(t, extractToolResult(t, searchResp), "E2E Test Secret")
		
		// 4. Update it
		updateResp, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "update_secret",
			"arguments": map[string]interface{}{
				"title": "E2E Test Secret",
				"fields": map[string]interface{}{
					"password": "UpdatedE2EPass456!",
				},
			},
		})
		require.NoError(t, err)
		assert.Contains(t, extractToolResult(t, updateResp), "updated successfully")
		
		// 5. Generate a new password for it
		genResp, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "generate_password",
			"arguments": map[string]interface{}{
				"length": 24,
			},
		})
		require.NoError(t, err)
		newPassword := extractToolResult(t, genResp)
		assert.Contains(t, newPassword, "Generated password:")
		
		// 6. List secrets again to verify count
		listResp2, err := h.SendRequest("tools/call", map[string]interface{}{
			"name": "list_secrets",
			"arguments": map[string]interface{}{},
		})
		require.NoError(t, err)
		assert.Contains(t, extractToolResult(t, listResp2), "13 secrets") // One more than before
	})
}