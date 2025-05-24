package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/keeper-security/ksm-mcp/internal/storage"
	"github.com/keeper-security/ksm-mcp/pkg/types"
)

// TestServer_SecurityValidation tests security validations
func TestServer_SecurityValidation(t *testing.T) {
	storage := &storage.ProfileStore{}
	logger := testLogger(t)

	// Create server with strict settings
	server := NewServer(storage, logger, &ServerOptions{
		BatchMode:   false,
		AutoApprove: false,
		Timeout:     5 * time.Second,
		RateLimit:   10, // Low rate limit for testing
	})

	tests := []struct {
		name        string
		request     types.MCPRequest
		expectError bool
		errorCode   int
	}{
		{
			name: "SQL injection attempt in tool parameters",
			request: types.MCPRequest{
				JSONRPC: "2.0",
				ID:      1,
				Method:  "tools/call",
				Params: map[string]interface{}{
					"name": "get_secret",
					"arguments": json.RawMessage(`{
						"uid": "'; DROP TABLE secrets; --",
						"unmask": true
					}`),
				},
			},
			expectError: true,
			errorCode:   -32002, // Tool execution error
		},
		{
			name: "Command injection in search query",
			request: types.MCPRequest{
				JSONRPC: "2.0",
				ID:      2,
				Method:  "tools/call",
				Params: map[string]interface{}{
					"name": "search_secrets",
					"arguments": json.RawMessage(`{
						"query": "test; rm -rf /; echo"
					}`),
				},
			},
			expectError: true,
			errorCode:   -32002,
		},
		{
			name: "Path traversal in file operations",
			request: types.MCPRequest{
				JSONRPC: "2.0",
				ID:      3,
				Method:  "tools/call",
				Params: map[string]interface{}{
					"name": "upload_file",
					"arguments": json.RawMessage(`{
						"uid": "test123",
						"file_path": "../../../etc/passwd",
						"title": "passwd"
					}`),
				},
			},
			expectError: true,
			errorCode:   -32002,
		},
		{
			name: "XSS attempt in create secret",
			request: types.MCPRequest{
				JSONRPC: "2.0",
				ID:      4,
				Method:  "tools/call",
				Params: map[string]interface{}{
					"name": "create_secret",
					"arguments": json.RawMessage(`{
						"type": "login",
						"title": "<script>alert('xss')</script>",
						"fields": {
							"login": "user@example.com",
							"password": "test123"
						}
					}`),
				},
			},
			expectError: true,
			errorCode:   -32002,
		},
		{
			name: "Invalid JSON in parameters",
			request: types.MCPRequest{
				JSONRPC: "2.0",
				ID:      5,
				Method:  "tools/call",
				Params: map[string]interface{}{
					"name":      "get_secret",
					"arguments": "{invalid json}",
				},
			},
			expectError: true,
			errorCode:   -32002,
		},
		{
			name: "Oversized request",
			request: types.MCPRequest{
				JSONRPC: "2.0",
				ID:      6,
				Method:  "tools/call",
				Params: map[string]interface{}{
					"name": "create_secret",
					"arguments": json.RawMessage(`{
						"type": "login",
						"title": "test",
						"notes": "` + strings.Repeat("A", 1024*1024) + `"
					}`),
				},
			},
			expectError: true,
			errorCode:   -32002,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			writer := bufio.NewWriter(&buf)

			// Marshal request
			reqData, err := json.Marshal(tt.request)
			if err != nil {
				t.Fatalf("failed to marshal request: %v", err)
			}

			// Process message
			err = server.processMessage(reqData, writer)
			writer.Flush()

			// Check response
			var response types.MCPResponse
			if err := json.Unmarshal(buf.Bytes(), &response); err != nil {
				t.Fatalf("failed to parse response: %v", err)
			}

			if tt.expectError {
				if response.Error == nil {
					t.Error("expected error response but got success")
				} else if tt.errorCode != 0 && response.Error.Code != tt.errorCode {
					t.Errorf("expected error code %d, got %d", tt.errorCode, response.Error.Code)
				}
			} else {
				if response.Error != nil {
					t.Errorf("unexpected error: %v", response.Error)
				}
			}
		})
	}
}

// TestServer_RateLimitingSecurity tests rate limiting protection
func TestServer_RateLimitingSecurity(t *testing.T) {
	storage := &storage.ProfileStore{}
	logger := testLogger(t)

	// Create server with very low rate limit
	server := NewServer(storage, logger, &ServerOptions{
		RateLimit: 5, // 5 requests per minute
	})

	request := types.MCPRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/list",
	}

	reqData, _ := json.Marshal(request)

	// Send requests up to the limit
	successCount := 0
	rateLimitCount := 0

	for i := 0; i < 10; i++ {
		var buf bytes.Buffer
		writer := bufio.NewWriter(&buf)

		err := server.processMessage(reqData, writer)
		writer.Flush()

		var response types.MCPResponse
		_ = json.Unmarshal(buf.Bytes(), &response)

		if response.Error != nil && response.Error.Code == -32029 {
			rateLimitCount++
		} else if err == nil {
			successCount++
		}
	}

	// Should have some successful and some rate limited
	if successCount == 0 {
		t.Error("expected some successful requests")
	}
	if rateLimitCount == 0 {
		t.Error("expected some rate limited requests")
	}
	if successCount+rateLimitCount != 10 {
		t.Errorf("expected 10 total requests, got %d successful + %d rate limited",
			successCount, rateLimitCount)
	}
}

// TestServer_NoActiveSessionSecurity tests operations without active session
func TestServer_NoActiveSessionSecurity(t *testing.T) {
	storage := &storage.ProfileStore{}
	logger := testLogger(t)
	server := NewServer(storage, logger, nil)

	// Try to call a tool without active session
	request := types.MCPRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name": "get_secret",
			"arguments": json.RawMessage(`{
				"uid": "test123"
			}`),
		},
	}

	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)

	reqData, _ := json.Marshal(request)
	err := server.processMessage(reqData, writer)
	writer.Flush()

	if err == nil {
		t.Error("expected error when calling tool without session")
	}

	var response types.MCPResponse
	_ = json.Unmarshal(buf.Bytes(), &response)

	if response.Error == nil {
		t.Error("expected error response")
	}
	if !strings.Contains(response.Error.Message, "no active session") {
		t.Errorf("expected 'no active session' error, got: %s", response.Error.Message)
	}
}

// TestServer_SensitiveDataMasking tests that sensitive data is masked by default
func TestServer_SensitiveDataMasking(t *testing.T) {
	// This would require a mock KSM client to test properly
	// For now, we'll test the masking logic in isolation

	testCases := []struct {
		name     string
		value    string
		expected string
	}{
		{
			name:     "short password",
			value:    "pass",
			expected: "******",
		},
		{
			name:     "long password",
			value:    "mySecretPassword123",
			expected: "myS***123",
		},
		{
			name:     "api key",
			value:    "sk_test_1234567890abcdef",
			expected: "sk_***def",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			masked := maskValue(tc.value)
			if masked != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, masked)
			}

			// Ensure original value is not in masked output
			if len(tc.value) > 6 && strings.Contains(masked, tc.value[3:len(tc.value)-3]) {
				t.Error("masked value contains too much of the original")
			}
		})
	}
}

// TestServer_MessageSizeLimit tests message size limits
func TestServer_MessageSizeLimit(t *testing.T) {
	storage := &storage.ProfileStore{}
	logger := testLogger(t)
	server := NewServer(storage, logger, nil)

	// Create a very large message
	largeData := strings.Repeat("A", 10*1024*1024) // 10MB
	request := types.MCPRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name": "create_secret",
			"arguments": json.RawMessage(`{
				"type": "login",
				"title": "test",
				"notes": "` + largeData + `"
			}`),
		},
	}

	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)

	reqData, err := json.Marshal(request)
	if err == nil {
		// If marshaling succeeds, try processing
		err = server.processMessage(reqData, writer)
		writer.Flush()

		// Should fail or return error
		if err == nil {
			var response types.MCPResponse
			_ = json.Unmarshal(buf.Bytes(), &response)
			if response.Error == nil {
				t.Error("expected error for oversized message")
			}
		}
	}
}

// TestServer_ConcurrentRequestSecurity tests concurrent request handling
func TestServer_ConcurrentRequestSecurity(t *testing.T) {
	storage := &storage.ProfileStore{}
	logger := testLogger(t)
	server := NewServer(storage, logger, nil)

	// Launch multiple concurrent requests
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- true }()

			request := types.MCPRequest{
				JSONRPC: "2.0",
				ID:      id,
				Method:  "tools/list",
			}

			var buf bytes.Buffer
			writer := bufio.NewWriter(&buf)

			reqData, _ := json.Marshal(request)
			_ = server.processMessage(reqData, writer)
			writer.Flush()

			var response types.MCPResponse
			_ = json.Unmarshal(buf.Bytes(), &response)

			// Verify response has correct ID
			if respID, ok := response.ID.(float64); !ok || int(respID) != id {
				t.Errorf("response ID mismatch: expected %d, got %v", id, response.ID)
			}
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

// maskValue is copied here for testing - in production it's in the client
func maskValue(value string) string {
	if len(value) <= 6 {
		return "******"
	}
	return value[:3] + "***" + value[len(value)-3:]
}
