package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/keeper-security/ksm-mcp/internal/audit"
	"github.com/keeper-security/ksm-mcp/internal/storage"
	"github.com/keeper-security/ksm-mcp/pkg/types"
	"github.com/stretchr/testify/assert"
)

// testLogger creates a logger for testing
func testLogger(t *testing.T) *audit.Logger {
	logger, err := audit.NewLogger(audit.Config{
		FilePath: "/tmp/test-audit.log",
		MaxSize:  1024 * 1024,
		MaxAge:   24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	return logger
}

func TestServer_NewServer(t *testing.T) {
	storage := &storage.ProfileStore{}
	logger := testLogger(t)

	tests := []struct {
		name    string
		options *ServerOptions
		check   func(*testing.T, *Server)
	}{
		{
			name:    "default options",
			options: nil,
			check: func(t *testing.T, s *Server) {
				if s.options.Timeout != 30*time.Second {
					t.Errorf("expected default timeout of 30s, got %v", s.options.Timeout)
				}
				if s.options.RateLimit != 60 {
					t.Errorf("expected default rate limit of 60, got %d", s.options.RateLimit)
				}
			},
		},
		{
			name: "custom options",
			options: &ServerOptions{
				BatchMode:   true,
				AutoApprove: true,
				Timeout:     60 * time.Second,
				ProfileName: "test",
				RateLimit:   120,
			},
			check: func(t *testing.T, s *Server) {
				if !s.options.BatchMode {
					t.Error("expected batch mode to be true")
				}
				if !s.options.AutoApprove {
					t.Error("expected auto approve to be true")
				}
				if s.options.Timeout != 60*time.Second {
					t.Errorf("expected timeout of 60s, got %v", s.options.Timeout)
				}
				if s.options.ProfileName != "test" {
					t.Errorf("expected profile name 'test', got %s", s.options.ProfileName)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := NewServer(storage, logger, tt.options)
			if server == nil {
				t.Fatal("expected server to be created")
			}
			if tt.check != nil {
				tt.check(t, server)
			}
		})
	}
}

func TestServer_HandleInitialize(t *testing.T) {
	storage := &storage.ProfileStore{}
	logger := testLogger(t)
	server := NewServer(storage, logger, nil)

	request := types.MCPRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: json.RawMessage(`{
			"protocolVersion": "1.0",
			"capabilities": {
				"tools": {
					"call": true
				}
			},
			"clientInfo": {
				"name": "test-client",
				"version": "1.0.0"
			}
		}`),
	}

	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)

	err := server.handleInitialize(request, writer)
	if err != nil {
		t.Fatalf("handleInitialize failed: %v", err)
	}

	// Check response
	writer.Flush()
	var response types.MCPResponse
	if err := json.Unmarshal(buf.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if response.Error != nil {
		t.Fatalf("expected no error, got %v", response.Error)
	}
}

func TestServer_HandleToolsList(t *testing.T) {
	storage := &storage.ProfileStore{}
	logger := testLogger(t)
	server := NewServer(storage, logger, nil)

	request := types.MCPRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/list",
	}

	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)

	err := server.handleToolsList(request, writer)
	if err != nil {
		t.Fatalf("handleToolsList failed: %v", err)
	}

	// Check response
	writer.Flush()
	var response types.MCPResponse
	if err := json.Unmarshal(buf.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if response.Error != nil {
		t.Fatalf("expected no error, got %v", response.Error)
	}

	// Check tools are returned
	result, ok := response.Result.(map[string]interface{})
	if !ok {
		t.Fatal("expected result to be a map")
	}

	tools, ok := result["tools"].([]interface{})
	if !ok {
		t.Fatal("expected tools to be an array")
	}

	if len(tools) == 0 {
		t.Error("expected at least one tool")
	}
}

func TestServer_RateLimiter(t *testing.T) {
	limiter := NewRateLimiter(60) // 60 per minute

	// Should allow initial requests
	for i := 0; i < 60; i++ {
		if !limiter.Allow("test") {
			t.Errorf("expected request %d to be allowed", i)
		}
	}

	// 61st request should be denied
	if limiter.Allow("test") {
		t.Error("expected request to be rate limited")
	}
}

func TestServer_ProcessMessage(t *testing.T) {
	storage := &storage.ProfileStore{}
	logger := testLogger(t)
	server := NewServer(storage, logger, &ServerOptions{RateLimit: 1000})

	tests := []struct {
		name               string
		message            string
		expectMCPErrorCode *int
	}{
		{
			name:               "valid request tools/list",
			message:            `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
			expectMCPErrorCode: nil,
		},
		{
			name:               "invalid json",
			message:            `{invalid json}`,
			expectMCPErrorCode: Pint(-32700),
		},
		{
			name:               "unknown method",
			message:            `{"jsonrpc":"2.0","id":1,"method":"unknown/method"}`,
			expectMCPErrorCode: Pint(-32601),
		},
		{
			name:               "notification unknown method",
			message:            `{"jsonrpc":"2.0","method":"unknown/notification"}`,
			expectMCPErrorCode: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			writer := bufio.NewWriter(&buf)

			funcErr := server.processMessage([]byte(tt.message), writer)
			writer.Flush()

			assert.NoError(t, funcErr, "processMessage itself should not return an error")

			responseBytes := buf.Bytes()
			if tt.expectMCPErrorCode != nil && len(responseBytes) == 0 {
				assert.FailNow(t, "Expected an MCP error response, but buffer is empty", "Test case: %s", tt.name)
			}

			if tt.expectMCPErrorCode != nil {
				assert.True(t, len(responseBytes) > 0, "Expected an MCP response, but buffer is empty. Test case: %s", tt.name)
				var response types.MCPResponse
				err := json.Unmarshal(responseBytes, &response)
				assert.NoError(t, err, "Failed to unmarshal MCP response: %s", buf.String())
				assert.NotNil(t, response.Error, "Expected an MCP error object in the response")
				if response.Error != nil {
					assert.Equal(t, *tt.expectMCPErrorCode, response.Error.Code, "MCP error code mismatch")
				}
			} else {
				if tt.name == "notification unknown method" {
					assert.Equal(t, 0, buf.Len(), "Expected no response for an unknown notification")
				} else if buf.Len() > 0 {
					var response types.MCPResponse
					err := json.Unmarshal(buf.Bytes(), &response)
					assert.NoError(t, err, "Failed to unmarshal MCP response: %s", buf.String())
					assert.Nil(t, response.Error, "Expected no MCP error object, but got one: %+v", response.Error)
				}
			}
		})
	}
}

func Pint(i int) *int {
	return &i
}

func TestServer_GetAvailableTools(t *testing.T) {
	storage := &storage.ProfileStore{}
	logger := testLogger(t)
	server := NewServer(storage, logger, nil)

	tools := server.getAvailableTools()

	// Check we have all expected tools
	expectedTools := []string{
		"list_secrets",
		"get_secret",
		"search_secrets",
		"get_field",
		"generate_password",
		"get_totp_code",
		"create_secret",
		"update_secret",
		"delete_secret",
		"upload_file",
		"download_file",
		"list_folders",
		"create_folder",
	}

	toolMap := make(map[string]bool)
	for _, tool := range tools {
		toolMap[tool.Name] = true
	}

	for _, expected := range expectedTools {
		if !toolMap[expected] {
			t.Errorf("missing expected tool: %s", expected)
		}
	}
}
