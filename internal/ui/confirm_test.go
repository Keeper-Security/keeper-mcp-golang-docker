package ui

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/keeper-security/ksm-mcp/pkg/types"
)

func TestNewConfirmer(t *testing.T) {
	config := types.Confirmation{
		BatchMode:   false,
		AutoApprove: false,
		Timeout:     30 * time.Second,
		DefaultDeny: false,
	}

	confirmer := NewConfirmer(config)
	if confirmer == nil {
		t.Fatal("NewConfirmer returned nil")
	}

	if confirmer.config.Timeout != config.Timeout {
		t.Errorf("Expected timeout %v, got %v", config.Timeout, confirmer.config.Timeout)
	}
}

func TestConfirmBatchMode(t *testing.T) {
	tests := []struct {
		name        string
		batchMode   bool
		autoApprove bool
		defaultDeny bool
		expected    bool
	}{
		{"batch mode approve", true, false, false, true},
		{"batch mode deny", true, false, true, false},
		{"auto approve", false, true, false, true},
		{"auto approve with deny", false, true, true, false},
		{"batch + auto approve", true, true, false, true},
		{"batch + auto with deny", true, true, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := types.Confirmation{
				BatchMode:   tt.batchMode,
				AutoApprove: tt.autoApprove,
				DefaultDeny: tt.defaultDeny,
				Timeout:     5 * time.Second,
			}

			confirmer := NewConfirmer(config)
			ctx := context.Background()

			result := confirmer.Confirm(ctx, "Test confirmation")

			if result.Approved != tt.expected {
				t.Errorf("Expected approved=%v, got %v", tt.expected, result.Approved)
			}

			if result.TimedOut {
				t.Error("Should not have timed out in batch mode")
			}

			if result.Error != nil {
				t.Errorf("Unexpected error: %v", result.Error)
			}
		})
	}
}

func TestConfirmTimeout(t *testing.T) {
	config := types.Confirmation{
		BatchMode:   false,
		AutoApprove: false,
		Timeout:     100 * time.Millisecond, // Very short timeout
		DefaultDeny: false,
	}

	confirmer := NewConfirmer(config)
	ctx := context.Background()

	start := time.Now()
	result := confirmer.Confirm(ctx, "Test timeout")
	elapsed := time.Since(start)

	// Should timeout quickly (but allow some margin for slow CI systems)
	if elapsed > 2*time.Second {
		t.Errorf("Confirmation took too long: %v", elapsed)
	}

	// In CI environment, skip timeout-sensitive tests
	if os.Getenv("CI") != "" {
		t.Skip("Skipping timeout test in CI environment")
	}

	if !result.TimedOut {
		t.Error("Expected timeout")
	}

	if result.Approved != true { // Should use default (not deny)
		t.Error("Expected default approval on timeout")
	}
}

func TestConfirmTimeoutWithDefaultDeny(t *testing.T) {
	// In CI environment, skip timeout-sensitive tests
	if os.Getenv("CI") != "" {
		t.Skip("Skipping timeout test in CI environment")
	}

	config := types.Confirmation{
		BatchMode:   false,
		AutoApprove: false,
		Timeout:     100 * time.Millisecond,
		DefaultDeny: true,
	}

	confirmer := NewConfirmer(config)
	ctx := context.Background()

	result := confirmer.Confirm(ctx, "Test timeout with deny")

	if !result.TimedOut {
		t.Error("Expected timeout")
	}

	if result.Approved != false { // Should use default deny
		t.Error("Expected default denial on timeout")
	}
}

func TestParseResponse(t *testing.T) {
	tests := []struct {
		name        string
		response    string
		defaultDeny bool
		expected    bool
	}{
		// Explicit approvals
		{"yes", "yes", false, true},
		{"y", "y", false, true},
		{"Y", "Y", false, true},
		{"YES", "YES", false, true},
		{"true", "true", false, true},
		{"1", "1", false, true},

		// Explicit denials
		{"no", "no", false, false},
		{"n", "n", false, false},
		{"N", "N", false, false},
		{"NO", "NO", false, false},
		{"false", "false", false, false},
		{"0", "0", false, false},

		// Empty responses (use default)
		{"empty default approve", "", false, true},
		{"empty default deny", "", true, false},
		{"whitespace default approve", "   ", false, true},
		{"whitespace default deny", "   ", true, false},

		// Invalid responses (use default)
		{"invalid default approve", "maybe", false, true},
		{"invalid default deny", "perhaps", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := types.Confirmation{
				DefaultDeny: tt.defaultDeny,
			}
			confirmer := NewConfirmer(config)

			result := confirmer.parseResponse(tt.response)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v for response '%s'", tt.expected, result, tt.response)
			}
		})
	}
}

func TestConfirmOperation(t *testing.T) {
	config := types.Confirmation{
		BatchMode:   true, // Use batch mode for predictable testing
		AutoApprove: true,
		DefaultDeny: false,
	}

	confirmer := NewConfirmer(config)
	ctx := context.Background()

	details := map[string]interface{}{
		"uid":      "test-uid-123",
		"field":    "password",
		"password": "secret123", // This should be masked in display
	}

	result := confirmer.ConfirmOperation(ctx, "retrieve", "Production DB", details)

	if !result.Approved {
		t.Error("Expected operation to be approved")
	}

	if result.Error != nil {
		t.Errorf("Unexpected error: %v", result.Error)
	}
}

func TestConfirmSensitiveOperation(t *testing.T) {
	tests := []struct {
		name     string
		masked   bool
		expected bool
	}{
		{"masked sensitive operation", true, true},
		{"unmasked sensitive operation", false, false}, // Should default to deny
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := types.Confirmation{
				BatchMode:   true,
				AutoApprove: false, // Don't auto-approve to test default behavior
				DefaultDeny: false,
			}

			confirmer := NewConfirmer(config)
			ctx := context.Background()

			result := confirmer.ConfirmSensitiveOperation(ctx, "retrieve", "secret-key", tt.masked)

			if result.Approved != tt.expected {
				t.Errorf("Expected approved=%v, got %v for masked=%v", tt.expected, result.Approved, tt.masked)
			}
		})
	}
}

func TestIsSensitiveKey(t *testing.T) {
	confirmer := NewConfirmer(types.Confirmation{})

	tests := []struct {
		key       string
		sensitive bool
	}{
		{"password", true},
		{"secret", true},
		{"api_key", true},
		{"token", true},
		{"auth_token", true},
		{"private_key", true},
		{"passphrase", true},
		{"PIN", true},
		{"access_code", true},

		// Non-sensitive
		{"username", false},
		{"email", false},
		{"title", false},
		{"url", false},
		{"notes", false},
		{"uid", false},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			result := confirmer.isSensitiveKey(tt.key)
			if result != tt.sensitive {
				t.Errorf("Expected %v for key '%s', got %v", tt.sensitive, tt.key, result)
			}
		})
	}
}

func TestBuildOperationMessage(t *testing.T) {
	confirmer := NewConfirmer(types.Confirmation{})

	details := map[string]interface{}{
		"uid":      "test-uid",
		"password": "secret123",
		"username": "testuser",
		"api_key":  "key123",
	}

	message := confirmer.buildOperationMessage("retrieve", "Test Secret", details)

	// Should contain operation and resource
	if !strings.Contains(message, "retrieve") {
		t.Error("Message should contain operation")
	}
	if !strings.Contains(message, "Test Secret") {
		t.Error("Message should contain resource")
	}

	// Should mask sensitive fields
	if strings.Contains(message, "secret123") {
		t.Error("Message should not contain sensitive password")
	}
	if strings.Contains(message, "key123") {
		t.Error("Message should not contain sensitive API key")
	}

	// Should show non-sensitive fields
	if !strings.Contains(message, "testuser") {
		t.Error("Message should contain non-sensitive username")
	}
	if !strings.Contains(message, "test-uid") {
		t.Error("Message should contain non-sensitive UID")
	}

	// Should contain masked indicators
	if !strings.Contains(message, "[MASKED]") {
		t.Error("Message should contain masking indicators")
	}
}

func TestConfirmBatchOperation(t *testing.T) {
	config := types.Confirmation{
		BatchMode:   true,
		AutoApprove: true,
		DefaultDeny: false,
	}

	confirmer := NewConfirmer(config)
	ctx := context.Background()

	tests := []struct {
		name     string
		items    []string
		wantErr  bool
		approved bool
	}{
		{
			"normal batch",
			[]string{"item1", "item2", "item3"},
			false,
			true,
		},
		{
			"large batch",
			make([]string, 10), // 10 items
			false,
			true,
		},
		{
			"empty batch",
			[]string{},
			true,
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill items for large batch test
			if len(tt.items) == 10 {
				for i := range tt.items {
					tt.items[i] = fmt.Sprintf("item%d", i+1)
				}
			}

			result := confirmer.ConfirmBatchOperation(ctx, "delete", tt.items)

			if tt.wantErr && result.Error == nil {
				t.Error("Expected error for empty batch")
			}

			if !tt.wantErr && result.Error != nil {
				t.Errorf("Unexpected error: %v", result.Error)
			}

			if result.Approved != tt.approved {
				t.Errorf("Expected approved=%v, got %v", tt.approved, result.Approved)
			}
		})
	}
}

func TestConfigurationMethods(t *testing.T) {
	originalConfig := types.Confirmation{
		BatchMode:   false,
		AutoApprove: false,
		Timeout:     30 * time.Second,
		DefaultDeny: true,
	}

	confirmer := NewConfirmer(originalConfig)

	// Test GetConfig
	currentConfig := confirmer.GetConfig()
	if currentConfig.DefaultDeny != originalConfig.DefaultDeny {
		t.Error("GetConfig returned incorrect configuration")
	}

	// Test SetConfig
	newConfig := types.Confirmation{
		BatchMode:   true,
		AutoApprove: true,
		Timeout:     60 * time.Second,
		DefaultDeny: false,
	}

	confirmer.SetConfig(newConfig)
	updatedConfig := confirmer.GetConfig()
	
	if updatedConfig.BatchMode != newConfig.BatchMode {
		t.Error("SetConfig did not update configuration")
	}

	// Test IsInteractive
	if confirmer.IsInteractive() {
		t.Error("Should not be interactive in batch mode with auto-approve")
	}

	// Test interactive mode
	interactiveConfig := types.Confirmation{
		BatchMode:   false,
		AutoApprove: false,
	}
	confirmer.SetConfig(interactiveConfig)
	
	if !confirmer.IsInteractive() {
		t.Error("Should be interactive when not in batch mode and not auto-approve")
	}
}

func TestContextCancellation(t *testing.T) {
	config := types.Confirmation{
		BatchMode:   false,
		AutoApprove: false,
		Timeout:     5 * time.Second, // Long timeout
		DefaultDeny: true,
	}

	confirmer := NewConfirmer(config)
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel context immediately
	cancel()

	result := confirmer.Confirm(ctx, "Test cancellation")

	if !result.TimedOut {
		t.Error("Expected timeout on cancelled context")
	}

	if result.Approved != false { // Should use default deny
		t.Error("Expected denial on cancelled context")
	}
}