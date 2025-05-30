//go:build integration
// +build integration

package ksm

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/keeper-security/ksm-mcp/internal/audit"
	"github.com/keeper-security/ksm-mcp/pkg/types"
)

// TestRealKSMIntegration tests against real KSM instance
// Run with: go test -tags=integration ./internal/ksm -v
func TestRealKSMIntegration(t *testing.T) {
	// Skip if no token provided
	token := os.Getenv("KSM_TEST_TOKEN")
	if token == "" {
		t.Skip("KSM_TEST_TOKEN not set, skipping integration test")
	}

	// Initialize with token
	t.Log("Testing token initialization...")
	config, err := InitializeWithToken(token)
	if err != nil {
		t.Fatalf("Failed to initialize with token: %v", err)
	}

	// Log the config structure (without sensitive data)
	t.Logf("Config keys received: %v", getMapKeys(config))

	// Save config for reuse
	configJSON, _ := json.MarshalIndent(config, "", "  ")
	t.Logf("Config structure (for mock data):\n%s", maskSensitiveJSON(configJSON))

	// Create client
	logger := createTestLogger(t)
	defer logger.Close()

	profile := &types.Profile{
		Name:      "test-integration",
		Config:    config,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	client, err := NewClient(profile, logger)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Test connection
	t.Log("Testing connection...")
	if err := client.TestConnection(); err != nil {
		t.Fatalf("Connection test failed: %v", err)
	}

	// Test ListSecrets
	secrets, err := client.ListSecrets([]string{})
	if err != nil {
		t.Fatalf("ListSecrets failed: %v", err)
	}

	t.Logf("Found %d secrets", len(secrets))
	for i, secret := range secrets {
		t.Logf("Secret %d: UID=%s, Title=%s, Type=%s", i+1, secret.UID, secret.Title, secret.Type)
	}

	// Test each secret
	for _, metadata := range secrets {
		t.Run(fmt.Sprintf("Secret_%s", metadata.Title), func(t *testing.T) {
			// Get full secret (masked)
			secret, err := client.GetSecret(metadata.UID, nil, false)
			if err != nil {
				t.Errorf("Failed to get secret: %v", err)
				return
			}

			// Log structure for mock data
			secretJSON, _ := json.MarshalIndent(secret, "", "  ")
			t.Logf("Secret structure (masked):\n%s", string(secretJSON))

			// Test field notation access
			testNotations := []string{
				fmt.Sprintf("%s/field/password", metadata.UID),
				fmt.Sprintf("%s/field/login", metadata.UID),
				fmt.Sprintf("%s/field/url", metadata.UID),
			}

			for _, notation := range testNotations {
				t.Logf("Testing notation: %s", notation)
				result, err := client.GetField(notation, false)
				if err != nil {
					t.Logf("Notation %s failed (may not exist): %v", notation, err)
				} else {
					t.Logf("Notation %s result: %v", notation, result)
				}
			}

			// Test TOTP if available
			t.Log("Testing TOTP...")
			totp, err := client.GetTOTPCode(metadata.UID)
			if err != nil {
				t.Logf("TOTP not available: %v", err)
			} else {
				t.Logf("TOTP code: %s (expires in %d seconds)", totp.Code, totp.TimeLeft)
			}
		})
	}

	// Test password generation
	t.Log("Testing password generation...")
	passwords := []types.GeneratePasswordParams{
		{Length: 16},
		{Length: 32, Lowercase: 8, Uppercase: 8, Digits: 8, Special: 8},
		{Length: 20, Special: 4, SpecialSet: "!@#$"},
	}

	for i, params := range passwords {
		password, err := client.GeneratePassword(params)
		if err != nil {
			t.Errorf("Failed to generate password %d: %v", i+1, err)
		} else {
			t.Logf("Generated password %d (length %d): %s", i+1, len(password), maskValue(password))
		}
	}

	// Test search
	t.Log("Testing search...")
	searchTerms := []string{"test", "login", "password"}
	for _, term := range searchTerms {
		results, err := client.SearchSecrets(term)
		if err != nil {
			t.Errorf("Search for '%s' failed: %v", term, err)
		} else {
			t.Logf("Search '%s' found %d results", term, len(results))
		}
	}

	// Test folder listing
	t.Log("Testing folder operations...")
	folders, err := client.ListFolders()
	if err != nil {
		t.Errorf("Failed to list folders: %v", err)
	} else {
		t.Logf("Found %d folders", len(folders.Folders))
		for _, folder := range folders.Folders {
			t.Logf("Folder: UID=%s, Name=%s", folder.UID, folder.Name)
		}
	}
}

// TestRealKSMConfig tests with existing config
func TestRealKSMConfig(t *testing.T) {
	configPath := os.Getenv("KSM_TEST_CONFIG")
	if configPath == "" {
		t.Skip("KSM_TEST_CONFIG not set, skipping config test")
	}

	// Read config file
	configData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read config file: %v", err)
	}

	// Initialize with config
	config, err := InitializeWithConfig(configData)
	if err != nil {
		t.Fatalf("Failed to initialize with config: %v", err)
	}

	// Create client and test
	logger := createTestLogger(t)
	defer logger.Close()

	profile := &types.Profile{
		Name:      "test-config",
		Config:    config,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	client, err := NewClient(profile, logger)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Quick connection test
	if err := client.TestConnection(); err != nil {
		t.Fatalf("Connection test failed: %v", err)
	}

	t.Log("Config-based connection successful!")
}

// Helper functions

func createTestLogger(t *testing.T) *audit.Logger {
	config := audit.Config{
		FilePath: t.TempDir() + "/integration-test.log",
		MaxSize:  10 * 1024 * 1024,
		MaxAge:   24 * time.Hour,
	}

	logger, err := audit.NewLogger(config)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	return logger
}

func getMapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func maskSensitiveJSON(data []byte) string {
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return string(data)
	}

	// Mask sensitive fields
	sensitiveFields := []string{"privateKey", "appKey", "clientKey", "serverPublicKey"}
	for _, field := range sensitiveFields {
		if _, exists := obj[field]; exists {
			obj[field] = "[MASKED]"
		}
	}

	masked, _ := json.MarshalIndent(obj, "", "  ")
	return string(masked)
}
