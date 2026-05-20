package ksm

// Integration tests for custom field create/read/update against a real vault.
// Skipped unless the KSM_CONFIG environment variable is set.
//
// Run with:
//   KSM_CONFIG=<base64> go test ./internal/ksm/ -run TestIntegration_CustomField -v

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/keeper-security/ksm-mcp/internal/audit"
	"github.com/keeper-security/ksm-mcp/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newIntegrationClient(t *testing.T) *Client {
	t.Helper()
	b64config := os.Getenv("KSM_CONFIG")
	if b64config == "" {
		t.Skip("KSM_CONFIG not set — skipping integration test")
	}
	// Decode base64 → raw JSON, then build map[string]string via InitializeWithConfig
	decoded, err := base64.StdEncoding.DecodeString(b64config)
	require.NoError(t, err, "KSM_CONFIG is not valid base64")

	ksmConfig, err := InitializeWithConfig(decoded)
	require.NoError(t, err, "KSM_CONFIG JSON is not a valid KSM configuration")

	logger, _ := audit.NewLogger(audit.Config{FilePath: "/tmp/ksm-mcp-integration-test.log"})
	client, err := NewClient(&types.Profile{
		Name:   "integration-test",
		Config: ksmConfig,
	}, logger)
	require.NoError(t, err)
	return client
}

func pickWritableFolder(t *testing.T, client *Client) string {
	t.Helper()
	folders, err := client.ListFolders()
	require.NoError(t, err)
	require.NotEmpty(t, folders.Folders, "vault has no accessible folders")
	return folders.Folders[0].UID
}

// TestIntegration_CustomField_CreateAndRead creates a record with two empty
// custom text fields and reads it back, asserting that both labels are stored
// exactly as sent — not as raw "custom.<label>" type strings.
func TestIntegration_CustomField_CreateAndRead(t *testing.T) {
	client := newIntegrationClient(t)
	folderUID := pickWritableFolder(t, client)

	params := types.CreateSecretParams{
		FolderUID: folderUID,
		Type:      "login",
		Title:     "ksm-mcp integration test — custom fields",
		Fields: []types.SecretField{
			{Type: "text", Label: "API Key", Value: []interface{}{""}, IsCustom: true},
			{Type: "text", Label: "Notes", Value: []interface{}{""}, IsCustom: true},
		},
	}

	uid, err := client.CreateSecret(params)
	require.NoError(t, err, "CreateSecret should succeed")
	require.NotEmpty(t, uid)

	t.Cleanup(func() {
		_ = client.DeleteSecret(uid, true)
	})

	// Read back
	secret, err := client.GetSecret(uid, nil, false)
	require.NoError(t, err)

	customFields, ok := secret["custom_fields"]
	require.True(t, ok, "record should have custom_fields key")

	cfMap, ok := customFields.(map[string]interface{})
	require.True(t, ok, "custom_fields should be a map")

	assert.Len(t, cfMap, 2, "should have exactly 2 custom fields")

	for expectedLabel := range map[string]struct{}{"API Key": {}, "Notes": {}} {
		_, exists := cfMap[expectedLabel]
		assert.True(t, exists, "custom field %q missing from stored record", expectedLabel)
	}

	// Regression guard: neither label must start with "custom." — that would
	// be the pre-fix bug where the raw type string leaked through as the label.
	for label := range cfMap {
		assert.False(t, strings.HasPrefix(label, "custom."),
			"label %q starts with 'custom.' — pre-fix bug has regressed", label)
	}
}

// TestIntegration_CustomField_UpdateValue creates a record with a custom field
// and then updates that field's value, verifying the new value is persisted.
func TestIntegration_CustomField_UpdateValue(t *testing.T) {
	client := newIntegrationClient(t)
	folderUID := pickWritableFolder(t, client)

	// Create
	uid, err := client.CreateSecret(types.CreateSecretParams{
		FolderUID: folderUID,
		Type:      "login",
		Title:     "ksm-mcp integration test — custom field update",
		Fields: []types.SecretField{
			{Type: "text", Label: "Project", Value: []interface{}{""}, IsCustom: true},
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.DeleteSecret(uid, true) })

	// Update
	err = client.UpdateSecret(types.UpdateSecretParams{
		UID: uid,
		Fields: []types.SecretField{
			{Type: "text", Label: "Project", Value: []interface{}{"Phoenix"}, IsCustom: true},
		},
	})
	require.NoError(t, err, "UpdateSecret should succeed")

	// Read back and verify
	secret, err := client.GetSecret(uid, nil, false)
	require.NoError(t, err)

	cfMap, ok := secret["custom_fields"].(map[string]interface{})
	require.True(t, ok)

	projectVal, exists := cfMap["Project"]
	assert.True(t, exists, "Project custom field should exist after update")

	// Value is stored as []interface{}{"Phoenix"}
	if vals, ok := projectVal.([]interface{}); ok && len(vals) > 0 {
		assert.Equal(t, "Phoenix", vals[0], "custom field value should be updated")
	} else {
		t.Errorf("unexpected Project value type: %T %v", projectVal, projectVal)
	}
}
