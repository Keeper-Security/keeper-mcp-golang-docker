package mcp

import (
	"encoding/json"
	"testing"

	"github.com/keeper-security/ksm-mcp/internal/audit"
	"github.com/keeper-security/ksm-mcp/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ─── processFieldsForSDK – custom field routing ────────────────────────────

func TestProcessFieldsForSDK_SimpleCustomField(t *testing.T) {
	// "custom.Notes" → IsCustom=true, Type="text", Label="Notes"
	input := []types.SecretField{
		{Type: "custom.Notes", Value: []interface{}{""}},
	}

	out, warnings, err := processFieldsForSDK(input)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.Len(t, out, 1)

	f := out[0]
	assert.True(t, f.IsCustom, "field should be marked IsCustom")
	assert.Equal(t, "text", f.Type, "simple custom field should default to type=text")
	assert.Equal(t, "Notes", f.Label, "label should be extracted from the type string")
	assert.Equal(t, []interface{}{""}, f.Value)
}

func TestProcessFieldsForSDK_TwoEmptyCustomFields(t *testing.T) {
	// The exact scenario from the bug report
	input := []types.SecretField{
		{Type: "custom.API Key", Value: []interface{}{""}},
		{Type: "custom.Notes", Value: []interface{}{""}},
	}

	out, warnings, err := processFieldsForSDK(input)
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.Len(t, out, 2)

	byLabel := make(map[string]types.SecretField)
	for _, f := range out {
		byLabel[f.Label] = f
	}

	apiKey, ok := byLabel["API Key"]
	require.True(t, ok, "API Key field not found")
	assert.True(t, apiKey.IsCustom)
	assert.Equal(t, "text", apiKey.Type)

	notes, ok := byLabel["Notes"]
	require.True(t, ok, "Notes field not found")
	assert.True(t, notes.IsCustom)
	assert.Equal(t, "text", notes.Type)
}

func TestProcessFieldsForSDK_CustomFieldWithValue(t *testing.T) {
	input := []types.SecretField{
		{Type: "custom.Department", Value: []interface{}{"Engineering"}},
	}

	out, _, err := processFieldsForSDK(input)
	require.NoError(t, err)
	require.Len(t, out, 1)

	f := out[0]
	assert.True(t, f.IsCustom)
	assert.Equal(t, "text", f.Type)
	assert.Equal(t, "Department", f.Label)
	assert.Equal(t, []interface{}{"Engineering"}, f.Value)
}

func TestProcessFieldsForSDK_ComplexCustomField(t *testing.T) {
	// "custom.Work Phone.number" + "custom.Work Phone.region" should be grouped
	// into a single custom phone field with label "Work Phone"
	input := []types.SecretField{
		{Type: "custom.Work Phone.number", Value: []interface{}{"+1-555-0100"}},
		{Type: "custom.Work Phone.region", Value: []interface{}{"US"}},
	}

	out, _, err := processFieldsForSDK(input)
	require.NoError(t, err)
	require.Len(t, out, 1, "two sub-fields should be merged into one custom field")

	f := out[0]
	assert.True(t, f.IsCustom)
	assert.Equal(t, "Work Phone", f.Label)
	assert.Equal(t, "phone", f.Type, "type should be inferred as phone from sub-field names")
	require.Len(t, f.Value, 1)

	valueMap, ok := f.Value[0].(map[string]interface{})
	require.True(t, ok, "value should be a map")
	assert.Equal(t, "+1-555-0100", valueMap["number"])
	assert.Equal(t, "US", valueMap["region"])
}

func TestProcessFieldsForSDK_MixedStandardAndCustomFields(t *testing.T) {
	// Standard and custom fields must be correctly separated
	input := []types.SecretField{
		{Type: "login", Value: []interface{}{"alice@example.com"}},
		{Type: "password", Value: []interface{}{"secret123"}},
		{Type: "custom.Employee ID", Value: []interface{}{""}},
		{Type: "custom.Cost Center", Value: []interface{}{""}},
	}

	out, _, err := processFieldsForSDK(input)
	require.NoError(t, err)
	require.Len(t, out, 4)

	standardCount := 0
	customCount := 0
	for _, f := range out {
		if f.IsCustom {
			customCount++
			assert.NotEmpty(t, f.Label, "custom field must have a label")
			assert.Equal(t, "text", f.Type, "custom field type should default to text")
		} else {
			standardCount++
			assert.Empty(t, f.Label, "standard field should not have a label")
		}
	}
	assert.Equal(t, 2, standardCount, "should have 2 standard fields")
	assert.Equal(t, 2, customCount, "should have 2 custom fields")
}

func TestProcessFieldsForSDK_CustomFieldDoesNotLeakIntoStandardFields(t *testing.T) {
	// Regression: custom fields must NOT appear with type "custom.<Label>" —
	// that would send an invalid type string to the SDK.
	input := []types.SecretField{
		{Type: "custom.My Label", Value: []interface{}{"value"}},
	}

	out, _, err := processFieldsForSDK(input)
	require.NoError(t, err)
	require.Len(t, out, 1)

	f := out[0]
	assert.NotEqual(t, "custom.My Label", f.Type,
		"type must NOT be the raw 'custom.<Label>' string")
	assert.True(t, f.IsCustom)
	assert.Equal(t, "text", f.Type)
	assert.Equal(t, "My Label", f.Label)
}

// ─── inferComplexCustomFieldType ─────────────────────────────────────────────

func TestInferComplexCustomFieldType(t *testing.T) {
	complexDefs := map[string]map[string]string{
		"phone":       {"region": "string", "number": "string", "ext": "string", "type": "string"},
		"host":        {"hostName": "string", "port": "string"},
		"bankAccount": {"accountType": "string", "routingNumber": "string", "accountNumber": "string", "otherType": "string"},
		"address":     {"street1": "string", "street2": "string", "city": "string", "state": "string", "zip": "string", "country": "string"},
	}

	tests := []struct {
		name     string
		subField map[string]interface{}
		want     string
	}{
		{"phone by number+region", map[string]interface{}{"number": "+1", "region": "US"}, "phone"},
		{"host by hostName+port", map[string]interface{}{"hostName": "localhost", "port": "8080"}, "host"},
		{"bankAccount by routingNumber", map[string]interface{}{"routingNumber": "021000021"}, "bankAccount"},
		{"address by city+zip", map[string]interface{}{"city": "Chicago", "zip": "60601"}, "address"},
		{"unknown sub-field defaults to text", map[string]interface{}{"somethingRandom": "x"}, "text"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inferComplexCustomFieldType(tt.subField, complexDefs)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ─── CreateSecretParams routing (unit-level) ─────────────────────────────────

// TestCreateSecretParams_CustomFieldsRoutedToCustomSection verifies that after
// processFieldsForSDK the caller correctly separates IsCustom fields.
// This mirrors exactly what client.go's CreateSecret does.
func TestCreateSecretParams_CustomFieldsRoutedToCustomSection(t *testing.T) {
	input := []types.SecretField{
		{Type: "login", Value: []interface{}{"user@example.com"}},
		{Type: "custom.Notes", Value: []interface{}{""}},
		{Type: "custom.Tag", Value: []interface{}{""}},
	}

	processed, _, err := processFieldsForSDK(input)
	require.NoError(t, err)

	// Simulate what client.go does
	var stdFields []map[string]interface{}
	var customFields []map[string]interface{}
	for _, f := range processed {
		if f.IsCustom {
			customFields = append(customFields, map[string]interface{}{
				"type":  f.Type,
				"label": f.Label,
				"value": f.Value,
			})
		} else {
			stdFields = append(stdFields, map[string]interface{}{
				"type":  f.Type,
				"value": f.Value,
			})
		}
	}

	require.Len(t, stdFields, 1, "only login should be in standard fields")
	assert.Equal(t, "login", stdFields[0]["type"])

	require.Len(t, customFields, 2, "Notes and Tag should be in custom fields")

	for _, cf := range customFields {
		assert.Equal(t, "text", cf["type"], "custom field type should be text")
		label, ok := cf["label"].(string)
		assert.True(t, ok && label != "", "custom field must have a non-empty label; got %v", cf["label"])
		// The label must NOT be empty and must NOT be the raw "custom.<Label>" string
		assert.NotContains(t, label, "custom.", "label should not contain 'custom.' prefix")
	}
}

// ─── Handler-level tests (full pipeline through executeCreate/UpdateConfirmed) ─

// newTestServer creates a minimal server wired to a mock client in batch mode.
func newTestServer(t *testing.T, mockClient *mockKSMClient) *Server {
	t.Helper()
	logger, _ := audit.NewLogger(audit.Config{FilePath: "/tmp/test-audit.log"})
	srv := &Server{
		confirmer: new(mockConfirmer),
		logger:    logger,
		options:   &ServerOptions{BatchMode: true},
	}
	srv.getCurrentClient = func() (KSMClient, error) { return mockClient, nil }
	return srv
}

// TestExecuteCreateSecretConfirmed_CustomFieldsReachClient verifies that when
// the handler receives custom fields ("custom.Notes", "custom.Employee ID"),
// executeCreateSecretConfirmed calls client.CreateSecret with IsCustom=true
// and the correct Label on each field — never with "custom." as the type.
func TestExecuteCreateSecretConfirmed_CustomFieldsReachClient(t *testing.T) {
	mc := new(mockKSMClient)
	mc.On("CreateSecret", mock.MatchedBy(func(p types.CreateSecretParams) bool {
		if p.Title != "Bug Repro" || p.FolderUID != "folder1" {
			return false
		}
		// Must have exactly 2 custom fields, each with IsCustom=true and Label set
		customCount := 0
		for _, f := range p.Fields {
			if f.IsCustom {
				customCount++
				if f.Label == "" || f.Type == "" {
					return false
				}
				// The type must NOT be "custom.<label>" — that would be the bug
				if len(f.Type) > 7 && f.Type[:7] == "custom." {
					return false
				}
			}
		}
		return customCount == 2
	})).Return("new-uid-123", nil)

	srv := newTestServer(t, mc)
	args := json.RawMessage(`{
		"folder_uid": "folder1",
		"type":       "login",
		"title":      "Bug Repro",
		"fields": [
			{"type": "custom.Notes",       "value": [""]},
			{"type": "custom.Employee ID", "value": [""]}
		]
	}`)

	result, err := srv.executeCreateSecretConfirmed(mc, args)
	require.NoError(t, err)
	resultMap := result.(map[string]interface{})
	assert.Equal(t, "new-uid-123", resultMap["uid"])
	mc.AssertExpectations(t)
}

// TestExecuteUpdateSecretConfirmed_CustomFieldsReachClient verifies that
// updating a custom field ("custom.Notes") results in client.UpdateSecret
// receiving IsCustom=true, Label="Notes", Type="text" — not the raw "custom.Notes" type.
func TestExecuteUpdateSecretConfirmed_CustomFieldsReachClient(t *testing.T) {
	mc := new(mockKSMClient)
	mc.On("UpdateSecret", mock.MatchedBy(func(p types.UpdateSecretParams) bool {
		if p.UID != "uid-abc" {
			return false
		}
		for _, f := range p.Fields {
			if f.IsCustom {
				if f.Label != "Notes" {
					return false
				}
				// type must be the real type ("text"), not "custom.Notes"
				if f.Type == "custom.Notes" {
					return false
				}
				if len(f.Value) == 0 {
					return false
				}
				v, ok := f.Value[0].(string)
				return ok && v == "new value"
			}
		}
		return false
	})).Return(nil)

	srv := newTestServer(t, mc)
	args := json.RawMessage(`{
		"uid": "uid-abc",
		"fields": [
			{"type": "custom.Notes", "value": ["new value"]}
		]
	}`)

	result, err := srv.executeUpdateSecretConfirmed(mc, args)
	require.NoError(t, err)
	resultMap := result.(map[string]interface{})
	assert.Equal(t, "uid-abc", resultMap["uid"])
	mc.AssertExpectations(t)
}

// TestExecuteCreateSecretConfirmed_MixedFields verifies that standard fields
// (login, password) and custom fields can coexist and are correctly separated.
func TestExecuteCreateSecretConfirmed_MixedFields(t *testing.T) {
	mc := new(mockKSMClient)
	mc.On("CreateSecret", mock.MatchedBy(func(p types.CreateSecretParams) bool {
		stdCount, customCount := 0, 0
		for _, f := range p.Fields {
			if f.IsCustom {
				customCount++
				// custom fields must not carry "custom." in their Type
				assert.NotContains(t, f.Type, "custom.", "IsCustom field has invalid type: %s", f.Type)
				assert.NotEmpty(t, f.Label, "IsCustom field must have a Label")
			} else {
				stdCount++
			}
		}
		return stdCount == 2 && customCount == 2
	})).Return("mixed-uid", nil)

	srv := newTestServer(t, mc)
	args := json.RawMessage(`{
		"folder_uid": "folder1",
		"type":       "login",
		"title":      "Mixed Test",
		"fields": [
			{"type": "login",            "value": ["user@example.com"]},
			{"type": "password",         "value": ["s3cr3t"]},
			{"type": "custom.API Key",   "value": [""]},
			{"type": "custom.Reference", "value": [""]}
		]
	}`)

	_, err := srv.executeCreateSecretConfirmed(mc, args)
	require.NoError(t, err)
	mc.AssertExpectations(t)
}
