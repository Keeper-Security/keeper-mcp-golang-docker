package mcp

import (
	"testing"

	"github.com/keeper-security/ksm-mcp/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBugRepro_CustomFieldLabelNotSet demonstrates the bug:
// When the AI sends "custom.Notes" as the field type, processFieldsForSDK
// must extract the label and set the correct type — it must NOT pass through
// "custom.Notes" as-is, because that is not a valid KSM field type and the
// label will never reach recordData.Custom.
func TestBugRepro_CustomFieldLabelNotSet(t *testing.T) {
	input := []types.SecretField{
		{Type: "custom.Notes", Value: []interface{}{""}},
		{Type: "custom.API Key", Value: []interface{}{""}},
	}

	out, _, err := processFieldsForSDK(input)
	require.NoError(t, err)
	require.Len(t, out, 2)

	for _, f := range out {
		// ❌ BUG (before fix): f.Type == "custom.Notes" — raw string passes through
		//    unchanged, label is lost, and the field ends up in recordData.Fields
		//    instead of recordData.Custom.
		// ✅ FIXED: f.Type must be a real field type ("text"), not "custom.<label>"
		assert.NotContains(t, f.Type, "custom.",
			"field Type must not contain 'custom.' — that raw string is not a valid KSM type")
		assert.Equal(t, "text", f.Type,
			"simple custom field should resolve to type=text")
	}
}
