package recordtemplates

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFieldTypesLoading(t *testing.T) {
	// Load the record templates
	err := LoadRecordTemplates()
	require.NoError(t, err, "LoadRecordTemplates should not error")

	// Test that the updated field types are loaded correctly
	tests := []struct {
		name             string
		fieldTypeID      string
		expectedElements []string
	}{
		{
			name:             "name field has correct elements",
			fieldTypeID:      "name",
			expectedElements: []string{"first", "middle", "last"},
		},
		{
			name:             "phone field has correct elements",
			fieldTypeID:      "phone",
			expectedElements: []string{"region", "number", "ext", "type"},
		},
		{
			name:             "bankAccount field has correct elements",
			fieldTypeID:      "bankAccount",
			expectedElements: []string{"accountType", "routingNumber", "accountNumber", "otherType"},
		},
		{
			name:             "privateKey field has correct elements",
			fieldTypeID:      "privateKey",
			expectedElements: []string{"publicKey", "privateKey"},
		},
		{
			name:             "schedule field has correct elements",
			fieldTypeID:      "schedule",
			expectedElements: []string{"type", "time", "month"},
		},
		{
			name:             "appFiller field has correct elements",
			fieldTypeID:      "appFiller",
			expectedElements: []string{"applicationTitle", "contentFilter", "macroSequence"},
		},
		{
			name:             "pamResources field has correct elements",
			fieldTypeID:      "pamResources",
			expectedElements: []string{"controllerUid", "folderUid", "resourceRef"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fieldType := GetFieldType(tt.fieldTypeID)
			require.NotNil(t, fieldType, "Field type %s should be found", tt.fieldTypeID)

			if len(tt.expectedElements) > 0 {
				assert.Equal(t, tt.expectedElements, fieldType.Elements,
					"Field type %s should have correct elements", tt.fieldTypeID)
			}
		})
	}
}

func TestFieldTypesLoadingIntegrity(t *testing.T) {
	// Load the record templates
	err := LoadRecordTemplates()
	require.NoError(t, err, "LoadRecordTemplates should not error")

	// Test that key field types exist (focus on the ones we just added/modified)
	requiredFieldTypes := []string{
		"text", "password", "url", "email", "multiline", "host", "phone", "name",
		"address", "bankAccount", "date", "securityQuestion", "paymentCard",
		"privateKey", "fileRef", "script", "schedule", "appFiller", "pamResources",
		"pamSettings", "pamHostname", "login", "recordRef", "passkey",
	}

	for _, fieldTypeID := range requiredFieldTypes {
		t.Run("field_type_"+fieldTypeID, func(t *testing.T) {
			fieldType := GetFieldType(fieldTypeID)
			assert.NotNil(t, fieldType, "Field type %s should exist", fieldTypeID)
		})
	}
}
