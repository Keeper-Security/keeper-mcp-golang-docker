package types

// Based on record-templates/fields.json
type TemplateBasicField struct {
	ID       string `json:"$id"`
	Type     string `json:"type"`
	Lookup   string `json:"lookup,omitempty"`
	Multiple string `json:"multiple,omitempty"` // e.g., "optional", "default"
}

// Based on record-templates/field-types.json
type TemplateFieldTypeDefinition struct {
	ID          string   `json:"$id"`
	Description string   `json:"description"`
	Elements    []string `json:"elements,omitempty"` // For complex types, lists sub-field names
}

// Based on record-templates/standard_templates/*.json (general structure)
// A single field within a record template's "fields" array
type RecordTemplateField struct {
	Ref               string      `json:"$ref"` // References $id in fields.json
	Label             string      `json:"label,omitempty"`
	Required          bool        `json:"required,omitempty"`
	PrivacyScreen     bool        `json:"privacyScreen,omitempty"`
	EnforceGeneration bool        `json:"enforceGeneration,omitempty"`
	Complexity        interface{} `json:"complexity,omitempty"` // Can be complex, keep as interface{}
	MaskData          bool        `json:"maskData,omitempty"`   // Custom property for masking specific fields
	// Other properties like appFillerData, selectableOptions might exist
	// For schema generation, $ref, label, and required are most important initially.
}

// Represents a full record template (e.g., bank_account.json)
// This is a simplified version for schema generation, actual templates might be more complex.
// We are primarily interested in the fields array and their $ref to link to fields.json and field-types.json
type FullRecordTemplate struct {
	ID          string                `json:"$id"` // e.g., "bankAccount", "login"
	Description string                `json:"description,omitempty"`
	Fields      []RecordTemplateField `json:"fields,omitempty"`
	Custom      []RecordTemplateField `json:"custom,omitempty"` // Custom fields also use RecordTemplateField structure
	// Other top-level properties like categories, icon, recordTypeId exist but may not be needed for field schema
}

// SchemaField represents a field in the schema returned to the AI
type SchemaField struct {
	Name          string        `json:"name"` // Flattened name, e.g., "login", "bankAccount.accountType"
	Description   string        `json:"description,omitempty"`
	Type          string        `json:"type"` // Underlying data type (e.g., "string", "number", "boolean", or original complex type for reference)
	Required      bool          `json:"required"`
	ExampleValues []string      `json:"example_values,omitempty"`
	SubFields     []SchemaField `json:"sub_fields,omitempty"` // For explicitly showing structure of complex types, if not fully flattened
}

// RecordTypeSchema is the structure returned by the get_record_type_schema tool
type RecordTypeSchema struct {
	RecordType  string        `json:"record_type"`
	Description string        `json:"description,omitempty"`
	Fields      []SchemaField `json:"fields"`
	Notes       string        `json:"notes,omitempty"` // General notes about creating this record type
}
