package recordtemplates

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/keeper-security/ksm-mcp/pkg/types"
)

//go:embed files/fields.json
var fieldsFile embed.FS

//go:embed files/field-types.json
var fieldTypesFile embed.FS

//go:embed files/standard_templates
//go:embed files/pam_templates
//go:embed files/pam_configuration_templates
var templateDirs embed.FS // Combined FS for all template directories

var (
	loadedTemplates     map[string]types.FullRecordTemplate
	loadedFields        map[string]types.TemplateBasicField
	loadedFieldTypes    map[string]types.TemplateFieldTypeDefinition
	templateParseErrors []string
)

// LoadRecordTemplates loads all record template definitions from the embedded files.
// It should be called once at server startup.
func LoadRecordTemplates() error {
	loadedTemplates = make(map[string]types.FullRecordTemplate)
	loadedFields = make(map[string]types.TemplateBasicField)
	loadedFieldTypes = make(map[string]types.TemplateFieldTypeDefinition)
	templateParseErrors = make([]string, 0)

	// Load fields.json
	fieldsData, err := fieldsFile.ReadFile("files/fields.json")
	if err != nil {
		return fmt.Errorf("failed to read embedded fields.json: %w", err)
	}
	var basicFields []types.TemplateBasicField
	if err := json.Unmarshal(fieldsData, &basicFields); err != nil {
		return fmt.Errorf("failed to parse embedded fields.json: %w", err)
	}
	for _, bf := range basicFields {
		loadedFields[bf.ID] = bf
	}
	fmt.Fprintf(os.Stderr, "DEBUG: Loaded %d basic fields. Example 'script': %+v\n", len(loadedFields), loadedFields["script"]) // DEBUG

	// Load field-types.json
	fieldTypesData, err := fieldTypesFile.ReadFile("files/field-types.json")
	if err != nil {
		return fmt.Errorf("failed to read embedded field-types.json: %w", err)
	}
	var fieldTypeDefinitions []types.TemplateFieldTypeDefinition
	if err := json.Unmarshal(fieldTypesData, &fieldTypeDefinitions); err != nil {
		return fmt.Errorf("failed to parse embedded field-types.json: %w", err)
	}
	for _, ftd := range fieldTypeDefinitions {
		loadedFieldTypes[ftd.ID] = ftd
	}

	// Directories to load templates from
	dirsToLoad := []string{
		"files/standard_templates",
		"files/pam_templates",
		"files/pam_configuration_templates",
	}

	for _, dirPath := range dirsToLoad {
		err = fs.WalkDir(templateDirs, dirPath, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				// Log or collect error, but allow WalkDir to attempt to continue for other files/dirs if appropriate
				templateParseErrors = append(templateParseErrors, fmt.Sprintf("error accessing path %s: %v", path, walkErr))
				return nil // Or return walkErr to stop for this directory
			}
			if !d.IsDir() && strings.HasSuffix(d.Name(), ".json") {
				templateData, readErr := templateDirs.ReadFile(path)
				if readErr != nil {
					templateParseErrors = append(templateParseErrors, fmt.Sprintf("error reading embedded template %s: %v", path, readErr))
					return nil // Continue walking
				}
				var template types.FullRecordTemplate
				if umErr := json.Unmarshal(templateData, &template); umErr != nil {
					templateParseErrors = append(templateParseErrors, fmt.Sprintf("error parsing embedded template %s: %v", path, umErr))
					return nil // Continue walking
				}
				if template.ID == "" {
					baseName := filepath.Base(path)
					template.ID = strings.TrimSuffix(baseName, ".json")
				}
				// Check for duplicates, or decide on an override strategy if IDs can clash across template directories
				if _, exists := loadedTemplates[template.ID]; exists {
					templateParseErrors = append(templateParseErrors, fmt.Sprintf("duplicate template ID '%s' found in %s", template.ID, path))
				} else {
					loadedTemplates[template.ID] = template
				}
			}
			return nil
		})
		if err != nil {
			// This error is from WalkDir itself, not from the callback. Should be treated seriously.
			return fmt.Errorf("error walking embedded directory %s: %w", dirPath, err)
		}
	}

	if len(templateParseErrors) > 0 {
		return fmt.Errorf("encountered %d errors while loading/parsing record templates: %s", len(templateParseErrors), strings.Join(templateParseErrors, "; "))
	}

	return nil
}

// GetSchema retrieves the processed schema for a given record type ID.
func GetSchema(recordTypeID string) (*types.RecordTypeSchema, error) {
	if loadedTemplates == nil || loadedFields == nil || loadedFieldTypes == nil {
		return nil, fmt.Errorf("record templates not loaded. Call LoadRecordTemplates first")
	}

	template, ok := loadedTemplates[recordTypeID]
	if !ok {
		// Attempt to find a template that might match by case-insensitive comparison or common aliases
		for id, t := range loadedTemplates {
			if strings.EqualFold(id, recordTypeID) || strings.EqualFold(strings.ReplaceAll(id, "_", ""), recordTypeID) {
				template = t
				ok = true
				recordTypeID = id // Use the canonical ID
				break
			}
		}
		if !ok {
			return nil, fmt.Errorf("record template not found for ID: %s", recordTypeID)
		}
	}

	schema := &types.RecordTypeSchema{
		RecordType:  template.ID,
		Description: template.Description,
		Fields:      make([]types.SchemaField, 0),
		Notes:       "Fields should be provided in a flattened format (e.g., 'bankAccount.accountType'). All 'value' properties must be single-element string arrays.",
	}

	// Process standard fields
	for _, tplField := range template.Fields {
		appendSchemaFields(tplField, &schema.Fields, false)
	}
	// Process custom fields (often not predefined with sub-elements in the same way, treat as simple for now)
	// Or, if custom fields can also be complex based on their type, this needs more sophisticated handling.
	for _, tplField := range template.Custom {
		appendSchemaFields(tplField, &schema.Fields, true)
	}

	return schema, nil
}

// appendSchemaFields is a helper to recursively build the schema fields.
func appendSchemaFields(tplField types.RecordTemplateField, schemaFields *[]types.SchemaField, isCustom bool) {
	fmt.Fprintf(os.Stderr, "DEBUG: Processing tplField with Ref: %s, Label: %s\n", tplField.Ref, tplField.Label) // DEBUG

	basicField, bfOk := loadedFields[tplField.Ref]
	if !bfOk {
		templateParseErrors = append(templateParseErrors, fmt.Sprintf("Referenced field $%s not found in fields.json for template field label '%s'", tplField.Ref, tplField.Label))
		fmt.Fprintf(os.Stderr, "DEBUG: basicField NOT FOUND for Ref: %s\n", tplField.Ref) // DEBUG
		*schemaFields = append(*schemaFields, types.SchemaField{
			Name:        tplField.Label,
			Description: "Error: Referenced field definition not found",
			Type:        "unknown",
			Required:    tplField.Required,
		})
		return
	}
	fmt.Fprintf(os.Stderr, "DEBUG: Found basicField for Ref: %s, BasicField Type: %s\n", tplField.Ref, basicField.Type) // DEBUG

	fieldTypeDefinition, ftdOk := loadedFieldTypes[basicField.Type]
	if !ftdOk {
		templateParseErrors = append(templateParseErrors, fmt.Sprintf("Field type definition '%s' not found in field-types.json for field $%s", basicField.Type, tplField.Ref))
		fmt.Fprintf(os.Stderr, "DEBUG: fieldTypeDefinition NOT FOUND for Type: %s (Ref: %s)\n", basicField.Type, tplField.Ref) // DEBUG
		*schemaFields = append(*schemaFields, types.SchemaField{
			Name:        tplField.Label,
			Description: fmt.Sprintf("Field type '%s' (Error: definition not found)", basicField.Type),
			Type:        basicField.Type,
			Required:    tplField.Required,
		})
		return
	}
	fmt.Fprintf(os.Stderr, "DEBUG: Found fieldTypeDefinition for Type: %s, Elements: %v\n", basicField.Type, fieldTypeDefinition.Elements) // DEBUG

	fieldLabel := tplField.Label
	if fieldLabel == "" {
		fieldLabel = basicField.ID
	}
	finalNamePrefix := ""
	if isCustom {
		finalNamePrefix = "custom."
	}

	if len(fieldTypeDefinition.Elements) > 0 { // Complex type with sub-fields
		for _, elementName := range fieldTypeDefinition.Elements {
			sf := types.SchemaField{
				Name:        finalNamePrefix + fieldLabel + "." + elementName,
				Description: fmt.Sprintf("%s - %s", fieldTypeDefinition.Description, elementName),
				Type:        "string",          // Sub-elements are treated as string inputs in flattened form
				Required:    tplField.Required, // Base field's required status for now
			}
			addExampleValuesToSubField(&sf, basicField.Type, elementName) // basicField.Type is like "phone", "bankAccount"
			*schemaFields = append(*schemaFields, sf)
		}
	} else { // Simple field
		sf := types.SchemaField{
			Name:        finalNamePrefix + fieldLabel,
			Description: fieldTypeDefinition.Description,
			Type:        basicField.Type,
			Required:    tplField.Required,
		}
		// Add example values for known enum-like simple fields based on their main type ID
		switch basicField.Type { // This refers to the $id from field-types.json, e.g., "phoneType", "accountType"
		// Case for a simple field that is an enum (e.g. if 'databaseType' was simple and not part of a complex field definition)
		// For example, if field-types.json had { "$id": "phoneType", "description": "Type of phone" ... }
		// and fields.json had { "$id": "mobilePhoneType", "type": "phoneType" }
		// and a template used { "$ref": "mobilePhoneType", "label": "Mobile Type" }
		// Then basicField.Type would be "phoneType"
		// This section is more for simple fields that are inherently enums.
		// Most enums we care about are sub-fields of complex types, handled by addExampleValuesToSubField.
		}
		*schemaFields = append(*schemaFields, sf)
	}
}

// Helper function to add example values to sub-fields of complex types
func addExampleValuesToSubField(schemaField *types.SchemaField, baseType string, elementName string) {
	if baseType == "phone" && elementName == "type" {
		schemaField.ExampleValues = []string{"Mobile", "Home", "Work", "Other"}
		schemaField.Description += " (e.g., Mobile, Home, Work)"
	} else if baseType == "bankAccount" && elementName == "accountType" {
		schemaField.ExampleValues = []string{"Checking", "Savings", "Other"} // As per vault's field-data.ts
		schemaField.Description += " (e.g., Checking, Savings, Other)"
	}
	// Add more cases for other complex_field.sub_field enums here
}

// GetParseErrors returns any errors encountered during template loading.
func GetParseErrors() []string {
	return templateParseErrors
}
