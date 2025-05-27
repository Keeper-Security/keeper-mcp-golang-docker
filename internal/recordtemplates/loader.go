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

// GetSchema retrieves the processed schema for a given record type ID,
// applying UI-specific transformations.
func GetSchema(recordTypeID string) (*types.RecordTypeSchema, error) {
	if loadedTemplates == nil || loadedFields == nil || loadedFieldTypes == nil {
		return nil, fmt.Errorf("record templates not loaded. Call LoadRecordTemplates first")
	}

	canonicalID := recordTypeID
	template, ok := loadedTemplates[recordTypeID]
	if !ok {
		foundMatch := false
		for id, t := range loadedTemplates {
			if strings.EqualFold(id, recordTypeID) || strings.EqualFold(strings.ReplaceAll(id, "_", ""), recordTypeID) {
				template = t
				canonicalID = id // Use the canonical ID from the loaded templates
				foundMatch = true
				break
			}
		}
		if !foundMatch {
			return nil, fmt.Errorf("record template not found for ID: %s", recordTypeID)
		}
	}

	schema := &types.RecordTypeSchema{
		RecordType:  canonicalID, // Use the ID found in the map key
		Description: template.Description,
		Fields:      make([]types.SchemaField, 0),
		Notes:       "Fields should be provided in a flattened format (e.g., 'bankAccount.accountType'). All 'value' properties must be single-element string arrays.",
	}

	// Process standard fields first
	for _, tplField := range template.Fields {
		appendSchemaFields(tplField, &schema.Fields, false, canonicalID)
	}
	// Process custom fields
	for _, tplField := range template.Custom {
		appendSchemaFields(tplField, &schema.Fields, true, canonicalID)
	}

	// Apply UI-specific transformations that mimic client-side processing
	applyUITransformations(canonicalID, schema)

	return schema, nil
}

// appendSchemaFields is a helper to recursively build the schema fields.
// It now takes recordTypeID to help with context-specific decisions if needed.
func appendSchemaFields(tplField types.RecordTemplateField, schemaFields *[]types.SchemaField, isCustom bool, recordTypeID string) {
	fmt.Fprintf(os.Stderr, "DEBUG: appendSchemaFields for %s - Ref: %s, Label: %s\n", recordTypeID, tplField.Ref, tplField.Label)

	basicField, bfOk := loadedFields[tplField.Ref]
	if !bfOk {
		templateParseErrors = append(templateParseErrors, fmt.Sprintf("[%s] Referenced field $%s not found in fields.json for template field label '%s'", recordTypeID, tplField.Ref, tplField.Label))
		*schemaFields = append(*schemaFields, types.SchemaField{
			Name:        tplField.Label,
			Description: "Error: Referenced field definition ($ref) not found in fields.json",
			Type:        "unknown",
			Required:    tplField.Required,
		})
		return
	}

	fieldTypeDefinition, ftdOk := loadedFieldTypes[basicField.Type]
	if !ftdOk {
		templateParseErrors = append(templateParseErrors, fmt.Sprintf("[%s] Field type definition '%s' (from $ref: %s) not found in field-types.json", recordTypeID, basicField.Type, tplField.Ref))
		*schemaFields = append(*schemaFields, types.SchemaField{
			Name:        tplField.Label,
			Description: fmt.Sprintf("Field type '%s' (Error: Type definition not found in field-types.json)", basicField.Type),
			Type:        basicField.Type,
			Required:    tplField.Required,
		})
		return
	}

	fieldLabelToUse := tplField.Label
	if fieldLabelToUse == "" {
		fieldLabelToUse = basicField.ID
	}
	finalNamePrefix := ""
	if isCustom {
		finalNamePrefix = "custom."
	}

	if len(fieldTypeDefinition.Elements) > 0 {
		for _, elementName := range fieldTypeDefinition.Elements {
			sf := types.SchemaField{
				Name:        finalNamePrefix + fieldLabelToUse + "." + elementName,
				Description: fmt.Sprintf("%s - %s", fieldTypeDefinition.Description, elementName),
				Type:        "string",
				Required:    tplField.Required,
			}
			addExampleValuesToSubField(&sf, basicField.Type, elementName)
			*schemaFields = append(*schemaFields, sf)
		}
	} else {
		sf := types.SchemaField{
			Name:        finalNamePrefix + fieldLabelToUse,
			Description: fieldTypeDefinition.Description,
			Type:        basicField.Type,
			Required:    tplField.Required,
		}
		addExampleValuesToSimpleField(&sf, basicField.Type)
		*schemaFields = append(*schemaFields, sf)
	}
}

// addExampleValuesToSimpleField adds example values for simple enum-like fields
func addExampleValuesToSimpleField(schemaField *types.SchemaField, fieldTypeID string) {
	// This is for simple fields that are enums directly, not sub-fields of complex types
	// Example: if 'databaseType' was a simple field itself.
	switch fieldTypeID {
	case "databaseType":
		schemaField.ExampleValues = []string{"PostgreSQL", "MySQL", "MariaDB", "MSSQL", "Oracle", "MongoDB"} // From vault's DatabaseType enum
		schemaField.Description += " (e.g., PostgreSQL, MySQL)"
	case "directoryType":
		schemaField.ExampleValues = []string{"Active Directory", "OpenLDAP"} // From vault's DirectoryType enum
		schemaField.Description += " (e.g., Active Directory)"
		// Add more simple enum field types here if needed
	}
}

func applyUITransformations(recordTypeID string, schema *types.RecordTypeSchema) {
	// Mimic logic from vault client's processGetRecordTypesResponse
	// This function modifies schema.Fields in place

	// The logic for adding pamSettings and trafficEncryptionSeed based on hasPamHostname
	// was commented out because the pamMachine.json template now directly includes $refs for these.
	// If that changes, or if other PAM types need this dynamic addition, that logic can be reinstated.
	// For now, ensure hasPamHostname and pamHostnameIndex are not declared if not used.
	// For example, if we needed to find the insertion point:
	// pamHostnameIndex := -1
	// for i, f := range schema.Fields {
	// 	if strings.HasPrefix(f.Name, "pamHostname.") {
	// 		if i > pamHostnameIndex {
	// 			pamHostnameIndex = i
	// 		}
	// 	}
	// }

	// Remove fields for certain PAM types
	fieldsToRemove := make(map[string]bool)
	if recordTypeID != "pamRemoteBrowser" && recordTypeID != "pamUser" { // This condition applied to login/password removal in UI code
		// For pamMachine specifically, UI code removes login, password, and privatePEMKey (if it was defined via a secret ref with that label)
		if recordTypeID == "pamMachine" {
			fieldsToRemove["login"] = true         // Base field name
			fieldsToRemove["password"] = true      // Base field name
			fieldsToRemove["privatePEMKey"] = true // Label used in pamUser, check pamMachine template for actual SSH key field
		}
		if recordTypeID == "pamDirectory" {
			fieldsToRemove["distinguishedName"] = true
		}
		if recordTypeID == "pamDatabase" {
			fieldsToRemove["connectDatabase"] = true
		}
	}

	if len(fieldsToRemove) > 0 {
		updatedFields := make([]types.SchemaField, 0)
		for _, field := range schema.Fields {
			// Check against the base name if it's a flattened field
			baseName := strings.Split(field.Name, ".")[0]
			if !fieldsToRemove[field.Name] && !fieldsToRemove[baseName] {
				updatedFields = append(updatedFields, field)
			}
		}
		schema.Fields = updatedFields
	}

	// Specific handling for pamRemoteBrowser - ensure it has rbiUrl, pamRemoteBrowserSettings, trafficEncryptionSeed
	if recordTypeID == "pamRemoteBrowser" {
		desiredFields := map[string]bool{"rbiUrl": false, "pamRemoteBrowserSettings": false, "trafficEncryptionSeed": false}
		currentFields := make([]types.SchemaField, 0)
		for _, field := range schema.Fields {
			baseName := strings.Split(field.Name, ".")[0] // Get base name for complex types
			if _, ok := desiredFields[baseName]; ok {
				currentFields = append(currentFields, field)
				desiredFields[baseName] = true
			} else if _, okSingle := desiredFields[field.Name]; okSingle { // For simple fields
				currentFields = append(currentFields, field)
				desiredFields[field.Name] = true
			}
		}
		schema.Fields = currentFields

		// Add missing desired fields
		for fName, found := range desiredFields {
			if !found {
				// This requires knowing the $ref for these fields to call appendSchemaFields correctly
				// e.g., if "rbiUrl" $ref is "rbiUrlField" in fields.json
				// This part is tricky without knowing the exact $ref for these specific fields.
				// For now, we'll log a warning if a hardcoded desired field is missing.
				templateParseErrors = append(templateParseErrors, fmt.Sprintf("Warning: For pamRemoteBrowser, desired field '%s' was not found in base template and was not dynamically added due to missing $ref info.", fName))
			}
		}
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
