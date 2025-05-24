package ksm

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/keeper-security/ksm-mcp/pkg/types"
)

var (
	// Notation patterns
	uidPattern    = regexp.MustCompile(`^([a-zA-Z0-9_-]{16,32})/(.+)$`)
	arrayPattern  = regexp.MustCompile(`^(.+)\[(\d+)\]$`)
	propPattern   = regexp.MustCompile(`^(.+)\[([a-zA-Z_]\w*)\]$`)
	nestedPattern = regexp.MustCompile(`^(.+)\[(\d+)\]\[([a-zA-Z_]\w*)\]$`)
)

// ParseNotation parses KSM notation into structured format
func ParseNotation(notation string) (*types.NotationResult, error) {
	if notation == "" {
		return nil, fmt.Errorf("notation cannot be empty")
	}

	parts := strings.Split(notation, "/")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid notation format: expected at least 2 parts separated by '/'")
	}

	result := &types.NotationResult{
		Index: -1, // Initialize to -1 (no index)
	}

	// First part is either UID or Title
	first := parts[0]
	if isValidUID(first) {
		result.UID = first
	} else {
		result.Title = first
	}

	// Parse the rest based on the second part
	switch parts[1] {
	case "field":
		if len(parts) < 3 {
			return nil, fmt.Errorf("field notation requires field name")
		}
		return parseFieldNotation(result, parts[2])

	case "custom_field":
		if len(parts) < 3 {
			return nil, fmt.Errorf("custom_field notation requires field name")
		}
		result.Custom = true
		return parseFieldNotation(result, parts[2])

	case "file":
		if len(parts) < 3 {
			return nil, fmt.Errorf("file notation requires filename")
		}
		result.File = parts[2]
		return result, nil

	default:
		return nil, fmt.Errorf("unknown notation type: %s", parts[1])
	}
}

// parseFieldNotation parses field notation including array/property access
func parseFieldNotation(result *types.NotationResult, fieldPart string) (*types.NotationResult, error) {
	// Check if field is empty
	if fieldPart == "" {
		return nil, fmt.Errorf("field name cannot be empty")
	}

	// Check for nested array with property: field[0][property]
	if matches := nestedPattern.FindStringSubmatch(fieldPart); matches != nil {
		result.Field = matches[1]
		index, err := strconv.Atoi(matches[2])
		if err != nil {
			return nil, fmt.Errorf("invalid array index: %s", matches[2])
		}
		result.Index = index
		result.Property = matches[3]
		return result, nil
	}

	// Check for array access: field[0]
	if matches := arrayPattern.FindStringSubmatch(fieldPart); matches != nil {
		result.Field = matches[1]
		index, err := strconv.Atoi(matches[2])
		if err != nil {
			return nil, fmt.Errorf("invalid array index: %s", matches[2])
		}
		result.Index = index
		return result, nil
	}

	// Check for property access: field[property]
	if matches := propPattern.FindStringSubmatch(fieldPart); matches != nil {
		result.Field = matches[1]
		result.Property = matches[2]
		return result, nil
	}

	// Simple field
	result.Field = fieldPart
	return result, nil
}

// BuildNotation builds a notation string from components
func BuildNotation(result *types.NotationResult) string {
	var parts []string

	// First part: UID or Title
	if result.UID != "" {
		parts = append(parts, result.UID)
	} else if result.Title != "" {
		parts = append(parts, result.Title)
	} else {
		return ""
	}

	// Second part: type
	if result.File != "" {
		parts = append(parts, "file", result.File)
		return strings.Join(parts, "/")
	}

	if result.Custom {
		parts = append(parts, "custom_field")
	} else {
		parts = append(parts, "field")
	}

	// Third part: field with optional array/property
	field := result.Field
	if result.Property != "" && result.Index >= 0 {
		// Nested: field[0][property]
		field = fmt.Sprintf("%s[%d][%s]", field, result.Index, result.Property)
	} else if result.Index >= 0 {
		// Array: field[0]
		field = fmt.Sprintf("%s[%d]", field, result.Index)
	} else if result.Property != "" {
		// Property: field[property]
		field = fmt.Sprintf("%s[%s]", field, result.Property)
	}

	parts = append(parts, field)
	return strings.Join(parts, "/")
}

// ValidateNotation validates a notation string
func ValidateNotation(notation string) error {
	_, err := ParseNotation(notation)
	return err
}

// isValidUID checks if a string is a valid UID format
func isValidUID(s string) bool {
	if len(s) < 16 || len(s) > 32 {
		return false
	}
	// UIDs typically contain alphanumeric, underscore, and hyphen
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || 
			  (r >= '0' && r <= '9') || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

// ExtractFieldPath extracts the field path from notation for SDK usage
func ExtractFieldPath(notation string) (string, error) {
	parsed, err := ParseNotation(notation)
	if err != nil {
		return "", err
	}

	// Build path for SDK
	var path string
	if parsed.Custom {
		path = "custom_field/"
	} else {
		path = "field/"
	}

	path += parsed.Field

	// Add array/property access if needed
	if parsed.Property != "" && parsed.Index >= 0 {
		path += fmt.Sprintf("[%d][%s]", parsed.Index, parsed.Property)
	} else if parsed.Index >= 0 {
		path += fmt.Sprintf("[%d]", parsed.Index)
	} else if parsed.Property != "" {
		path += fmt.Sprintf("[%s]", parsed.Property)
	}

	return path, nil
}

// IsFileNotation checks if notation refers to a file
func IsFileNotation(notation string) bool {
	parts := strings.Split(notation, "/")
	return len(parts) >= 2 && parts[1] == "file"
}

// IsCustomFieldNotation checks if notation refers to a custom field
func IsCustomFieldNotation(notation string) bool {
	parts := strings.Split(notation, "/")
	return len(parts) >= 2 && parts[1] == "custom_field"
}

// SplitNotationParts splits notation into its component parts
func SplitNotationParts(notation string) (recordRef string, fieldType string, fieldPath string, err error) {
	parts := strings.Split(notation, "/")
	if len(parts) < 3 {
		return "", "", "", fmt.Errorf("invalid notation: expected at least 3 parts")
	}

	recordRef = parts[0]
	fieldType = parts[1]
	fieldPath = strings.Join(parts[2:], "/")

	return recordRef, fieldType, fieldPath, nil
}