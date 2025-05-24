package ksm

import (
	"testing"

	"github.com/keeper-security/ksm-mcp/pkg/types"
)

func TestParseNotation(t *testing.T) {
	tests := []struct {
		name     string
		notation string
		want     *types.NotationResult
		wantErr  bool
	}{
		{
			name:     "UID with field",
			notation: "NJ_xXSkk3xYI1h9ql5lAiQ/field/password",
			want: &types.NotationResult{
				UID:   "NJ_xXSkk3xYI1h9ql5lAiQ",
				Field: "password",
				Index: -1,
			},
			wantErr: false,
		},
		{
			name:     "UID with array field",
			notation: "NJ_xXSkk3xYI1h9ql5lAiQ/field/url[0]",
			want: &types.NotationResult{
				UID:   "NJ_xXSkk3xYI1h9ql5lAiQ",
				Field: "url",
				Index: 0,
			},
			wantErr: false,
		},
		{
			name:     "UID with custom field property",
			notation: "NJ_xXSkk3xYI1h9ql5lAiQ/custom_field/name[first]",
			want: &types.NotationResult{
				UID:      "NJ_xXSkk3xYI1h9ql5lAiQ",
				Field:    "name",
				Custom:   true,
				Property: "first",
				Index:    -1,
			},
			wantErr: false,
		},
		{
			name:     "UID with nested array property",
			notation: "NJ_xXSkk3xYI1h9ql5lAiQ/custom_field/phone[0][number]",
			want: &types.NotationResult{
				UID:      "NJ_xXSkk3xYI1h9ql5lAiQ",
				Field:    "phone",
				Custom:   true,
				Index:    0,
				Property: "number",
			},
			wantErr: false,
		},
		{
			name:     "UID with file",
			notation: "NJ_xXSkk3xYI1h9ql5lAiQ/file/document.pdf",
			want: &types.NotationResult{
				UID:   "NJ_xXSkk3xYI1h9ql5lAiQ",
				File:  "document.pdf",
				Index: -1,
			},
			wantErr: false,
		},
		{
			name:     "Title with field",
			notation: "My Secret/field/password",
			want: &types.NotationResult{
				Title: "My Secret",
				Field: "password",
				Index: -1,
			},
			wantErr: false,
		},
		{
			name:     "empty notation",
			notation: "",
			want:     nil,
			wantErr:  true,
		},
		{
			name:     "invalid format - no slash",
			notation: "UID123",
			want:     nil,
			wantErr:  true,
		},
		{
			name:     "invalid format - one part",
			notation: "UID123/",
			want:     nil,
			wantErr:  true,
		},
		{
			name:     "missing field name",
			notation: "UID123/field/",
			want:     nil,
			wantErr:  true,
		},
		{
			name:     "invalid field type",
			notation: "UID123/invalid/password",
			want:     nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseNotation(tt.notation)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseNotation() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.UID != tt.want.UID {
					t.Errorf("ParseNotation() UID = %v, want %v", got.UID, tt.want.UID)
				}
				if got.Title != tt.want.Title {
					t.Errorf("ParseNotation() Title = %v, want %v", got.Title, tt.want.Title)
				}
				if got.Field != tt.want.Field {
					t.Errorf("ParseNotation() Field = %v, want %v", got.Field, tt.want.Field)
				}
				if got.Custom != tt.want.Custom {
					t.Errorf("ParseNotation() Custom = %v, want %v", got.Custom, tt.want.Custom)
				}
				if got.Index != tt.want.Index {
					t.Errorf("ParseNotation() Index = %v, want %v", got.Index, tt.want.Index)
				}
				if got.Property != tt.want.Property {
					t.Errorf("ParseNotation() Property = %v, want %v", got.Property, tt.want.Property)
				}
				if got.File != tt.want.File {
					t.Errorf("ParseNotation() File = %v, want %v", got.File, tt.want.File)
				}
			}
		})
	}
}

func TestBuildNotation(t *testing.T) {
	tests := []struct {
		name   string
		result *types.NotationResult
		want   string
	}{
		{
			name: "UID with field",
			result: &types.NotationResult{
				UID:   "NJ_xXSkk3xYI1h9ql5lAiQ",
				Field: "password",
				Index: -1,
			},
			want: "NJ_xXSkk3xYI1h9ql5lAiQ/field/password",
		},
		{
			name: "UID with array field",
			result: &types.NotationResult{
				UID:   "NJ_xXSkk3xYI1h9ql5lAiQ",
				Field: "url",
				Index: 0,
			},
			want: "NJ_xXSkk3xYI1h9ql5lAiQ/field/url[0]",
		},
		{
			name: "UID with custom field property",
			result: &types.NotationResult{
				UID:      "NJ_xXSkk3xYI1h9ql5lAiQ",
				Field:    "name",
				Custom:   true,
				Property: "first",
				Index:    -1,
			},
			want: "NJ_xXSkk3xYI1h9ql5lAiQ/custom_field/name[first]",
		},
		{
			name: "UID with nested array property",
			result: &types.NotationResult{
				UID:      "NJ_xXSkk3xYI1h9ql5lAiQ",
				Field:    "phone",
				Custom:   true,
				Index:    0,
				Property: "number",
			},
			want: "NJ_xXSkk3xYI1h9ql5lAiQ/custom_field/phone[0][number]",
		},
		{
			name: "UID with file",
			result: &types.NotationResult{
				UID:   "NJ_xXSkk3xYI1h9ql5lAiQ",
				File:  "document.pdf",
				Index: -1,
			},
			want: "NJ_xXSkk3xYI1h9ql5lAiQ/file/document.pdf",
		},
		{
			name: "Title with field",
			result: &types.NotationResult{
				Title: "My Secret",
				Field: "password",
				Index: -1,
			},
			want: "My Secret/field/password",
		},
		{
			name:   "empty result",
			result: &types.NotationResult{},
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildNotation(tt.result)
			if got != tt.want {
				t.Errorf("BuildNotation() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsValidUID(t *testing.T) {
	tests := []struct {
		name  string
		uid   string
		valid bool
	}{
		{"valid 16 chars", "1234567890123456", true},
		{"valid 32 chars", "12345678901234567890123456789012", true},
		{"valid with underscore", "NJ_xXSkk3xYI1h9ql5lAiQ", true},
		{"valid with hyphen", "abc-def-123-456-789", true},
		{"too short", "123456789012345", false},
		{"too long", "123456789012345678901234567890123", false},
		{"with space", "12345678901234 56", false},
		{"with special char", "1234567890123456!", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidUID(tt.uid)
			if got != tt.valid {
				t.Errorf("isValidUID(%s) = %v, want %v", tt.uid, got, tt.valid)
			}
		})
	}
}

func TestExtractFieldPath(t *testing.T) {
	tests := []struct {
		name     string
		notation string
		want     string
		wantErr  bool
	}{
		{
			name:     "simple field",
			notation: "UID123/field/password",
			want:     "field/password",
			wantErr:  false,
		},
		{
			name:     "custom field",
			notation: "UID123/custom_field/apiKey",
			want:     "custom_field/apiKey",
			wantErr:  false,
		},
		{
			name:     "array field",
			notation: "UID123/field/url[0]",
			want:     "field/url[0]",
			wantErr:  false,
		},
		{
			name:     "property field",
			notation: "UID123/custom_field/name[first]",
			want:     "custom_field/name[first]",
			wantErr:  false,
		},
		{
			name:     "nested field",
			notation: "UID123/custom_field/phone[0][number]",
			want:     "custom_field/phone[0][number]",
			wantErr:  false,
		},
		{
			name:     "invalid notation",
			notation: "invalid",
			want:     "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractFieldPath(tt.notation)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractFieldPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ExtractFieldPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsFileNotation(t *testing.T) {
	tests := []struct {
		name     string
		notation string
		want     bool
	}{
		{"file notation", "UID123/file/document.pdf", true},
		{"field notation", "UID123/field/password", false},
		{"custom field notation", "UID123/custom_field/apiKey", false},
		{"invalid notation", "invalid", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsFileNotation(tt.notation)
			if got != tt.want {
				t.Errorf("IsFileNotation(%s) = %v, want %v", tt.notation, got, tt.want)
			}
		})
	}
}

func TestIsCustomFieldNotation(t *testing.T) {
	tests := []struct {
		name     string
		notation string
		want     bool
	}{
		{"custom field notation", "UID123/custom_field/apiKey", true},
		{"field notation", "UID123/field/password", false},
		{"file notation", "UID123/file/document.pdf", false},
		{"invalid notation", "invalid", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsCustomFieldNotation(tt.notation)
			if got != tt.want {
				t.Errorf("IsCustomFieldNotation(%s) = %v, want %v", tt.notation, got, tt.want)
			}
		})
	}
}

func TestSplitNotationParts(t *testing.T) {
	tests := []struct {
		name     string
		notation string
		wantRef  string
		wantType string
		wantPath string
		wantErr  bool
	}{
		{
			name:     "simple field",
			notation: "UID123/field/password",
			wantRef:  "UID123",
			wantType: "field",
			wantPath: "password",
			wantErr:  false,
		},
		{
			name:     "custom field with array",
			notation: "UID123/custom_field/phones[0]",
			wantRef:  "UID123",
			wantType: "custom_field",
			wantPath: "phones[0]",
			wantErr:  false,
		},
		{
			name:     "file with path",
			notation: "UID123/file/folder/document.pdf",
			wantRef:  "UID123",
			wantType: "file",
			wantPath: "folder/document.pdf",
			wantErr:  false,
		},
		{
			name:     "title based",
			notation: "My Secret/field/password",
			wantRef:  "My Secret",
			wantType: "field",
			wantPath: "password",
			wantErr:  false,
		},
		{
			name:     "invalid - too short",
			notation: "UID123/field",
			wantRef:  "",
			wantType: "",
			wantPath: "",
			wantErr:  true,
		},
		{
			name:     "invalid - empty",
			notation: "",
			wantRef:  "",
			wantType: "",
			wantPath: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRef, gotType, gotPath, err := SplitNotationParts(tt.notation)
			if (err != nil) != tt.wantErr {
				t.Errorf("SplitNotationParts() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotRef != tt.wantRef {
				t.Errorf("SplitNotationParts() ref = %v, want %v", gotRef, tt.wantRef)
			}
			if gotType != tt.wantType {
				t.Errorf("SplitNotationParts() type = %v, want %v", gotType, tt.wantType)
			}
			if gotPath != tt.wantPath {
				t.Errorf("SplitNotationParts() path = %v, want %v", gotPath, tt.wantPath)
			}
		})
	}
}

func TestValidateNotation(t *testing.T) {
	tests := []struct {
		name     string
		notation string
		wantErr  bool
	}{
		{"valid field", "UID123/field/password", false},
		{"valid custom field", "UID123/custom_field/apiKey", false},
		{"valid file", "UID123/file/document.pdf", false},
		{"valid array", "UID123/field/url[0]", false},
		{"valid property", "UID123/custom_field/name[first]", false},
		{"valid nested", "UID123/custom_field/phone[0][number]", false},
		{"invalid empty", "", true},
		{"invalid format", "UID123", true},
		{"invalid type", "UID123/invalid/password", true},
		{"missing field", "UID123/field/", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateNotation(tt.notation)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateNotation() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRoundTripNotation(t *testing.T) {
	// Test that parse -> build produces the same notation
	notations := []string{
		"NJ_xXSkk3xYI1h9ql5lAiQ/field/password",
		"NJ_xXSkk3xYI1h9ql5lAiQ/field/url[0]",
		"NJ_xXSkk3xYI1h9ql5lAiQ/custom_field/name[first]",
		"NJ_xXSkk3xYI1h9ql5lAiQ/custom_field/phone[0][number]",
		"NJ_xXSkk3xYI1h9ql5lAiQ/file/document.pdf",
		"My Secret/field/password",
	}

	for _, notation := range notations {
		t.Run(notation, func(t *testing.T) {
			parsed, err := ParseNotation(notation)
			if err != nil {
				t.Fatalf("Failed to parse notation: %v", err)
			}

			rebuilt := BuildNotation(parsed)
			if rebuilt != notation {
				t.Errorf("Round trip failed: got %s, want %s", rebuilt, notation)
			}
		})
	}
}
