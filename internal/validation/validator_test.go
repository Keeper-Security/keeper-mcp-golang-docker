package validation

import (
	"strings"
	"testing"
)

func TestNewValidator(t *testing.T) {
	v := NewValidator()
	if v == nil {
		t.Fatal("NewValidator returned nil")
	}
	
	// Verify patterns are initialized
	if v.uidPattern == nil {
		t.Error("UID pattern not initialized")
	}
	if v.tokenPattern == nil {
		t.Error("Token pattern not initialized")
	}
	if len(v.commandInjectionPatterns) == 0 {
		t.Error("Command injection patterns not initialized")
	}
	if len(v.pathTraversalPatterns) == 0 {
		t.Error("Path traversal patterns not initialized")
	}
}

func TestValidateUID(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name    string
		uid     string
		wantErr bool
	}{
		// Valid UIDs
		{"valid uid 16 chars", "1234567890123456", false},
		{"valid uid 32 chars", "12345678901234567890123456789012", false},
		{"valid with underscore", "NJ_xXSkk3xYI1h9ql5lAiQ", false},
		{"valid with hyphen", "abc-def-123-456-789", false},
		
		// Invalid UIDs
		{"empty", "", true},
		{"too short", "123456789012345", true},
		{"too long", "123456789012345678901234567890123", true},
		{"with spaces", "1234567890 123456", true},
		{"with special chars", "1234567890!@#$%^", true},
		{"command injection semicolon", "valid123456789012;rm -rf /", true},
		{"command injection pipe", "valid123456789012|cat /etc/passwd", true},
		{"command injection backtick", "valid123456789012`whoami`", true},
		{"with newline", "valid123456789012\n", true},
		{"with null byte", "valid123456789012\x00", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateUID(tt.uid)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateUID() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateToken(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		// Valid tokens
		{"valid US token", "US:abcdef123456789012345678901234567890", false},
		{"valid EU token", "EU:abcdef123456789012345678901234567890", false},
		{"valid AU token", "AU:abcdef123456789012345678901234567890", false},
		{"valid JP token", "JP:abcdef123456789012345678901234567890", false},
		{"valid CA token", "CA:abcdef123456789012345678901234567890", false},
		{"valid GOV token", "GOV:abcdef123456789012345678901234567890", false},
		{"token with special base64", "US:abc+def/123=456_789-012", false},
		
		// Invalid tokens
		{"empty", "", true},
		{"no region", "abcdef123456789012345678901234567890", true},
		{"invalid region", "XX:abcdef123456789012345678901234567890", true},
		{"no colon", "USabcdef123456789012345678901234567890", true},
		{"short token", "US:tooshort", true},
		{"with spaces", "US:abc def 123", true},
		{"lowercase region", "us:abcdef123456789012345678901234567890", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateToken(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateToken() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateProfileName(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name        string
		profileName string
		wantErr     bool
	}{
		// Valid names
		{"simple name", "myprofile", false},
		{"with numbers", "profile123", false},
		{"with underscore", "my_profile", false},
		{"with hyphen", "my-profile", false},
		{"with dot", "my.profile", false},
		{"mixed", "My-Profile_123.test", false},
		
		// Invalid names
		{"empty", "", true},
		{"too long", strings.Repeat("a", 65), true},
		{"with spaces", "my profile", true},
		{"with special chars", "my@profile", true},
		{"reserved default", "default", true},
		{"reserved system", "system", true},
		{"reserved root", "root", true},
		{"reserved admin", "admin", true},
		{"reserved uppercase", "DEFAULT", true},
		{"with slash", "my/profile", true},
		{"with backslash", "my\\profile", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateProfileName(tt.profileName)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateProfileName() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateFilePath(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		// Valid paths
		{"simple file", "file.txt", false},
		{"relative path", "folder/file.txt", false},
		{"nested path", "folder/subfolder/file.txt", false},
		{"with dot", "./file.txt", false},
		{"absolute unix", "/etc/passwd", false}, // Absolute paths are allowed
		{"absolute windows", "C:\\Windows\\System32", false}, // Absolute paths are allowed
		{"UNC path", "\\\\server\\share", false}, // UNC paths are allowed
		
		// Invalid paths
		{"empty", "", true},
		{"parent traversal", "../file.txt", true},
		{"parent traversal nested", "folder/../../file.txt", true},
		{"url encoded traversal", "%2e%2e/file.txt", true},
		{"null byte", "file.txt\x00", true},
		{"with semicolon", "file.txt;rm -rf /", true},
		
		// Note: Absolute paths are not rejected by ValidateFilePath
		// They should be validated separately based on context
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateFilePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFilePath() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateKSMNotation(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name     string
		notation string
		wantErr  bool
	}{
		// Valid notations
		{"uid field", "UID123/field/password", false},
		{"uid array", "UID123/field/url[0]", false},
		{"custom field", "UID123/custom_field/name[first]", false},
		{"nested array", "UID123/custom_field/phone[0][number]", false},
		{"file notation", "UID123/file/document.pdf", false},
		{"title search", "MyTitle/field/password", false},
		
		// Invalid notations
		{"empty", "", true},
		{"no slash", "UID123", true},
		{"command injection", "UID123/field/password;whoami", true},
		{"pipe injection", "UID123/field/password|cat", true},
		{"backtick injection", "UID123/field/`password`", true},
		{"newline injection", "UID123/field/password\n", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateKSMNotation(tt.notation)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateKSMNotation() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateSearchQuery(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name    string
		query   string
		wantErr bool
	}{
		// Valid queries
		{"simple search", "password", false},
		{"with spaces", "my password", false},
		{"with numbers", "password123", false},
		{"with special", "user@example.com", false},
		
		// Invalid queries
		{"empty", "", true},
		{"too long", strings.Repeat("a", 257), true},
		{"sql comment", "password--", true},
		{"sql union", "password UNION SELECT", true},
		{"command injection", "password;ls", true},
		{"pipe injection", "password|grep", true},
		{"null byte", "password\x00", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateSearchQuery(tt.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSearchQuery() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSanitizeString(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"normal string", "hello world", "hello world"},
		{"with null byte", "hello\x00world", "helloworld"},
		{"with control chars", "hello\x01\x02world", "helloworld"},
		{"keep tab newline", "hello\tworld\n", "hello\tworld\n"},
		{"unicode", "hello 世界", "hello 世界"},
		{"emoji", "hello 😀", "hello 😀"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.SanitizeString(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeString() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestSanitizeForShell(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"normal string", "hello world", "hello world"},
		{"with backtick", "hello`world", "hello\\`world"},
		{"with dollar", "hello$world", "hello\\$world"},
		{"with quote", `hello"world`, `hello\"world`},
		{"with backslash", `hello\world`, `hello\\world`},
		{"with newline", "hello\nworld", "hello\\nworld"},
		{"multiple escapes", `$("test")`, `\$(\"test\")`},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.SanitizeForShell(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeForShell() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestValidateMapKeys(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name    string
		data    map[string]interface{}
		wantErr bool
	}{
		{
			"valid keys",
			map[string]interface{}{
				"key1": "value1",
				"key2": "value2",
			},
			false,
		},
		{
			"injection in key",
			map[string]interface{}{
				"key1;rm -rf /": "value1",
			},
			true,
		},
		{
			"pipe in key",
			map[string]interface{}{
				"key1|cat": "value1",
			},
			true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateMapKeys(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateMapKeys() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateJSONField(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name    string
		field   string
		wantErr bool
	}{
		{"simple field", "password", false},
		{"with underscore", "user_name", false},
		{"with number", "field123", false},
		
		{"empty", "", true},
		{"with dot", "user.name", true},
		{"with bracket", "user[0]", true},
		{"with quote", `user"name`, true},
		{"with single quote", "user'name", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateJSONField(tt.field)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateJSONField() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsAlphanumeric(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"letters", "abcXYZ", true},
		{"numbers", "123456", true},
		{"mixed", "abc123XYZ", true},
		{"empty", "", true}, // Empty is considered alphanumeric
		
		{"with space", "abc 123", false},
		{"with underscore", "abc_123", false},
		{"with hyphen", "abc-123", false},
		{"with special", "abc@123", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.IsAlphanumeric(tt.input)
			if result != tt.expected {
				t.Errorf("IsAlphanumeric() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestValidatePasswordStrength(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"strong password", "MyStr0ng!Pass123", false},
		{"all requirements", "Abc123!@#def", false},
		
		{"too short", "Abc123!", true},
		{"no uppercase", "abc123!@#def", true},
		{"no lowercase", "ABC123!@#DEF", true},
		{"no digit", "AbcDef!@#ghi", true},
		{"no special", "AbcDef123ghi", true},
		{"empty", "", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidatePasswordStrength(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePasswordStrength() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTruncateString(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{"no truncate", "hello", 10, "hello"},
		{"exact length", "hello", 5, "hello"},
		{"truncate", "hello world", 8, "hello..."},
		{"unicode", "hello 世界", 7, "hell..."},
		{"empty", "", 5, ""},
		{"very short max", "hello", 3, "..."},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.TruncateString(tt.input, tt.maxLen)
			if result != tt.expected {
				t.Errorf("TruncateString() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestCommandInjectionPatterns(t *testing.T) {
	v := NewValidator()
	
	// Test that all dangerous patterns are caught
	dangerousInputs := []string{
		"test;rm -rf /",
		"test && cat /etc/passwd",
		"test || whoami",
		"test`whoami`",
		"test$(whoami)",
		"test${USER}",
		"test > /tmp/out",
		"test < /etc/passwd",
		"test >> log",
		"test\nwhoami",
		"test\rwhoami",
		"test|grep password",
		"test\x00",
	}
	
	for _, input := range dangerousInputs {
		t.Run(input, func(t *testing.T) {
			if !v.containsCommandInjection(input) {
				t.Errorf("Failed to detect command injection in: %q", input)
			}
		})
	}
}

func TestPathTraversalPatterns(t *testing.T) {
	v := NewValidator()
	
	// Test that path traversal patterns are caught
	traversalInputs := []string{
		"../etc/passwd",
		"..\\windows\\system32",
		"%2e%2e/etc/passwd",
		"%252e%252e/etc/passwd",
		"file\x00.txt",
	}
	
	for _, input := range traversalInputs {
		t.Run(input, func(t *testing.T) {
			if !v.containsPathTraversal(input) {
				t.Errorf("Failed to detect path traversal in: %q", input)
			}
		})
	}
	
	// Test that absolute paths are NOT detected as traversal
	// (they should be validated separately if needed)
	absolutePaths := []string{
		"/etc/passwd",
		"C:\\Windows\\System32",
		"\\\\server\\share",
	}
	
	for _, input := range absolutePaths {
		t.Run(input, func(t *testing.T) {
			if v.containsPathTraversal(input) {
				t.Errorf("Incorrectly detected absolute path as traversal: %q", input)
			}
		})
	}
}