package validation

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

// Validator provides input validation and sanitization
type Validator struct {
	// Patterns for validation
	uidPattern         *regexp.Regexp
	tokenPattern       *regexp.Regexp
	profileNamePattern *regexp.Regexp

	// Security patterns to detect injection attempts
	commandInjectionPatterns []*regexp.Regexp
	pathTraversalPatterns    []*regexp.Regexp
}

// NewValidator creates a new validator instance
func NewValidator() *Validator {
	return &Validator{
		// Valid UID format: alphanumeric with underscores and hyphens, 16-32 characters
		uidPattern: regexp.MustCompile(`^[a-zA-Z0-9_-]{16,32}$`),

		// Token format: US:TOKEN or EU:TOKEN format
		tokenPattern: regexp.MustCompile(`^(US|EU|AU|JP|CA|GOV):[A-Za-z0-9+/=_-]+$`),

		// Profile name: alphanumeric with underscores, hyphens, dots (1-64 chars)
		profileNamePattern: regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`),

		// Command injection patterns
		commandInjectionPatterns: []*regexp.Regexp{
			regexp.MustCompile(`[;&|]`),     // Command separators
			regexp.MustCompile("`"),         // Backticks
			regexp.MustCompile(`\$\(`),      // Command substitution
			regexp.MustCompile(`\$\{`),      // Variable expansion
			regexp.MustCompile(`<<|>>`),     // Redirections
			regexp.MustCompile(`\|\||\&\&`), // Logical operators
			regexp.MustCompile(`\n|\r`),     // Newlines
			regexp.MustCompile(`[<>]`),      // IO redirection
			regexp.MustCompile(`\x00`),      // Null bytes
		},

		// Path traversal patterns
		pathTraversalPatterns: []*regexp.Regexp{
			regexp.MustCompile(`\.\.[\\/]`),         // ../ or ..\
			regexp.MustCompile(`%2e%2e|%252e%252e`), // URL encoded traversal
			regexp.MustCompile(`\x00`),              // Null bytes
		},
	}
}

// ValidateUID validates a KSM record UID
func (v *Validator) ValidateUID(uid string) error {
	if uid == "" {
		return fmt.Errorf("UID cannot be empty")
	}

	if len(uid) < 16 || len(uid) > 32 {
		return fmt.Errorf("UID must be between 16 and 32 characters")
	}

	if !v.uidPattern.MatchString(uid) {
		return fmt.Errorf("invalid UID format: must contain only alphanumeric characters, underscores, and hyphens")
	}

	// Check for command injection attempts
	if v.containsCommandInjection(uid) {
		return fmt.Errorf("UID contains invalid characters")
	}

	return nil
}

// ValidateToken validates a KSM one-time token
func (v *Validator) ValidateToken(token string) error {
	if token == "" {
		return fmt.Errorf("token cannot be empty")
	}

	if !v.tokenPattern.MatchString(token) {
		return fmt.Errorf("invalid token format: expected format REGION:TOKEN (e.g., US:TOKEN_HERE)")
	}

	// Extract region and token parts
	parts := strings.SplitN(token, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid token format: missing region prefix")
	}

	// Validate token length (minimum reasonable length)
	if len(parts[1]) < 20 {
		return fmt.Errorf("token appears to be too short")
	}

	return nil
}

// ValidateProfileName validates a profile name
func (v *Validator) ValidateProfileName(name string) error {
	if name == "" {
		return fmt.Errorf("profile name cannot be empty")
	}

	if len(name) > 64 {
		return fmt.Errorf("profile name too long: maximum 64 characters")
	}

	if !v.profileNamePattern.MatchString(name) {
		return fmt.Errorf("invalid profile name: must contain only alphanumeric characters, dots, underscores, and hyphens")
	}

	// Check for reserved names
	reservedNames := []string{"default", "system", "root", "admin", "config", "test"}
	nameLower := strings.ToLower(name)
	for _, reserved := range reservedNames {
		if nameLower == reserved {
			return fmt.Errorf("profile name '%s' is reserved", name)
		}
	}

	return nil
}

// ValidateFilePath validates and sanitizes a file path
func (v *Validator) ValidateFilePath(path string) error {
	if path == "" {
		return fmt.Errorf("file path cannot be empty")
	}

	// Check for path traversal attempts
	if v.containsPathTraversal(path) {
		return fmt.Errorf("file path contains invalid characters or patterns")
	}

	// Check for command injection attempts in file paths
	// But allow forward slashes which are valid in paths
	if v.containsFilePathCommandInjection(path) {
		return fmt.Errorf("file path contains invalid characters")
	}

	// Clean the path
	cleaned := filepath.Clean(path)

	// Ensure it's not trying to access parent directories
	if strings.HasPrefix(cleaned, "..") {
		return fmt.Errorf("file path cannot traverse to parent directories")
	}

	// Check for null bytes
	if strings.Contains(path, "\x00") {
		return fmt.Errorf("file path contains null bytes")
	}

	return nil
}

// ValidateKSMNotation validates KSM notation strings
func (v *Validator) ValidateKSMNotation(notation string) error {
	if notation == "" {
		return fmt.Errorf("notation cannot be empty")
	}

	// Check for command injection
	if v.containsCommandInjection(notation) {
		return fmt.Errorf("notation contains invalid characters")
	}

	// Basic notation format validation
	// Formats: UID/field/name, Title/field/name, UID/file/filename
	parts := strings.Split(notation, "/")
	if len(parts) < 2 {
		return fmt.Errorf("invalid notation format: expected at least 2 parts separated by '/'")
	}

	// Validate each part doesn't contain injection attempts
	for _, part := range parts {
		if v.containsCommandInjection(part) {
			return fmt.Errorf("notation part contains invalid characters")
		}
		// Check for path traversal patterns in each part
		if strings.Contains(part, "..") {
			return fmt.Errorf("notation contains path traversal patterns")
		}
	}

	return nil
}

// ValidateSearchQuery validates a search query
func (v *Validator) ValidateSearchQuery(query string) error {
	if query == "" {
		return fmt.Errorf("search query cannot be empty")
	}

	if len(query) > 256 {
		return fmt.Errorf("search query too long: maximum 256 characters")
	}

	// Check for injection attempts
	if v.containsCommandInjection(query) {
		return fmt.Errorf("search query contains invalid characters")
	}

	// Check for SQL injection patterns (even though we're not using SQL)
	sqlPatterns := []string{
		"--", "/*", "*/", "xp_", "sp_", "';", "\";",
		"union", "select", "insert", "update", "delete", "drop",
	}

	queryLower := strings.ToLower(query)
	for _, pattern := range sqlPatterns {
		if strings.Contains(queryLower, pattern) {
			return fmt.Errorf("search query contains suspicious patterns")
		}
	}

	// Check for LDAP injection
	if strings.Contains(query, "*)(") || strings.Contains(query, ")(|") {
		return fmt.Errorf("search query contains invalid characters")
	}

	// Check for NoSQL injection
	if strings.Contains(query, "$ne") || strings.Contains(query, "$regex") ||
		strings.Contains(query, "$gt") || strings.Contains(query, "$lt") {
		return fmt.Errorf("search query contains invalid characters")
	}

	return nil
}

// SanitizeString removes potentially dangerous characters from a string
func (v *Validator) SanitizeString(input string) string {
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")

	// Remove control characters except tab, newline, carriage return
	var sanitized strings.Builder
	for _, r := range input {
		if unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' {
			continue
		}
		sanitized.WriteRune(r)
	}

	return sanitized.String()
}

// SanitizeForShell escapes a string for safe use in shell commands
func (v *Validator) SanitizeForShell(input string) string {
	// Replace potentially dangerous characters in order
	// Process backslash first to avoid double-escaping
	result := strings.ReplaceAll(input, "\\", "\\\\")
	result = strings.ReplaceAll(result, "`", "\\`")
	result = strings.ReplaceAll(result, "$", "\\$")
	result = strings.ReplaceAll(result, "\"", "\\\"")
	result = strings.ReplaceAll(result, "\n", "\\n")
	result = strings.ReplaceAll(result, "\r", "\\r")

	return result
}

// ValidateMapKeys validates all keys in a map don't contain injection attempts
func (v *Validator) ValidateMapKeys(data map[string]interface{}) error {
	for key := range data {
		if v.containsCommandInjection(key) {
			return fmt.Errorf("map key '%s' contains invalid characters", key)
		}
	}
	return nil
}

// ValidateJSONField validates a field name for JSON usage
func (v *Validator) ValidateJSONField(field string) error {
	if field == "" {
		return fmt.Errorf("field name cannot be empty")
	}

	// Check for dots (property access)
	if strings.Contains(field, ".") {
		return fmt.Errorf("field name cannot contain dots")
	}

	// Check for brackets (array access)
	if strings.Contains(field, "[") || strings.Contains(field, "]") {
		return fmt.Errorf("field name cannot contain brackets")
	}

	// Check for quotes
	if strings.Contains(field, "\"") || strings.Contains(field, "'") {
		return fmt.Errorf("field name cannot contain quotes")
	}

	return nil
}

// ValidateTitle validates a title field
func (v *Validator) ValidateTitle(title string) error {
	if title == "" {
		return fmt.Errorf("title cannot be empty")
	}

	if len(title) > 255 {
		return fmt.Errorf("title cannot exceed 255 characters")
	}

	if v.containsCommandInjection(title) {
		return fmt.Errorf("title contains invalid characters")
	}

	// Check for XSS attempts
	if v.containsHTML(title) {
		return fmt.Errorf("title cannot contain HTML")
	}

	// Check for dangerous Unicode characters
	if v.containsDangerousUnicode(title) {
		return fmt.Errorf("title contains invalid Unicode characters")
	}

	return nil
}

// ValidateNotes validates notes field
func (v *Validator) ValidateNotes(notes string) error {
	if len(notes) > 10000 {
		return fmt.Errorf("notes cannot exceed 10000 characters")
	}

	if v.containsCommandInjection(notes) {
		return fmt.Errorf("notes contain invalid characters")
	}

	// Check for XSS attempts
	if v.containsHTML(notes) {
		return fmt.Errorf("notes cannot contain HTML")
	}

	// Check for format string vulnerabilities
	if strings.Contains(notes, "%n") {
		return fmt.Errorf("notes contain invalid format specifiers")
	}

	return nil
}

// ValidateURL validates a URL field
func (v *Validator) ValidateURL(url string) error {
	if url == "" {
		return nil // URLs are optional
	}

	if len(url) > 2048 {
		return fmt.Errorf("URL cannot exceed 2048 characters")
	}

	// Check for dangerous protocols
	lowerURL := strings.ToLower(url)
	dangerousProtocols := []string{"javascript:", "data:", "vbscript:", "file:"}
	for _, proto := range dangerousProtocols {
		if strings.HasPrefix(lowerURL, proto) {
			return fmt.Errorf("URL contains dangerous protocol")
		}
	}

	if v.containsCommandInjection(url) {
		return fmt.Errorf("URL contains invalid characters")
	}

	return nil
}

// ValidateUsername validates a username field
func (v *Validator) ValidateUsername(username string) error {
	if username == "" {
		return nil // Usernames are optional
	}

	if len(username) > 255 {
		return fmt.Errorf("username cannot exceed 255 characters")
	}

	if v.containsCommandInjection(username) {
		return fmt.Errorf("username contains invalid characters")
	}

	// Check for LDAP injection
	ldapDangerous := []string{"*", "(", ")", "\\", "/", "\x00"}
	for _, char := range ldapDangerous {
		if strings.Contains(username, char) {
			return fmt.Errorf("username contains invalid characters")
		}
	}

	return nil
}

// containsCommandInjection checks if input contains command injection patterns
func (v *Validator) containsCommandInjection(input string) bool {
	for _, pattern := range v.commandInjectionPatterns {
		if pattern.MatchString(input) {
			return true
		}
	}
	return false
}

// containsHTML checks for HTML/XML content
func (v *Validator) containsHTML(input string) bool {
	htmlPatterns := []string{
		"<script", "</script>", "<iframe", "<object", "<embed",
		"<img", "onerror=", "onclick=", "onload=", "javascript:",
		"<!ENTITY", "<![CDATA[", "<?xml",
	}

	lowerInput := strings.ToLower(input)
	for _, pattern := range htmlPatterns {
		if strings.Contains(lowerInput, strings.ToLower(pattern)) {
			return true
		}
	}

	// Check for any HTML tags
	if strings.Contains(input, "<") && strings.Contains(input, ">") {
		return true
	}

	return false
}

// containsDangerousUnicode checks for dangerous Unicode characters
func (v *Validator) containsDangerousUnicode(input string) bool {
	for _, r := range input {
		// Check for RTL override characters
		if r == '\u202E' || r == '\u202D' || r == '\u202C' {
			return true
		}
		// Check for other dangerous Unicode categories
		if unicode.Is(unicode.Cf, r) { // Format characters
			return true
		}
	}
	return false
}

// containsFilePathCommandInjection checks for command injection in file paths
// This is more permissive than general command injection as paths need slashes
func (v *Validator) containsFilePathCommandInjection(path string) bool {
	// Check for dangerous patterns but allow forward/back slashes
	dangerousPatterns := []string{
		";", "|", "&", "$", "`", "(", ")", "<", ">", "\n", "\r",
		"${", "$(", "\x00", "%00", "&&", "||", ">>", "<<", "|&",
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(path, pattern) {
			return true
		}
	}

	return false
}

// containsPathTraversal checks if input contains path traversal patterns
func (v *Validator) containsPathTraversal(input string) bool {
	for _, pattern := range v.pathTraversalPatterns {
		if pattern.MatchString(input) {
			return true
		}
	}
	return false
}

// escapeShellArg escapes a string for safe use in shell commands
func (v *Validator) escapeShellArg(arg string) string {
	// Use single quotes to escape most special characters
	// Replace single quotes with '\''
	escaped := strings.ReplaceAll(arg, "'", "'\\''")
	return "'" + escaped + "'"
}

// IsAlphanumeric checks if a string contains only alphanumeric characters
func (v *Validator) IsAlphanumeric(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

// ValidatePasswordStrength validates password meets minimum requirements
func (v *Validator) ValidatePasswordStrength(password string) error {
	if len(password) < 12 {
		return fmt.Errorf("password must be at least 12 characters long")
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool

	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return fmt.Errorf("password must contain uppercase, lowercase, digits, and special characters")
	}

	return nil
}

// TruncateString safely truncates a string to a maximum length
func (v *Validator) TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}

	// Truncate at rune boundary to avoid breaking multi-byte characters
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}

	return string(runes[:maxLen-3]) + "..."
}
