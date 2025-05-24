package types

import "time"

// Profile represents a Keeper Secrets Manager configuration profile
type Profile struct {
	Name      string            `json:"name"`
	Config    map[string]string `json:"config"` // Encrypted KSM config
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// SecretMetadata represents basic information about a secret
type SecretMetadata struct {
	UID    string `json:"uid"`
	Title  string `json:"title"`
	Type   string `json:"type"`
	Folder string `json:"folder,omitempty"`
}

// ListSecretsParams parameters for listing secrets
type ListSecretsParams struct {
	FolderUID string `json:"folder_uid,omitempty"`
	Type      string `json:"type,omitempty"`
}

// GetSecretParams parameters for getting a secret
type GetSecretParams struct {
	UID    string   `json:"uid"`
	Fields []string `json:"fields,omitempty"`
	Unmask bool     `json:"unmask,omitempty"`
}

// SearchParams parameters for searching secrets
type SearchParams struct {
	Query string `json:"query"`
	Type  string `json:"type,omitempty"`
}

// GetFieldParams parameters for getting a field using KSM notation
type GetFieldParams struct {
	Notation string `json:"notation"` // KSM notation: RECORD_UID/field/password, etc.
	Unmask   bool   `json:"unmask,omitempty"`
}

// GeneratePasswordParams parameters for password generation
type GeneratePasswordParams struct {
	Length       int    `json:"length,omitempty"` // Default: 32
	Lowercase    int    `json:"lowercase,omitempty"`
	Uppercase    int    `json:"uppercase,omitempty"`
	Digits       int    `json:"digits,omitempty"`
	Special      int    `json:"special,omitempty"`
	SpecialSet   string `json:"special_set,omitempty"`
	SaveToSecret string `json:"save_to_secret,omitempty"` // If specified, saves password to this secret
}

// GetTOTPParams parameters for getting TOTP code
type GetTOTPParams struct {
	UID string `json:"uid"` // Record UID containing TOTP
}

// TOTPResponse TOTP code response
type TOTPResponse struct {
	Code     string `json:"code"`
	TimeLeft int    `json:"time_left"` // Seconds until expiry
}

// SecretField represents a field in a secret
type SecretField struct {
	Type  string        `json:"type"`
	Value []interface{} `json:"value"`
}

// CreateSecretParams parameters for creating a secret
type CreateSecretParams struct {
	FolderUID string        `json:"folder_uid"`
	Type      string        `json:"type"`
	Title     string        `json:"title"`
	Fields    []SecretField `json:"fields"`
	Notes     string        `json:"notes,omitempty"`
}

// UpdateSecretParams parameters for updating a secret
type UpdateSecretParams struct {
	UID    string        `json:"uid"`
	Title  string        `json:"title,omitempty"`
	Fields []SecretField `json:"fields,omitempty"`
	Notes  string        `json:"notes,omitempty"`
}

// DeleteSecretParams parameters for deleting a secret
type DeleteSecretParams struct {
	UID     string `json:"uid"`
	Confirm bool   `json:"confirm"` // Must be true
}

// UploadFileParams parameters for uploading a file
type UploadFileParams struct {
	UID      string `json:"uid"`       // Record UID
	FilePath string `json:"file_path"` // Local file path
	Title    string `json:"title,omitempty"`
}

// DownloadFileParams parameters for downloading a file
type DownloadFileParams struct {
	UID      string `json:"uid"`      // Record UID
	FileUID  string `json:"file_uid"` // File UID or name
	SavePath string `json:"save_path,omitempty"`
}

// FolderInfo folder information
type FolderInfo struct {
	UID       string `json:"uid"`
	Name      string `json:"name"`
	ParentUID string `json:"parent_uid,omitempty"`
}

// ListFoldersResponse response for listing folders
type ListFoldersResponse struct {
	Folders []FolderInfo `json:"folders"`
}

// CreateFolderParams parameters for creating a folder
type CreateFolderParams struct {
	Name      string `json:"name"`
	ParentUID string `json:"parent_uid"`
}

// MCPRequest represents an MCP protocol request
type MCPRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// MCPResponse represents an MCP protocol response
type MCPResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *MCPError   `json:"error,omitempty"`
}

// MCPError represents an MCP protocol error
type MCPError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// MCPTool represents an MCP tool definition
type MCPTool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// SafeError represents a safe error that can be exposed to clients
type SafeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// NotationResult represents parsed KSM notation
type NotationResult struct {
	UID      string `json:"uid,omitempty"`
	Title    string `json:"title,omitempty"`
	Field    string `json:"field,omitempty"`
	Custom   bool   `json:"custom,omitempty"`
	Index    int    `json:"index,omitempty"`
	Property string `json:"property,omitempty"`
	File     string `json:"file,omitempty"`
}

// Confirmation represents user confirmation settings
type Confirmation struct {
	BatchMode   bool          `json:"batch_mode"`
	AutoApprove bool          `json:"auto_approve"`
	Timeout     time.Duration `json:"timeout"`
	DefaultDeny bool          `json:"default_deny"`
}

// ProfileMetadata represents metadata about a profile
type ProfileMetadata struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
