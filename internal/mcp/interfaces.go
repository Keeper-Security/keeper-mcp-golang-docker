package mcp

import (
	"context"

	"github.com/keeper-security/ksm-mcp/internal/ui"
	"github.com/keeper-security/ksm-mcp/pkg/types"
)

// KSMClient defines the interface for KSM operations
type KSMClient interface {
	// Basic secret operations
	ListSecrets(folderUID string) ([]*types.SecretMetadata, error)
	GetSecret(uid string, fields []string, unmask bool) (map[string]interface{}, error)
	GetField(notation string, unmask bool) (interface{}, error)
	SearchSecrets(query string) ([]*types.SecretMetadata, error)
	CreateSecret(params types.CreateSecretParams) (string, error)
	UpdateSecret(params types.UpdateSecretParams) error
	DeleteSecret(uid string, permanent bool) error

	// Password operations
	GeneratePassword(params types.GeneratePasswordParams) (string, error)

	// TOTP operations
	GetTOTPCode(uid string) (*types.TOTPResponse, error)

	// File operations
	UploadFile(uid, filePath, title string) error
	DownloadFile(uid, fileUID, savePath string) error

	// Folder operations
	ListFolders() (*types.ListFoldersResponse, error)
	CreateFolder(name string, parentUID string) (string, error)
	DeleteFolder(uid string, force bool) error

	// Connection testing
	TestConnection() error
}

// ConfirmerInterface defines the interface for confirmation operations
type ConfirmerInterface interface {
	Confirm(ctx context.Context, message string) *ui.ConfirmationResult
	ConfirmOperation(ctx context.Context, operation, resource string, details map[string]interface{}) *ui.ConfirmationResult
}
