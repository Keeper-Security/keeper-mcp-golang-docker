package storage

import "github.com/keeper-security/ksm-mcp/pkg/types"

// ProfileStoreInterface defines the interface for profile storage
type ProfileStoreInterface interface {
	GetProfile(name string) (*types.Profile, error)
	CreateProfile(name string, config map[string]string) error
	UpdateProfile(name string, config map[string]string) error
	DeleteProfile(name string) error
	ListProfiles() []string
	ProfileExists(name string) bool
}
