package storage

import (
	"fmt"
	"sync"
	"time"

	"github.com/keeper-security/ksm-mcp/pkg/types"
)

// Ensure MemoryProfileStore implements ProfileStoreInterface
var _ ProfileStoreInterface = (*MemoryProfileStore)(nil)

// MemoryProfileStore is an in-memory implementation of profile storage for testing
type MemoryProfileStore struct {
	mu       sync.RWMutex
	profiles map[string]*types.Profile
	clients  map[string]interface{} // Store actual client instances
}

// NewMemoryProfileStore creates a new in-memory profile store
func NewMemoryProfileStore() *MemoryProfileStore {
	return &MemoryProfileStore{
		profiles: make(map[string]*types.Profile),
		clients:  make(map[string]interface{}),
	}
}

// AddProfile adds a profile to the memory store with its client
func (m *MemoryProfileStore) AddProfile(name string, client interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()

	profile := &types.Profile{
		Name:      name,
		Config:    make(map[string]string),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	m.profiles[name] = profile
	m.clients[name] = client
}

// GetProfile retrieves a profile from the memory store
func (m *MemoryProfileStore) GetProfile(name string) (*types.Profile, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	profile, exists := m.profiles[name]
	if !exists {
		return nil, fmt.Errorf("profile '%s' not found", name)
	}

	return profile, nil
}

// ListProfiles returns all profile names
func (m *MemoryProfileStore) ListProfiles() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.profiles))
	for name := range m.profiles {
		names = append(names, name)
	}
	return names
}

// CreateProfile creates a new profile with the given configuration
func (m *MemoryProfileStore) CreateProfile(name string, config map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.profiles[name]; exists {
		return fmt.Errorf("profile '%s' already exists", name)
	}

	profile := &types.Profile{
		Name:      name,
		Config:    config,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	m.profiles[name] = profile
	return nil
}

// UpdateProfile updates an existing profile
func (m *MemoryProfileStore) UpdateProfile(name string, config map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	profile, exists := m.profiles[name]
	if !exists {
		return fmt.Errorf("profile '%s' not found", name)
	}

	profile.Config = config
	profile.UpdatedAt = time.Now()
	return nil
}

// ProfileExists checks if a profile exists
func (m *MemoryProfileStore) ProfileExists(name string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, exists := m.profiles[name]
	return exists
}

// DeleteProfile removes a profile from memory
func (m *MemoryProfileStore) DeleteProfile(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.profiles, name)
	return nil
}

// SetMasterPassword is a no-op for memory store
func (m *MemoryProfileStore) SetMasterPassword(password string) error {
	return nil
}

// IsLocked always returns false for memory store
func (m *MemoryProfileStore) IsLocked() bool {
	return false
}

// Unlock is a no-op for memory store
func (m *MemoryProfileStore) Unlock(password string) error {
	return nil
}

// Lock is a no-op for memory store
func (m *MemoryProfileStore) Lock() error {
	return nil
}

// GetClient returns the stored client for a profile
func (m *MemoryProfileStore) GetClient(name string) (interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	client, exists := m.profiles[name]
	if !exists {
		return nil, fmt.Errorf("profile '%s' not found", name)
	}

	return client, nil
}
