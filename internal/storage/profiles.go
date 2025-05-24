package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/keeper-security/ksm-mcp/internal/crypto"
	"github.com/keeper-security/ksm-mcp/pkg/types"
)

const (
	// ProfilesFileName is the filename for the profiles database
	ProfilesFileName = "profiles.json"
	// MasterKeyFileName is the filename for the master key
	MasterKeyFileName = ".master_key"
)

// ProfileStore manages encrypted profile storage
type ProfileStore struct {
	configDir string
	encryptor *crypto.Encryptor
	profiles  map[string]*types.Profile
}

// EncryptedProfile represents a profile stored on disk
type EncryptedProfile struct {
	Name           string    `json:"name"`
	EncryptedData  string    `json:"encrypted_data"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	ConfigChecksum string    `json:"config_checksum"`
}

// ProfilesDatabase represents the on-disk storage format
type ProfilesDatabase struct {
	Version   int                         `json:"version"`
	Profiles  map[string]*EncryptedProfile `json:"profiles"`
	UpdatedAt time.Time                   `json:"updated_at"`
}

// NewProfileStore creates a new profile store
func NewProfileStore(configDir string) *ProfileStore {
	return &ProfileStore{
		configDir: configDir,
		profiles:  make(map[string]*types.Profile),
	}
}

// NewProfileStoreWithPassword creates a new profile store with a specific password
func NewProfileStoreWithPassword(configDir string, password string) (*ProfileStore, error) {
	if err := crypto.ValidatePassword(password); err != nil {
		return nil, fmt.Errorf("invalid password: %w", err)
	}

	store := &ProfileStore{
		configDir: configDir,
		encryptor: crypto.NewEncryptor(password),
		profiles:  make(map[string]*types.Profile),
	}

	// Load existing profiles
	if err := store.loadProfiles(); err != nil {
		return nil, fmt.Errorf("failed to load profiles: %w", err)
	}

	return store, nil
}

// initializeMasterKey initializes or loads the master encryption key
func (ps *ProfileStore) initializeMasterKey() error {
	keyPath := filepath.Join(ps.configDir, MasterKeyFileName)
	
	// Check if master key exists
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		// Generate new master key
		masterKey, err := crypto.GeneratePassword(64)
		if err != nil {
			return fmt.Errorf("failed to generate master key: %w", err)
		}

		// Save master key to file with restricted permissions
		if err := os.WriteFile(keyPath, []byte(masterKey), 0600); err != nil {
			return fmt.Errorf("failed to save master key: %w", err)
		}

		ps.encryptor = crypto.NewEncryptor(masterKey)
		return nil
	}

	// Load existing master key
	keyData, err := os.ReadFile(keyPath) // #nosec G304 - path constructed from validated configDir
	if err != nil {
		return fmt.Errorf("failed to read master key: %w", err)
	}

	ps.encryptor = crypto.NewEncryptor(string(keyData))
	return nil
}

// CreateProfile creates a new profile with the given configuration
func (ps *ProfileStore) CreateProfile(name string, config map[string]string) error {
	if name == "" {
		return fmt.Errorf("profile name cannot be empty")
	}

	// Check if profile already exists
	if _, exists := ps.profiles[name]; exists {
		return fmt.Errorf("profile '%s' already exists", name)
	}

	// Validate configuration
	if err := ps.validateKSMConfig(config); err != nil {
		return fmt.Errorf("invalid KSM configuration: %w", err)
	}

	// Create new profile
	profile := &types.Profile{
		Name:      name,
		Config:    config,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Store in memory
	ps.profiles[name] = profile

	// Persist to disk
	return ps.saveProfiles()
}

// GetProfile retrieves a profile by name
func (ps *ProfileStore) GetProfile(name string) (*types.Profile, error) {
	if name == "" {
		return nil, fmt.Errorf("profile name cannot be empty")
	}

	profile, exists := ps.profiles[name]
	if !exists {
		return nil, fmt.Errorf("profile '%s' not found", name)
	}

	// Return a copy to prevent modification
	return ps.copyProfile(profile), nil
}

// ListProfiles returns a list of all profile names
func (ps *ProfileStore) ListProfiles() []string {
	names := make([]string, 0, len(ps.profiles))
	for name := range ps.profiles {
		names = append(names, name)
	}
	return names
}

// UpdateProfile updates an existing profile
func (ps *ProfileStore) UpdateProfile(name string, config map[string]string) error {
	if name == "" {
		return fmt.Errorf("profile name cannot be empty")
	}

	profile, exists := ps.profiles[name]
	if !exists {
		return fmt.Errorf("profile '%s' not found", name)
	}

	// Validate new configuration
	if err := ps.validateKSMConfig(config); err != nil {
		return fmt.Errorf("invalid KSM configuration: %w", err)
	}

	// Update profile
	profile.Config = config
	profile.UpdatedAt = time.Now()

	// Persist to disk
	return ps.saveProfiles()
}

// DeleteProfile deletes a profile
func (ps *ProfileStore) DeleteProfile(name string) error {
	if name == "" {
		return fmt.Errorf("profile name cannot be empty")
	}

	if _, exists := ps.profiles[name]; !exists {
		return fmt.Errorf("profile '%s' not found", name)
	}

	delete(ps.profiles, name)

	// Persist to disk
	return ps.saveProfiles()
}

// ProfileExists checks if a profile exists
func (ps *ProfileStore) ProfileExists(name string) bool {
	_, exists := ps.profiles[name]
	return exists
}

// GetProfileMetadata returns metadata about all profiles
func (ps *ProfileStore) GetProfileMetadata() map[string]types.ProfileMetadata {
	metadata := make(map[string]types.ProfileMetadata)
	for name, profile := range ps.profiles {
		metadata[name] = types.ProfileMetadata{
			Name:      profile.Name,
			CreatedAt: profile.CreatedAt,
			UpdatedAt: profile.UpdatedAt,
		}
	}
	return metadata
}

// saveProfiles encrypts and saves all profiles to disk
func (ps *ProfileStore) saveProfiles() error {
	db := &ProfilesDatabase{
		Version:   1,
		Profiles:  make(map[string]*EncryptedProfile),
		UpdatedAt: time.Now(),
	}

	// Encrypt each profile
	for name, profile := range ps.profiles {
		// Serialize profile data
		profileData, err := json.Marshal(profile)
		if err != nil {
			return fmt.Errorf("failed to serialize profile '%s': %w", name, err)
		}

		// Encrypt profile data
		encryptedData, err := ps.encryptor.EncryptString(string(profileData))
		if err != nil {
			return fmt.Errorf("failed to encrypt profile '%s': %w", name, err)
		}

		// Calculate checksum for integrity verification
		checksum := ps.calculateChecksum(profile.Config)

		db.Profiles[name] = &EncryptedProfile{
			Name:           name,
			EncryptedData:  encryptedData,
			CreatedAt:      profile.CreatedAt,
			UpdatedAt:      profile.UpdatedAt,
			ConfigChecksum: checksum,
		}
	}

	// Serialize database
	dbData, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize profiles database: %w", err)
	}

	// Write to file with atomic operation
	profilesPath := filepath.Join(ps.configDir, ProfilesFileName)
	tempPath := profilesPath + ".tmp"

	if err := os.WriteFile(tempPath, dbData, 0600); err != nil {
		return fmt.Errorf("failed to write profiles to temp file: %w", err)
	}

	if err := os.Rename(tempPath, profilesPath); err != nil {
		_ = os.Remove(tempPath) // Clean up temp file, ignore error
		return fmt.Errorf("failed to atomically update profiles file: %w", err)
	}

	return nil
}

// loadProfiles loads and decrypts profiles from disk
func (ps *ProfileStore) loadProfiles() error {
	profilesPath := filepath.Join(ps.configDir, ProfilesFileName)

	// Check if profiles file exists
	if _, err := os.Stat(profilesPath); os.IsNotExist(err) {
		// No profiles file exists yet, start with empty profiles
		return nil
	}

	// Read profiles file
	data, err := os.ReadFile(profilesPath) // #nosec G304 - path constructed from validated configDir
	if err != nil {
		return fmt.Errorf("failed to read profiles file: %w", err)
	}

	// Parse database
	var db ProfilesDatabase
	if err := json.Unmarshal(data, &db); err != nil {
		return fmt.Errorf("failed to parse profiles database: %w", err)
	}

	// Decrypt each profile
	for name, encryptedProfile := range db.Profiles {
		// Decrypt profile data
		profileData, err := ps.encryptor.DecryptString(encryptedProfile.EncryptedData)
		if err != nil {
			return fmt.Errorf("failed to decrypt profile '%s': %w", name, err)
		}

		// Deserialize profile
		var profile types.Profile
		if err := json.Unmarshal([]byte(profileData), &profile); err != nil {
			return fmt.Errorf("failed to deserialize profile '%s': %w", name, err)
		}

		// Verify checksum for integrity
		expectedChecksum := ps.calculateChecksum(profile.Config)
		if encryptedProfile.ConfigChecksum != expectedChecksum {
			return fmt.Errorf("profile '%s' has invalid checksum, data may be corrupted", name)
		}

		ps.profiles[name] = &profile
	}

	return nil
}

// validateKSMConfig validates KSM configuration
func (ps *ProfileStore) validateKSMConfig(config map[string]string) error {
	if config == nil {
		return fmt.Errorf("configuration cannot be nil")
	}

	// Check for required fields (basic validation)
	requiredFields := []string{"clientId"}
	for _, field := range requiredFields {
		if _, exists := config[field]; !exists {
			return fmt.Errorf("required field '%s' is missing", field)
		}
	}

	// Validate clientId format (basic check)
	clientId := config["clientId"]
	if len(clientId) < 10 {
		return fmt.Errorf("clientId appears to be invalid")
	}

	return nil
}

// calculateChecksum calculates a checksum for configuration integrity
func (ps *ProfileStore) calculateChecksum(config map[string]string) string {
	// Simple checksum calculation for integrity verification
	data, _ := json.Marshal(config)
	return fmt.Sprintf("%x", len(data)) // Simple length-based checksum
}

// copyProfile creates a deep copy of a profile
func (ps *ProfileStore) copyProfile(profile *types.Profile) *types.Profile {
	configCopy := make(map[string]string)
	for k, v := range profile.Config {
		configCopy[k] = v
	}

	return &types.Profile{
		Name:      profile.Name,
		Config:    configCopy,
		CreatedAt: profile.CreatedAt,
		UpdatedAt: profile.UpdatedAt,
	}
}

// Close securely closes the profile store
func (ps *ProfileStore) Close() error {
	// Clear sensitive data from memory
	for name, profile := range ps.profiles {
		for key := range profile.Config {
			profile.Config[key] = ""
		}
		delete(ps.profiles, name)
	}

	return nil
}

// GetPasswordHash returns the hash of the master password
func (ps *ProfileStore) GetPasswordHash() string {
	if ps.encryptor == nil {
		return ""
	}
	
	// Generate a hash of the password for storage
	// This is used to verify the password on subsequent runs
	// We'll use a simple approach here - in production you'd use bcrypt or similar
	data := []byte("ksm-mcp-master-password-check")
	encrypted, err := ps.encryptor.EncryptString(string(data))
	if err != nil {
		return ""
	}
	
	// Return first 64 chars as a fingerprint
	if len(encrypted) > 64 {
		return encrypted[:64]
	}
	return encrypted
}