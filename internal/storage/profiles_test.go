package storage

import (
	"os"
	"testing"
	"time"
)

func TestNewProfileStore(t *testing.T) {
	// Create temporary directory for testing
	tempDir := t.TempDir()
	originalConfigDir := os.Getenv("KSM_MCP_CONFIG_DIR")
	os.Setenv("KSM_MCP_CONFIG_DIR", tempDir)
	defer func() {
		if originalConfigDir != "" {
			os.Setenv("KSM_MCP_CONFIG_DIR", originalConfigDir)
		} else {
			os.Unsetenv("KSM_MCP_CONFIG_DIR")
		}
	}()

	store := NewProfileStore(tempDir)
	defer store.Close()

	// Note: NewProfileStore no longer automatically creates a master key
	// It's created when needed (e.g., when calling Initialize or CreateProfile)

	// Verify initial state
	profiles := store.ListProfiles()
	if len(profiles) != 0 {
		t.Errorf("Expected 0 profiles, got %d", len(profiles))
	}
}

func TestNewProfileStoreWithPassword(t *testing.T) {
	tempDir := t.TempDir()
	originalConfigDir := os.Getenv("KSM_MCP_CONFIG_DIR")
	os.Setenv("KSM_MCP_CONFIG_DIR", tempDir)
	defer func() {
		if originalConfigDir != "" {
			os.Setenv("KSM_MCP_CONFIG_DIR", originalConfigDir)
		} else {
			os.Unsetenv("KSM_MCP_CONFIG_DIR")
		}
	}()

	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"valid password", "secure-password-123", false},
		{"minimum length", "12characters", false},
		{"too short", "short", true},
		{"empty password", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			store, err := NewProfileStoreWithPassword(tempDir, tt.password)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error for invalid password")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			defer store.Close()

			// Verify store was created successfully
			profiles := store.ListProfiles()
			if len(profiles) != 0 {
				t.Errorf("Expected 0 profiles, got %d", len(profiles))
			}
		})
	}
}

func TestCreateProfile(t *testing.T) {
	store := setupTestStore(t)
	defer store.Close()

	config := map[string]string{
		"clientId": "test-client-id-123456789",
		"appKey":   "test-app-key",
	}

	// Test successful creation
	err := store.CreateProfile("test-profile", config)
	if err != nil {
		t.Fatalf("Failed to create profile: %v", err)
	}

	// Verify profile exists
	if !store.ProfileExists("test-profile") {
		t.Error("Profile was not created")
	}

	// Test duplicate creation
	err = store.CreateProfile("test-profile", config)
	if err == nil {
		t.Error("Expected error for duplicate profile")
	}

	// Test empty name
	err = store.CreateProfile("", config)
	if err == nil {
		t.Error("Expected error for empty profile name")
	}

	// Test invalid config
	invalidConfig := map[string]string{
		"invalid": "config",
	}
	err = store.CreateProfile("invalid-profile", invalidConfig)
	if err == nil {
		t.Error("Expected error for invalid config")
	}
}

func TestGetProfile(t *testing.T) {
	store := setupTestStore(t)
	defer store.Close()

	config := map[string]string{
		"clientId": "test-client-id-123456789",
		"appKey":   "test-app-key",
	}

	// Create test profile
	err := store.CreateProfile("test-profile", config)
	if err != nil {
		t.Fatalf("Failed to create profile: %v", err)
	}

	// Test successful retrieval
	profile, err := store.GetProfile("test-profile")
	if err != nil {
		t.Fatalf("Failed to get profile: %v", err)
	}

	// Verify profile data
	if profile.Name != "test-profile" {
		t.Errorf("Expected name 'test-profile', got '%s'", profile.Name)
	}
	if profile.Config["clientId"] != config["clientId"] {
		t.Error("Profile config does not match")
	}

	// Test non-existent profile
	_, err = store.GetProfile("non-existent")
	if err == nil {
		t.Error("Expected error for non-existent profile")
	}

	// Test empty name
	_, err = store.GetProfile("")
	if err == nil {
		t.Error("Expected error for empty profile name")
	}
}

func TestUpdateProfile(t *testing.T) {
	store := setupTestStore(t)
	defer store.Close()

	originalConfig := map[string]string{
		"clientId": "test-client-id-123456789",
		"appKey":   "original-app-key",
	}

	// Create test profile
	err := store.CreateProfile("test-profile", originalConfig)
	if err != nil {
		t.Fatalf("Failed to create profile: %v", err)
	}

	// Get original timestamp
	originalProfile, _ := store.GetProfile("test-profile")
	originalUpdatedAt := originalProfile.UpdatedAt

	// Wait a moment to ensure timestamp changes
	time.Sleep(time.Millisecond)

	// Update profile
	newConfig := map[string]string{
		"clientId": "test-client-id-123456789",
		"appKey":   "updated-app-key",
	}

	err = store.UpdateProfile("test-profile", newConfig)
	if err != nil {
		t.Fatalf("Failed to update profile: %v", err)
	}

	// Verify update
	updatedProfile, err := store.GetProfile("test-profile")
	if err != nil {
		t.Fatalf("Failed to get updated profile: %v", err)
	}

	if updatedProfile.Config["appKey"] != "updated-app-key" {
		t.Error("Profile was not updated")
	}

	if !updatedProfile.UpdatedAt.After(originalUpdatedAt) {
		t.Error("UpdatedAt timestamp was not updated")
	}

	// Test updating non-existent profile
	err = store.UpdateProfile("non-existent", newConfig)
	if err == nil {
		t.Error("Expected error for non-existent profile")
	}
}

func TestDeleteProfile(t *testing.T) {
	store := setupTestStore(t)
	defer store.Close()

	config := map[string]string{
		"clientId": "test-client-id-123456789",
		"appKey":   "test-app-key",
	}

	// Create test profile
	err := store.CreateProfile("test-profile", config)
	if err != nil {
		t.Fatalf("Failed to create profile: %v", err)
	}

	// Verify profile exists
	if !store.ProfileExists("test-profile") {
		t.Error("Profile was not created")
	}

	// Delete profile
	err = store.DeleteProfile("test-profile")
	if err != nil {
		t.Fatalf("Failed to delete profile: %v", err)
	}

	// Verify profile is gone
	if store.ProfileExists("test-profile") {
		t.Error("Profile was not deleted")
	}

	// Test deleting non-existent profile
	err = store.DeleteProfile("non-existent")
	if err == nil {
		t.Error("Expected error for non-existent profile")
	}

	// Test deleting with empty name
	err = store.DeleteProfile("")
	if err == nil {
		t.Error("Expected error for empty profile name")
	}
}

func TestListProfiles(t *testing.T) {
	store := setupTestStore(t)
	defer store.Close()

	config := map[string]string{
		"clientId": "test-client-id-123456789",
		"appKey":   "test-app-key",
	}

	// Initially empty
	profiles := store.ListProfiles()
	if len(profiles) != 0 {
		t.Errorf("Expected 0 profiles, got %d", len(profiles))
	}

	// Create multiple profiles
	profileNames := []string{"profile1", "profile2", "profile3"}
	for _, name := range profileNames {
		err := store.CreateProfile(name, config)
		if err != nil {
			t.Fatalf("Failed to create profile %s: %v", name, err)
		}
	}

	// Verify all profiles are listed
	profiles = store.ListProfiles()
	if len(profiles) != len(profileNames) {
		t.Errorf("Expected %d profiles, got %d", len(profileNames), len(profiles))
	}

	// Verify all expected profiles are present
	profileMap := make(map[string]bool)
	for _, name := range profiles {
		profileMap[name] = true
	}

	for _, expectedName := range profileNames {
		if !profileMap[expectedName] {
			t.Errorf("Profile '%s' not found in list", expectedName)
		}
	}
}

func TestGetProfileMetadata(t *testing.T) {
	store := setupTestStore(t)
	defer store.Close()

	config := map[string]string{
		"clientId": "test-client-id-123456789",
		"appKey":   "test-app-key",
	}

	// Create test profile
	err := store.CreateProfile("test-profile", config)
	if err != nil {
		t.Fatalf("Failed to create profile: %v", err)
	}

	// Get metadata
	metadata := store.GetProfileMetadata()
	if len(metadata) != 1 {
		t.Errorf("Expected 1 profile metadata, got %d", len(metadata))
	}

	profileMeta, exists := metadata["test-profile"]
	if !exists {
		t.Error("Profile metadata not found")
	}

	if profileMeta.Name != "test-profile" {
		t.Errorf("Expected name 'test-profile', got '%s'", profileMeta.Name)
	}

	if profileMeta.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}

	if profileMeta.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should not be zero")
	}
}

func TestPersistence(t *testing.T) {
	tempDir := t.TempDir()
	originalConfigDir := os.Getenv("KSM_MCP_CONFIG_DIR")
	os.Setenv("KSM_MCP_CONFIG_DIR", tempDir)
	defer func() {
		if originalConfigDir != "" {
			os.Setenv("KSM_MCP_CONFIG_DIR", originalConfigDir)
		} else {
			os.Unsetenv("KSM_MCP_CONFIG_DIR")
		}
	}()

	config := map[string]string{
		"clientId": "test-client-id-123456789",
		"appKey":   "test-app-key",
	}

	// Create first store and add profile
	store1 := NewProfileStore(tempDir)

	err := store1.CreateProfile("persistent-profile", config)
	if err != nil {
		t.Fatalf("Failed to create profile: %v", err)
	}
	store1.Close()

	// Create second store (should load existing data)
	store2 := NewProfileStore(tempDir)
	defer store2.Close()

	// Verify profile was persisted
	if !store2.ProfileExists("persistent-profile") {
		t.Error("Profile was not persisted")
	}

	profile, err := store2.GetProfile("persistent-profile")
	if err != nil {
		t.Fatalf("Failed to get persisted profile: %v", err)
	}

	if profile.Config["clientId"] != config["clientId"] {
		t.Error("Persisted profile config does not match")
	}
}

func TestValidateKSMConfig(t *testing.T) {
	store := setupTestStore(t)
	defer store.Close()

	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
	}{
		{
			"valid config",
			map[string]string{
				"clientId": "test-client-id-123456789",
				"appKey":   "test-app-key",
			},
			false,
		},
		{
			"missing clientId",
			map[string]string{
				"appKey": "test-app-key",
			},
			true,
		},
		{
			"short clientId",
			map[string]string{
				"clientId": "short",
			},
			true,
		},
		{
			"nil config",
			nil,
			true,
		},
		{
			"empty config",
			map[string]string{},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.validateKSMConfig(tt.config)

			if tt.wantErr && err == nil {
				t.Error("Expected validation to fail")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected validation error: %v", err)
			}
		})
	}
}

func TestProfileCopy(t *testing.T) {
	store := setupTestStore(t)
	defer store.Close()

	config := map[string]string{
		"clientId": "test-client-id-123456789",
		"appKey":   "test-app-key",
	}

	// Create profile
	err := store.CreateProfile("test-profile", config)
	if err != nil {
		t.Fatalf("Failed to create profile: %v", err)
	}

	// Get profile (should be a copy)
	profile1, err := store.GetProfile("test-profile")
	if err != nil {
		t.Fatalf("Failed to get profile: %v", err)
	}

	profile2, err := store.GetProfile("test-profile")
	if err != nil {
		t.Fatalf("Failed to get profile: %v", err)
	}

	// Modify one copy
	profile1.Config["appKey"] = "modified"

	// Verify the other copy is unchanged
	if profile2.Config["appKey"] == "modified" {
		t.Error("Profile modification affected other copy")
	}

	// Verify original in store is unchanged
	originalProfile, _ := store.GetProfile("test-profile")
	if originalProfile.Config["appKey"] == "modified" {
		t.Error("Profile modification affected stored copy")
	}
}

// setupTestStore creates a test profile store with temporary directory
func setupTestStore(t *testing.T) *ProfileStore {
	tempDir := t.TempDir()
	originalConfigDir := os.Getenv("KSM_MCP_CONFIG_DIR")
	os.Setenv("KSM_MCP_CONFIG_DIR", tempDir)

	t.Cleanup(func() {
		if originalConfigDir != "" {
			os.Setenv("KSM_MCP_CONFIG_DIR", originalConfigDir)
		} else {
			os.Unsetenv("KSM_MCP_CONFIG_DIR")
		}
	})

	store := NewProfileStore(tempDir)

	return store
}
