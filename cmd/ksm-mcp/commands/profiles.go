package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/keeper-security/ksm-mcp/internal/config"
	"github.com/keeper-security/ksm-mcp/internal/storage"
	"github.com/spf13/cobra"
)

// profilesCmd represents the profiles command
var profilesCmd = &cobra.Command{
	Use:   "profiles",
	Short: "Manage KSM profiles",
	Long: `List, delete, and manage Keeper Secrets Manager profiles.

Profiles store encrypted KSM configurations that can be used to connect
to different Keeper accounts or vaults.`,
}

// profilesListCmd represents the profiles list command
var profilesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all profiles",
	Long:  `List all configured KSM profiles with their metadata.`,
	RunE:  runProfilesList,
}

// profilesDeleteCmd represents the profiles delete command
var profilesDeleteCmd = &cobra.Command{
	Use:   "delete [profile]",
	Short: "Delete a profile",
	Long:  `Delete a KSM profile. This action cannot be undone.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runProfilesDelete,
}

// profilesSetDefaultCmd represents the profiles set-default command
var profilesSetDefaultCmd = &cobra.Command{
	Use:   "set-default [profile]",
	Short: "Set default profile",
	Long:  `Set the default profile to use when no --profile flag is specified.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runProfilesSetDefault,
}

// profilesShowCmd represents the profiles show command
var profilesShowCmd = &cobra.Command{
	Use:   "show [profile]",
	Short: "Show profile details",
	Long:  `Show detailed information about a specific profile.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runProfilesShow,
}

func init() {
	rootCmd.AddCommand(profilesCmd)
	profilesCmd.AddCommand(profilesListCmd)
	profilesCmd.AddCommand(profilesDeleteCmd)
	profilesCmd.AddCommand(profilesSetDefaultCmd)
	profilesCmd.AddCommand(profilesShowCmd)
}

func runProfilesList(cmd *cobra.Command, args []string) error {
	// Get config directory
	configDir := os.Getenv("KSM_MCP_CONFIG_DIR")
	if configDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		configDir = filepath.Join(home, ".keeper", "ksm-mcp")
	}

	// Load config to get default profile
	cfg, err := config.Load(filepath.Join(configDir, "config.yaml"))
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Create storage
	var store *storage.ProfileStore
	if cfg.Security.MasterPasswordHash != "" {
		fmt.Fprint(os.Stderr, "Enter master password: ")
		password, err := readPassword()
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		
		store, err = storage.NewProfileStoreWithPassword(configDir, password)
		if err != nil {
			return fmt.Errorf("failed to unlock profile store: %w", err)
		}
	} else {
		store = storage.NewProfileStore(configDir)
	}

	// List profiles
	profileNames := store.ListProfiles()

	if len(profileNames) == 0 {
		fmt.Println("No profiles configured.")
		fmt.Println("\nTo create a profile, run:")
		fmt.Println("  ksm-mcp init --profile <name> --token <token>")
		return nil
	}

	// Display profiles in a table
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PROFILE\tDEFAULT")
	fmt.Fprintln(w, "-------\t-------")

	for _, name := range profileNames {
		isDefault := ""
		if name == cfg.Profiles.Default {
			isDefault = "✓"
		}

		fmt.Fprintf(w, "%s\t%s\n", name, isDefault)
	}
	w.Flush()

	return nil
}

func runProfilesDelete(cmd *cobra.Command, args []string) error {
	profileName := args[0]

	// Get config directory
	configDir := os.Getenv("KSM_MCP_CONFIG_DIR")
	if configDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		configDir = filepath.Join(home, ".keeper", "ksm-mcp")
	}

	// Load config
	cfg, err := config.Load(filepath.Join(configDir, "config.yaml"))
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Create storage
	var store *storage.ProfileStore
	if cfg.Security.MasterPasswordHash != "" {
		fmt.Fprint(os.Stderr, "Enter master password: ")
		password, err := readPassword()
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		
		store, err = storage.NewProfileStoreWithPassword(configDir, password)
		if err != nil {
			return fmt.Errorf("failed to unlock profile store: %w", err)
		}
	} else {
		store = storage.NewProfileStore(configDir)
	}

	// Confirm deletion
	fmt.Printf("Are you sure you want to delete profile '%s'? This action cannot be undone.\n", profileName)
	fmt.Print("Type 'yes' to confirm: ")
	
	var confirm string
	fmt.Scanln(&confirm)
	if strings.ToLower(strings.TrimSpace(confirm)) != "yes" {
		fmt.Println("Deletion cancelled.")
		return nil
	}

	// Delete profile
	if err := store.DeleteProfile(profileName); err != nil {
		return fmt.Errorf("failed to delete profile: %w", err)
	}

	// If this was the default profile, clear it
	if cfg.Profiles.Default == profileName {
		cfg.Profiles.Default = ""
		if err := cfg.SaveDefault(); err != nil {
			return fmt.Errorf("failed to update config: %w", err)
		}
		fmt.Println("⚠️  Default profile cleared")
	}

	fmt.Printf("✓ Profile '%s' deleted successfully\n", profileName)
	return nil
}

func runProfilesSetDefault(cmd *cobra.Command, args []string) error {
	profileName := args[0]

	// Get config directory
	configDir := os.Getenv("KSM_MCP_CONFIG_DIR")
	if configDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		configDir = filepath.Join(home, ".keeper", "ksm-mcp")
	}

	// Load config
	cfg, err := config.Load(filepath.Join(configDir, "config.yaml"))
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Create storage to verify profile exists
	var store *storage.ProfileStore
	if cfg.Security.MasterPasswordHash != "" {
		fmt.Fprint(os.Stderr, "Enter master password: ")
		password, err := readPassword()
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		
		store, err = storage.NewProfileStoreWithPassword(configDir, password)
		if err != nil {
			return fmt.Errorf("failed to unlock profile store: %w", err)
		}
	} else {
		store = storage.NewProfileStore(configDir)
	}

	// Check if profile exists
	if _, err := store.GetProfile(profileName); err != nil {
		return fmt.Errorf("profile '%s' does not exist", profileName)
	}

	// Update default profile
	cfg.Profiles.Default = profileName
	if err := cfg.SaveDefault(); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("✓ Default profile set to '%s'\n", profileName)
	return nil
}

func runProfilesShow(cmd *cobra.Command, args []string) error {
	profileName := args[0]

	// Get config directory
	configDir := os.Getenv("KSM_MCP_CONFIG_DIR")
	if configDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		configDir = filepath.Join(home, ".keeper", "ksm-mcp")
	}

	// Load config
	cfg, err := config.Load(filepath.Join(configDir, "config.yaml"))
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Create storage
	var store *storage.ProfileStore
	if cfg.Security.MasterPasswordHash != "" {
		fmt.Fprint(os.Stderr, "Enter master password: ")
		password, err := readPassword()
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		
		store, err = storage.NewProfileStoreWithPassword(configDir, password)
		if err != nil {
			return fmt.Errorf("failed to unlock profile store: %w", err)
		}
	} else {
		store = storage.NewProfileStore(configDir)
	}

	// Get profile
	profile, err := store.GetProfile(profileName)
	if err != nil {
		return fmt.Errorf("profile '%s' not found", profileName)
	}

	// Display profile information
	fmt.Printf("Profile: %s\n", profile.Name)
	fmt.Printf("Default: %v\n", profile.Name == cfg.Profiles.Default)
	
	if !profile.CreatedAt.IsZero() {
		fmt.Printf("Created: %s\n", profile.CreatedAt.Format(time.RFC3339))
	}
	
	if !profile.UpdatedAt.IsZero() {
		fmt.Printf("Updated: %s\n", profile.UpdatedAt.Format(time.RFC3339))
	}

	// Show KSM config details (without sensitive data)
	if profile.Config != nil && len(profile.Config) > 0 {
		fmt.Println("\nKSM Configuration:")
		if clientId, ok := profile.Config["clientId"]; ok {
			fmt.Printf("  Client ID: %s\n", clientId)
		}
		if hostname, ok := profile.Config["hostname"]; ok && hostname != "" {
			fmt.Printf("  Hostname: %s\n", hostname)
		}
		if privateKey, ok := profile.Config["privateKey"]; ok {
			fmt.Printf("  Private Key: %s\n", maskSensitive(privateKey))
		}
		if appKey, ok := profile.Config["appKey"]; ok {
			fmt.Printf("  App Key: %s\n", maskSensitive(appKey))
		}
	}

	// Get metadata about secrets access
	allMetadata := store.GetProfileMetadata()
	if metadata, ok := allMetadata[profileName]; ok {
		fmt.Println("\nMetadata:")
		fmt.Printf("  Created: %s\n", metadata.CreatedAt.Format(time.RFC3339))
		if !metadata.UpdatedAt.IsZero() {
			fmt.Printf("  Updated: %s\n", metadata.UpdatedAt.Format(time.RFC3339))
		}
	}

	return nil
}

func maskSensitive(value string) string {
	if len(value) <= 8 {
		return "********"
	}
	return value[:4] + "..." + value[len(value)-4:]
}