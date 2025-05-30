package commands

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/keeper-security/ksm-mcp/internal/config"
	"github.com/keeper-security/ksm-mcp/internal/ksm"
	"github.com/keeper-security/ksm-mcp/internal/storage"
	"github.com/keeper-security/ksm-mcp/internal/validation"
	"github.com/keeper-security/ksm-mcp/pkg/types"
	"github.com/spf13/cobra"
)

var (
	initProfile              string
	initToken                string
	initConfig               string
	initNoProtectionPassword bool
)

// initCmd represents the init command
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new KSM profile",
	Long: `Initialize a new Keeper Secrets Manager profile with either a one-time token or existing config file.

Examples:
  # Initialize with one-time token
  ksm-mcp init --profile myprofile --token US:TOKEN_HERE

  # Initialize from existing KSM config file
  ksm-mcp init --profile myprofile --config ~/path/to/config.json

  # Initialize with base64-encoded config
  ksm-mcp init --profile myprofile --config "BASE64_ENCODED_CONFIG"

  # Initialize from environment variable
  export KSM_CONFIG="BASE64_ENCODED_CONFIG"
  ksm-mcp init --profile myprofile`,
	RunE: runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)

	// Ensure init command outputs to stderr (important for Docker entrypoint)
	initCmd.SetOut(os.Stderr)
	initCmd.SetErr(os.Stderr)

	initCmd.Flags().StringVar(&initProfile, "profile", "", "profile name (required)")
	initCmd.Flags().StringVar(&initToken, "token", "", "one-time token (US:TOKEN_HERE)")
	initCmd.Flags().StringVar(&initConfig, "config", "", "path to KSM config file or base64-encoded config")
	initCmd.Flags().BoolVar(&initNoProtectionPassword, "no-protection-password", false, "disable protection password for local profile encryption (NOT RECOMMENDED)")
	_ = initCmd.MarkFlagRequired("profile")
}

func runInit(cmd *cobra.Command, args []string) error {
	// Check for KSM_CONFIG_BASE64 or KSM_CONFIG environment variable if no flags provided
	if initToken == "" && initConfig == "" {
		if envConfig := os.Getenv("KSM_CONFIG_BASE64"); envConfig != "" {
			initConfig = envConfig
		} else if envConfig := os.Getenv("KSM_CONFIG"); envConfig != "" {
			initConfig = envConfig
		}
	}

	if initToken == "" && initConfig == "" {
		return fmt.Errorf("either --token, --config, KSM_CONFIG_BASE64 or KSM_CONFIG environment variable must be provided")
	}

	// Validate only one config source is provided
	if initToken != "" && initConfig != "" {
		return fmt.Errorf("cannot specify both --token and --config")
	}

	// Validate profile name
	validator := validation.NewValidator()
	if err := validator.ValidateProfileName(initProfile); err != nil {
		return fmt.Errorf("invalid profile name: %w", err)
	}

	// Get or create config directory
	configDir := os.Getenv("KSM_MCP_CONFIG_DIR")
	if configDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		configDir = filepath.Join(home, ".keeper", "ksm-mcp")
	}

	// Create config directory if it doesn't exist
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Load or create config
	cfg, err := config.LoadOrCreate(filepath.Join(configDir, "config.yaml"))
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Create storage with password if config has one
	var store *storage.ProfileStore
	if cfg.Security.ProtectionPasswordHash != "" {
		fmt.Fprint(os.Stderr, "Enter protection password: ")
		password, err := readPassword()
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}

		store, err = storage.NewProfileStoreWithPassword(configDir, password)
		if err != nil {
			return fmt.Errorf("failed to create profile store: %w", err)
		}
	} else {
		// First time setup
		if initNoProtectionPassword {
			// Create store without password
			fmt.Fprintln(os.Stderr, "⚠️  WARNING: Creating profile WITHOUT protection password for local profile encryption.")
			fmt.Fprintln(os.Stderr, "Your KSM credentials will be stored in plain text.")
			fmt.Fprintln(os.Stderr, "This is NOT RECOMMENDED for production use.")

			store = storage.NewProfileStore(configDir)
		} else {
			// Prompt for protection password
			fmt.Fprintln(os.Stderr, "First time setup - please create a protection password for local profile encryption.")
			fmt.Fprintln(os.Stderr, "This password will be used to encrypt all stored profiles.")
			fmt.Fprint(os.Stderr, "Enter protection password: ")
			password, err := readPassword()
			if err != nil {
				return fmt.Errorf("failed to read password: %w", err)
			}

			fmt.Fprint(os.Stderr, "Confirm protection password: ")
			confirm, err := readPassword()
			if err != nil {
				return fmt.Errorf("failed to read password: %w", err)
			}

			if password != confirm {
				return fmt.Errorf("passwords do not match")
			}

			store, err = storage.NewProfileStoreWithPassword(configDir, password)
			if err != nil {
				return fmt.Errorf("failed to create profile store: %w", err)
			}

			// Save protection password hash in config
			cfg.Security.ProtectionPasswordHash = store.GetPasswordHash()
			if err := cfg.SaveDefault(); err != nil {
				return fmt.Errorf("failed to save config: %w", err)
			}
		}
	}

	// Check if profile already exists
	if _, err := store.GetProfile(initProfile); err == nil {
		return fmt.Errorf("profile '%s' already exists", initProfile)
	}

	fmt.Fprintf(os.Stderr, "Initializing profile '%s'...\n", initProfile)

	var ksmConfig map[string]string

	if initToken != "" {
		// Validate token
		if err := validator.ValidateToken(initToken); err != nil {
			return fmt.Errorf("invalid token: %w", err)
		}

		// Initialize with one-time token
		verboseLog("Initializing KSM with token")
		ksmConfig, err = ksm.InitializeWithToken(initToken)
		if err != nil {
			return fmt.Errorf("failed to initialize with token: %w", err)
		}
		fmt.Fprintln(os.Stderr, "✓ Successfully initialized KSM configuration")
	} else {
		// Determine if config is a file path or base64
		var configData []byte
		var err error

		// Check if it's a file path (contains / or \ or starts with ~ or .)
		if strings.ContainsAny(initConfig, "/\\") || strings.HasPrefix(initConfig, "~") || strings.HasPrefix(initConfig, ".") {
			// Load from file
			verboseLog("Loading KSM config from file: %s", initConfig)
			configPath := initConfig
			if strings.HasPrefix(configPath, "~") {
				home, err := os.UserHomeDir()
				if err != nil {
					return fmt.Errorf("failed to get home directory: %w", err)
				}
				configPath = filepath.Join(home, configPath[1:])
			}

			// Clean and validate the path
			cleanPath := filepath.Clean(configPath)
			configData, err = os.ReadFile(cleanPath) // #nosec G304 - user-provided path for config
			if err != nil {
				return fmt.Errorf("failed to read config file: %w", err)
			}
			fmt.Fprintln(os.Stderr, "✓ Successfully loaded KSM configuration from file")
		} else {
			// Assume it's base64-encoded
			verboseLog("Loading base64-encoded KSM config")
			configData, err = base64.StdEncoding.DecodeString(initConfig)
			if err != nil {
				return fmt.Errorf("failed to decode base64 config: %w", err)
			}
			fmt.Fprintln(os.Stderr, "✓ Successfully loaded KSM configuration from base64")
		}

		ksmConfig, err = ksm.InitializeWithConfig(configData)
		if err != nil {
			return fmt.Errorf("failed to initialize with config: %w", err)
		}
	}

	// Test the connection
	fmt.Fprint(os.Stderr, "Testing connection to Keeper Secrets Manager... ")
	client, err := ksm.NewClient(&types.Profile{
		Name:   initProfile,
		Config: ksmConfig,
	}, nil) // No logger for CLI
	if err != nil {
		fmt.Fprintln(os.Stderr, "✗")
		return fmt.Errorf("failed to create client: %w", err)
	}

	// Test the connection by listing secrets
	if _, err := client.ListSecrets([]string{}); err != nil {
		return fmt.Errorf("failed to test KSM connection: %w", err)
	}

	// Create and save profile
	profile := &types.Profile{
		Name:   initProfile,
		Config: ksmConfig,
	}

	if err := store.CreateProfile(profile.Name, profile.Config); err != nil {
		return fmt.Errorf("failed to save profile: %w", err)
	}

	// If this is the first profile, make it default
	if cfg.Profiles.Default == "" {
		cfg.Profiles.Default = initProfile
		if err := cfg.SaveDefault(); err != nil {
			return fmt.Errorf("failed to update default profile: %w", err)
		}
		fmt.Fprintf(os.Stderr, "✓ Set '%s' as default profile\n", initProfile)
	}

	fmt.Fprintf(os.Stderr, "\nProfile '%s' initialized successfully!\n", initProfile)
	fmt.Fprintln(os.Stderr, "\nTo start the MCP server, run:")
	fmt.Fprintf(os.Stderr, "  ksm-mcp serve --profile %s\n", initProfile)

	return nil
}

// readPassword reads a password from stdin without echoing
func readPassword() (string, error) {
	// Simple implementation - in production use golang.org/x/term
	var password string
	_, err := fmt.Scanln(&password)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(password), nil
}
