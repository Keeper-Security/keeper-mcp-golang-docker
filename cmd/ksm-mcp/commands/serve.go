package commands

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/keeper-security/ksm-mcp/internal/audit"
	"github.com/keeper-security/ksm-mcp/internal/config"
	"github.com/keeper-security/ksm-mcp/internal/ksm"
	"github.com/keeper-security/ksm-mcp/internal/mcp"
	"github.com/keeper-security/ksm-mcp/internal/storage"
	"github.com/keeper-security/ksm-mcp/pkg/types"
	"github.com/spf13/cobra"
)

var (
	serveBatch        bool
	serveAutoApprove  bool
	serveTimeout      time.Duration
	serveLogLevel     string
	serveConfigBase64 string // Add CLI flag for base64 config
	serveNoLogs       bool   // Add flag to disable logging
	// profile flag is defined in root.go and available here
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the KSM MCP server",
	Long: `Start the KSM Model Context Protocol server to handle requests from AI agents.

The server communicates over stdio (stdin/stdout) using the MCP protocol.
It requires a configured profile to connect to Keeper Secrets Manager.

Examples:
  # Start server with default profile
  ksm-mcp serve

  # Start server with specific profile
  ksm-mcp serve --profile production

  # Start server with base64 config (no init required)
  ksm-mcp serve --config-base64 "ewog..."

  # Start server with base64 config and custom profile name
  ksm-mcp serve --profile myprofile --config-base64 "ewog..."

  # Start in batch mode (no interactive prompts)
  ksm-mcp serve --batch

  # Auto-approve all operations (use with caution!)
  ksm-mcp serve --auto-approve --timeout 30s`,
	RunE: runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)

	// Ensure serve command outputs to stderr (important for MCP protocol)
	serveCmd.SetOut(os.Stderr)
	serveCmd.SetErr(os.Stderr)

	serveCmd.Flags().BoolVar(&serveBatch, "batch", false, "enable batch mode (no interactive prompts)")
	serveCmd.Flags().BoolVar(&serveAutoApprove, "auto-approve", false, "auto-approve all operations (dangerous)")
	serveCmd.Flags().DurationVar(&serveTimeout, "timeout", 30*time.Second, "operation timeout")
	serveCmd.Flags().StringVar(&serveLogLevel, "log-level", "info", "logging level (debug, info, warn, error)")
	serveCmd.Flags().StringVar(&serveConfigBase64, "config-base64", "", "base64-encoded KSM configuration (bypasses profile loading)")
	serveCmd.Flags().BoolVar(&serveNoLogs, "no-logs", false, "disable audit logging")
}

func runServe(cmd *cobra.Command, args []string) error {
	var envVarProfile *types.Profile
	var finalProfileToUse *types.Profile
	var store storage.ProfileStoreInterface

	// Attempt to load configuration from CLI flag first, then environment variable
	// 'profile' is the global variable bound to the --profile flag from root.go
	profileNameFromFlag := profile
	var configBase64 string

	// Priority 1: CLI flag --config-base64
	if serveConfigBase64 != "" {
		configBase64 = serveConfigBase64
		// fmt.Fprintf(os.Stderr, "Using KSM configuration from --config-base64 flag\\n")
	} else if envConfigBase64 := os.Getenv("KSM_CONFIG_BASE64"); envConfigBase64 != "" {
		// Priority 2: Environment variable KSM_CONFIG_BASE64
		configBase64 = envConfigBase64
		// fmt.Fprintf(os.Stderr, "Using KSM configuration from KSM_CONFIG_BASE64 environment variable\\n")
	}

	if configBase64 != "" {
		profileNameToUseForEnv := "env_profile" // Default name if --profile flag is not set
		if profileNameFromFlag != "" {
			profileNameToUseForEnv = profileNameFromFlag
		}

		if prof, err := loadProfileFromBase64(profileNameToUseForEnv, configBase64); err == nil {
			envVarProfile = prof
			// fmt.Fprintf(os.Stderr, "Loaded KSM configuration for profile '%s'\\n", envVarProfile.Name)
		} else {
			return fmt.Errorf("failed to load KSM configuration from base64: %w", err)
		}
	}

	if envVarProfile != nil {
		// Priority 1: Use profile from base64 config (CLI flag or env var) if loaded
		store = &inMemoryProfileStore{profile: envVarProfile}
		finalProfileToUse = envVarProfile
		// fmt.Fprintf(os.Stderr, "Using KSM configuration for profile '%s' (in-memory)\\n", finalProfileToUse.Name)
	} else {
		// Priority 2: Fall back to file-based profiles if no base64 config provided
		configDir := os.Getenv("KSM_MCP_CONFIG_DIR")
		if configDir == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("failed to get home directory: %w", err)
			}
			configDir = filepath.Join(home, ".keeper", "ksm-mcp")
		}

		cfg, err := config.LoadOrCreate(filepath.Join(configDir, "config.yaml"))
		if err != nil {
			return fmt.Errorf("failed to load config.yaml: %w. Please run 'ksm-mcp init', set KSM_CONFIG_BASE64, or use --config-base64", err)
		}

		effectiveProfileName := profileNameFromFlag
		if effectiveProfileName == "" {
			effectiveProfileName = cfg.Profiles.Default
			if effectiveProfileName == "" {
				return fmt.Errorf("no profile specified (via --profile) and no default profile configured in config.yaml, and no base64 config provided")
			}
		}
		// fmt.Fprintf(os.Stderr, "Attempting to load profile '%s' from file-based storage\\n", effectiveProfileName)

		var fileStore storage.ProfileStoreInterface
		if cfg.Security.ProtectionPasswordHash != "" {
			var password string
			if config.IsRunningInDocker() { // Check Docker secrets for password only if in Docker
				if secretPassword, err := config.LoadProtectionPasswordFromSecret(); err == nil {
					password = secretPassword
					// fmt.Fprintf(os.Stderr, "Loaded protection password from Docker secret\\n")
				}
			}
			if password == "" && !serveBatch { // Don't prompt if in batch mode
				fmt.Fprint(os.Stderr, "Enter protection password: ")
				var ferr error
				password, ferr = readPassword() // Assumes readPassword() is available or defined
				if ferr != nil {
					return fmt.Errorf("failed to read password: %w", ferr)
				}
			} else if password == "" && serveBatch {
				return fmt.Errorf("protection password required for profile '%s' but running in batch mode", effectiveProfileName)
			}

			fs, ferr := storage.NewProfileStoreWithPassword(configDir, password)
			if ferr != nil {
				return fmt.Errorf("failed to unlock profile store for profile '%s': %w", effectiveProfileName, ferr)
			}
			fileStore = fs
		} else {
			fileStore = storage.NewProfileStore(configDir)
		}
		store = fileStore

		loadedProfile, err := store.GetProfile(effectiveProfileName)
		if err != nil {
			return fmt.Errorf("failed to get profile '%s' from store: %w. Set KSM_CONFIG_BASE64, use --config-base64, or run 'ksm-mcp init --profile %s'", effectiveProfileName, err, effectiveProfileName)
		}
		finalProfileToUse = loadedProfile
	}

	if finalProfileToUse == nil {
		return fmt.Errorf("could not determine a KSM profile to use. Check --profile flag, --config-base64 flag, KSM_CONFIG_BASE64 env var, or default profile in config.yaml")
	}

	// Create audit logger (or skip if --no-logs flag is set)
	var logger *audit.Logger
	if serveNoLogs {
		// Skip audit logging entirely - use a null logger
		logger = nil
	} else {
		// Get config directory for logger (even if using env var profile, logs go to standard location)
		logConfigDir := os.Getenv("KSM_MCP_CONFIG_DIR")
		if logConfigDir == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				// Log to stderr if we can't get home dir for logs, but don't fail server start
				fmt.Fprintf(os.Stderr, "Warning: failed to get home directory for logs: %v\\n", err)
				logConfigDir = "." // Fallback to current directory for logs if home fails
			} else {
				logConfigDir = filepath.Join(home, ".keeper", "ksm-mcp")
			}
		}
		// Ensure log directory exists
		if err := os.MkdirAll(filepath.Join(logConfigDir, "logs"), 0700); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to create log directory at %s: %v\\n", filepath.Join(logConfigDir, "logs"), err)
		}

		// Create audit logger
		logPath := filepath.Join(logConfigDir, "logs", "audit.log")
		var err error
		logger, err = audit.NewLogger(audit.Config{
			FilePath: logPath,
			MaxSize:  10 * 1024 * 1024, // 10MB
			MaxAge:   24 * time.Hour,
		})
		if err != nil {
			return fmt.Errorf("failed to create audit logger: %w", err)
		}
		defer logger.Close()
	}

	// Check environment variables for batch mode
	if os.Getenv("KSM_MCP_BATCH_MODE") == "true" {
		serveBatch = true
	}

	// Create MCP server with options
	serverOpts := &mcp.ServerOptions{
		BatchMode:   serveBatch,
		AutoApprove: serveAutoApprove,
		Timeout:     serveTimeout,
		ProfileName: finalProfileToUse.Name, // Use the name from the actually loaded/used profile
		RateLimit:   100,                    // requests per minute
		Version:     version,                // Use the package-level version variable
	}

	server := mcp.NewServer(store, logger, serverOpts)

	// Set up signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		// fmt.Fprintf(os.Stderr, "\nShutting down server...\n")
		cancel()
	}()

	// Start the server
	// fmt.Fprintf(os.Stderr, "Server ready. Starting MCP server...\n")

	// The server handles its own stdio reading/writing
	if err := server.Start(ctx); err != nil {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}

// dockerProfileStore is a simple in-memory profile store for Docker direct config
// Rename to inMemoryProfileStore to reflect its broader use
type inMemoryProfileStore struct {
	profile *types.Profile
}

func (d *inMemoryProfileStore) GetProfile(name string) (*types.Profile, error) {
	if d.profile != nil && d.profile.Name == name {
		return d.profile, nil
	}
	// If the requested name is different but we only have one profile (from env var),
	// still return it, as the name matching is mostly for file-based stores with multiple profiles.
	if d.profile != nil {
		// Optionally log: fmt.Fprintf(os.Stderr, "Warning: inMemoryProfileStore returning profile '%s' for requested name '%s'\\n", d.profile.Name, name)
		return d.profile, nil
	}
	return nil, fmt.Errorf("profile '%s' not found in inMemoryProfileStore", name)
}

func (d *inMemoryProfileStore) CreateProfile(name string, config map[string]string) error {
	return fmt.Errorf("profile creation not supported in in-memory direct config mode")
}

func (d *inMemoryProfileStore) UpdateProfile(name string, config map[string]string) error {
	return fmt.Errorf("profile updates not supported in in-memory direct config mode")
}

func (d *inMemoryProfileStore) DeleteProfile(name string) error {
	return fmt.Errorf("profile deletion not supported in in-memory direct config mode")
}

func (d *inMemoryProfileStore) ListProfiles() []string {
	if d.profile != nil {
		return []string{d.profile.Name}
	}
	return []string{}
}

func (d *inMemoryProfileStore) ProfileExists(name string) bool {
	// Similar to GetProfile, if a profile exists, consider it a match
	// as there's only one profile in this store.
	return d.profile != nil
}

// loadProfileFromBase64 loads a profile from base64-encoded KSM config
// Modified to take the desired profileName as an argument
func loadProfileFromBase64(profileName string, configBase64 string) (*types.Profile, error) {
	// Decode base64
	configData, err := base64.StdEncoding.DecodeString(configBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 config: %w", err)
	}

	// Initialize KSM config
	ksmConfig, err := ksm.InitializeWithConfig(configData)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize KSM config: %w", err)
	}

	// Create profile
	profile := &types.Profile{
		Name:   profileName, // Use the provided profileName
		Config: ksmConfig,
	}

	return profile, nil
}
