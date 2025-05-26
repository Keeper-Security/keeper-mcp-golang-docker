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
	serveBatch       bool
	serveAutoApprove bool
	serveTimeout     time.Duration
	serveLogLevel    string
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
}

func runServe(cmd *cobra.Command, args []string) error {
	// Check if running in Docker and load configuration
	var dockerProfile *types.Profile
	if config.IsRunningInDocker() {
		// fmt.Fprintf(os.Stderr, "Running in Docker environment\n")

		// First try to load from Docker secrets
		if prof, err := config.LoadDockerSecrets(); err == nil {
			dockerProfile = prof
			// fmt.Fprintf(os.Stderr, "Loaded configuration from Docker secrets\n")
		} else if configBase64 := os.Getenv("KSM_CONFIG_BASE64"); configBase64 != "" {
			// Try environment variable
			if prof, err := loadProfileFromBase64(configBase64); err == nil {
				dockerProfile = prof
				// fmt.Fprintf(os.Stderr, "Loaded configuration from KSM_CONFIG_BASE64\n")
			}
			// If loading from environment fails, continue without Docker profile
		}
	}

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
	cfg, err := config.LoadOrCreate(filepath.Join(configDir, "config.yaml"))
	if err != nil {
		// If running in Docker with secrets, create minimal config
		if dockerProfile != nil {
			cfg = &config.Config{
				Profiles: config.ProfilesConfig{
					Default: "docker",
				},
			}
			// Apply Docker-specific config
			// TODO: Add server config to Config struct
			// dockerConfig := config.GetDockerConfig()
			// if serverCfg, ok := dockerConfig["server"].(map[string]interface{}); ok {
			// 	cfg.Server.Host = serverCfg["host"].(string)
			// 	cfg.Server.Port = serverCfg["port"].(int)
			// }
		} else {
			return fmt.Errorf("failed to load config: %w", err)
		}
	}

	// Determine which profile to use
	profileName := profile // from global flag
	useDirectConfig := false

	if profileName == "" && dockerProfile != nil {
		// When running in Docker with KSM_CONFIG_BASE64, use direct config without profiles
		useDirectConfig = true
		profileName = "docker" // Just for logging
	} else if profileName == "" {
		profileName = cfg.Profiles.Default
		if profileName == "" {
			return fmt.Errorf("no profile specified and no default profile configured")
		}
	}

	// Log to stderr since stdout is used for MCP protocol
	// fmt.Fprintf(os.Stderr, "Starting KSM MCP server...\n")
	// fmt.Fprintf(os.Stderr, "Using profile: %s\n", profileName)

	// Configure server modes based on flags
	_ = serveBatch       // Batch mode flag processed in server options
	_ = serveAutoApprove // Auto-approve flag processed in server options

	// Create storage - handle Docker case specially
	var store storage.ProfileStoreInterface

	if useDirectConfig && dockerProfile != nil {
		// Create a simple in-memory store for Docker with direct config
		store = &dockerProfileStore{
			profile: dockerProfile,
		}
		// fmt.Fprintf(os.Stderr, "Using direct KSM configuration (no profile storage)\n")
	} else if cfg.Security.ProtectionPasswordHash != "" {
		// Handle protection password case
		var password string

		// Try to load from Docker secret first
		if config.IsRunningInDocker() {
			if secretPassword, err := config.LoadProtectionPasswordFromSecret(); err == nil {
				password = secretPassword
				// fmt.Fprintf(os.Stderr, "Loaded protection password from Docker secret\n")
			}
		}

		// If not in Docker or secret not found, prompt
		if password == "" {
			fmt.Fprint(os.Stderr, "Enter protection password: ")
			var err error
			password, err = readPassword()
			if err != nil {
				return fmt.Errorf("failed to read password: %w", err)
			}
		}

		store, err = storage.NewProfileStoreWithPassword(configDir, password)
		if err != nil {
			return fmt.Errorf("failed to unlock profile store: %w", err)
		}
	} else {
		// Regular profile store
		store = storage.NewProfileStore(configDir)
	}

	// Create audit logger
	logPath := filepath.Join(configDir, "logs", "audit.log")
	logger, err := audit.NewLogger(audit.Config{
		FilePath: logPath,
		MaxSize:  100 * 1024 * 1024,   // 100MB in bytes
		MaxAge:   30 * 24 * time.Hour, // 30 days
	})
	if err != nil {
		return fmt.Errorf("failed to create audit logger: %w", err)
	}
	defer logger.Close()

	// Check environment variables for batch mode
	if os.Getenv("KSM_MCP_BATCH_MODE") == "true" {
		serveBatch = true
	}

	// Create MCP server with options
	serverOpts := &mcp.ServerOptions{
		BatchMode:   serveBatch,
		AutoApprove: serveAutoApprove,
		Timeout:     serveTimeout,
		ProfileName: profileName,
		RateLimit:   100, // requests per minute
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
type dockerProfileStore struct {
	profile *types.Profile
}

func (d *dockerProfileStore) GetProfile(name string) (*types.Profile, error) {
	if d.profile != nil && d.profile.Name == name {
		return d.profile, nil
	}
	return nil, fmt.Errorf("profile '%s' not found", name)
}

func (d *dockerProfileStore) CreateProfile(name string, config map[string]string) error {
	return fmt.Errorf("profile creation not supported in direct config mode")
}

func (d *dockerProfileStore) UpdateProfile(name string, config map[string]string) error {
	return fmt.Errorf("profile updates not supported in direct config mode")
}

func (d *dockerProfileStore) DeleteProfile(name string) error {
	return fmt.Errorf("profile deletion not supported in direct config mode")
}

func (d *dockerProfileStore) ListProfiles() []string {
	if d.profile != nil {
		return []string{d.profile.Name}
	}
	return []string{}
}

func (d *dockerProfileStore) ProfileExists(name string) bool {
	return d.profile != nil && d.profile.Name == name
}

// loadProfileFromBase64 loads a profile from base64-encoded KSM config
func loadProfileFromBase64(configBase64 string) (*types.Profile, error) {
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
		Name:   "docker",
		Config: ksmConfig,
	}

	return profile, nil
}
