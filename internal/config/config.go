package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/viper"
)

// ErrConfigNotFound is returned when the config file is not found by Load.
var ErrConfigNotFound = errors.New("configuration file not found")

// Config represents the application configuration
type Config struct {
	MCP      MCPConfig      `mapstructure:"mcp"`
	Security SecurityConfig `mapstructure:"security"`
	Logging  LoggingConfig  `mapstructure:"logging"`
	Profiles ProfilesConfig `mapstructure:"profiles"`
}

// MCPConfig represents MCP protocol settings
type MCPConfig struct {
	Timeout   time.Duration `mapstructure:"timeout"`
	RateLimit RateLimit     `mapstructure:"rate_limit"`
}

// RateLimit represents rate limiting configuration
type RateLimit struct {
	RequestsPerMinute int `mapstructure:"requests_per_minute"`
	RequestsPerHour   int `mapstructure:"requests_per_hour"`
}

// SecurityConfig represents security settings
type SecurityConfig struct {
	BatchMode              bool          `mapstructure:"batch_mode"`
	AutoApprove            bool          `mapstructure:"auto_approve"`
	MaskByDefault          bool          `mapstructure:"mask_by_default"`
	SessionTimeout         time.Duration `mapstructure:"session_timeout"`
	ConfirmationTimeout    time.Duration `mapstructure:"confirmation_timeout"`
	ProtectionPasswordHash string        `mapstructure:"protection_password_hash"`
}

// LoggingConfig represents logging configuration
type LoggingConfig struct {
	Level string `mapstructure:"level"`
	File  string `mapstructure:"file"`
}

// ProfilesConfig represents profile settings
type ProfilesConfig struct {
	Default string `mapstructure:"default"`
}

// DefaultConfig returns a configuration with default values
func DefaultConfig() *Config {
	return &Config{
		MCP: MCPConfig{
			Timeout: 30 * time.Second,
			RateLimit: RateLimit{
				RequestsPerMinute: 60,
				RequestsPerHour:   1000,
			},
		},
		Security: SecurityConfig{
			BatchMode:           false,
			AutoApprove:         false,
			MaskByDefault:       true,
			SessionTimeout:      15 * time.Minute,
			ConfirmationTimeout: 30 * time.Second,
		},
		Logging: LoggingConfig{
			Level: "info",
			File:  "",
		},
		Profiles: ProfilesConfig{
			Default: "default",
		},
	}
}

// Load loads configuration from file
func Load(configFile string) (*Config, error) {
	config := DefaultConfig()

	v := viper.New()
	v.SetConfigName("config") // Default name if configFile is a directory
	v.SetConfigType("yaml")

	configDir := getConfigDir()
	resolvedConfigFile := configFile

	if configFile == "" || configFile == filepath.Join(configDir, "config.yaml") {
		// We are attempting to load the default config file.
		// Viper will search in AddConfigPath locations if SetConfigFile isn't called with a specific file.
		v.AddConfigPath(configDir)
		v.AddConfigPath(".")
		// Determine the exact path Viper would use for "config.yaml" in the primary configDir
		// This is to check its existence accurately.
		if configFile == "" { // If no specific configFile was passed to Load, assume default.
			resolvedConfigFile = filepath.Join(configDir, "config.yaml")
		}
	} else {
		// A specific configFile (potentially outside default paths) was given.
		v.SetConfigFile(configFile)
		resolvedConfigFile = configFile
	}

	// Explicitly check if the resolved config file exists before Viper tries to read it.
	// This gives us a more reliable way to detect "file not found".
	if _, err := os.Stat(resolvedConfigFile); os.IsNotExist(err) {
		return nil, ErrConfigNotFound // Return our distinct error
	}

	// Environment variable overrides
	v.SetEnvPrefix("KSM_MCP")
	v.AutomaticEnv()

	// Map environment variables
	_ = v.BindEnv("security.batch_mode", "KSM_MCP_BATCH_MODE")
	_ = v.BindEnv("security.auto_approve", "KSM_MCP_AUTO_APPROVE")
	_ = v.BindEnv("logging.level", "KSM_MCP_LOG_LEVEL")
	_ = v.BindEnv("profiles.default", "KSM_MCP_PROFILE")

	// Read config file - at this point, we expect it to exist,
	// so errors are more likely parsing/permission issues.
	if err := v.ReadInConfig(); err != nil {
		// Though we checked for existence, ReadInConfig can still fail (e.g. permissions)
		// or if os.Stat passed but Viper has an issue with the path for some reason.
		// If by some chance it's still a Viper ConfigFileNotFoundError, treat it as our ErrConfigNotFound.
		var vfnfError viper.ConfigFileNotFoundError
		if errors.As(err, &vfnfError) {
			return nil, ErrConfigNotFound
		}
		return nil, fmt.Errorf("failed to read config file content: %w", err)
	}

	// Unmarshal config
	if err := v.Unmarshal(config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Set default log file if not specified
	if config.Logging.File == "" {
		config.Logging.File = filepath.Join(configDir, "audit.log")
	}

	return config, nil
}

// Save saves configuration to file
func (c *Config) Save(configFile string) error {
	if configFile == "" {
		configFile = filepath.Join(getConfigDir(), "config.yaml")
	}

	// Ensure config directory exists
	if err := os.MkdirAll(filepath.Dir(configFile), 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	v := viper.New()
	v.SetConfigFile(configFile)

	// Set values
	v.Set("mcp.timeout", c.MCP.Timeout)
	v.Set("mcp.rate_limit.requests_per_minute", c.MCP.RateLimit.RequestsPerMinute)
	v.Set("mcp.rate_limit.requests_per_hour", c.MCP.RateLimit.RequestsPerHour)
	v.Set("security.batch_mode", c.Security.BatchMode)
	v.Set("security.auto_approve", c.Security.AutoApprove)
	v.Set("security.mask_by_default", c.Security.MaskByDefault)
	v.Set("security.session_timeout", c.Security.SessionTimeout)
	v.Set("security.confirmation_timeout", c.Security.ConfirmationTimeout)
	v.Set("security.protection_password_hash", c.Security.ProtectionPasswordHash)
	v.Set("logging.level", c.Logging.Level)
	v.Set("logging.file", c.Logging.File)
	v.Set("profiles.default", c.Profiles.Default)

	return v.WriteConfig()
}

// SaveDefault saves configuration to the default location
func (c *Config) SaveDefault() error {
	return c.Save("")
}

// getConfigDir returns the configuration directory
func getConfigDir() string {
	if configDir := os.Getenv("KSM_MCP_CONFIG_DIR"); configDir != "" {
		return configDir
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		// Fall back to current directory with absolute path
		cwd, _ := os.Getwd()
		return filepath.Join(cwd, ".keeper", "ksm-mcp")
	}

	return filepath.Join(homeDir, ".keeper", "ksm-mcp")
}

// GetConfigDir returns the configuration directory (exported)
func GetConfigDir() string {
	return getConfigDir()
}

// EnsureConfigDir ensures the configuration directory exists
func EnsureConfigDir() error {
	configDir := getConfigDir()
	return os.MkdirAll(configDir, 0700)
}

// LoadOrCreate loads existing config or creates a new one
func LoadOrCreate(configFile string) (*Config, error) {
	cfg, err := Load(configFile)
	if err == nil {
		return cfg, nil
	}

	if errors.Is(err, ErrConfigNotFound) {
		// Config doesn't exist, create default
		cfg = DefaultConfig()

		// Save the default config
		// Ensure configFile is the full path for saving if it was initially empty or just "config.yaml"
		finalConfigFile := configFile
		if finalConfigFile == "" || finalConfigFile == "config.yaml" {
			finalConfigFile = filepath.Join(getConfigDir(), "config.yaml")
		}

		if errSave := cfg.Save(finalConfigFile); errSave != nil {
			return nil, fmt.Errorf("failed to save default config to %s: %w", finalConfigFile, errSave)
		}
		return cfg, nil
	} else {
		// It's some other error from Load
		return nil, err
	}
}
