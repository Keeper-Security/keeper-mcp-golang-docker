package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/viper"
)

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
	BatchMode           bool          `mapstructure:"batch_mode"`
	AutoApprove         bool          `mapstructure:"auto_approve"`
	MaskByDefault       bool          `mapstructure:"mask_by_default"`
	SessionTimeout      time.Duration `mapstructure:"session_timeout"`
	ConfirmationTimeout time.Duration `mapstructure:"confirmation_timeout"`
	MasterPasswordHash  string        `mapstructure:"master_password_hash"`
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
	v.SetConfigName("config")
	v.SetConfigType("yaml")

	// Set default search paths
	configDir := getConfigDir()
	v.AddConfigPath(configDir)
	v.AddConfigPath(".")

	// If specific config file is provided, use it
	if configFile != "" {
		v.SetConfigFile(configFile)
	}

	// Environment variable overrides
	v.SetEnvPrefix("KSM_MCP")
	v.AutomaticEnv()

	// Map environment variables
	_ = v.BindEnv("security.batch_mode", "KSM_MCP_BATCH_MODE")
	_ = v.BindEnv("security.auto_approve", "KSM_MCP_AUTO_APPROVE")
	_ = v.BindEnv("logging.level", "KSM_MCP_LOG_LEVEL")
	_ = v.BindEnv("profiles.default", "KSM_MCP_PROFILE")

	// Read config file
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found is okay, we'll use defaults
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
	v.Set("security.master_password_hash", c.Security.MasterPasswordHash)
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
		return ".keeper/ksm-mcp"
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
	// Try to load existing config
	config, err := Load(configFile)
	if err == nil {
		return config, nil
	}

	// If it's a parsing error, return it
	if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
		return nil, err
	}

	// Config doesn't exist, create default
	config = DefaultConfig()

	// Save the default config
	if err := config.Save(configFile); err != nil {
		return nil, fmt.Errorf("failed to save default config: %w", err)
	}

	return config, nil
}
