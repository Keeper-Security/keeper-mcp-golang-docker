package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/keeper-security/ksm-mcp/pkg/types"
)

const (
	// Docker secret paths
	DockerSecretsPath        = "/run/secrets"
	TokenSecretName          = "ksm_token"
	ConfigSecretName         = "ksm_config" // #nosec G101 - not a credential, just a filename
	MasterPasswordSecretName = "master_password"
)

// LoadDockerSecrets attempts to load configuration from Docker secrets
func LoadDockerSecrets() (*types.Profile, error) {
	// Check if running in Docker (secrets directory exists)
	if _, err := os.Stat(DockerSecretsPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("not running in Docker environment")
	}

	// Try to load token first
	tokenPath := filepath.Join(DockerSecretsPath, TokenSecretName)
	if tokenData, err := os.ReadFile(tokenPath); err == nil { // #nosec G304 - Docker secret path
		token := strings.TrimSpace(string(tokenData))
		if token != "" {
			profile := &types.Profile{
				Name: "docker",
				Config: map[string]string{
					"token": token,
				},
			}
			return profile, nil
		}
	}

	// Try to load config file
	configPath := filepath.Join(DockerSecretsPath, ConfigSecretName)
	if configData, err := os.ReadFile(configPath); err == nil { // #nosec G304 - Docker secret path
		// Try to parse as JSON first
		var config map[string]interface{}
		if err := json.Unmarshal(configData, &config); err == nil {
			// Convert map[string]interface{} to map[string]string
			configStr := make(map[string]string)
			for k, v := range config {
				if str, ok := v.(string); ok {
					configStr[k] = str
				} else {
					// Convert non-string values to JSON
					if bytes, err := json.Marshal(v); err == nil {
						configStr[k] = string(bytes)
					}
				}
			}
			profile := &types.Profile{
				Name:   "docker",
				Config: configStr,
			}
			return profile, nil
		}

		// Try as base64-encoded config
		decoded, err := base64.StdEncoding.DecodeString(string(configData))
		if err == nil {
			if err := json.Unmarshal(decoded, &config); err == nil {
				// Convert map[string]interface{} to map[string]string
				configStr := make(map[string]string)
				for k, v := range config {
					if str, ok := v.(string); ok {
						configStr[k] = str
					} else {
						// Convert non-string values to JSON
						if bytes, err := json.Marshal(v); err == nil {
							configStr[k] = string(bytes)
						}
					}
				}
				profile := &types.Profile{
					Name:   "docker",
					Config: configStr,
				}
				return profile, nil
			}
		}
	}

	return nil, fmt.Errorf("no valid Docker secrets found")
}

// LoadMasterPasswordFromSecret loads the master password from Docker secret
func LoadMasterPasswordFromSecret() (string, error) {
	passwordPath := filepath.Join(DockerSecretsPath, MasterPasswordSecretName)
	if passwordData, err := os.ReadFile(passwordPath); err == nil { // #nosec G304 - Docker secret path
		password := strings.TrimSpace(string(passwordData))
		if password != "" {
			return password, nil
		}
	}
	return "", fmt.Errorf("master password secret not found")
}

// IsRunningInDocker checks if the application is running inside a Docker container
func IsRunningInDocker() bool {
	// Check for Docker-specific files
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	// Check for Docker in /proc/1/cgroup
	if cgroup, err := os.ReadFile("/proc/1/cgroup"); err == nil { // #nosec G304 - well-known proc path
		if strings.Contains(string(cgroup), "docker") {
			return true
		}
	}

	// Check if secrets directory exists
	if _, err := os.Stat(DockerSecretsPath); err == nil {
		return true
	}

	return false
}

// GetDockerConfig returns Docker-specific configuration overrides
func GetDockerConfig() map[string]interface{} {
	config := make(map[string]interface{})

	// Set Docker-specific defaults
	config["server"] = map[string]interface{}{
		"host": "0.0.0.0", // Listen on all interfaces in container
		"port": 8080,
	}

	config["logging"] = map[string]interface{}{
		"output": "stdout", // Always log to stdout in Docker
		"format": "json",   // JSON format for log aggregators
	}

	// Disable interactive prompts in Docker
	config["batch_mode"] = true

	return config
}
