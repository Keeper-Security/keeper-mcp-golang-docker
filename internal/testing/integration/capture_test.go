package integration

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	ksm "github.com/keeper-security/secrets-manager-go/core"
	"github.com/keeper-security/ksm-mcp/internal/testing/capture"
)

var (
	captureData  = flag.Bool("capture", false, "Capture real KSM data for fixtures")
	oneTimeToken = flag.String("token", "", "One-time token for KSM")
	configFile   = flag.String("config", "", "Base64 config file path")
	outputDir    = flag.String("output", "fixtures", "Output directory for captured data")
)

func TestCaptureRealData(t *testing.T) {
	if !*captureData {
		t.Skip("Skipping data capture test. Use -capture flag to enable")
	}

	// Use provided values or defaults for testing
	token := *oneTimeToken
	if token == "" {
		token = os.Getenv("KSM_ONE_TIME_TOKEN")
		if token == "" {
			token = "US:3J8QgphqMQjeEr_BHvELdfvbRwPNbqr9FgzSo6SqGaU" // Your provided token
		}
	}

	configPath := *configFile
	if configPath == "" {
		configPath = os.Getenv("KSM_CONFIG_FILE")
		if configPath == "" {
			configPath = "/Users/mustinov/Downloads/config.base64" // Your provided path
		}
	}

	// Read config file
	configData, err := ioutil.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read config file: %v", err)
	}

	// Initialize KSM client
	options := &ksm.ClientOptions{
		Token:  token,
		Config: ksm.NewMemoryKeyValueStorage(string(configData)),
	}

	client := ksm.NewSecretsManager(options)

	// Create data capture
	captureDir := filepath.Join(*outputDir, "ksm-capture")
	dc := capture.NewDataCapture(captureDir)

	// Capture vault data
	if err := dc.CaptureVault(client); err != nil {
		t.Fatalf("Failed to capture vault data: %v", err)
	}

	// Verify captured data
	fixtureFile := filepath.Join(captureDir, "vault_fixtures.json")
	if _, err := os.Stat(fixtureFile); os.IsNotExist(err) {
		t.Fatalf("Fixture file was not created")
	}

	// Load and verify fixtures
	captured, err := capture.LoadFixtures(fixtureFile)
	if err != nil {
		t.Fatalf("Failed to load fixtures: %v", err)
	}

	t.Logf("Successfully captured %d records", len(captured.Records))
	t.Logf("Folders: %d", len(captured.Folders))
	t.Logf("Files: %d", len(captured.Files))
	t.Logf("API calls: %d", len(captured.Calls))
}

// TestGenerateMockData generates mock data without real KSM connection
func TestGenerateMockData(t *testing.T) {
	// This test always runs and generates mock data
	outputDir := filepath.Join("fixtures", "mock-data")
	
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		t.Fatalf("Failed to create output directory: %v", err)
	}

	// Generate large test files (couple of megs as requested)
	largeConfigData := generateLargeConfigFile(2 * 1024 * 1024) // 2MB
	largeConfigPath := filepath.Join(outputDir, "large_config.json")
	if err := ioutil.WriteFile(largeConfigPath, largeConfigData, 0644); err != nil {
		t.Fatalf("Failed to write large config file: %v", err)
	}

	largeSQLDump := generateSQLDump(3 * 1024 * 1024) // 3MB
	sqlDumpPath := filepath.Join(outputDir, "database_dump.sql")
	if err := ioutil.WriteFile(sqlDumpPath, largeSQLDump, 0644); err != nil {
		t.Fatalf("Failed to write SQL dump file: %v", err)
	}

	// Generate binary test file
	binaryData := generateBinaryFile(1 * 1024 * 1024) // 1MB
	binaryPath := filepath.Join(outputDir, "test_binary.dat")
	if err := ioutil.WriteFile(binaryPath, binaryData, 0644); err != nil {
		t.Fatalf("Failed to write binary file: %v", err)
	}

	t.Logf("Generated mock test files:")
	t.Logf("- Large config: %s (%.2f MB)", largeConfigPath, float64(len(largeConfigData))/1024/1024)
	t.Logf("- SQL dump: %s (%.2f MB)", sqlDumpPath, float64(len(largeSQLDump))/1024/1024)
	t.Logf("- Binary file: %s (%.2f MB)", binaryPath, float64(len(binaryData))/1024/1024)
}

func generateLargeConfigFile(size int) []byte {
	config := `{
  "application": {
    "name": "TestApplication",
    "version": "1.0.0",
    "environment": "production",
    "debug": false,
    "features": {`

	// Add many feature flags
	for i := 0; i < 1000; i++ {
		if i > 0 {
			config += ","
		}
		config += fmt.Sprintf(`
      "feature_%d": {
        "enabled": %v,
        "description": "Test feature number %d for testing large configuration files",
        "metadata": {
          "created": "2024-01-01T00:00:00Z",
          "author": "test_user_%d",
          "tags": ["test", "feature", "config"]
        }
      }`, i, i%2 == 0, i, i%10)
	}

	config += `
    },
    "servers": [`

	// Add server configurations
	for i := 0; i < 50; i++ {
		if i > 0 {
			config += ","
		}
		config += fmt.Sprintf(`
      {
        "id": "server_%d",
        "host": "server%d.example.com",
        "port": %d,
        "protocol": "https",
        "region": "us-east-%d",
        "capacity": %d,
        "metrics": {
          "cpu_usage": %.2f,
          "memory_usage": %.2f,
          "disk_usage": %.2f,
          "network_in": %d,
          "network_out": %d
        }
      }`, i, i, 8000+i, (i%4)+1, (i+1)*100, 
			float64(i%100)/100, float64((i+20)%100)/100, float64((i+40)%100)/100,
			i*1024*1024, i*512*1024)
	}

	config += `
    ]
  }
}`

	// Pad to reach target size
	result := []byte(config)
	for len(result) < size {
		result = append(result, []byte("\n// Padding to reach target file size\n")...)
		result = append(result, []byte(fmt.Sprintf("// Line %d: Lorem ipsum dolor sit amet, consectetur adipiscing elit...\n", len(result)))...)
	}

	return result[:size]
}

func generateSQLDump(size int) []byte {
	dump := `-- Test Database Dump
-- Generated for KSM MCP Testing
-- Version: 1.0.0
-- Date: 2024-01-23

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";

CREATE DATABASE IF NOT EXISTS test_database;
USE test_database;

-- Table structure for users
CREATE TABLE IF NOT EXISTS users (
  id INT(11) NOT NULL AUTO_INCREMENT,
  username VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY username (username),
  UNIQUE KEY email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Dumping data for table users
INSERT INTO users (username, email, password_hash) VALUES
`

	// Generate user records
	for i := 0; i < 10000; i++ {
		if i > 0 {
			dump += ",\n"
		}
		hashBytes := []byte(fmt.Sprintf("hash_%d_padding_to_make_it_longer_for_base64_encoding", i))
		encodedHash := base64.StdEncoding.EncodeToString(hashBytes)
		if len(encodedHash) > 60 {
			encodedHash = encodedHash[:60]
		}
		dump += fmt.Sprintf("('user_%d', 'user%d@example.com', '$2y$10$%s')",
			i, i, encodedHash)
	}
	dump += ";\n\n"

	// Add more tables
	dump += `
-- Table structure for logs
CREATE TABLE IF NOT EXISTS application_logs (
  id BIGINT NOT NULL AUTO_INCREMENT,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  level VARCHAR(10) NOT NULL,
  message TEXT,
  metadata JSON,
  PRIMARY KEY (id),
  KEY idx_timestamp (timestamp),
  KEY idx_level (level)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Dumping data for table application_logs
INSERT INTO application_logs (level, message, metadata) VALUES
`

	// Generate log records
	for i := 0; i < 5000; i++ {
		if i > 0 {
			dump += ",\n"
		}
		level := []string{"DEBUG", "INFO", "WARN", "ERROR"}[i%4]
		dump += fmt.Sprintf("('%s', 'Log message %d: %s', '{\"request_id\": \"%d\", \"user_id\": %d}')",
			level, i, generateRandomMessage(i), i*1000, i%1000)
	}
	dump += ";\n\nCOMMIT;\n"

	// Pad to reach target size
	result := []byte(dump)
	for len(result) < size {
		result = append(result, []byte("\n-- Additional padding data\n")...)
		result = append(result, []byte(fmt.Sprintf("-- Padding line %d\n", len(result)))...)
	}

	return result[:size]
}

func generateBinaryFile(size int) []byte {
	// Generate pseudo-random binary data
	data := make([]byte, size)
	
	// Add some structure to make it interesting
	// File header
	copy(data[0:8], []byte("TESTBIN\x00"))
	
	// Version
	data[8] = 1
	data[9] = 0
	data[10] = 0
	data[11] = 0
	
	// Fill with pattern
	for i := 12; i < size; i++ {
		data[i] = byte((i * 7) % 256)
	}
	
	return data
}

func generateRandomMessage(seed int) string {
	messages := []string{
		"Processing request",
		"Database query executed",
		"Cache miss for key",
		"User authenticated successfully",
		"File uploaded",
		"Background job completed",
		"API rate limit checked",
		"Session validated",
		"Configuration reloaded",
		"Health check passed",
	}
	return messages[seed%len(messages)]
}