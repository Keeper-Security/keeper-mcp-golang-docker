package commands

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/keeper-security/ksm-mcp/internal/config"
	"github.com/keeper-security/ksm-mcp/internal/ksm"
	"github.com/keeper-security/ksm-mcp/internal/storage"
	"github.com/spf13/cobra"
)

var (
	testDetails bool
	runTests    bool
	testMode    string
	captureData bool
	testFilter  string
	testTimeout string
)

// testCmd represents the test command
var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Test KSM connection or run test suites",
	Long: `Test the connection to Keeper Secrets Manager or run the test suites.

Connection Test Mode (default):
This command verifies that:
- The profile configuration is valid
- Authentication with KSM succeeds
- API access is working correctly

Test Suite Mode (--run-tests):
Run various test suites for KSM MCP:
- unit: Unit tests only
- integration: Integration tests (may require KSM connection)
- e2e: End-to-end MCP tool tests
- all: All test suites (default)

Examples:
  # Test KSM connection
  ksm-mcp test

  # Test specific profile
  ksm-mcp test --profile production

  # Run all test suites
  ksm-mcp test --run-tests

  # Run only E2E tests
  ksm-mcp test --run-tests --mode e2e

  # Capture real KSM data for offline testing
  ksm-mcp test --run-tests --mode integration --capture`,
	RunE: runTestCommand,
}

func init() {
	rootCmd.AddCommand(testCmd)
	testCmd.Flags().BoolVar(&testDetails, "details", false, "show detailed test results")
	testCmd.Flags().BoolVar(&runTests, "run-tests", false, "run test suites instead of connection test")
	testCmd.Flags().StringVar(&testMode, "mode", "all", "test mode: unit, integration, e2e, or all")
	testCmd.Flags().BoolVar(&captureData, "capture", false, "capture real KSM data (requires token)")
	testCmd.Flags().StringVar(&testFilter, "filter", "", "filter tests by name")
	testCmd.Flags().StringVar(&testTimeout, "timeout", "10m", "test timeout")
}

func runTest(cmd *cobra.Command, args []string) error {
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

	// Determine which profile to use
	profileName := profile // from global flag
	if profileName == "" {
		profileName = cfg.Profiles.Default
		if profileName == "" {
			return fmt.Errorf("no profile specified and no default profile configured")
		}
	}

	fmt.Printf("Testing profile: %s\n\n", profileName)

	// Create storage
	var store *storage.ProfileStore
	if cfg.Security.ProtectionPasswordHash != "" {
		fmt.Fprint(os.Stderr, "Enter protection password: ")
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
	fmt.Print("1. Loading profile... ")
	prof, err := store.GetProfile(profileName)
	if err != nil {
		fmt.Println("✗")
		return fmt.Errorf("failed to load profile: %w", err)
	}
	fmt.Println("✓")

	// Create KSM client
	fmt.Print("2. Creating KSM client... ")
	client, err := ksm.NewClient(prof, nil)
	if err != nil {
		fmt.Println("✗")
		return fmt.Errorf("failed to create client: %w", err)
	}
	fmt.Println("✓")

	// Test listing secrets
	fmt.Fprint(os.Stderr, "Testing secret listing... ")
	secrets, err := client.ListSecrets([]string{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "✗")
		return fmt.Errorf("failed to list secrets: %w", err)
	}
	fmt.Fprintf(os.Stderr, "✓ (found %d secrets)\n", len(secrets))

	// Show results
	fmt.Printf("\n✓ Connection successful!\n")
	fmt.Printf("  Found %d secrets\n", len(secrets))

	if testDetails && len(secrets) > 0 {
		fmt.Println("\nSecret Types:")
		typeCounts := make(map[string]int)
		for _, s := range secrets {
			typeCounts[s.Type]++
		}

		for typ, count := range typeCounts {
			fmt.Printf("  - %s: %d\n", typ, count)
		}

		// Test retrieving a specific secret (without unmasking)
		fmt.Print("\n4. Testing secret retrieval... ")
		testSecret := secrets[0]
		secret, err := client.GetSecret(testSecret.UID, []string{}, false)
		if err != nil {
			fmt.Println("✗")
			fmt.Printf("   Failed to retrieve secret: %v\n", err)
		} else {
			fmt.Println("✓")
			if title, ok := secret["title"].(string); ok {
				secretType := "unknown"
				if t, ok := secret["type"].(string); ok {
					secretType = t
				}
				fmt.Printf("   Retrieved: %s (type: %s)\n", title, secretType)
			}

			// Show available fields
			if fields, ok := secret["fields"].(map[string]interface{}); ok && len(fields) > 0 {
				fmt.Println("   Available fields:")
				for fieldName, fieldValue := range fields {
					// Show field names but mask values
					value := fmt.Sprintf("%v", fieldValue)
					if isSensitiveField(fieldName) && len(value) > 0 {
						value = maskSensitive(value)
					}
					fmt.Printf("     - %s: %s\n", fieldName, value)
				}
			}
		}

		// Test searching
		fmt.Print("\n5. Testing search functionality... ")
		searchStart := time.Now()
		searchResults, err := client.SearchSecrets("")
		searchElapsed := time.Since(searchStart)

		if err != nil {
			fmt.Println("✗")
			fmt.Printf("   Search failed: %v\n", err)
		} else {
			fmt.Printf("✓ (%.2fs)\n", searchElapsed.Seconds())
			fmt.Printf("   Search returned %d results\n", len(searchResults))
		}
	}

	// Show configuration details
	if verbose {
		fmt.Println("\nConfiguration Details:")
		fmt.Printf("  Config Directory: %s\n", configDir)
		fmt.Printf("  Profile: %s\n", profileName)
		if prof.Config != nil {
			if clientId, ok := prof.Config["clientId"]; ok {
				fmt.Printf("  Client ID: %s\n", clientId)
			}
			if hostname, ok := prof.Config["hostname"]; ok && hostname != "" {
				fmt.Printf("  Hostname: %s\n", hostname)
			}
		}
	}

	return nil
}

func isSensitiveField(fieldType string) bool {
	sensitive := []string{
		"password", "secret", "api_key", "apiKey", "token",
		"private_key", "privateKey", "passphrase", "pin",
		"cardNumber", "securityCode", "cvv",
	}

	fieldLower := strings.ToLower(fieldType)
	for _, s := range sensitive {
		if strings.Contains(fieldLower, strings.ToLower(s)) {
			return true
		}
	}
	return false
}

func runTestCommand(cmd *cobra.Command, args []string) error {
	if runTests {
		return runTestSuites(cmd, args)
	}
	return runTest(cmd, args)
}

func runTestSuites(cmd *cobra.Command, args []string) error {
	fmt.Printf("Running KSM MCP test suites (mode: %s)\n", testMode)

	// Determine which test packages to run
	var testPackages []string
	switch testMode {
	case "unit":
		testPackages = []string{
			"./internal/validation/...",
			"./internal/crypto/...",
			"./internal/storage/...",
			"./internal/audit/...",
		}
	case "integration":
		testPackages = []string{
			"./internal/testing/integration/...",
		}
	case "e2e":
		testPackages = []string{
			"./internal/testing/e2e/...",
		}
	case "all":
		testPackages = []string{"./..."}
	default:
		return fmt.Errorf("invalid test mode: %s", testMode)
	}

	// Build test command
	testArgs := []string{"test"}

	// Add coverage if not capturing data
	if !captureData {
		testArgs = append(testArgs, "-cover")
	}

	// Add timeout
	testArgs = append(testArgs, "-timeout", testTimeout)

	// Add verbose flag
	if verbose {
		testArgs = append(testArgs, "-v")
	}

	// Add test filter
	if testFilter != "" {
		testArgs = append(testArgs, "-run", testFilter)
	}

	// Add capture flag for integration tests
	if captureData && testMode == "integration" {
		testArgs = append(testArgs, "-capture")

		// Set environment variables
		if token := os.Getenv("KSM_ONE_TIME_TOKEN"); token == "" {
			fmt.Println("Warning: KSM_ONE_TIME_TOKEN not set. Using provided test token.")
			_ = os.Setenv("KSM_ONE_TIME_TOKEN", "US:3J8QgphqMQjeEr_BHvELdfvbRwPNbqr9FgzSo6SqGaU")
		}

		if configFile := os.Getenv("KSM_CONFIG_FILE"); configFile == "" {
			fmt.Println("Warning: KSM_CONFIG_FILE not set. Using provided path.")
			_ = os.Setenv("KSM_CONFIG_FILE", "/Users/mustinov/Downloads/config.base64")
		}
	}

	// Add packages
	testArgs = append(testArgs, testPackages...)

	// Run tests
	fmt.Printf("Executing: go %s\n\n", strings.Join(testArgs, " "))

	testExec := exec.Command("go", testArgs...)
	testExec.Stdout = os.Stdout
	testExec.Stderr = os.Stderr
	testExec.Env = os.Environ()

	if err := testExec.Run(); err != nil {
		return fmt.Errorf("tests failed: %w", err)
	}

	fmt.Println("\nAll tests passed!")

	// Show coverage report location
	if !captureData {
		fmt.Println("\nCoverage report generated. View with:")
		fmt.Println("  go tool cover -html=coverage.out")
	}

	// Show captured data location
	if captureData {
		fixtureDir := filepath.Join("fixtures", "ksm-capture")
		if _, err := os.Stat(fixtureDir); err == nil {
			fmt.Printf("\nCaptured data saved to: %s\n", fixtureDir)
			fmt.Println("Files:")
			_ = filepath.Walk(fixtureDir, func(path string, info os.FileInfo, err error) error {
				if err == nil && !info.IsDir() {
					fmt.Printf("  - %s (%d bytes)\n", path, info.Size())
				}
				return nil
			})
		}
	}

	return nil
}
