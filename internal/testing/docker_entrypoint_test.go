package testing

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestDockerEntrypoint tests the docker-entrypoint.sh script behavior
func TestDockerEntrypoint(t *testing.T) {
	// Skip if not in integration mode
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping docker-entrypoint.sh tests (set INTEGRATION_TEST=true to run)")
	}

	// Find docker-entrypoint.sh
	scriptPath := filepath.Join("..", "..", "docker-entrypoint.sh")
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		t.Fatalf("docker-entrypoint.sh not found at %s", scriptPath)
	}

	// Create temp directory for tests
	tempDir := t.TempDir()

	// Create mock ksm-mcp executable
	mockKsmMcp := filepath.Join(tempDir, "ksm-mcp")
	mockScript := `#!/bin/sh
if [ "$1" = "init" ]; then
    echo "Mock init stdout"
    echo "Mock init stderr" >&2
    exit 0
fi
exec "$@"
`
	if err := os.WriteFile(mockKsmMcp, []byte(mockScript), 0755); err != nil {
		t.Fatalf("Failed to create mock ksm-mcp: %v", err)
	}

	// Copy docker-entrypoint.sh to temp directory
	entrypointPath := filepath.Join(tempDir, "docker-entrypoint.sh")
	input, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read docker-entrypoint.sh: %v", err)
	}
	if err := os.WriteFile(entrypointPath, input, 0755); err != nil {
		t.Fatalf("Failed to copy docker-entrypoint.sh: %v", err)
	}

	tests := []struct {
		name           string
		env            map[string]string
		args           []string
		wantStdout     string
		wantStderr     string
		stdoutContains []string
		stderrContains []string
		stdoutEmpty    bool
		stderrEmpty    bool
	}{
		{
			name: "batch_mode_auto_init_stderr_only",
			env: map[string]string{
				"KSM_CONFIG_BASE64":  "dGVzdA==",
				"KSM_MCP_BATCH_MODE": "true",
				"KSM_MCP_CONFIG_DIR": tempDir,
				"PATH":               tempDir + ":" + os.Getenv("PATH"),
			},
			args:           []string{"echo", "test"},
			stdoutContains: []string{"test"},
			stderrContains: []string{"Mock init"},
		},
		{
			name: "batch_mode_no_init_messages",
			env: map[string]string{
				"KSM_CONFIG_BASE64":  "dGVzdA==",
				"KSM_MCP_BATCH_MODE": "true",
				"KSM_MCP_CONFIG_DIR": tempDir,
				"PATH":               tempDir + ":" + os.Getenv("PATH"),
			},
			args: []string{"echo", "test"},
			// Should not contain initialization messages in stderr
		},
		{
			name: "normal_mode_init_messages_visible",
			env: map[string]string{
				"KSM_CONFIG_BASE64":  "dGVzdA==",
				"KSM_MCP_CONFIG_DIR": tempDir,
				"PATH":               tempDir + ":" + os.Getenv("PATH"),
			},
			args:           []string{"echo", "test"},
			stderrContains: []string{"Auto-initializing KSM MCP", "Initialization complete"},
		},
		{
			name: "no_init_when_profile_exists",
			env: map[string]string{
				"KSM_CONFIG_BASE64":  "dGVzdA==",
				"KSM_MCP_CONFIG_DIR": tempDir,
				"PATH":               tempDir + ":" + os.Getenv("PATH"),
			},
			args:           []string{"echo", "test"},
			stdoutContains: []string{"test"},
			// Create profiles.db before this test runs
		},
		{
			name: "no_init_without_config",
			env: map[string]string{
				"KSM_MCP_CONFIG_DIR": tempDir,
				"PATH":               tempDir + ":" + os.Getenv("PATH"),
			},
			args:           []string{"echo", "test"},
			stdoutContains: []string{"test"},
		},
		{
			name: "custom_profile_name",
			env: map[string]string{
				"KSM_CONFIG_BASE64":  "dGVzdA==",
				"KSM_MCP_PROFILE":    "custom",
				"KSM_MCP_CONFIG_DIR": tempDir,
				"PATH":               tempDir + ":" + os.Getenv("PATH"),
			},
			args: []string{"echo", "test"},
			// Should use custom profile name
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up any existing profiles.db
			os.Remove(filepath.Join(tempDir, "profiles.db"))

			// Special case: create profiles.db for "no_init_when_profile_exists" test
			if tt.name == "no_init_when_profile_exists" {
				if err := os.WriteFile(filepath.Join(tempDir, "profiles.db"), []byte("dummy"), 0644); err != nil {
					t.Fatalf("Failed to create profiles.db: %v", err)
				}
			}

			// Prepare command
			cmd := exec.Command(entrypointPath, tt.args...)
			
			// Set environment
			for k, v := range tt.env {
				cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
			}

			// Capture output
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			// Run command
			err := cmd.Run()
			if err != nil && !strings.Contains(err.Error(), "exit status") {
				t.Fatalf("Command failed: %v", err)
			}

			// Check stdout
			stdoutStr := stdout.String()
			if tt.stdoutEmpty && stdoutStr != "" {
				t.Errorf("Expected empty stdout, got: %s", stdoutStr)
			}
			for _, contains := range tt.stdoutContains {
				if !strings.Contains(stdoutStr, contains) {
					t.Errorf("Stdout does not contain %q, got: %s", contains, stdoutStr)
				}
			}

			// Check stderr
			stderrStr := stderr.String()
			if tt.stderrEmpty && stderrStr != "" {
				t.Errorf("Expected empty stderr, got: %s", stderrStr)
			}
			for _, contains := range tt.stderrContains {
				if !strings.Contains(stderrStr, contains) {
					t.Errorf("Stderr does not contain %q, got: %s", contains, stderrStr)
				}
			}

			// Special checks for batch mode
			if tt.env["KSM_MCP_BATCH_MODE"] == "true" {
				// In batch mode, initialization messages should not appear in stderr
				if strings.Contains(stderrStr, "Auto-initializing KSM MCP") {
					t.Errorf("Batch mode should not show initialization message in stderr")
				}
				if strings.Contains(stderrStr, "Initialization complete") {
					t.Errorf("Batch mode should not show completion message in stderr")
				}
			}
		})
	}
}

// TestDockerEntrypointBatchModeOutput specifically tests that auto-init output
// goes to stderr when KSM_MCP_BATCH_MODE=true
func TestDockerEntrypointBatchModeOutput(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping docker-entrypoint.sh tests (set INTEGRATION_TEST=true to run)")
	}

	// Create temp directory
	tempDir := t.TempDir()

	// Create a more detailed mock that shows where output goes
	mockKsmMcp := filepath.Join(tempDir, "ksm-mcp")
	mockScript := `#!/bin/sh
if [ "$1" = "init" ]; then
    echo "STDOUT: init called with args: $@"
    echo "STDERR: init called with args: $@" >&2
    exit 0
fi
exec "$@"
`
	if err := os.WriteFile(mockKsmMcp, []byte(mockScript), 0755); err != nil {
		t.Fatalf("Failed to create mock ksm-mcp: %v", err)
	}

	// Copy docker-entrypoint.sh
	scriptPath := filepath.Join("..", "..", "docker-entrypoint.sh")
	entrypointPath := filepath.Join(tempDir, "docker-entrypoint.sh")
	input, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read docker-entrypoint.sh: %v", err)
	}
	if err := os.WriteFile(entrypointPath, input, 0755); err != nil {
		t.Fatalf("Failed to copy docker-entrypoint.sh: %v", err)
	}

	// Test batch mode
	cmd := exec.Command(entrypointPath, "echo", "FINAL_COMMAND")
	cmd.Env = []string{
		"KSM_CONFIG_BASE64=dGVzdA==",
		"KSM_MCP_BATCH_MODE=true",
		"KSM_MCP_CONFIG_DIR=" + tempDir,
		"PATH=" + tempDir + ":" + os.Getenv("PATH"),
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("Command failed: %v", err)
	}

	stdoutStr := stdout.String()
	stderrStr := stderr.String()

	// In batch mode:
	// 1. The final command output should go to stdout
	if !strings.Contains(stdoutStr, "FINAL_COMMAND") {
		t.Errorf("Expected 'FINAL_COMMAND' in stdout, got: %s", stdoutStr)
	}

	// 2. The init command's stdout should be redirected to stderr
	if strings.Contains(stdoutStr, "STDOUT: init") {
		t.Errorf("Init stdout should not appear in stdout in batch mode")
	}

	// 3. Both init outputs should be in stderr
	if !strings.Contains(stderrStr, "STDOUT: init") {
		t.Errorf("Init stdout should be redirected to stderr in batch mode")
	}
	if !strings.Contains(stderrStr, "STDERR: init") {
		t.Errorf("Init stderr should remain in stderr in batch mode")
	}
}