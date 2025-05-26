package ui

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/keeper-security/ksm-mcp/pkg/types"
)

// ConfirmationResult represents the result of a confirmation prompt
type ConfirmationResult struct {
	Approved bool
	TimedOut bool
	Error    error
}

// Confirmer handles user confirmation prompts
type Confirmer struct {
	config types.Confirmation
}

// NewConfirmer creates a new confirmer with the given configuration
func NewConfirmer(config types.Confirmation) *Confirmer {
	return &Confirmer{
		config: config,
	}
}

// Confirm prompts the user for confirmation with the given message
func (c *Confirmer) Confirm(ctx context.Context, message string) *ConfirmationResult {
	// Check if context is already cancelled
	select {
	case <-ctx.Done():
		return &ConfirmationResult{
			Approved: !c.config.DefaultDeny,
			TimedOut: true,
			Error:    nil,
		}
	default:
	}

	// In batch mode or with auto-approve, skip confirmation
	if c.config.BatchMode || c.config.AutoApprove {
		return &ConfirmationResult{
			Approved: !c.config.DefaultDeny, // Respect default deny even in batch mode
			TimedOut: false,
			Error:    nil,
		}
	}

	// For non-batch/auto-approve modes, direct terminal confirmation is no longer supported
	// for tool calls that should go through the MCP Prompt confirmation flow.
	return &ConfirmationResult{
		Approved: false,
		TimedOut: false,
		Error:    fmt.Errorf("interactive confirmation via terminal is not supported for this operation; use MCP prompts or batch/auto-approve modes"),
	}
}

// ConfirmOperation prompts for confirmation of a specific operation
func (c *Confirmer) ConfirmOperation(ctx context.Context, operation, resource string, details map[string]interface{}) *ConfirmationResult {
	message := c.buildOperationMessage(operation, resource, details)
	return c.Confirm(ctx, message)
}

// ConfirmSensitiveOperation prompts for confirmation of operations involving sensitive data
func (c *Confirmer) ConfirmSensitiveOperation(ctx context.Context, operation, resource string, masked bool) *ConfirmationResult {
	var message string
	if masked {
		message = fmt.Sprintf("🔐 Confirm: %s '%s' (data will be masked from AI)? [Y/n]", operation, resource)
	} else {
		message = fmt.Sprintf(`⚠️  SECURITY WARNING: %s '%s'
   
   The UNMASKED PASSWORD WILL BE VISIBLE TO THE AI MODEL.
   This defeats the security purpose of KSM MCP.
   
   Continue only if absolutely necessary (e.g., test/QA passwords).
   
   Reveal password to AI? [y/N]`, operation, resource)
	}

	// For unmasked sensitive operations, default to deny
	config := c.config
	if !masked {
		config.DefaultDeny = true
	}

	confirmer := NewConfirmer(config)
	return confirmer.Confirm(ctx, message)
}

// parseResponse parses the user's response to determine approval
func (c *Confirmer) parseResponse(response string) bool {
	response = strings.ToLower(strings.TrimSpace(response))

	// Empty response uses default
	if response == "" {
		return !c.config.DefaultDeny
	}

	// Explicit responses
	switch response {
	case "y", "yes", "true", "1":
		return true
	case "n", "no", "false", "0":
		return false
	default:
		// Invalid response uses default
		fmt.Fprintf(os.Stderr, "Invalid response '%s', using default\n", response)
		return !c.config.DefaultDeny
	}
}

// buildOperationMessage builds a formatted message for operation confirmation
func (c *Confirmer) buildOperationMessage(operation, resource string, details map[string]interface{}) string {
	message := fmt.Sprintf("Confirm: %s '%s'", operation, resource)

	if len(details) > 0 {
		message += " with:"
		for key, value := range details {
			// Mask sensitive details
			if c.isSensitiveKey(key) {
				message += fmt.Sprintf("\n  %s: [MASKED]", key)
			} else {
				message += fmt.Sprintf("\n  %s: %v", key, value)
			}
		}
	}

	message += "?"
	return message
}

// isSensitiveKey checks if a key contains sensitive information
func (c *Confirmer) isSensitiveKey(key string) bool {
	sensitiveKeys := []string{
		"password", "secret", "key", "token", "auth", "credential",
		"private", "passphrase", "pin", "code", "signature",
	}

	keyLower := strings.ToLower(key)
	for _, sensitive := range sensitiveKeys {
		if strings.Contains(keyLower, sensitive) {
			return true
		}
	}
	return false
}

// DisplayWarning displays a warning message to the user
func (c *Confirmer) DisplayWarning(message string) {
	fmt.Fprintf(os.Stderr, "⚠️  WARNING: %s\n", message)
}

// DisplayInfo displays an informational message to the user
func (c *Confirmer) DisplayInfo(message string) {
	fmt.Fprintf(os.Stderr, "ℹ️  INFO: %s\n", message)
}

// DisplayError displays an error message to the user
func (c *Confirmer) DisplayError(message string) {
	fmt.Fprintf(os.Stderr, "❌ ERROR: %s\n", message)
}

// DisplaySuccess displays a success message to the user
func (c *Confirmer) DisplaySuccess(message string) {
	fmt.Fprintf(os.Stderr, "✅ SUCCESS: %s\n", message)
}

// ConfirmBatchOperation handles batch operation confirmations
func (c *Confirmer) ConfirmBatchOperation(ctx context.Context, operation string, items []string) *ConfirmationResult {
	if len(items) == 0 {
		return &ConfirmationResult{
			Approved: false,
			TimedOut: false,
			Error:    fmt.Errorf("no items to process"),
		}
	}

	// In batch mode, auto-approve
	if c.config.BatchMode || c.config.AutoApprove {
		return &ConfirmationResult{
			Approved: !c.config.DefaultDeny,
			TimedOut: false,
			Error:    nil,
		}
	}

	// Build batch message
	message := fmt.Sprintf("Confirm batch %s for %d items:", operation, len(items))

	// Show first few items
	showCount := 5
	for i, item := range items {
		if i >= showCount {
			message += fmt.Sprintf("\n  ... and %d more", len(items)-showCount)
			break
		}
		message += fmt.Sprintf("\n  - %s", item)
	}

	message += "\nProceed?"

	return c.Confirm(ctx, message)
}

// SetConfig updates the confirmer configuration
func (c *Confirmer) SetConfig(config types.Confirmation) {
	c.config = config
}

// GetConfig returns the current confirmer configuration
func (c *Confirmer) GetConfig() types.Confirmation {
	return c.config
}

// IsInteractive returns true if the confirmer is in interactive mode
func (c *Confirmer) IsInteractive() bool {
	return !c.config.BatchMode && !c.config.AutoApprove
}

// ShowProgress displays a progress indicator for long operations
func (c *Confirmer) ShowProgress(current, total int, message string) {
	if c.config.BatchMode {
		return // Don't show progress in batch mode
	}

	percent := float64(current) / float64(total) * 100
	fmt.Fprintf(os.Stderr, "\r[%3.0f%%] %s (%d/%d)", percent, message, current, total)

	if current == total {
		fmt.Fprintln(os.Stderr) // New line when complete
	}
}
