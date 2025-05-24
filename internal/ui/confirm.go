package ui

import (
	"bufio"
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
	// In batch mode or with auto-approve, skip confirmation
	if c.config.BatchMode || c.config.AutoApprove {
		return &ConfirmationResult{
			Approved: !c.config.DefaultDeny, // Respect default deny even in batch mode
			TimedOut: false,
			Error:    nil,
		}
	}

	// Interactive confirmation
	return c.promptUser(ctx, message)
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

// promptUser handles the interactive confirmation prompt
func (c *Confirmer) promptUser(ctx context.Context, message string) *ConfirmationResult {
	// Create a context with timeout if specified
	var promptCtx context.Context
	var cancel context.CancelFunc
	
	if c.config.Timeout > 0 {
		promptCtx, cancel = context.WithTimeout(ctx, c.config.Timeout)
	} else {
		promptCtx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	// Channel to receive user input
	responseChan := make(chan string, 1)
	errorChan := make(chan error, 1)

	// Start goroutine to read user input
	go func() {
		defer close(responseChan)
		defer close(errorChan)

		// Display the prompt
		timeoutMsg := ""
		if c.config.Timeout > 0 {
			timeoutMsg = fmt.Sprintf(" (%v)", c.config.Timeout)
		}
		
		defaultHint := "[Y/n]"
		if c.config.DefaultDeny {
			defaultHint = "[y/N]"
		}
		
		fmt.Printf("%s %s%s ", message, defaultHint, timeoutMsg)

		// Read user input
		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			errorChan <- fmt.Errorf("failed to read user input: %w", err)
			return
		}

		responseChan <- strings.TrimSpace(response)
	}()

	// Wait for user input or timeout
	select {
	case <-promptCtx.Done():
		// Timeout or cancellation
		fmt.Println("\nTimeout - using default response")
		return &ConfirmationResult{
			Approved: !c.config.DefaultDeny,
			TimedOut: true,
			Error:    nil,
		}

	case err := <-errorChan:
		return &ConfirmationResult{
			Approved: false,
			TimedOut: false,
			Error:    err,
		}

	case response := <-responseChan:
		approved := c.parseResponse(response)
		return &ConfirmationResult{
			Approved: approved,
			TimedOut: false,
			Error:    nil,
		}
	}
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
		fmt.Printf("Invalid response '%s', using default\n", response)
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
	fmt.Printf("⚠️  WARNING: %s\n", message)
}

// DisplayInfo displays an informational message to the user
func (c *Confirmer) DisplayInfo(message string) {
	fmt.Printf("ℹ️  INFO: %s\n", message)
}

// DisplayError displays an error message to the user
func (c *Confirmer) DisplayError(message string) {
	fmt.Printf("❌ ERROR: %s\n", message)
}

// DisplaySuccess displays a success message to the user
func (c *Confirmer) DisplaySuccess(message string) {
	fmt.Printf("✅ SUCCESS: %s\n", message)
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
	fmt.Printf("\r[%3.0f%%] %s (%d/%d)", percent, message, current, total)
	
	if current == total {
		fmt.Println() // New line when complete
	}
}