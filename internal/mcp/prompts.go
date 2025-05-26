package mcp

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/keeper-security/ksm-mcp/pkg/types"
)

// getAvailablePrompts returns the list of available MCP prompts for KSM
func (s *Server) getAvailablePrompts() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"name":        "ksm_confirm_action",
			"description": "Presents a sensitive KSM action to the user for confirmation before execution.",
			"arguments": []map[string]interface{}{
				{
					"name":        "action_description",
					"description": "A human-readable description of the action requiring confirmation (e.g., \"Create new secret 'My Test Secret'\").",
					"required":    true,
				},
				{
					"name":        "warning_message",
					"description": "An optional warning message to display to the user (e.g., \"This will expose the password to the AI.\").",
					"required":    false,
				},
				{
					"name":        "details_json",
					"description": "Optional JSON string of key-value pairs providing additional context or details about the action.",
					"required":    false,
				},
				{
					"name":        "original_tool_name",
					"description": "The name of the original tool that requires confirmation (e.g., 'create_secret'). This will be passed to ksm_execute_confirmed_action.",
					"required":    true,
				},
				{
					"name":        "original_tool_args_json",
					"description": "The JSON string of arguments originally passed to the tool. This will be passed to ksm_execute_confirmed_action.",
					"required":    true,
				},
			},
		},
	}
}

// handleGetPrompt handles the prompts/get request
// This function will be called by the MCP server when a client requests a specific prompt.
func (s *Server) handleGetPrompt(request types.MCPRequest) (map[string]interface{}, error) {
	var params struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments,omitempty"`
	}

	if request.Params != nil {
		paramsBytes, err := json.Marshal(request.Params)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal prompt/get params: %w", err)
		}
		if err := json.Unmarshal(paramsBytes, &params); err != nil {
			return nil, fmt.Errorf("failed to parse prompt/get params: %w", err)
		}
	} else {
		return nil, fmt.Errorf("missing params for prompts/get")
	}

	if params.Name != "ksm_confirm_action" {
		return nil, fmt.Errorf("unknown prompt requested: %s", params.Name)
	}

	if params.Arguments == nil {
		return nil, fmt.Errorf("missing arguments for ksm_confirm_action prompt")
	}

	actionDesc, ok := params.Arguments["action_description"].(string)
	if !ok || actionDesc == "" {
		return nil, fmt.Errorf("missing or invalid 'action_description' in prompt arguments")
	}

	warningMsg, _ := params.Arguments["warning_message"].(string) // Optional
	// originalToolName, _ := params.Arguments["original_tool_name"].(string) // Not used in message to user
	// originalToolArgsJSON, _ := params.Arguments["original_tool_args_json"].(string) // Not used in message to user
	// detailsJSON, _ := params.Arguments["details_json"].(string) // Not used for now

	var responseTextBuilder strings.Builder
	responseTextBuilder.WriteString(fmt.Sprintf("**KSM Action Confirmation Required**\n\nACTION: %s.", actionDesc))

	if warningMsg != "" {
		responseTextBuilder.WriteString(fmt.Sprintf("\n\n**WARNING:** %s", warningMsg))
	}

	responseTextBuilder.WriteString("\n\nPlease explicitly state if you 'approve' or 'deny' this action.")
	responseTextBuilder.WriteString("\n(The AI will then call 'ksm_execute_confirmed_action' with your decision.)")

	messages := []map[string]interface{}{
		{
			// Role "user" might imply the AI should present this as if the user needs to respond to the system.
			// Role "assistant" might be if the AI is relaying this and asking for user input on its behalf.
			// Let's use "assistant" to frame it as the system/assistant presenting the confirmation.
			"role": "assistant",
			"content": map[string]interface{}{
				"type": "text",
				"text": responseTextBuilder.String(),
			},
		},
	}

	return map[string]interface{}{"messages": messages}, nil
}
