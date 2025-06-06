package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"

	"github.com/keeper-security/ksm-mcp/internal/audit"
	"github.com/keeper-security/ksm-mcp/pkg/types"
)

// handleInitialize handles the initialize request
func (s *Server) handleInitialize(request types.MCPRequest, writer *bufio.Writer) error {
	// Debug log the request
	// fmt.Fprintf(os.Stderr, "DEBUG: Initialize request ID: %v (type: %T)\n", request.ID, request.ID)
	// Parse initialize params
	var params struct {
		ProtocolVersion string `json:"protocolVersion"`
		Capabilities    struct {
			Tools struct {
				Call bool `json:"call"`
			} `json:"tools"`
		} `json:"capabilities"`
		ClientInfo struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"clientInfo"`
	}

	if request.Params != nil {
		// Handle params as either json.RawMessage or map[string]interface{}
		switch p := request.Params.(type) {
		case json.RawMessage:
			if err := json.Unmarshal(p, &params); err != nil {
				return fmt.Errorf("failed to parse initialize params: %w", err)
			}
		case map[string]interface{}:
			// Convert map to JSON then unmarshal
			jsonBytes, err := json.Marshal(p)
			if err != nil {
				return fmt.Errorf("failed to marshal params: %w", err)
			}
			if err := json.Unmarshal(jsonBytes, &params); err != nil {
				return fmt.Errorf("failed to parse initialize params: %w", err)
			}
		default:
			return fmt.Errorf("unexpected params type: %T", request.Params)
		}
	}

	// Log client info
	s.logSystem(audit.EventAccess, "Client connected", map[string]interface{}{
		"client_name":    params.ClientInfo.Name,
		"client_version": params.ClientInfo.Version,
		"protocol":       params.ProtocolVersion,
	})

	// Send initialize response
	return s.sendInitializeResponse(writer, request.ID)
}

// sendInitializeResponse sends the server capabilities
func (s *Server) sendInitializeResponse(writer *bufio.Writer, requestID interface{}) error {
	response := map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities": map[string]interface{}{
			"tools": map[string]interface{}{
				"list": true,
				"call": true,
			},
			"sessions": map[string]interface{}{
				"list":   true,
				"create": true,
				"end":    true,
			},
		},
		"serverInfo": map[string]interface{}{
			"name":    "ksm-mcp",
			"version": "1.0.0",
		},
	}

	return s.sendResponse(writer, requestID, response)
}

// handleInitialized handles the initialized notification
func (s *Server) handleInitialized(request types.MCPRequest, writer *bufio.Writer) error {
	// This is a notification, no response needed
	s.logSystem(audit.EventAccess, "Client initialization complete", nil)
	return nil
}

// handleToolsList handles the tools/list request
func (s *Server) handleToolsList(request types.MCPRequest, writer *bufio.Writer) error {
	tools := s.getAvailableTools()

	response := map[string]interface{}{
		"tools": tools,
	}

	return s.sendResponse(writer, request.ID, response)
}

// handleToolCall handles the tools/call request
func (s *Server) handleToolCall(request types.MCPRequest, writer *bufio.Writer) error {
	// Parse tool call params
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}

	if request.Params != nil {
		paramsBytes, err := json.Marshal(request.Params)
		if err != nil {
			return fmt.Errorf("failed to marshal params: %w", err)
		}
		if err := json.Unmarshal(paramsBytes, &params); err != nil {
			return fmt.Errorf("failed to parse tool call params: %w", err)
		}
	}

	// Route to appropriate tool handler
	result, err := s.executeTool(params.Name, params.Arguments)
	if err != nil {
		_ = s.sendErrorResponse(writer, request.ID, -32002, err.Error(), nil)
		return nil // Don't return error after sending response
	}

	// Wrap tool result in proper format
	response := map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": formatToolResult(result),
			},
		},
	}

	return s.sendResponse(writer, request.ID, response)
}

// handleSessionsList handles the sessions/list request
func (s *Server) handleSessionsList(request types.MCPRequest, writer *bufio.Writer) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// List available profiles
	profileNames := s.storage.ListProfiles()

	sessions := make([]map[string]interface{}, 0, len(profileNames))
	for _, name := range profileNames {
		// Check if this profile is loaded
		_, isLoaded := s.profiles[name]

		// Get profile details
		profile, _ := s.storage.GetProfile(name)

		session := map[string]interface{}{
			"id":        name,
			"name":      name,
			"is_active": name == s.currentProfile,
			"is_loaded": isLoaded,
		}

		if profile != nil {
			session["created_at"] = profile.CreatedAt
		}

		sessions = append(sessions, session)
	}

	response := map[string]interface{}{
		"sessions": sessions,
		"current":  s.currentProfile,
	}

	return s.sendResponse(writer, request.ID, response)
}

// handleSessionCreate handles the sessions/create request
func (s *Server) handleSessionCreate(request types.MCPRequest, writer *bufio.Writer) error {
	// Parse session create params
	var params struct {
		ProfileName string `json:"profile_name"`
	}

	if request.Params != nil {
		paramsBytes, err := json.Marshal(request.Params)
		if err != nil {
			return fmt.Errorf("failed to marshal params: %w", err)
		}
		if err := json.Unmarshal(paramsBytes, &params); err != nil {
			return fmt.Errorf("failed to parse session create params: %w", err)
		}
	}

	if params.ProfileName == "" {
		return fmt.Errorf("profile_name is required")
	}

	// Load the profile
	if err := s.loadProfile(params.ProfileName); err != nil {
		return fmt.Errorf("failed to load profile: %w", err)
	}

	// Set as current profile
	s.mu.Lock()
	s.currentProfile = params.ProfileName
	s.mu.Unlock()

	// Log session change
	s.logSystem(audit.EventAccess, "Profile session activated", map[string]interface{}{
		"profile": params.ProfileName,
	})

	response := map[string]interface{}{
		"session_id": params.ProfileName,
		"status":     "active",
	}

	return s.sendResponse(writer, request.ID, response)
}

// handleSessionEnd handles the sessions/end request
func (s *Server) handleSessionEnd(request types.MCPRequest, writer *bufio.Writer) error {
	// Parse session end params
	var params struct {
		ProfileName string `json:"profile_name"`
	}

	if request.Params != nil {
		paramsBytes, err := json.Marshal(request.Params)
		if err != nil {
			return fmt.Errorf("failed to marshal params: %w", err)
		}
		if err := json.Unmarshal(paramsBytes, &params); err != nil {
			return fmt.Errorf("failed to parse session end params: %w", err)
		}
	}

	profileToEnd := params.ProfileName
	if profileToEnd == "" {
		profileToEnd = s.currentProfile
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Remove the client
	delete(s.profiles, profileToEnd)

	// Clear current profile if it's the one being ended
	if s.currentProfile == profileToEnd {
		s.currentProfile = ""
	}

	// Log session end
	s.logSystem(audit.EventAccess, "Profile session ended", map[string]interface{}{
		"profile": profileToEnd,
	})

	response := map[string]interface{}{
		"session_id": profileToEnd,
		"status":     "ended",
	}

	return s.sendResponse(writer, request.ID, response)
}

// formatToolResult formats the tool result as a string for the text content
func formatToolResult(result interface{}) string {
	// Minified JSON for faster AI processing and reduced token count
	jsonBytes, err := json.Marshal(result)
	if err != nil {
		// Fallback to simple string conversion
		return fmt.Sprintf("%v", result)
	}
	return string(jsonBytes)
}
