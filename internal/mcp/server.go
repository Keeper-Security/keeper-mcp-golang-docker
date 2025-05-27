package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/keeper-security/ksm-mcp/internal/audit"
	"github.com/keeper-security/ksm-mcp/internal/ksm"
	"github.com/keeper-security/ksm-mcp/internal/storage"
	"github.com/keeper-security/ksm-mcp/internal/ui"
	"github.com/keeper-security/ksm-mcp/pkg/types"
)

// KSMClientProvider defines a function type that can return a KSMClient.
// This allows for easier mocking in tests.
type KSMClientProvider func() (KSMClient, error)

// Server implements the MCP protocol server
type Server struct {
	storage          storage.ProfileStoreInterface
	profiles         map[string]KSMClient
	currentProfile   string
	logger           *audit.Logger
	confirmer        ConfirmerInterface
	options          *ServerOptions
	mu               sync.RWMutex
	getCurrentClient KSMClientProvider

	// Rate limiting
	rateLimiter *RateLimiter

	// Session management
	sessionID string
	startTime time.Time
}

// ServerOptions configuration for the server
type ServerOptions struct {
	BatchMode   bool
	AutoApprove bool
	Timeout     time.Duration
	ProfileName string
	RateLimit   int    // requests per minute
	Version     string // Server version
}

// NewServer creates a new MCP server
func NewServer(storage storage.ProfileStoreInterface, logger *audit.Logger, options *ServerOptions) *Server {
	if options == nil {
		options = &ServerOptions{
			Timeout:   30 * time.Second,
			RateLimit: 60,
			Version:   "unknown", // Default version if not provided
		}
	}
	if options.Version == "" { // Ensure version is not empty
		options.Version = "unknown"
	}

	confirmConfig := types.Confirmation{
		BatchMode:   options.BatchMode,
		AutoApprove: options.AutoApprove,
		Timeout:     options.Timeout,
		DefaultDeny: false,
	}

	s := &Server{
		storage:     storage,
		profiles:    make(map[string]KSMClient),
		logger:      logger,
		confirmer:   ui.NewConfirmer(confirmConfig),
		options:     options,
		rateLimiter: NewRateLimiter(options.RateLimit),
		sessionID:   generateSessionID(),
		startTime:   time.Now(),
	}
	s.getCurrentClient = s.defaultGetCurrentClientImpl
	return s
}

// defaultGetCurrentClientImpl is the actual implementation for getting the current KSM client.
func (s *Server) defaultGetCurrentClientImpl() (KSMClient, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.currentProfile == "" {
		return nil, fmt.Errorf("no profile selected or active")
	}

	client, exists := s.profiles[s.currentProfile]
	if !exists {
		if err := s.loadProfile(s.currentProfile); err != nil {
			return nil, fmt.Errorf("profile '%s' not loaded and failed to load: %w", s.currentProfile, err)
		}
		client, exists = s.profiles[s.currentProfile]
		if !exists {
			return nil, fmt.Errorf("profile '%s' loaded but not found in map, internal error", s.currentProfile)
		}
	}

	return client, nil
}

// Start starts the MCP server
func (s *Server) Start(ctx context.Context) error {
	// Log server start
	s.logSystem(audit.EventStartup, "MCP server started", map[string]interface{}{
		"session_id": s.sessionID,
		"batch_mode": s.options.BatchMode,
		"profile":    s.options.ProfileName,
	})

	// Load initial profile if specified
	if s.options.ProfileName != "" {
		if err := s.loadProfile(s.options.ProfileName); err != nil {
			s.logError("startup", fmt.Errorf("failed to load initial profile '%s': %w", s.options.ProfileName, err), nil)
			return fmt.Errorf("failed to load initial profile '%s': %w", s.options.ProfileName, err)
		}
		s.currentProfile = s.options.ProfileName
		s.logSystem(audit.EventStartup, "Initial profile loaded", map[string]interface{}{"profile": s.currentProfile})
	} else {
		s.logSystem(audit.EventStartup, "No initial profile specified, server will wait for session/create or use direct config if available.", nil)
	}

	// Start reading from stdin
	reader := bufio.NewReader(os.Stdin)
	writer := bufio.NewWriter(os.Stdout)
	defer writer.Flush()

	// Main message loop
	for {
		select {
		case <-ctx.Done():
			s.logSystem(audit.EventShutdown, "MCP server stopped", map[string]interface{}{
				"session_id": s.sessionID,
				"duration":   time.Since(s.startTime).String(),
			})
			return ctx.Err()
		default:
			// Read next message
			line, err := reader.ReadBytes('\n')
			if err != nil {
				if err == io.EOF {
					return nil
				}
				return fmt.Errorf("failed to read message: %w", err)
			}

			// Process message
			if err := s.processMessage(line, writer); err != nil {
				s.logError("mcp", err, map[string]interface{}{
					"message": string(line),
				})
				// Send error response
				_ = s.sendErrorResponse(writer, nil, -32603, err.Error(), nil)
			}
		}
	}
}

// processMessage processes a single MCP message
func (s *Server) processMessage(data []byte, writer *bufio.Writer) error {
	var request types.MCPRequest
	if err := json.Unmarshal(data, &request); err != nil {
		_ = s.sendErrorResponse(writer, nil, -32700, "Parse error", nil)
		return nil // Already sent error response
	}

	// Check rate limit
	if !s.rateLimiter.Allow(request.Method) {
		_ = s.sendErrorResponse(writer, request.ID, -32029, "Rate limit exceeded", nil)
		return nil // Already sent error response
	}

	// Log request
	s.logSystem(audit.EventAccess, "MCP request received", map[string]interface{}{
		"method":     request.Method,
		"request_id": request.ID,
	})

	// Route to appropriate handler
	switch request.Method {
	case "initialize":
		return s.handleInitialize(request, writer)
	case "initialized", "notifications/initialized": // Handle notification variant too
		return s.handleInitialized(request, writer)
	case "tools/list":
		return s.handleToolsList(request, writer)
	case "tools/call":
		return s.handleToolCall(request, writer)
	case "sessions/list":
		return s.handleSessionsList(request, writer)
	case "sessions/create":
		return s.handleSessionCreate(request, writer)
	case "sessions/end":
		return s.handleSessionEnd(request, writer)
	case "resources/list":
		// Resources not supported yet, send empty list
		return s.sendResponse(writer, request.ID, map[string]interface{}{
			"resources": []interface{}{},
		})
	case "prompts/list": // New handler for listing prompts
		prompts := s.getAvailablePrompts()
		return s.sendResponse(writer, request.ID, map[string]interface{}{"prompts": prompts})
	case "prompts/get": // New handler for getting a specific prompt
		promptResult, err := s.handleGetPrompt(request) // Assumes handleGetPrompt is now part of Server methods
		if err != nil {
			_ = s.sendErrorResponse(writer, request.ID, -32003, fmt.Sprintf("Error getting prompt: %s", err.Error()), nil)
			return nil
		}
		return s.sendResponse(writer, request.ID, promptResult)
	default:
		// Only send error response if this is a request (has an ID)
		if request.ID != nil {
			_ = s.sendErrorResponse(writer, request.ID, -32601, "Method not found", nil)
		}
		return nil // Already handled
	}
}

// loadProfile loads a KSM client for the given profile
func (s *Server) loadProfile(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if already loaded
	if _, exists := s.profiles[name]; exists {
		return nil
	}

	// Load profile from storage
	profile, err := s.storage.GetProfile(name)
	if err != nil {
		return fmt.Errorf("failed to get profile: %w", err)
	}

	// Create KSM client
	client, err := ksm.NewClient(profile, s.logger)
	if err != nil {
		return fmt.Errorf("failed to create KSM client: %w", err)
	}

	// Test connection
	if err := client.TestConnection(); err != nil {
		return fmt.Errorf("failed to connect to KSM: %w", err)
	}

	s.profiles[name] = client
	return nil
}

// sendResponse sends a JSON-RPC response
func (s *Server) sendResponse(writer *bufio.Writer, id interface{}, result interface{}) error {
	response := types.MCPResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}

	data, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	// Debug log the response
	// fmt.Fprintf(os.Stderr, "DEBUG: Sending response: %s\n", string(data))

	if _, err := writer.Write(data); err != nil {
		return fmt.Errorf("failed to write response: %w", err)
	}

	if _, err := writer.Write([]byte("\n")); err != nil {
		return fmt.Errorf("failed to write newline: %w", err)
	}

	return writer.Flush()
}

// sendErrorResponse sends a JSON-RPC error response
func (s *Server) sendErrorResponse(writer *bufio.Writer, id interface{}, code int, message string, data interface{}) error {
	response := types.MCPResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &types.MCPError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}

	responseData, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal error response: %w", err)
	}

	if _, err := writer.Write(responseData); err != nil {
		return fmt.Errorf("failed to write error response: %w", err)
	}

	if _, err := writer.Write([]byte("\n")); err != nil {
		return fmt.Errorf("failed to write newline: %w", err)
	}

	return writer.Flush()
}

// generateSessionID generates a unique session ID
func generateSessionID() string {
	return fmt.Sprintf("mcp-%d", time.Now().Unix())
}

// Helper logging methods that handle nil logger checks
func (s *Server) logSystem(eventType audit.EventType, message string, details map[string]interface{}) {
	if s.logger != nil {
		s.logger.LogSystem(eventType, message, details)
	}
}

func (s *Server) logError(source string, err error, details map[string]interface{}) {
	if s.logger != nil {
		s.logger.LogError(source, err, details)
	}
}

func (s *Server) logAccess(resource, action, user string, allowed bool, details map[string]interface{}) {
	if s.logger != nil {
		s.logger.LogAccess(resource, action, user, "", allowed, details)
	}
}

// handleToolCall processes a tools/call request
// func (s *Server) handleToolCall(request types.MCPRequest, writer *bufio.Writer) error {
