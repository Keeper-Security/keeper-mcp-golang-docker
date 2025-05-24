package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewLogger(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "audit.log")

	config := Config{
		FilePath: logPath,
		MaxSize:  1024 * 1024, // 1MB
		MaxAge:   24 * time.Hour,
	}

	logger, err := NewLogger(config)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	// Verify log file was created
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Error("Log file was not created")
	}

	// Wait for startup event
	time.Sleep(100 * time.Millisecond)

	// Verify startup event was logged
	events := readEvents(t, logPath)
	if len(events) == 0 {
		t.Error("No startup event logged")
	}

	if events[0].Type != EventStartup {
		t.Errorf("Expected startup event, got %s", events[0].Type)
	}
}

func TestLogAuth(t *testing.T) {
	logger := setupTestLogger(t)
	defer logger.Close()

	// Test successful auth
	logger.LogAuth(true, "testuser", "production", map[string]interface{}{
		"ip": "192.168.1.1",
	})

	// Test failed auth
	logger.LogAuth(false, "baduser", "production", map[string]interface{}{
		"ip":     "10.0.0.1",
		"reason": "invalid credentials",
	})

	// Wait for events to be written
	time.Sleep(100 * time.Millisecond)

	events := readEvents(t, logger.filepath)

	// Find auth events (skip startup)
	authEvents := filterEventsByType(events, EventAuth, EventAuthFailed)

	if len(authEvents) != 2 {
		t.Fatalf("Expected 2 auth events, got %d", len(authEvents))
	}

	// Verify successful auth
	if authEvents[0].Type != EventAuth {
		t.Error("First event should be successful auth")
	}
	if authEvents[0].User != "testuser" {
		t.Error("Wrong user in successful auth")
	}
	if authEvents[0].Result != "SUCCESS" {
		t.Error("Wrong result in successful auth")
	}

	// Verify failed auth
	if authEvents[1].Type != EventAuthFailed {
		t.Error("Second event should be failed auth")
	}
	if authEvents[1].User != "baduser" {
		t.Error("Wrong user in failed auth")
	}
	if authEvents[1].Result != "FAILED" {
		t.Error("Wrong result in failed auth")
	}
}

func TestLogAccess(t *testing.T) {
	logger := setupTestLogger(t)
	defer logger.Close()

	// Test allowed access
	logger.LogAccess("secret-123", "read", "user1", "prod", true, map[string]interface{}{
		"field": "password",
	})

	// Test denied access
	logger.LogAccess("secret-456", "write", "user2", "dev", false, map[string]interface{}{
		"reason": "insufficient permissions",
	})

	time.Sleep(100 * time.Millisecond)

	events := readEvents(t, logger.filepath)
	accessEvents := filterEventsByType(events, EventAccess, EventAccessDenied)

	if len(accessEvents) != 2 {
		t.Fatalf("Expected 2 access events, got %d", len(accessEvents))
	}

	// Verify allowed access
	if accessEvents[0].Type != EventAccess {
		t.Error("First event should be allowed access")
	}
	if accessEvents[0].Resource != "secret-123" {
		t.Error("Wrong resource in allowed access")
	}

	// Verify denied access
	if accessEvents[1].Type != EventAccessDenied {
		t.Error("Second event should be denied access")
	}
	if accessEvents[1].Severity != SeverityWarning {
		t.Error("Denied access should have warning severity")
	}
}

func TestLogSecretOperation(t *testing.T) {
	logger := setupTestLogger(t)
	defer logger.Close()

	// Test with sensitive data (should be filtered)
	details := map[string]interface{}{
		"title":    "My Secret",
		"password": "secret123", // Should be filtered
		"token":    "abc123",    // Should be filtered
		"notes":    "general notes",
	}

	logger.LogSecretOperation(EventSecretAccess, "uid-123", "user1", "prod", true, details)

	time.Sleep(100 * time.Millisecond)

	events := readEvents(t, logger.filepath)
	secretEvents := filterEventsByType(events, EventSecretAccess)

	if len(secretEvents) == 0 {
		t.Fatal("No secret operation event found")
	}

	event := secretEvents[0]

	// Verify sensitive data was filtered
	if event.Details["password"] != nil {
		t.Error("Password should have been filtered from details")
	}
	if event.Details["token"] != nil {
		t.Error("Token should have been filtered from details")
	}
	if event.Details["title"] != "My Secret" {
		t.Error("Non-sensitive data should be preserved")
	}
}

func TestLogError(t *testing.T) {
	logger := setupTestLogger(t)
	defer logger.Close()

	testErr := errors.New("test error occurred")
	logger.LogError("test-component", testErr, map[string]interface{}{
		"operation": "test-op",
		"context":   "unit test",
	})

	time.Sleep(100 * time.Millisecond)

	events := readEvents(t, logger.filepath)
	errorEvents := filterEventsByType(events, EventError)

	if len(errorEvents) == 0 {
		t.Fatal("No error event found")
	}

	event := errorEvents[0]
	if event.Error != "test error occurred" {
		t.Errorf("Wrong error message: %s", event.Error)
	}
	if event.Source != "test-component" {
		t.Errorf("Wrong source: %s", event.Source)
	}
	if event.Severity != SeverityError {
		t.Error("Error event should have error severity")
	}
}

func TestLogWithCorrelation(t *testing.T) {
	logger := setupTestLogger(t)
	defer logger.Close()

	correlationID := "test-correlation-123"

	event := &AuditEvent{
		Type:     EventAccess,
		Severity: SeverityInfo,
		Source:   "test",
		Action:   "test-action",
		Result:   "SUCCESS",
	}

	logger.LogWithCorrelation(event, correlationID)

	time.Sleep(100 * time.Millisecond)

	events := readEvents(t, logger.filepath)
	accessEvents := filterEventsByType(events, EventAccess)

	if len(accessEvents) == 0 {
		t.Fatal("No access event found")
	}

	if accessEvents[0].CorrelationID != correlationID {
		t.Errorf("Wrong correlation ID: expected %s, got %s", correlationID, accessEvents[0].CorrelationID)
	}
}

func TestLogRotation(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "audit.log")

	config := Config{
		FilePath: logPath,
		MaxSize:  100, // Very small size to trigger rotation
		MaxAge:   24 * time.Hour,
	}

	logger, err := NewLogger(config)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	// Log many events to trigger rotation
	for i := 0; i < 10; i++ {
		logger.LogAuth(true, "user", "profile", map[string]interface{}{
			"iteration": i,
			"data":      "some data to increase size",
		})
	}

	time.Sleep(500 * time.Millisecond)

	// Check for rotated files
	files, err := filepath.Glob(filepath.Join(tempDir, "audit.log.*"))
	if err != nil {
		t.Fatalf("Failed to list files: %v", err)
	}

	if len(files) == 0 {
		t.Error("No rotated files found")
	}
}

func TestSearch(t *testing.T) {
	logger := setupTestLogger(t)
	defer logger.Close()

	// Log various events
	logger.LogAuth(true, "user1", "prod", nil)
	logger.LogAuth(false, "user2", "dev", nil)
	logger.LogAccess("resource1", "read", "user1", "prod", true, nil)
	logger.LogError("component1", errors.New("error1"), nil)

	time.Sleep(200 * time.Millisecond)

	// Test search by event type
	results, err := logger.Search(Query{
		EventTypes: []EventType{EventAuth},
	})
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	authCount := 0
	for _, event := range results {
		if event.Type == EventAuth {
			authCount++
		}
	}
	if authCount != 1 {
		t.Errorf("Expected 1 auth event, got %d", authCount)
	}

	// Test search by user
	results, err = logger.Search(Query{
		Users: []string{"user1"},
	})
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	user1Count := 0
	for _, event := range results {
		if event.User == "user1" {
			user1Count++
		}
	}
	if user1Count < 2 { // Auth + Access
		t.Errorf("Expected at least 2 events for user1, got %d", user1Count)
	}

	// Test search with limit
	results, err = logger.Search(Query{
		Limit: 2,
	})
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if len(results) > 2 {
		t.Errorf("Expected max 2 results, got %d", len(results))
	}
}

func TestConcurrentLogging(t *testing.T) {
	logger := setupTestLogger(t)
	defer logger.Close()

	// Log events concurrently
	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func(id int) {
			logger.LogAuth(true, fmt.Sprintf("user%d", id), "prod", nil)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	time.Sleep(200 * time.Millisecond)

	events := readEvents(t, logger.filepath)
	authEvents := filterEventsByType(events, EventAuth)

	if len(authEvents) != 10 {
		t.Errorf("Expected 10 auth events, got %d", len(authEvents))
	}
}

func TestGenerateEventID(t *testing.T) {
	id1 := generateEventID()
	id2 := generateEventID()

	if id1 == id2 {
		t.Error("Event IDs should be unique")
	}

	if id1 == "" || id2 == "" {
		t.Error("Event IDs should not be empty")
	}
}

func TestIsSensitiveKey(t *testing.T) {
	tests := []struct {
		key       string
		sensitive bool
	}{
		{"password", true},
		{"secret", true},
		{"api_key", true},
		{"token", true},
		{"auth_token", true},
		{"private_key", true},
		{"passphrase", true},
		{"PIN", true},
		{"access_code", true},
		{"username", false},
		{"email", false},
		{"title", false},
		{"notes", false},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			result := isSensitiveKey(tt.key)
			if result != tt.sensitive {
				t.Errorf("Expected %v for key '%s', got %v", tt.sensitive, tt.key, result)
			}
		})
	}
}

// Helper functions

func setupTestLogger(t *testing.T) *Logger {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "test-audit.log")

	config := Config{
		FilePath: logPath,
		MaxSize:  10 * 1024 * 1024, // 10MB
		MaxAge:   24 * time.Hour,
	}

	logger, err := NewLogger(config)
	if err != nil {
		t.Fatalf("Failed to create test logger: %v", err)
	}

	// Give logger time to initialize
	time.Sleep(50 * time.Millisecond)

	return logger
}

func readEvents(t *testing.T, filepath string) []*AuditEvent {
	data, err := os.ReadFile(filepath)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	var events []*AuditEvent
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}

		var event AuditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Logf("Failed to parse event: %v", err)
			continue
		}

		events = append(events, &event)
	}

	return events
}

func filterEventsByType(events []*AuditEvent, types ...EventType) []*AuditEvent {
	var filtered []*AuditEvent

	typeMap := make(map[EventType]bool)
	for _, t := range types {
		typeMap[t] = true
	}

	for _, event := range events {
		if typeMap[event.Type] {
			filtered = append(filtered, event)
		}
	}

	return filtered
}
