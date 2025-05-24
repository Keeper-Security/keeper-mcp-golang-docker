package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// EventType represents the type of audit event
type EventType string

const (
	// Security events
	EventAuth         EventType = "AUTH"
	EventAuthFailed   EventType = "AUTH_FAILED"
	EventAccess       EventType = "ACCESS"
	EventAccessDenied EventType = "ACCESS_DENIED"
	EventModification EventType = "MODIFICATION"

	// Operation events
	EventProfileCreate EventType = "PROFILE_CREATE"
	EventProfileUpdate EventType = "PROFILE_UPDATE"
	EventProfileDelete EventType = "PROFILE_DELETE"
	EventSecretAccess  EventType = "SECRET_ACCESS"
	EventSecretCreate  EventType = "SECRET_CREATE"
	EventSecretUpdate  EventType = "SECRET_UPDATE"
	EventSecretDelete  EventType = "SECRET_DELETE"

	// System events
	EventStartup      EventType = "STARTUP"
	EventShutdown     EventType = "SHUTDOWN"
	EventError        EventType = "ERROR"
	EventConfigChange EventType = "CONFIG_CHANGE"
)

// Severity represents the severity level of an audit event
type Severity string

const (
	SeverityDebug    Severity = "DEBUG"
	SeverityInfo     Severity = "INFO"
	SeverityWarning  Severity = "WARNING"
	SeverityError    Severity = "ERROR"
	SeverityCritical Severity = "CRITICAL"
)

// AuditEvent represents a single audit log entry
type AuditEvent struct {
	ID            string                 `json:"id"`
	Timestamp     time.Time              `json:"timestamp"`
	Type          EventType              `json:"type"`
	Severity      Severity               `json:"severity"`
	Source        string                 `json:"source"`
	User          string                 `json:"user,omitempty"`
	Profile       string                 `json:"profile,omitempty"`
	Resource      string                 `json:"resource,omitempty"`
	Action        string                 `json:"action"`
	Result        string                 `json:"result"`
	Details       map[string]interface{} `json:"details,omitempty"`
	Error         string                 `json:"error,omitempty"`
	CorrelationID string                 `json:"correlation_id,omitempty"`
}

// Logger provides audit logging functionality
type Logger struct {
	mu        sync.Mutex
	file      *os.File
	filepath  string
	maxSize   int64
	maxAge    time.Duration
	encoder   *json.Encoder
	eventChan chan *AuditEvent
	stopChan  chan struct{}
	wg        sync.WaitGroup
}

// Config represents logger configuration
type Config struct {
	FilePath string
	MaxSize  int64         // Maximum file size in bytes
	MaxAge   time.Duration // Maximum age of log files
}

// NewLogger creates a new audit logger
func NewLogger(config Config) (*Logger, error) {
	// Ensure directory exists
	dir := filepath.Dir(config.FilePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create audit log directory: %w", err)
	}

	// Open log file
	file, err := os.OpenFile(config.FilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log file: %w", err)
	}

	logger := &Logger{
		file:      file,
		filepath:  config.FilePath,
		maxSize:   config.MaxSize,
		maxAge:    config.MaxAge,
		encoder:   json.NewEncoder(file),
		eventChan: make(chan *AuditEvent, 100),
		stopChan:  make(chan struct{}),
	}

	// Start background worker
	logger.wg.Add(1)
	go logger.worker()

	// Log startup event
	logger.LogSystem(EventStartup, "Audit logger started", nil)

	return logger, nil
}

// Log writes an audit event
func (l *Logger) Log(event *AuditEvent) {
	if event.ID == "" {
		event.ID = generateEventID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	select {
	case l.eventChan <- event:
	case <-time.After(time.Second):
		// Timeout to prevent blocking
		fmt.Fprintf(os.Stderr, "Failed to log audit event: timeout\n")
	}
}

// LogAuth logs an authentication event
func (l *Logger) LogAuth(success bool, user, profile string, details map[string]interface{}) {
	eventType := EventAuth
	result := "SUCCESS"
	severity := SeverityInfo

	if !success {
		eventType = EventAuthFailed
		result = "FAILED"
		severity = SeverityWarning
	}

	l.Log(&AuditEvent{
		Type:     eventType,
		Severity: severity,
		Source:   "auth",
		User:     user,
		Profile:  profile,
		Action:   "authenticate",
		Result:   result,
		Details:  details,
	})
}

// LogAccess logs a resource access event
func (l *Logger) LogAccess(resource, action, user, profile string, allowed bool, details map[string]interface{}) {
	eventType := EventAccess
	result := "ALLOWED"
	severity := SeverityInfo

	if !allowed {
		eventType = EventAccessDenied
		result = "DENIED"
		severity = SeverityWarning
	}

	l.Log(&AuditEvent{
		Type:     eventType,
		Severity: severity,
		Source:   "access",
		User:     user,
		Profile:  profile,
		Resource: resource,
		Action:   action,
		Result:   result,
		Details:  details,
	})
}

// LogSecretOperation logs a secret operation
func (l *Logger) LogSecretOperation(operation EventType, secretUID, user, profile string, success bool, details map[string]interface{}) {
	result := "SUCCESS"
	severity := SeverityInfo

	if !success {
		result = "FAILED"
		severity = SeverityError
	}

	// Never log sensitive data
	if details != nil {
		sanitizedDetails := make(map[string]interface{})
		for k, v := range details {
			if !isSensitiveKey(k) {
				sanitizedDetails[k] = v
			}
		}
		details = sanitizedDetails
	}

	l.Log(&AuditEvent{
		Type:     operation,
		Severity: severity,
		Source:   "secrets",
		User:     user,
		Profile:  profile,
		Resource: secretUID,
		Action:   string(operation),
		Result:   result,
		Details:  details,
	})
}

// LogError logs an error event
func (l *Logger) LogError(source string, err error, details map[string]interface{}) {
	l.Log(&AuditEvent{
		Type:     EventError,
		Severity: SeverityError,
		Source:   source,
		Action:   "error",
		Result:   "ERROR",
		Error:    err.Error(),
		Details:  details,
	})
}

// LogSystem logs a system event
func (l *Logger) LogSystem(eventType EventType, message string, details map[string]interface{}) {
	l.Log(&AuditEvent{
		Type:     eventType,
		Severity: SeverityInfo,
		Source:   "system",
		Action:   string(eventType),
		Result:   message,
		Details:  details,
	})
}

// LogWithCorrelation logs an event with a correlation ID
func (l *Logger) LogWithCorrelation(event *AuditEvent, correlationID string) {
	event.CorrelationID = correlationID
	l.Log(event)
}

// worker processes audit events in the background
func (l *Logger) worker() {
	defer l.wg.Done()

	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case event := <-l.eventChan:
			l.writeEvent(event)

		case <-ticker.C:
			l.performMaintenance()

		case <-l.stopChan:
			// Drain remaining events
			for {
				select {
				case event := <-l.eventChan:
					l.writeEvent(event)
				default:
					return
				}
			}
		}
	}
}

// writeEvent writes an event to the log file
func (l *Logger) writeEvent(event *AuditEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.encoder.Encode(event); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write audit event: %v\n", err)
	}

	// Check if rotation is needed
	if l.maxSize > 0 {
		if info, err := l.file.Stat(); err == nil && info.Size() > l.maxSize {
			l.rotate()
		}
	}
}

// rotate performs log rotation
func (l *Logger) rotate() {
	// Close current file
	_ = l.file.Close()

	// Rename current file with timestamp
	timestamp := time.Now().Format("20060102-150405")
	rotatedPath := fmt.Sprintf("%s.%s", l.filepath, timestamp)
	_ = os.Rename(l.filepath, rotatedPath)

	// Open new file
	file, err := os.OpenFile(l.filepath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open new audit log file: %v\n", err)
		return
	}

	l.file = file
	l.encoder = json.NewEncoder(file)
}

// performMaintenance removes old log files
func (l *Logger) performMaintenance() {
	if l.maxAge <= 0 {
		return
	}

	dir := filepath.Dir(l.filepath)
	base := filepath.Base(l.filepath)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	cutoff := time.Now().Add(-l.maxAge)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !filepath.HasPrefix(name, base) {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
}

// Close closes the audit logger
func (l *Logger) Close() error {
	// Log shutdown event
	l.LogSystem(EventShutdown, "Audit logger shutting down", nil)

	// Stop worker
	close(l.stopChan)
	l.wg.Wait()

	// Close file
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.file.Close()
}

// generateEventID generates a unique event ID
func generateEventID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())
}

// isSensitiveKey checks if a key contains sensitive information
func isSensitiveKey(key string) bool {
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

// Query represents an audit log query
type Query struct {
	StartTime     time.Time
	EndTime       time.Time
	EventTypes    []EventType
	Severities    []Severity
	Users         []string
	Resources     []string
	CorrelationID string
	Limit         int
}

// Search searches the audit log (basic implementation)
func (l *Logger) Search(query Query) ([]*AuditEvent, error) {
	// This is a basic implementation that reads the entire file
	// For production, consider using a database or indexed storage

	l.mu.Lock()
	defer l.mu.Unlock()

	// Open file for reading
	file, err := os.Open(l.filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log: %w", err)
	}
	defer file.Close()

	var events []*AuditEvent
	decoder := json.NewDecoder(file)

	for {
		var event AuditEvent
		if err := decoder.Decode(&event); err != nil {
			break // EOF or error
		}

		// Apply filters
		if !query.StartTime.IsZero() && event.Timestamp.Before(query.StartTime) {
			continue
		}
		if !query.EndTime.IsZero() && event.Timestamp.After(query.EndTime) {
			continue
		}
		if len(query.EventTypes) > 0 && !contains(query.EventTypes, event.Type) {
			continue
		}
		if len(query.Severities) > 0 && !containsSeverity(query.Severities, event.Severity) {
			continue
		}
		if len(query.Users) > 0 && !containsString(query.Users, event.User) {
			continue
		}
		if len(query.Resources) > 0 && !containsString(query.Resources, event.Resource) {
			continue
		}
		if query.CorrelationID != "" && event.CorrelationID != query.CorrelationID {
			continue
		}

		events = append(events, &event)

		if query.Limit > 0 && len(events) >= query.Limit {
			break
		}
	}

	return events, nil
}

// Helper functions
func contains(slice []EventType, item EventType) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

func containsSeverity(slice []Severity, item Severity) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

func containsString(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}
