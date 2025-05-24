package mcp

import (
	"context"
	"fmt"
	"time"
)

// HealthStatus represents the health check result
type HealthStatus struct {
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
	Profile   string    `json:"profile,omitempty"`
	Uptime    string    `json:"uptime,omitempty"`
	Checks    []Check   `json:"checks,omitempty"`
}

// Check represents an individual health check
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// HealthCheck performs a health check on the MCP server
func (s *Server) HealthCheck(ctx context.Context) (*HealthStatus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	status := &HealthStatus{
		Status:    "healthy",
		Timestamp: time.Now(),
		Profile:   s.currentProfile,
		Uptime:    time.Since(s.startTime).Round(time.Second).String(),
		Checks:    []Check{},
	}

	// Check storage
	storageCheck := Check{Name: "storage", Status: "ok"}
	if s.storage == nil {
		storageCheck.Status = "failed"
		storageCheck.Error = "storage not initialized"
		status.Status = "unhealthy"
	} else {
		// Try to list profiles to verify storage is working
		if _, err := s.storage.ListProfiles(); err != nil {
			storageCheck.Status = "failed"
			storageCheck.Error = err.Error()
			status.Status = "unhealthy"
		}
	}
	status.Checks = append(status.Checks, storageCheck)

	// Check current profile
	profileCheck := Check{Name: "profile", Status: "ok"}
	if s.currentProfile == "" {
		profileCheck.Status = "warning"
		profileCheck.Error = "no profile loaded"
		if status.Status == "healthy" {
			status.Status = "degraded"
		}
	} else {
		// Verify profile can be loaded
		if client, exists := s.profiles[s.currentProfile]; !exists || client == nil {
			profileCheck.Status = "failed"
			profileCheck.Error = "profile not accessible"
			status.Status = "unhealthy"
		}
	}
	status.Checks = append(status.Checks, profileCheck)

	// Check KSM connection (if profile is loaded)
	ksmCheck := Check{Name: "ksm_connection", Status: "ok"}
	if s.currentProfile != "" {
		if client, exists := s.profiles[s.currentProfile]; exists && client != nil {
			// Try a simple operation to verify connection
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			
			// Use a lightweight operation to check connectivity
			if _, err := client.ListSecrets(""); err != nil {
				ksmCheck.Status = "failed"
				ksmCheck.Error = fmt.Sprintf("connection test failed: %v", err)
				status.Status = "unhealthy"
			}
		} else {
			ksmCheck.Status = "skipped"
			ksmCheck.Error = "no active profile"
		}
	} else {
		ksmCheck.Status = "skipped"
		ksmCheck.Error = "no profile configured"
	}
	status.Checks = append(status.Checks, ksmCheck)

	// Check audit logger
	auditCheck := Check{Name: "audit_logger", Status: "ok"}
	if s.logger == nil {
		auditCheck.Status = "warning"
		auditCheck.Error = "audit logging disabled"
		if status.Status == "healthy" {
			status.Status = "degraded"
		}
	}
	status.Checks = append(status.Checks, auditCheck)

	// Check rate limiter
	rateCheck := Check{Name: "rate_limiter", Status: "ok"}
	if s.rateLimiter != nil {
		// Check if we're being rate limited
		if !s.rateLimiter.checkLimit("health_check") {
			rateCheck.Status = "warning"
			rateCheck.Error = "rate limit exceeded"
			if status.Status == "healthy" {
				status.Status = "degraded"
			}
		}
	} else {
		rateCheck.Status = "disabled"
	}
	status.Checks = append(status.Checks, rateCheck)

	return status, nil
}

// handleHealthCheck processes health check requests via MCP
func (s *Server) handleHealthCheck(ctx context.Context, params interface{}) (interface{}, error) {
	health, err := s.HealthCheck(ctx)
	if err != nil {
		return nil, err
	}

	// Return simplified status for MCP
	result := map[string]interface{}{
		"status":    health.Status,
		"timestamp": health.Timestamp.Format(time.RFC3339),
		"uptime":    health.Uptime,
		"profile":   health.Profile,
	}

	// Add check details if not healthy
	if health.Status != "healthy" {
		checks := make(map[string]interface{})
		for _, check := range health.Checks {
			checkInfo := map[string]string{"status": check.Status}
			if check.Error != "" {
				checkInfo["error"] = check.Error
			}
			checks[check.Name] = checkInfo
		}
		result["checks"] = checks
	}

	return result, nil
}