package mcp

import (
	"sync"
	"time"
)

// RateLimiter implements a simple token bucket rate limiter
type RateLimiter struct {
	rate       int       // requests per minute
	tokens     int       // current tokens
	maxTokens  int       // max tokens (burst)
	lastUpdate time.Time // last token update
	mu         sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(ratePerMinute int) *RateLimiter {
	return &RateLimiter{
		rate:       ratePerMinute,
		tokens:     ratePerMinute,
		maxTokens:  ratePerMinute * 2, // Allow burst of 2x rate
		lastUpdate: time.Now(),
	}
}

// Allow checks if a request is allowed
func (r *RateLimiter) Allow(method string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Update tokens based on time passed
	now := time.Now()
	elapsed := now.Sub(r.lastUpdate)
	tokensToAdd := int(elapsed.Minutes() * float64(r.rate))

	if tokensToAdd > 0 {
		r.tokens = min(r.tokens+tokensToAdd, r.maxTokens)
		r.lastUpdate = now
	}

	// Check if we have tokens
	if r.tokens > 0 {
		r.tokens--
		return true
	}

	return false
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
