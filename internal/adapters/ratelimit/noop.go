package ratelimit

// NoOpRateLimiter is a no-operation rate limiter that allows all requests
// Use this for testing or when rate limiting is disabled
type NoOpRateLimiter struct{}

// Allow always returns true, allowing all requests
func (r *NoOpRateLimiter) Allow(sourceIP string, responseBytes int) bool {
	return true
}
