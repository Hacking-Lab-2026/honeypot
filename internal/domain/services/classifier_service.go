package services

import (
	"strings"
	"sync"
	"time"
)

var knownScannerPrefixes = []string{
	"66.240.",     // Shodan
	"71.6.",       // Shodan
	"216.239.",    // Shodan
	"198.108.66.", // Censys
	"162.142.",    // Censys
	"167.94.",     // Censys
	"192.35.168.", // ZMap
	"141.212.",    // University of Michigan / ZMap research
}

// ClassifierService classifies incoming probes by source IP and query type.
type ClassifierService struct {
	requestCounts map[string][]time.Time
	mu            sync.Mutex
	rateWindow    time.Duration
	rateThreshold int
}

// NewClassifierService creates a ClassifierService with a 60-second sliding window
// and a threshold of 25 requests, aligned with the rate-limiter burst setting.
func NewClassifierService() *ClassifierService {
	return &ClassifierService{
		requestCounts: make(map[string][]time.Time),
		rateWindow:    60 * time.Second,
		rateThreshold: 25,
	}
}

// Classify returns "scanner", "attacker", or "noise" for a given source IP and DNS query type string.
// Rules are evaluated in priority order: scanner prefix → high rate → attacker query type → noise.
func (c *ClassifierService) Classify(sourceIP string, queryType string) string {
	// Rule 1: known scanner IP ranges
	for _, prefix := range knownScannerPrefixes {
		if strings.HasPrefix(sourceIP, prefix) {
			return "scanner"
		}
	}

	// Rule 2: high request rate (sliding window)
	c.mu.Lock()
	now := time.Now()
	cutoff := now.Add(-c.rateWindow)
	ts := c.requestCounts[sourceIP]
	filtered := ts[:0]
	for _, t := range ts {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}
	filtered = append(filtered, now)
	c.requestCounts[sourceIP] = filtered
	count := len(filtered)
	c.mu.Unlock()

	if count > c.rateThreshold {
		return "attacker"
	}

	// Rule 3: amplification-favoured query types
	if queryType == "ANY" || queryType == "TXT" {
		return "attacker"
	}

	return "noise"
}

// Cleanup removes IPs from the internal map that have no timestamps newer than maxAge.
// Call periodically to prevent unbounded memory growth.
func (c *ClassifierService) Cleanup(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	c.mu.Lock()
	defer c.mu.Unlock()
	for ip, ts := range c.requestCounts {
		hasRecent := false
		for _, t := range ts {
			if t.After(cutoff) {
				hasRecent = true
				break
			}
		}
		if !hasRecent {
			delete(c.requestCounts, ip)
		}
	}
}
