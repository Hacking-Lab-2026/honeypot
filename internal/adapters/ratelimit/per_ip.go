package ratelimit

import (
	"sync"
	"time"
)

const egressBytesPerToken = 128

// Maps IP - bucket and has bucket spec instance

type IPAggregate struct {
	cfg     IPBucketConfig
	mutex   sync.Mutex
	entries map[string]*ipEntry
	done    chan struct{}
}

type ipEntry struct {
	bucket   *Bucket
	lastUsed time.Time
}

// struct for bucket specs
type IPBucketConfig struct {
	Burst        int
	RefillPerSec float64
	TTL          time.Duration
}

// default config, stolen from Griffioen
func DefaultIPBucketConfig() IPBucketConfig {
	return IPBucketConfig{
		Burst:        25,
		RefillPerSec: 1.0,
		TTL:          10 * time.Minute,
	}
}

// constructor, starts the kick_out_loop to remove stale IPs
func NewIPAggregate(conf IPBucketConfig) *IPAggregate {
	aggregate := &IPAggregate{
		cfg:     conf,
		entries: make(map[string]*ipEntry),
		done:    make(chan struct{}),
	}
	go aggregate.kick_out_loop()
	return aggregate
}

// Checks IP and makes/updates bucket entry and then tries to consume weighted tokens.
func (aggregate *IPAggregate) Allow(sourceIP string, responseBytes int) bool {
	aggregate.mutex.Lock()
	e, ok := aggregate.entries[sourceIP]
	// make bucket on first encounter
	if !ok {
		e = &ipEntry{bucket: NewBucket(aggregate.cfg.Burst, aggregate.cfg.RefillPerSec)}
		aggregate.entries[sourceIP] = e
	}
	e.lastUsed = time.Now()
	aggregate.mutex.Unlock()

	return e.bucket.AllowN(egressTokenCost(responseBytes))
}

// egressTokenCost converts a response size into a token cost.
// It always charges at least one token, and scales roughly one token per 512 bytes.
func egressTokenCost(responseBytes int) int {
	if responseBytes <= 0 {
		return 1
	}
	cost := (responseBytes + egressBytesPerToken - 1) / egressBytesPerToken
	if cost < 1 {
		return 1
	}
	return cost
}

// scheduler helper, starts the kick_out procedure once every ttl/2
func (aggregate *IPAggregate) kick_out_loop() {
	interval := aggregate.cfg.TTL / 2
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			aggregate.kick_out()
		case <-aggregate.done:
			return
		}
	}
}

// Removes entries for IPs that haven't been seen in more than ttl.
func (aggregate *IPAggregate) kick_out() {
	cutoff := time.Now().Add(-aggregate.cfg.TTL)
	aggregate.mutex.Lock()
	defer aggregate.mutex.Unlock()
	for ip, e := range aggregate.entries {
		if e.lastUsed.Before(cutoff) {
			delete(aggregate.entries, ip)
		}
	}
}

func (aggregate *IPAggregate) Close() {
	close(aggregate.done)
}
