package ratelimit

import "golang.org/x/time/rate"

// use rate lib cause it's tested
type Bucket struct {
	inner *rate.Limiter
}

// bucket constructor, max tokens and refill rate tok/sec
func NewBucket(burst int, refillPerSec float64) *Bucket {
	return &Bucket{
		inner: rate.NewLimiter(rate.Limit(refillPerSec), burst),
	}
}

// Consume token from bucket, true if success
func (b *Bucket) Allow() bool {
	return b.inner.Allow()
}
