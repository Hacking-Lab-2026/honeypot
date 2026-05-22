package ratelimit_test

import (
	"testing"
	"time"

	"github.com/Hacking-Lab-2026/honeypot/internal/adapters/ratelimit"
)

func TestBucket_AllowsBurst(t *testing.T) {
	b := ratelimit.NewBucket(25, 1.0)
	for i := 0; i < 25; i++ {
		if !b.Allow() {
			t.Fatalf("packet %d denied; expected allowed within burst", i+1)
		}
	}
	if b.Allow() {
		t.Fatal("26th packet allowed; expected denied after burst exhausted")
	}
}

func TestBucket_RefillsAtRate(t *testing.T) {
	b := ratelimit.NewBucket(1, 10.0) // 1 burst, 10 tok/sec refill
	if !b.Allow() {
		t.Fatal("initial token denied")
	}
	if b.Allow() {
		t.Fatal("second consecutive token allowed; bucket should be empty")
	}
	time.Sleep(150 * time.Millisecond)
	if !b.Allow() {
		t.Fatal("token not refilled after 150ms with 10pps rate")
	}
}

func TestBucket_SeparateBuckets(t *testing.T) {
	b1 := ratelimit.NewBucket(1, 1.0)
	b2 := ratelimit.NewBucket(1, 1.0)
	if !b1.Allow() || !b2.Allow() {
		t.Fatal("separate buckets should not share state")
	}
}
