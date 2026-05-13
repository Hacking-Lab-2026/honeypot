package ratelimit_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/Hacking-Lab-2026/honeypot/internal/adapters/ratelimit"
)

func TestRateLimiter(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Rate Limiter Adapters Suite")
}

var _ = Describe("NoOpRateLimiter", func() {
	var limiter *ratelimit.NoOpRateLimiter

	BeforeEach(func() {
		limiter = &ratelimit.NoOpRateLimiter{}
	})

	Describe("Allow", func() {
		It("should always allow requests", func() {
			Expect(limiter.Allow("192.168.1.1")).To(BeTrue())
			Expect(limiter.Allow("10.0.0.1")).To(BeTrue())
		})

		It("should allow multiple requests from same IP", func() {
			ip := "192.168.1.1"

			result1 := limiter.Allow(ip)
			result2 := limiter.Allow(ip)
			result3 := limiter.Allow(ip)

			Expect(result1).To(BeTrue())
			Expect(result2).To(BeTrue())
			Expect(result3).To(BeTrue())
		})

		It("should allow requests from many different IPs", func() {
			ips := []string{
				"192.168.1.1",
				"10.0.0.1",
				"172.16.0.1",
				"8.8.8.8",
				"1.1.1.1",
			}

			for _, ip := range ips {
				Expect(limiter.Allow(ip)).To(BeTrue())
			}
		})
	})
})
