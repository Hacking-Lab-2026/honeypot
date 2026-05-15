package handlers_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/Hacking-Lab-2026/honeypot/internal/adapters/handlers"
	"github.com/Hacking-Lab-2026/honeypot/internal/adapters/logging"
	"github.com/Hacking-Lab-2026/honeypot/internal/adapters/persistence"
	"github.com/Hacking-Lab-2026/honeypot/internal/adapters/ratelimit"
	"github.com/Hacking-Lab-2026/honeypot/internal/domain/services"
	"github.com/Hacking-Lab-2026/honeypot/internal/ports"
	"github.com/Hacking-Lab-2026/honeypot/internal/usecases/probe"
)

func TestHandlers(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Handlers Adapters Suite")
}

var _ = Describe("ProbeHandler", func() {
	var handler *handlers.ProbeHandler
	var repository *persistence.InMemoryEventRepository
	var logger *logging.ConsoleLogger
	var rateLimiter ports.RateLimiter
	var probeService *services.ProbeService

	BeforeEach(func() {
		logger = &logging.ConsoleLogger{}
		repository = persistence.NewInMemoryEventRepository()
		rateLimiter = &ratelimit.NoOpRateLimiter{}
		probeService = &services.ProbeService{}

		usecase := probe.NewProcessProbeUsecase(
			probeService,
			repository,
			logger,
			rateLimiter,
		)

		handler = handlers.NewProbeHandler(usecase)
	})

	Describe("Handle", func() {
		It("should process a probe successfully", func() {
			response, err := handler.Handle("192.168.1.100", 53, "UDP", "test-payload")

			Expect(err).NotTo(HaveOccurred())
			Expect(response).NotTo(BeEmpty())
		})

		It("should store the event in the repository", func() {
			sourceIP := "192.168.1.100"
			port := 53

			handler.Handle(sourceIP, port, "UDP", "test-payload")

			event, err := repository.Get("192.168.1.100-53")
			Expect(err).NotTo(HaveOccurred())
			Expect(event).NotTo(BeNil())
			Expect(event.SourceIP).To(Equal(sourceIP))
			Expect(event.Port).To(Equal(port))
		})

		It("should process multiple probes from different sources", func() {
			handler.Handle("192.168.1.1", 53, "UDP", "payload1")
			handler.Handle("192.168.1.2", 53, "UDP", "payload2")
			handler.Handle("192.168.1.3", 53, "UDP", "payload3")

			event1, _ := repository.Get("192.168.1.1-53")
			event2, _ := repository.Get("192.168.1.2-53")
			event3, _ := repository.Get("192.168.1.3-53")

			Expect(event1).NotTo(BeNil())
			Expect(event2).NotTo(BeNil())
			Expect(event3).NotTo(BeNil())
			Expect(event1.SourceIP).To(Equal("192.168.1.1"))
			Expect(event2.SourceIP).To(Equal("192.168.1.2"))
			Expect(event3.SourceIP).To(Equal("192.168.1.3"))
		})

		It("should return empty response when rate limited", func() {
			// Create handler with mock rate limiter that blocks
			mockLimiter := &mockRateLimiter{allowRequests: false}
			usecase := probe.NewProcessProbeUsecase(
				probeService,
				repository,
				logger,
				mockLimiter,
			)
			limitedHandler := handlers.NewProbeHandler(usecase)

			response, err := limitedHandler.Handle("192.168.1.100", 53, "UDP", "payload")

			Expect(err).NotTo(HaveOccurred())
			Expect(response).To(BeEmpty())
		})

		It("should process probes from various ports", func() {
			ports := []int{53, 5353, 19, 69, 123}

			for _, port := range ports {
				response, err := handler.Handle("192.168.1.1", port, "UDP", "payload")
				Expect(err).NotTo(HaveOccurred())
				Expect(response).NotTo(BeEmpty())
			}
		})
	})
})

// Mock rate limiter for testing
type mockRateLimiter struct {
	allowRequests bool
}

func (m *mockRateLimiter) Allow(sourceIP string, responseBytes int) bool {
	return m.allowRequests
}
