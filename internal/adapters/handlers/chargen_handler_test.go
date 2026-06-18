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
	chargenUsecase "github.com/Hacking-Lab-2026/honeypot/internal/usecases/chargen"
)

func TestHandlers(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Handlers Adapters Suite")
}

var _ = Describe("ChargenHandler", func() {
	var handler *handlers.ChargenHandler
	var repository *persistence.InMemoryChargenEventRepository
	var logger *logging.ConsoleLogger
	var rateLimiter ports.RateLimiter
	var chargenService *services.ChargenService

	BeforeEach(func() {
		logger = &logging.ConsoleLogger{}
		repository = persistence.NewInMemoryChargenEventRepository()
		rateLimiter = &ratelimit.NoOpRateLimiter{}
		chargenService = &services.ChargenService{}

		usecase := chargenUsecase.NewHandleChargenRequestUsecase(
			chargenService,
			repository,
			logger,
			rateLimiter,
		)

		handler = handlers.NewChargenHandler(usecase)
	})

	Describe("Handle", func() {
		It("should process a CHARGEN probe successfully", func() {
			response, err := handler.Handle("192.168.1.100", 19, "UDP", "test-payload")

			Expect(err).NotTo(HaveOccurred())
			Expect(response).NotTo(BeEmpty())
		})

		It("should store the event in the repository", func() {
			sourceIP := "192.168.1.100"
			port := 19

			handler.Handle(sourceIP, port, "UDP", "test-payload")

			event, err := repository.Get("192.168.1.100-19")
			Expect(err).NotTo(HaveOccurred())
			Expect(event).NotTo(BeNil())
			Expect(event.SourceIP).To(Equal(sourceIP))
			Expect(event.Port).To(Equal(port))
		})

		It("should process multiple probes from different sources", func() {
			handler.Handle("192.168.1.1", 19, "UDP", "payload1")
			handler.Handle("192.168.1.2", 19, "UDP", "payload2")
			handler.Handle("192.168.1.3", 19, "UDP", "payload3")

			event1, _ := repository.Get("192.168.1.1-19")
			event2, _ := repository.Get("192.168.1.2-19")
			event3, _ := repository.Get("192.168.1.3-19")

			Expect(event1).NotTo(BeNil())
			Expect(event2).NotTo(BeNil())
			Expect(event3).NotTo(BeNil())
			Expect(event1.SourceIP).To(Equal("192.168.1.1"))
			Expect(event2.SourceIP).To(Equal("192.168.1.2"))
			Expect(event3.SourceIP).To(Equal("192.168.1.3"))
		})

		It("should return empty response when rate limited", func() {
			mockLimiter := &mockRateLimiter{allowRequests: false}
			usecase := chargenUsecase.NewHandleChargenRequestUsecase(
				chargenService,
				repository,
				logger,
				mockLimiter,
			)
			limitedHandler := handlers.NewChargenHandler(usecase)

			response, err := limitedHandler.Handle("192.168.1.100", 19, "UDP", "payload")

			Expect(err).NotTo(HaveOccurred())
			Expect(response).To(BeEmpty())
		})

		It("should process probes on CHARGEN port 19", func() {
			response, err := handler.Handle("192.168.1.1", 19, "UDP", "payload")
			Expect(err).NotTo(HaveOccurred())
			Expect(response).NotTo(BeEmpty())
		})
	})
})

// test mock rate limiter
type mockRateLimiter struct {
	allowRequests bool
}

func (m *mockRateLimiter) Allow(sourceIP string, responseBytes int) bool {
	return m.allowRequests
}
