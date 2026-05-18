package services_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/services"
)

func TestServices(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Domain Services Suite")
}

var _ = Describe("ProbeService", func() {
	var service *services.ProbeService

	BeforeEach(func() {
		service = &services.ProbeService{}
	})

	Describe("ProcessProbe", func() {
		It("should create a probe event with correct values", func() {
			sourceIP := "192.168.1.100"
			port := 53
			protocol := "UDP"
			payload := "test-probe"

			event := service.ProcessProbe(sourceIP, port, protocol, payload)

			Expect(event).NotTo(BeNil())
			Expect(event.SourceIP).To(Equal(sourceIP))
			Expect(event.Port).To(Equal(port))
			Expect(event.Protocol).To(Equal(protocol))
			Expect(event.Payload).To(Equal(payload))
		})

		It("should generate a non-empty response", func() {
			event := service.ProcessProbe("10.0.0.1", 5353, "UDP", "payload")

			Expect(event.Response).NotTo(BeEmpty())
		})

		It("should set a non-zero timestamp", func() {
			event := service.ProcessProbe("10.0.0.1", 5353, "UDP", "payload")

			Expect(event.Timestamp.IsZero()).To(BeFalse())
		})

		It("should generate unique IDs for different sources", func() {
			event1 := service.ProcessProbe("192.168.1.1", 53, "UDP", "payload")
			event2 := service.ProcessProbe("192.168.1.2", 53, "UDP", "payload")

			Expect(event1.ID).NotTo(Equal(event2.ID))
		})

		It("should include port in the ID", func() {
			event1 := service.ProcessProbe("192.168.1.1", 53, "UDP", "payload")
			event2 := service.ProcessProbe("192.168.1.1", 5353, "UDP", "payload")

			Expect(event1.ID).NotTo(Equal(event2.ID))
		})
	})
})
