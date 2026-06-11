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

var _ = Describe("ChargenService", func() {
	var service *services.ChargenService

	BeforeEach(func() {
		service = &services.ChargenService{}
	})

	Describe("ProcessChargen", func() {
		It("should create a chargen event with correct values", func() {
			sourceIP := "192.168.1.100"
			port := 19
			protocol := "UDP"
			payload := "test-probe"

			event := service.ProcessChargen(sourceIP, port, protocol, payload)

			Expect(event).NotTo(BeNil())
			Expect(event.SourceIP).To(Equal(sourceIP))
			Expect(event.Port).To(Equal(port))
			Expect(event.Protocol).To(Equal(protocol))
			Expect(event.Payload).To(Equal(payload))
		})

		It("should generate a non-empty response", func() {
			event := service.ProcessChargen("10.0.0.1", 19, "UDP", "payload")

			Expect(event.Response).NotTo(BeEmpty())
		})

		It("should set a non-zero timestamp", func() {
			event := service.ProcessChargen("10.0.0.1", 19, "UDP", "payload")

			Expect(event.Timestamp.IsZero()).To(BeFalse())
		})

		It("should generate unique IDs for different sources", func() {
			event1 := service.ProcessChargen("192.168.1.1", 19, "UDP", "payload")
			event2 := service.ProcessChargen("192.168.1.2", 19, "UDP", "payload")

			Expect(event1.ID).NotTo(Equal(event2.ID))
		})

		It("should include port in the ID", func() {
			event1 := service.ProcessChargen("192.168.1.1", 19, "UDP", "payload")
			event2 := service.ProcessChargen("192.168.1.1", 20, "UDP", "payload")

			Expect(event1.ID).NotTo(Equal(event2.ID))
		})
	})
})
