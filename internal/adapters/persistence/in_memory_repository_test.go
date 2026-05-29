package persistence_test

import (
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/Hacking-Lab-2026/honeypot/internal/adapters/persistence"
	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
)

func TestPersistence(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Persistence Adapters Suite")
}

var _ = Describe("InMemoryEventRepository", func() {
	var repo *persistence.InMemoryEventRepository
	var testEvent *models.ProbeEvent

	BeforeEach(func() {
		repo = persistence.NewInMemoryEventRepository()
		testEvent = &models.ProbeEvent{
			ID:        "test-1",
			SourceIP:  "192.168.1.1",
			Port:      53,
			Protocol:  "UDP",
			Payload:   "test",
			Timestamp: time.Now(),
			Response:  "response",
		}
	})

	Describe("Save", func() {
		It("should save an event successfully", func() {
			err := repo.Save(testEvent)

			Expect(err).NotTo(HaveOccurred())
		})

		It("should reject nil events", func() {
			err := repo.Save(nil)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("event cannot be nil"))
		})

		It("should allow saving multiple events", func() {
			event1 := &models.ProbeEvent{ID: "event-1"}
			event2 := &models.ProbeEvent{ID: "event-2"}

			Expect(repo.Save(event1)).NotTo(HaveOccurred())
			Expect(repo.Save(event2)).NotTo(HaveOccurred())
		})

		It("should overwrite event with same ID", func() {
			event := &models.ProbeEvent{
				ID:       "test-id",
				SourceIP: "192.168.1.1",
			}
			updatedEvent := &models.ProbeEvent{
				ID:       "test-id",
				SourceIP: "192.168.1.2",
			}

			repo.Save(event)
			repo.Save(updatedEvent)

			retrieved, _ := repo.Get("test-id")
			Expect(retrieved.SourceIP).To(Equal("192.168.1.2"))
		})
	})

	Describe("Get", func() {
		It("should retrieve a saved event", func() {
			repo.Save(testEvent)

			retrieved, err := repo.Get("test-1")

			Expect(err).NotTo(HaveOccurred())
			Expect(retrieved).NotTo(BeNil())
			Expect(retrieved.ID).To(Equal("test-1"))
			Expect(retrieved.SourceIP).To(Equal("192.168.1.1"))
		})

		It("should return error for nonexistent event", func() {
			_, err := repo.Get("nonexistent")

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("event not found"))
		})

		It("should retrieve correct event among multiple", func() {
			event1 := &models.ProbeEvent{ID: "event-1", SourceIP: "10.0.0.1"}
			event2 := &models.ProbeEvent{ID: "event-2", SourceIP: "10.0.0.2"}
			event3 := &models.ProbeEvent{ID: "event-3", SourceIP: "10.0.0.3"}

			repo.Save(event1)
			repo.Save(event2)
			repo.Save(event3)

			retrieved, err := repo.Get("event-2")

			Expect(err).NotTo(HaveOccurred())
			Expect(retrieved.SourceIP).To(Equal("10.0.0.2"))
		})
	})
})
