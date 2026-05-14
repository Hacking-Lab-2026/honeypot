package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/hacking-lab/ddos-honeypot/internal/app"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg := app.Config{
		ProbeAddr:          getEnv("PROBE_ADDR", "127.0.0.1:5353"),
		CoordinatorAddr:    getEnv("COORDINATOR_ADDR", "0.0.0.0:8080"),
		ActiveExperimentID: getEnv("ACTIVE_EXPERIMENT_ID", ""),
		HoneypotIPs:        getEnv("HONEYPOT_IPS", "127.0.0.1"),
		DNSPort:            getEnv("DNS_PORT", "5354"),
		EventsFile:         getEnv("EVENTS_FILE", ""),
	}

	application, err := app.NewApplication(cfg)
	if err != nil {
		log.Fatalf("Failed to initialise application: %v", err)
	}

	if err := application.Start(ctx); err != nil {
		log.Fatalf("Application error: %v", err)
	}
}

func getEnv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}
