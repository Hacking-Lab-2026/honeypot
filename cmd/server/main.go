package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Hacking-Lab-2026/honeypot/internal/app"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg := app.Config{
		ChargenAddr:     getEnv("CHARGEN_ADDR", "127.0.0.1:19"),
		CoordinatorAddr: getEnv("COORDINATOR_ADDR", "0.0.0.0:8080"),
		HoneypotIPs:     getEnv("HONEYPOT_IPS", "127.0.0.1"),
		DNSPort:         getEnv("DNS_PORT", "53"),
		NTPPort:         getEnv("NTP_PORT", "123"),
		SSDPPort:        getEnv("SSDP_PORT", "1900"),
		EventsFile:      getEnv("EVENTS_FILE", ""),
		ExperimentsFile: os.Getenv("EXPERIMENTS_FILE"),
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
