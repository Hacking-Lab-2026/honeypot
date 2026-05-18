package main

import (
	"github.com/Hacking-Lab-2026/honeypot/internal/app"
	"log"
)

func main() {
	application := app.NewApplication("127.0.0.1:5353")

	if err := application.Start(); err != nil {
		log.Fatalf("Application error: %v", err)
	}
}
