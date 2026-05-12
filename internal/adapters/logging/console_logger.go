package logging

import "fmt"

// ConsoleLogger implements the Logger port using console output
type ConsoleLogger struct{}

// Info logs an info message to console
func (cl *ConsoleLogger) Info(message string) {
	fmt.Println("[INFO] " + message)
}

// Error logs an error message to console
func (cl *ConsoleLogger) Error(message string) {
	fmt.Println("[ERROR] " + message)
}
