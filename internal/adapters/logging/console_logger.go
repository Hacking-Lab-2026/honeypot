package logging

import "fmt"
type ConsoleLogger struct{}

func (cl *ConsoleLogger) Info(message string) {
	fmt.Println("[INFO] " + message)
}

func (cl *ConsoleLogger) Error(message string) {
	fmt.Println("[ERROR] " + message)
}
