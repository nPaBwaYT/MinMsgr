package helpers

import "log"

// Logger provides simplified logging with prefixes
type Logger struct {
	prefix string
}

// NewLogger creates a new logger with a prefix
func NewLogger(prefix string) *Logger {
	return &Logger{prefix: "[" + prefix + "]"}
}

// Info logs an info message
func (l *Logger) Info(msg string, args ...interface{}) {
	log.Printf("%s INFO: %s %v", l.prefix, msg, args)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, args ...interface{}) {
	log.Printf("%s WARN: %s %v", l.prefix, msg, args)
}

// Error logs an error message
func (l *Logger) Error(msg string, err error, args ...interface{}) {
	log.Printf("%s ERROR: %s - %v %v", l.prefix, msg, err, args)
}

// Debug logs a debug message
func (l *Logger) Debug(msg string, args ...interface{}) {
	log.Printf("%s DEBUG: %s %v", l.prefix, msg, args)
}
