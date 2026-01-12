package logger

import (
	"io"
	"log"
	"os"
)

// Level represents the logging level
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelNone
)

// Logger provides leveled logging
type Logger struct {
	level  Level
	debug  *log.Logger
	info   *log.Logger
	warn   *log.Logger
	errLog *log.Logger
}

// Global logger instance
var defaultLogger *Logger

// Init initializes the global logger with the specified level
func Init(levelStr string) {
	level := ParseLevel(levelStr)
	defaultLogger = New(level, os.Stdout)
}

// New creates a new logger with the specified level and output
func New(level Level, out io.Writer) *Logger {
	return &Logger{
		level:  level,
		debug:  log.New(out, "[DEBUG] ", log.LstdFlags),
		info:   log.New(out, "[INFO] ", log.LstdFlags),
		warn:   log.New(out, "[WARN] ", log.LstdFlags),
		errLog: log.New(out, "[ERROR] ", log.LstdFlags),
	}
}

// ParseLevel converts a string to a Level
func ParseLevel(s string) Level {
	switch s {
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	case "none", "off":
		return LevelNone
	default:
		return LevelInfo
	}
}

// Debug logs a debug message
func Debug(format string, v ...interface{}) {
	if defaultLogger != nil && defaultLogger.level <= LevelDebug {
		defaultLogger.debug.Printf(format, v...)
	}
}

// Info logs an info message
func Info(format string, v ...interface{}) {
	if defaultLogger != nil && defaultLogger.level <= LevelInfo {
		defaultLogger.info.Printf(format, v...)
	}
}

// Warn logs a warning message
func Warn(format string, v ...interface{}) {
	if defaultLogger != nil && defaultLogger.level <= LevelWarn {
		defaultLogger.warn.Printf(format, v...)
	}
}

// Error logs an error message
func Error(format string, v ...interface{}) {
	if defaultLogger != nil && defaultLogger.level <= LevelError {
		defaultLogger.errLog.Printf(format, v...)
	}
}

// Debugf is an alias for Debug
func Debugf(format string, v ...interface{}) {
	Debug(format, v...)
}

// Infof is an alias for Info
func Infof(format string, v ...interface{}) {
	Info(format, v...)
}

// Warnf is an alias for Warn
func Warnf(format string, v ...interface{}) {
	Warn(format, v...)
}

// Errorf is an alias for Error
func Errorf(format string, v ...interface{}) {
	Error(format, v...)
}
