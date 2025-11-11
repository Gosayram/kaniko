/*
Copyright 2024 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package logging

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// ANSI color codes for log levels
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorGray   = "\033[37m"
	colorCyan   = "\033[36m"
)

// KanikoFormatter provides a clean, readable log format for Kaniko
type KanikoFormatter struct {
	ShowTimestamp bool
	ShowLevel     bool
	CompactMode   bool
	ForceColors   bool
	DisableColors bool
}

// Format formats a log entry for Kaniko with color coding
func (f *KanikoFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var output strings.Builder

	// Add timestamp if enabled
	if f.ShowTimestamp {
		output.WriteString(entry.Time.Format("15:04:05"))
		output.WriteString(" ")
	}

	// Add level with color if enabled
	if f.ShowLevel {
		level := strings.ToUpper(entry.Level.String())
		if f.shouldUseColors() {
			levelColor := f.getLevelColor(entry.Level)
			output.WriteString(fmt.Sprintf("%s%s%s ", levelColor, level, colorReset))
		} else {
			output.WriteString(fmt.Sprintf("%s ", level))
		}
	}

	// Add message
	message := entry.Message

	// Clean up common Kaniko messages
	message = f.cleanupMessage(message)

	output.WriteString(message)

	// Add fields if not in compact mode
	if !f.CompactMode && len(entry.Data) > 0 {
		output.WriteString(" ")
		for key, value := range entry.Data {
			output.WriteString(fmt.Sprintf("%s=%v ", key, value))
		}
	}

	output.WriteString("\n")
	return []byte(output.String()), nil
}

// shouldUseColors determines if colors should be used
func (f *KanikoFormatter) shouldUseColors() bool {
	if f.DisableColors {
		return false
	}
	if f.ForceColors {
		return true
	}
	// Check NO_COLOR environment variable (standard for disabling colors)
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	// Check if output is a terminal (basic check via TERM variable)
	// In CI/CD environments, TERM is usually not set or set to "dumb"
	term := os.Getenv("TERM")
	if term == "" || term == "dumb" {
		return false
	}
	// Default to colors if TERM is set (most terminals support ANSI colors)
	return true
}

// getLevelColor returns ANSI color code for log level
func (f *KanikoFormatter) getLevelColor(level logrus.Level) string {
	switch level {
	case logrus.ErrorLevel, logrus.FatalLevel, logrus.PanicLevel:
		return colorRed
	case logrus.WarnLevel:
		return colorYellow
	case logrus.InfoLevel:
		return colorBlue
	case logrus.DebugLevel, logrus.TraceLevel:
		return colorGray
	default:
		return colorCyan
	}
}

// cleanupMessage cleans up common Kaniko log messages for better readability
func (f *KanikoFormatter) cleanupMessage(message string) string {
	// Remove redundant prefixes
	message = strings.TrimPrefix(message, "INFO[")
	message = strings.TrimPrefix(message, "WARN[")
	message = strings.TrimPrefix(message, "ERROR[")
	message = strings.TrimPrefix(message, "DEBUG[")

	// Clean up common patterns
	message = strings.ReplaceAll(message, "Creating world-writable", "World-writable")
	message = strings.ReplaceAll(message, "Sanitizing world-writable", "Sanitizing")
	message = strings.ReplaceAll(message, "Auto-sanitized", "Auto-fixed")
	message = strings.ReplaceAll(message, "Taking snapshot", "Snapshot")
	message = strings.ReplaceAll(message, "Using files from context", "Context files")
	message = strings.ReplaceAll(message, "No files changed", "No changes")
	message = strings.ReplaceAll(message, "Skipping snapshotting", "Skipping")
	message = strings.ReplaceAll(message, "Building stage", "Building")
	message = strings.ReplaceAll(message, "Retrieving image", "Retrieving")
	message = strings.ReplaceAll(message, "Returning cached", "Cached")
	message = strings.ReplaceAll(message, "Checking for cached layer", "Cache check")
	message = strings.ReplaceAll(message, "No cached layer found", "No cache")
	message = strings.ReplaceAll(message, "Unpacking rootfs", "Unpacking")
	message = strings.ReplaceAll(message, "Changed working directory", "Working dir")
	message = strings.ReplaceAll(message, "Creating directory", "Creating dir")
	message = strings.ReplaceAll(message, "Initializing snapshotter", "Snapshotter")
	message = strings.ReplaceAll(message, "Taking snapshot of full filesystem", "Full snapshot")
	message = strings.ReplaceAll(message, "Taking snapshot of files", "File snapshot")

	return message
}

// NewKanikoFormatter creates a new Kaniko formatter with default settings
func NewKanikoFormatter() *KanikoFormatter {
	return &KanikoFormatter{
		ShowTimestamp: true,
		ShowLevel:     true,
		CompactMode:   false,
	}
}

// NewCompactKanikoFormatter creates a compact Kaniko formatter
func NewCompactKanikoFormatter() *KanikoFormatter {
	return &KanikoFormatter{
		ShowTimestamp: false,
		ShowLevel:     true,
		CompactMode:   true,
	}
}

// ConfigureKanikoLogging sets up enhanced logging for Kaniko
func ConfigureKanikoLogging(level, format string, logTimestamp bool) error {
	// Parse log level
	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		return fmt.Errorf("parsing log level: %w", err)
	}
	logrus.SetLevel(lvl)

	// Set formatter based on format
	switch format {
	case "kaniko":
		logrus.SetFormatter(NewKanikoFormatter())
	case "kaniko-compact":
		logrus.SetFormatter(NewCompactKanikoFormatter())
	case "json":
		logrus.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339,
		})
	case "text":
		logrus.SetFormatter(&logrus.TextFormatter{
			DisableColors:   true,
			FullTimestamp:   logTimestamp,
			TimestampFormat: "15:04:05",
		})
	case "color":
		logrus.SetFormatter(&logrus.TextFormatter{
			ForceColors:     true,
			FullTimestamp:   logTimestamp,
			TimestampFormat: "15:04:05",
		})
	default:
		return fmt.Errorf("unsupported log format: %s. Supported formats: kaniko, kaniko-compact, json, text, color", format)
	}

	return nil
}
