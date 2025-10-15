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

// Package logging provides enhanced logging utilities for Kaniko
// including progress tracking, log grouping, and cleaner output
package logging

import (
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Constants for log levels and emojis
const (
	LevelInfo  = "info"
	LevelWarn  = "warn"
	LevelError = "error"
	LevelDebug = "debug"

	EmojiError   = "❌"
	EmojiWarning = "⚠️"
	EmojiSuccess = "✅"

	PercentageMultiplier = 100
)

// LogGroup represents a group of related log messages
type LogGroup struct {
	Name         string
	StartTime    time.Time
	MessageCount int
	Warnings     int
	Errors       int
	mu           sync.RWMutex
}

// EnhancedLogger provides improved logging with grouping and progress tracking
type EnhancedLogger struct {
	groups map[string]*LogGroup
	mu     sync.RWMutex
}

var (
	enhancedLogger *EnhancedLogger
	once           sync.Once
)

// GetEnhancedLogger returns the singleton enhanced logger instance
func GetEnhancedLogger() *EnhancedLogger {
	once.Do(func() {
		enhancedLogger = &EnhancedLogger{
			groups: make(map[string]*LogGroup),
		}
	})
	return enhancedLogger
}

// StartGroup starts a new log group for related operations
func (el *EnhancedLogger) StartGroup(name string) *LogGroup {
	el.mu.Lock()
	defer el.mu.Unlock()

	group := &LogGroup{
		Name:      name,
		StartTime: time.Now(),
	}
	el.groups[name] = group

	// Log group start with emoji and formatting
	logrus.Infof("🚀 Starting %s", name)
	return group
}

// EndGroup ends a log group and provides summary
func (el *EnhancedLogger) EndGroup(name string) {
	el.mu.Lock()
	defer el.mu.Unlock()

	group, exists := el.groups[name]
	if !exists {
		return
	}

	duration := time.Since(group.StartTime)

	// Create summary with appropriate emoji
	var statusEmoji string
	switch {
	case group.Errors > 0:
		statusEmoji = EmojiError
	case group.Warnings > 0:
		statusEmoji = EmojiWarning
	default:
		statusEmoji = EmojiSuccess
	}

	// Log group completion with summary
	logrus.Infof("%s Completed %s in %v (%d messages, %d warnings, %d errors)",
		statusEmoji, name, duration.Round(time.Millisecond),
		group.MessageCount, group.Warnings, group.Errors)

	delete(el.groups, name)
}

// LogWithGroup logs a message within a specific group
func (el *EnhancedLogger) LogWithGroup(groupName, level, message string, args ...interface{}) {
	el.mu.RLock()
	group, exists := el.groups[groupName]
	el.mu.RUnlock()

	if !exists {
		// Fallback to regular logging if group doesn't exist
		switch level {
		case LevelInfo:
			logrus.Infof(message, args...)
		case LevelWarn:
			logrus.Warnf(message, args...)
		case LevelError:
			logrus.Errorf(message, args...)
		case LevelDebug:
			logrus.Debugf(message, args...)
		}
		return
	}

	// Update group statistics
	group.mu.Lock()
	group.MessageCount++
	switch level {
	case LevelWarn:
		group.Warnings++
	case LevelError:
		group.Errors++
	}
	group.mu.Unlock()

	// Log with group context
	formattedMessage := fmt.Sprintf("[%s] %s", groupName, message)
	switch level {
	case LevelInfo:
		logrus.Infof(formattedMessage, args...)
	case LevelWarn:
		logrus.Warnf(formattedMessage, args...)
	case LevelError:
		logrus.Errorf(formattedMessage, args...)
	case LevelDebug:
		logrus.Debugf(formattedMessage, args...)
	}
}

// LogProgress logs progress information with visual indicators
func (el *EnhancedLogger) LogProgress(groupName, operation string, current, total int) {
	if total == 0 {
		return
	}

	percentage := float64(current) / float64(total) * PercentageMultiplier
	barLength := 20
	filledLength := int(percentage / 100 * float64(barLength))

	bar := ""
	for i := 0; i < barLength; i++ {
		if i < filledLength {
			bar += "█"
		} else {
			bar += "░"
		}
	}

	el.LogWithGroup(groupName, LevelInfo, "📊 %s: [%s] %.1f%% (%d/%d)",
		operation, bar, percentage, current, total)
}

// LogFileOperation logs file operations with appropriate emojis
func (el *EnhancedLogger) LogFileOperation(groupName, operation, path string, size int64) {
	var emoji string
	switch operation {
	case "create":
		emoji = "📄"
	case "copy":
		emoji = "📋"
	case "move":
		emoji = "📦"
	case "delete":
		emoji = "🗑️"
	case "permission":
		emoji = "🔒"
	default:
		emoji = "📁"
	}

	if size > 0 {
		el.LogWithGroup(groupName, LevelDebug, "%s %s %s (%d bytes)",
			emoji, operation, path, size)
	} else {
		el.LogWithGroup(groupName, LevelDebug, "%s %s %s",
			emoji, operation, path)
	}
}

// LogSecurityEvent logs security-related events with appropriate severity
func (el *EnhancedLogger) LogSecurityEvent(groupName, event, severity string, details ...interface{}) {
	var emoji string
	var level string

	switch severity {
	case "critical":
		emoji = "🚨"
		level = "error"
	case "high":
		emoji = "⚠️"
		level = "warn"
	case "medium":
		emoji = "🔍"
		level = "info"
	case "low":
		emoji = "ℹ️"
		level = "debug"
	default:
		emoji = "🔒"
		level = "info"
	}

	message := fmt.Sprintf("%s Security: %s", emoji, event)
	el.LogWithGroup(groupName, level, message, details...)
}

// LogBuildStep logs build steps with clear formatting
func (el *EnhancedLogger) LogBuildStep(step, command string, success bool) {
	var emoji string
	if success {
		emoji = "✅"
	} else {
		emoji = "❌"
	}

	logrus.Infof("%s Step %s: %s", emoji, step, command)
}

// LogSummary provides a final build summary
func (el *EnhancedLogger) LogSummary(totalSteps, successfulSteps, failedSteps int, duration time.Duration) {
	logrus.Infof("🎯 Build Summary:")
	logrus.Infof("   Total steps: %d", totalSteps)
	logrus.Infof("   Successful: %d", successfulSteps)
	logrus.Infof("   Failed: %d", failedSteps)
	logrus.Infof("   Duration: %v", duration.Round(time.Millisecond))

	if failedSteps == 0 {
		logrus.Infof("🎉 Build completed successfully!")
	} else {
		logrus.Errorf("💥 Build completed with %d errors", failedSteps)
	}
}
