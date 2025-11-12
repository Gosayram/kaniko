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
	"testing"
	"time"
)

func TestEnhancedLogger_StartGroup_EndGroup(t *testing.T) {
	logger := GetEnhancedLogger()

	// Start a group
	group := logger.StartGroup("test-group")
	if group == nil {
		t.Fatal("StartGroup() returned nil")
	}
	if group.Name != "test-group" {
		t.Errorf("StartGroup() group.Name = %q, want %q", group.Name, "test-group")
	}
	if group.StartTime.IsZero() {
		t.Error("StartGroup() group.StartTime should not be zero")
	}

	// End the group
	logger.EndGroup("test-group")

	// Try to end non-existent group (should not panic)
	logger.EndGroup("non-existent-group")
}

func TestEnhancedLogger_LogWithGroup(t *testing.T) {
	logger := GetEnhancedLogger()

	// Start a group
	logger.StartGroup("test-group")
	defer logger.EndGroup("test-group")

	// Log with group
	logger.LogWithGroup("test-group", LevelInfo, "Test message %s", "value")
	logger.LogWithGroup("test-group", LevelWarn, "Warning message")
	logger.LogWithGroup("test-group", LevelError, "Error message")
	logger.LogWithGroup("test-group", LevelDebug, "Debug message")

	// Log with non-existent group (should fallback to regular logging)
	logger.LogWithGroup("non-existent", LevelInfo, "Fallback message")
}

func TestEnhancedLogger_LogProgress(t *testing.T) {
	logger := GetEnhancedLogger()

	logger.StartGroup("progress-test")
	defer logger.EndGroup("progress-test")

	// Test progress logging
	logger.LogProgress("progress-test", "Building", 50, 100)
	logger.LogProgress("progress-test", "Copying", 25, 50)

	// Test with zero total (should return early)
	logger.LogProgress("progress-test", "Skipped", 0, 0)

	// Test with 100% progress
	logger.LogProgress("progress-test", "Complete", 100, 100)
}

func TestEnhancedLogger_LogFileOperation(t *testing.T) {
	logger := GetEnhancedLogger()

	logger.StartGroup("file-test")
	defer logger.EndGroup("file-test")

	// Test file operation with size
	logger.LogFileOperation("file-test", "Copying", "/path/to/file.txt", 1024)

	// Test file operation without size
	logger.LogFileOperation("file-test", "Creating", "/path/to/dir", 0)
}

func TestEnhancedLogger_LogSecurityEvent(t *testing.T) {
	logger := GetEnhancedLogger()

	logger.StartGroup("security-test")
	defer logger.EndGroup("security-test")

	// Test different severity levels
	logger.LogSecurityEvent("security-test", "Unauthorized access", "critical")
	logger.LogSecurityEvent("security-test", "Suspicious activity", "high")
	logger.LogSecurityEvent("security-test", "Permission check", "medium")
	logger.LogSecurityEvent("security-test", "Info event", "low")
	logger.LogSecurityEvent("security-test", "Default event", "unknown")
}

func TestEnhancedLogger_LogBuildStep(t *testing.T) {
	logger := GetEnhancedLogger()

	// Test successful step
	logger.LogBuildStep("1", "RUN apt-get update", true)

	// Test failed step
	logger.LogBuildStep("2", "COPY file.txt /app/", false)
}

func TestEnhancedLogger_LogSummary(t *testing.T) {
	logger := GetEnhancedLogger()

	// Test successful build summary
	logger.LogSummary(10, 10, 0, 5*time.Second)

	// Test build with failures
	logger.LogSummary(10, 8, 2, 10*time.Second)
}

func TestLogGroup_Concurrency(t *testing.T) {
	logger := GetEnhancedLogger()

	// Test concurrent access to groups
	done := make(chan bool)

	// Start multiple groups concurrently
	for i := 0; i < 10; i++ {
		go func(id int) {
			groupName := "concurrent-group-" + string(rune(id))
			logger.StartGroup(groupName)
			logger.LogWithGroup(groupName, LevelInfo, "Message from goroutine %d", id)
			time.Sleep(10 * time.Millisecond)
			logger.EndGroup(groupName)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestGetEnhancedLogger_Singleton(t *testing.T) {
	logger1 := GetEnhancedLogger()
	logger2 := GetEnhancedLogger()

	if logger1 != logger2 {
		t.Error("GetEnhancedLogger() should return the same instance (singleton)")
	}
}
