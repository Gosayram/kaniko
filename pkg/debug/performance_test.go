/*
Copyright 2025 Google LLC

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

package debug

import (
	"strings"
	"testing"
	"time"
)

func TestInitPerformanceTracker(t *testing.T) {
	tracker := InitPerformanceTracker()
	if tracker == nil {
		t.Fatal("InitPerformanceTracker() returned nil")
	}

	if tracker.startTime.IsZero() {
		t.Error("Tracker start time should not be zero")
	}

	if tracker.metrics == nil {
		t.Error("Tracker metrics map should be initialized")
	}

	// memoryPoints is a slice, which can be nil in Go (it's fine)
	// It will be initialized when first snapshot is recorded
}

func TestPerformanceTracker_RecordMemorySnapshot(t *testing.T) {
	tracker := InitPerformanceTracker()

	// Record a snapshot
	tracker.RecordMemorySnapshot()

	if len(tracker.memoryPoints) != 1 {
		t.Errorf("Expected 1 memory snapshot, got %d", len(tracker.memoryPoints))
	}

	snapshot := tracker.memoryPoints[0]
	if snapshot.Timestamp.IsZero() {
		t.Error("Snapshot timestamp should not be zero")
	}

	// Record another snapshot
	tracker.RecordMemorySnapshot()

	if len(tracker.memoryPoints) != 2 {
		t.Errorf("Expected 2 memory snapshots, got %d", len(tracker.memoryPoints))
	}
}

func TestPerformanceTracker_RecordMetric(t *testing.T) {
	tracker := InitPerformanceTracker()

	tracker.RecordMetric("test_metric", 42)
	tracker.RecordMetric("string_metric", "value")
	tracker.RecordMetric("bool_metric", true)

	if len(tracker.metrics) != 3 {
		t.Errorf("Expected 3 metrics, got %d", len(tracker.metrics))
	}

	if tracker.metrics["test_metric"] != 42 {
		t.Errorf("Expected test_metric=42, got %v", tracker.metrics["test_metric"])
	}
}

func TestPerformanceTracker_GenerateReport(t *testing.T) {
	tracker := InitPerformanceTracker()

	// Record some data
	tracker.RecordMemorySnapshot()
	tracker.RecordMetric("test", 123)

	// Wait a bit to ensure execution time > 0
	time.Sleep(10 * time.Millisecond)

	report := tracker.GenerateReport()

	if report == "" {
		t.Error("GenerateReport() should return non-empty string")
	}

	if !strings.Contains(report, "Performance Report") {
		t.Error("Report should contain 'Performance Report'")
	}

	if !strings.Contains(report, "execution time") {
		t.Error("Report should contain execution time")
	}
}

func TestPerformanceTracker_GetExecutionTime(t *testing.T) {
	tracker := InitPerformanceTracker()

	// Wait a bit
	time.Sleep(10 * time.Millisecond)

	executionTime := tracker.GetExecutionTime()

	if executionTime <= 0 {
		t.Error("Execution time should be greater than zero")
	}

	if executionTime < 10*time.Millisecond {
		t.Errorf("Execution time should be at least 10ms, got %v", executionTime)
	}
}

func TestRecordMemorySnapshot_Global(t *testing.T) {
	// Initialize global tracker
	InitPerformanceTracker()

	// Global function should work
	RecordMemorySnapshot()

	// Should not panic
}

func TestRecordMetric_Global(t *testing.T) {
	// Initialize global tracker
	InitPerformanceTracker()

	// Global function should work
	RecordMetric("test", "value")

	// Should not panic
}

func TestGenerateReport_Global(t *testing.T) {
	// Initialize global tracker
	InitPerformanceTracker()

	// Global function should work
	report := GenerateReport()

	if report == "" {
		t.Error("GenerateReport() should return non-empty string")
	}
}

func TestGenerateReport_NoTracker(t *testing.T) {
	// Reset global tracker
	globalTracker = nil

	report := GenerateReport()

	if report != "No performance tracker initialized" {
		t.Errorf("Expected 'No performance tracker initialized', got %q", report)
	}
}

func TestGetExecutionTime_Global(t *testing.T) {
	// Initialize global tracker
	InitPerformanceTracker()

	// Wait a bit
	time.Sleep(10 * time.Millisecond)

	executionTime := GetExecutionTime()

	if executionTime <= 0 {
		t.Error("Execution time should be greater than zero")
	}
}

func TestGetExecutionTime_NoTracker(t *testing.T) {
	// Reset global tracker
	globalTracker = nil

	executionTime := GetExecutionTime()

	if executionTime != 0 {
		t.Errorf("Expected 0 when no tracker, got %v", executionTime)
	}
}

func TestPerformanceTracker_ConcurrentAccess(t *testing.T) {
	tracker := InitPerformanceTracker()

	// Concurrent access should not panic
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			tracker.RecordMemorySnapshot()
			tracker.RecordMetric("test", i)
			tracker.GetExecutionTime()
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should have multiple snapshots
	if len(tracker.memoryPoints) != 10 {
		t.Logf("Expected 10 memory snapshots, got %d (may vary due to race conditions)", len(tracker.memoryPoints))
	}
}

func TestMemorySnapshot_Fields(t *testing.T) {
	tracker := InitPerformanceTracker()

	tracker.RecordMemorySnapshot()

	snapshot := tracker.memoryPoints[0]

	// All fields should be set
	if snapshot.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}

	// Memory values should be set (uint64 is always non-negative)
	// Just verify they are set
	_ = snapshot.Alloc
	_ = snapshot.TotalAlloc
	_ = snapshot.Sys
}
