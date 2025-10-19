package util

import (
	"fmt"
	"testing"
	"time"
)

func TestNewResourceLimits(t *testing.T) {
	// Test with default values
	rl := NewResourceLimits(0, 0, 0)

	if rl.MaxMemoryUsage != DefaultMaxMemoryUsage {
		t.Errorf("Expected MaxMemoryUsage %d, got %d", DefaultMaxMemoryUsage, rl.MaxMemoryUsage)
	}

	if rl.MaxFileSize != DefaultMaxFileSize {
		t.Errorf("Expected MaxFileSize %d, got %d", DefaultMaxFileSize, rl.MaxFileSize)
	}

	if rl.MaxTotalFileSize != DefaultMaxTotalFileSize {
		t.Errorf("Expected MaxTotalFileSize %d, got %d", DefaultMaxTotalFileSize, rl.MaxTotalFileSize)
	}

	if rl.GCThreshold != DefaultGCThreshold {
		t.Errorf("Expected GCThreshold %d, got %d", DefaultGCThreshold, rl.GCThreshold)
	}

	if rl.MonitoringInterval != DefaultMonitoringInterval {
		t.Errorf("Expected MonitoringInterval %v, got %v", DefaultMonitoringInterval, rl.MonitoringInterval)
	}
}

func TestResourceLimitsWithCustomValues(t *testing.T) {
	maxMemory := int64(1024 * 1024 * 1024)            // 1GB
	maxFileSize := int64(100 * 1024 * 1024)           // 100MB
	maxTotalFileSize := int64(5 * 1024 * 1024 * 1024) // 5GB

	rl := NewResourceLimits(maxMemory, maxFileSize, maxTotalFileSize)

	if rl.MaxMemoryUsage != maxMemory {
		t.Errorf("Expected MaxMemoryUsage %d, got %d", maxMemory, rl.MaxMemoryUsage)
	}

	if rl.MaxFileSize != maxFileSize {
		t.Errorf("Expected MaxFileSize %d, got %d", maxFileSize, rl.MaxFileSize)
	}

	if rl.MaxTotalFileSize != maxTotalFileSize {
		t.Errorf("Expected MaxTotalFileSize %d, got %d", maxTotalFileSize, rl.MaxTotalFileSize)
	}
}

func TestCheckFileSize(t *testing.T) {
	rl := NewResourceLimits(0, 100*1024*1024, 0) // 100MB file limit

	// Test valid file size
	err := rl.CheckFileSize("/test/file.txt", 50*1024*1024) // 50MB
	if err != nil {
		t.Errorf("Expected no error for valid file size, got %v", err)
	}

	// Test file size exceeding limit
	err = rl.CheckFileSize("/test/large.txt", 150*1024*1024) // 150MB
	if err == nil {
		t.Error("Expected error for file size exceeding limit")
	}

	// Test file size exceeding absolute maximum
	err = rl.CheckFileSize("/test/huge.txt", 2*1024*1024*1024) // 2GB
	if err == nil {
		t.Error("Expected error for file size exceeding absolute maximum")
	}
}

func TestCheckMemoryUsage(t *testing.T) {
	rl := NewResourceLimits(100*1024*1024, 0, 0) // 100MB memory limit

	// Test normal memory usage
	err := rl.CheckMemoryUsage()
	if err != nil {
		t.Errorf("Expected no error for normal memory usage, got %v", err)
	}
}

func TestMonitoring(t *testing.T) {
	rl := NewResourceLimits(0, 0, 0)

	// Test starting monitoring
	if rl.IsMonitoringEnabled() {
		t.Error("Expected monitoring to be disabled initially")
	}

	rl.StartMonitoring()
	if !rl.IsMonitoringEnabled() {
		t.Error("Expected monitoring to be enabled after StartMonitoring")
	}

	// Test stopping monitoring
	rl.StopMonitoring()
	if rl.IsMonitoringEnabled() {
		t.Error("Expected monitoring to be disabled after StopMonitoring")
	}
}

func TestStats(t *testing.T) {
	rl := NewResourceLimits(0, 0, 0)

	// Test initial stats
	stats := rl.GetStats()
	if stats.PeakMemoryUsage != 0 {
		t.Errorf("Expected initial PeakMemoryUsage 0, got %d", stats.PeakMemoryUsage)
	}

	if stats.TotalFilesProcessed != 0 {
		t.Errorf("Expected initial TotalFilesProcessed 0, got %d", stats.TotalFilesProcessed)
	}

	// Test file processing stats
	err := rl.CheckFileSize("/test/file1.txt", 10*1024*1024) // 10MB
	if err != nil {
		t.Errorf("Expected no error for valid file size, got %v", err)
	}

	stats = rl.GetStats()
	if stats.TotalFilesProcessed != 1 {
		t.Errorf("Expected TotalFilesProcessed 1, got %d", stats.TotalFilesProcessed)
	}

	if stats.TotalFileSize != 10*1024*1024 {
		t.Errorf("Expected TotalFileSize %d, got %d", 10*1024*1024, stats.TotalFileSize)
	}
}

func TestResetStats(t *testing.T) {
	rl := NewResourceLimits(0, 0, 0)

	// Process some files
	rl.CheckFileSize("/test/file1.txt", 10*1024*1024)
	rl.CheckFileSize("/test/file2.txt", 20*1024*1024)

	// Verify stats are updated
	stats := rl.GetStats()
	if stats.TotalFilesProcessed != 2 {
		t.Errorf("Expected TotalFilesProcessed 2, got %d", stats.TotalFilesProcessed)
	}

	// Reset stats
	rl.ResetStats()

	// Verify stats are reset
	stats = rl.GetStats()
	if stats.TotalFilesProcessed != 0 {
		t.Errorf("Expected TotalFilesProcessed 0 after reset, got %d", stats.TotalFilesProcessed)
	}

	if stats.TotalFileSize != 0 {
		t.Errorf("Expected TotalFileSize 0 after reset, got %d", stats.TotalFileSize)
	}
}

func TestSetGCThreshold(t *testing.T) {
	rl := NewResourceLimits(0, 0, 0)

	// Test valid threshold
	rl.SetGCThreshold(70)
	if rl.GCThreshold != 70 {
		t.Errorf("Expected GCThreshold 70, got %d", rl.GCThreshold)
	}

	// Test invalid threshold (too low)
	rl.SetGCThreshold(0)
	if rl.GCThreshold != DefaultGCThreshold {
		t.Errorf("Expected GCThreshold %d for invalid input, got %d", DefaultGCThreshold, rl.GCThreshold)
	}

	// Test invalid threshold (too high)
	rl.SetGCThreshold(101)
	if rl.GCThreshold != DefaultGCThreshold {
		t.Errorf("Expected GCThreshold %d for invalid input, got %d", DefaultGCThreshold, rl.GCThreshold)
	}
}

func TestSetMonitoringInterval(t *testing.T) {
	rl := NewResourceLimits(0, 0, 0)

	// Test valid interval
	interval := 10 * time.Second
	rl.SetMonitoringInterval(interval)
	if rl.MonitoringInterval != interval {
		t.Errorf("Expected MonitoringInterval %v, got %v", interval, rl.MonitoringInterval)
	}

	// Test invalid interval (too short)
	rl.SetMonitoringInterval(100 * time.Millisecond)
	if rl.MonitoringInterval != DefaultMonitoringInterval {
		t.Errorf("Expected MonitoringInterval %v for invalid input, got %v", DefaultMonitoringInterval, rl.MonitoringInterval)
	}
}

func TestGetCurrentMemoryUsage(t *testing.T) {
	rl := NewResourceLimits(0, 0, 0)

	// Get memory usage

	usage := rl.GetCurrentMemoryUsage()
	if usage <= 0 {
		t.Error("Expected positive memory usage")
	}
}

func TestGetCurrentFileSize(t *testing.T) {
	rl := NewResourceLimits(0, 0, 0)

	// Process some files
	rl.CheckFileSize("/test/file1.txt", 10*1024*1024)
	rl.CheckFileSize("/test/file2.txt", 20*1024*1024)

	currentSize := rl.GetCurrentFileSize()
	expectedSize := int64(30 * 1024 * 1024)
	if currentSize != expectedSize {
		t.Errorf("Expected current file size %d, got %d", expectedSize, currentSize)
	}
}

func TestGetTotalFilesProcessed(t *testing.T) {
	rl := NewResourceLimits(0, 0, 0)

	// Process some files
	rl.CheckFileSize("/test/file1.txt", 10*1024*1024)
	rl.CheckFileSize("/test/file2.txt", 20*1024*1024)
	rl.CheckFileSize("/test/file3.txt", 30*1024*1024)

	totalFiles := rl.GetTotalFilesProcessed()
	if totalFiles != 3 {
		t.Errorf("Expected total files processed 3, got %d", totalFiles)
	}
}

func TestResourceLimitsIntegration(t *testing.T) {
	// Create resource limits with small limits for testing
	rl := NewResourceLimits(50*1024*1024, 10*1024*1024, 30*1024*1024) // 50MB memory, 10MB file, 30MB total

	// Test file size limits
	err := rl.CheckFileSize("/test/small.txt", 5*1024*1024) // 5MB
	if err != nil {
		t.Errorf("Expected no error for small file, got %v", err)
	}

	err = rl.CheckFileSize("/test/medium.txt", 8*1024*1024) // 8MB
	if err != nil {
		t.Errorf("Expected no error for medium file, got %v", err)
	}

	// Test total file size limit
	err = rl.CheckFileSize("/test/large.txt", 20*1024*1024) // 20MB (total would be 33MB, exceeding 30MB limit)
	if err == nil {
		t.Error("Expected error for total file size exceeding limit")
	}

	// Test memory usage
	err = rl.CheckMemoryUsage()
	if err != nil {
		t.Errorf("Expected no error for normal memory usage, got %v", err)
	}

	// Test stats
	stats := rl.GetStats()
	if stats.TotalFilesProcessed != 2 { // Only 2 files processed successfully
		t.Errorf("Expected TotalFilesProcessed 2, got %d", stats.TotalFilesProcessed)
	}

	if stats.TotalFileSize != 13*1024*1024 { // 5MB + 8MB = 13MB
		t.Errorf("Expected TotalFileSize %d, got %d", 13*1024*1024, stats.TotalFileSize)
	}
}

func TestResourceLimitsConcurrency(t *testing.T) {
	rl := NewResourceLimits(0, 0, 0)

	// Test concurrent access
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- true }()

			// Simulate file processing
			for j := 0; j < 10; j++ {
				filePath := fmt.Sprintf("/test/file_%d_%d.txt", id, j)
				fileSize := int64((id + j + 1) * 1024 * 1024) // 1MB to 20MB

				err := rl.CheckFileSize(filePath, fileSize)
				if err != nil {
					t.Errorf("Error processing file %s: %v", filePath, err)
				}
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify final stats
	stats := rl.GetStats()
	expectedFiles := int64(100) // 10 goroutines * 10 files each
	if stats.TotalFilesProcessed != expectedFiles {
		t.Errorf("Expected TotalFilesProcessed %d, got %d", expectedFiles, stats.TotalFilesProcessed)
	}
}
