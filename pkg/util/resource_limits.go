/*
Copyright 2024 Kaniko Contributors

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

package util

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Constants for resource limits
const (
	// Default memory limits
	DefaultMaxMemoryUsage   = 2 * 1024 * 1024 * 1024  // 2GB
	DefaultMaxFileSize      = 500 * 1024 * 1024       // 500MB
	DefaultMaxTotalFileSize = 10 * 1024 * 1024 * 1024 // 10GB

	// Memory monitoring thresholds
	DefaultGCThreshold        = 80 // 80% memory usage triggers GC
	DefaultMonitoringInterval = 5 * time.Second

	// File size limits
	MaxSingleFileSize = 1024 * 1024 * 1024 // 1GB max single file

	// File count limits
	// Increased from 100k to 1M to support larger monorepos
	DefaultMaxFilesProcessed = 1000000 // 1M files max per operation
)

// ResourceLimits provides resource control and monitoring
type ResourceLimits struct {
	// Memory limits
	MaxMemoryUsage    int64
	MaxFileSize       int64
	MaxTotalFileSize  int64
	MaxFilesProcessed int64 // Maximum number of files to process

	// Monitoring settings
	GCThreshold        int
	MonitoringInterval time.Duration

	// Current state
	currentMemoryUsage int64
	currentFileSize    int64

	// Monitoring
	monitoringEnabled bool
	stopMonitoring    chan bool
	monitoringMutex   sync.RWMutex

	// Statistics
	stats ResourceStats
}

// ResourceStats holds statistics about resource usage
type ResourceStats struct {
	PeakMemoryUsage     int64
	TotalFilesProcessed int64
	TotalFileSize       int64
	GCTriggered         int64
	WarningsIssued      int64
	StartTime           time.Time
	LastGC              time.Time
}

// CheckFileCount checks if the number of files being processed is within limits
func (rl *ResourceLimits) CheckFileCount(fileCount int64) error {
	rl.monitoringMutex.Lock()
	defer rl.monitoringMutex.Unlock()

	if rl.MaxFilesProcessed > 0 && fileCount > rl.MaxFilesProcessed {
		rl.stats.WarningsIssued++
		return fmt.Errorf("file count %d exceeds limit %d", fileCount, rl.MaxFilesProcessed)
	}

	return nil
}

// NewResourceLimits creates a new resource limits controller
func NewResourceLimits(maxMemory, maxFileSize, maxTotalFileSize int64) *ResourceLimits {
	if maxMemory <= 0 {
		maxMemory = DefaultMaxMemoryUsage
	}
	if maxFileSize <= 0 {
		maxFileSize = DefaultMaxFileSize
	}
	if maxTotalFileSize <= 0 {
		maxTotalFileSize = DefaultMaxTotalFileSize
	}

	// Get max files from environment or use default
	maxFiles := int64(DefaultMaxFilesProcessed)
	if maxFilesStr := os.Getenv("MAX_FILES_PROCESSED"); maxFilesStr != "" {
		if parsed, err := strconv.ParseInt(maxFilesStr, 10, 64); err == nil && parsed > 0 {
			maxFiles = parsed
		}
	}

	rl := &ResourceLimits{
		MaxMemoryUsage:     maxMemory,
		MaxFileSize:        maxFileSize,
		MaxTotalFileSize:   maxTotalFileSize,
		MaxFilesProcessed:  maxFiles,
		GCThreshold:        DefaultGCThreshold,
		MonitoringInterval: DefaultMonitoringInterval,
		stopMonitoring:     make(chan bool),
		stats: ResourceStats{
			StartTime: time.Now(),
		},
	}

	//nolint:mnd // Constants for MB conversion
	logrus.Infof("Resource limits initialized: Memory=%dMB, File=%dMB, Total=%dMB, MaxFiles=%d",
		maxMemory/(1024*1024), maxFileSize/(1024*1024), maxTotalFileSize/(1024*1024), maxFiles)

	return rl
}

// StartMonitoring starts background resource monitoring
func (rl *ResourceLimits) StartMonitoring() {
	if rl.monitoringEnabled {
		return
	}

	rl.monitoringEnabled = true
	go rl.monitorResources()

	logrus.Info("Resource monitoring started")
}

// StopMonitoring stops background resource monitoring
func (rl *ResourceLimits) StopMonitoring() {
	if !rl.monitoringEnabled {
		return
	}

	rl.monitoringEnabled = false
	rl.stopMonitoring <- true

	logrus.Info("Resource monitoring stopped")
}

// monitorResources runs background monitoring
func (rl *ResourceLimits) monitorResources() {
	ticker := time.NewTicker(rl.MonitoringInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.checkResourceUsage()
		case <-rl.stopMonitoring:
			return
		}
	}
}

// checkResourceUsage checks current resource usage and triggers actions
func (rl *ResourceLimits) checkResourceUsage() {
	rl.monitoringMutex.Lock()
	defer rl.monitoringMutex.Unlock()

	// Get current memory usage
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	// #nosec G115 - Memory stats conversion is safe
	currentUsage := int64(m.Alloc)
	rl.currentMemoryUsage = currentUsage

	// Update peak memory usage
	if currentUsage > rl.stats.PeakMemoryUsage {
		rl.stats.PeakMemoryUsage = currentUsage
	}

	// Check memory threshold
	//nolint:mnd // Percentage calculation
	memoryPercent := float64(currentUsage) / float64(rl.MaxMemoryUsage) * 100

	if memoryPercent >= float64(rl.GCThreshold) {
		//nolint:mnd // Constants for MB conversion
		logrus.Warnf("High memory usage detected: %.1f%% (%dMB/%dMB). Triggering GC.",
			memoryPercent, currentUsage/(1024*1024), rl.MaxMemoryUsage/(1024*1024))

		rl.triggerGC()
		rl.stats.GCTriggered++
		rl.stats.LastGC = time.Now()
	}

	// Log resource usage periodically
	if rl.stats.TotalFilesProcessed%100 == 0 && rl.stats.TotalFilesProcessed > 0 {
		//nolint:mnd // Constants for MB conversion
		logrus.Debugf("Resource usage: Memory=%.1f%% (%dMB), Files=%d, TotalSize=%dMB",
			memoryPercent, currentUsage/(1024*1024), rl.stats.TotalFilesProcessed, rl.stats.TotalFileSize/(1024*1024))
	}
}

// triggerGC forces garbage collection
func (rl *ResourceLimits) triggerGC() {
	logrus.Debug("🧹 Triggering garbage collection")

	// Force multiple GC cycles for better cleanup
	for i := 0; i < 3; i++ {
		runtime.GC()
		runtime.Gosched() // Allow other goroutines to run
	}

	// Log memory after GC
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	//nolint:mnd // Constants for MB conversion
	logrus.Debugf("🧹 GC completed. Memory after GC: %dMB", m.Alloc/(1024*1024))
}

// CheckFileSize checks if a file size is within limits
func (rl *ResourceLimits) CheckFileSize(filePath string, fileSize int64) error {
	rl.monitoringMutex.Lock()
	defer rl.monitoringMutex.Unlock()

	// Check single file size limit
	if fileSize > rl.MaxFileSize {
		rl.stats.WarningsIssued++
		//nolint:mnd // Constants for MB conversion
		return fmt.Errorf("file size %dMB exceeds limit %dMB: %s",
			fileSize/(1024*1024), rl.MaxFileSize/(1024*1024), filePath)
	}

	// Check absolute maximum file size
	if fileSize > MaxSingleFileSize {
		rl.stats.WarningsIssued++
		//nolint:mnd // Constants for MB conversion
		return fmt.Errorf("file size %dMB exceeds absolute maximum %dMB: %s",
			fileSize/(1024*1024), MaxSingleFileSize/(1024*1024), filePath)
	}

	// Update current file size
	rl.currentFileSize += fileSize
	rl.stats.TotalFileSize += fileSize
	rl.stats.TotalFilesProcessed++

	// Check total file size limit
	if rl.stats.TotalFileSize > rl.MaxTotalFileSize {
		rl.stats.WarningsIssued++
		//nolint:mnd // Constants for MB conversion
		return fmt.Errorf("total file size %dMB exceeds limit %dMB",
			rl.stats.TotalFileSize/(1024*1024), rl.MaxTotalFileSize/(1024*1024))
	}

	//nolint:mnd // Constants for MB conversion
	logrus.Debugf("File size check passed: %s (%dMB)", filePath, fileSize/(1024*1024))
	return nil
}

// CheckMemoryUsage checks if current memory usage is within limits
func (rl *ResourceLimits) CheckMemoryUsage() error {
	rl.monitoringMutex.RLock()
	defer rl.monitoringMutex.RUnlock()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	// #nosec G115 - Memory stats conversion is safe
	currentUsage := int64(m.Alloc)

	if currentUsage > rl.MaxMemoryUsage {
		rl.stats.WarningsIssued++
		//nolint:mnd // Constants for MB conversion
		return fmt.Errorf("memory usage %dMB exceeds limit %dMB",
			currentUsage/(1024*1024), rl.MaxMemoryUsage/(1024*1024))
	}

	return nil
}

// GetStats returns current resource statistics
func (rl *ResourceLimits) GetStats() ResourceStats {
	rl.monitoringMutex.RLock()
	defer rl.monitoringMutex.RUnlock()

	// Update current memory usage
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	// #nosec G115 - Memory stats conversion is safe
	rl.currentMemoryUsage = int64(m.Alloc)

	return rl.stats
}

// LogStats logs current resource statistics
func (rl *ResourceLimits) LogStats() {
	stats := rl.GetStats()

	logrus.Infof("Resource Statistics:")
	//nolint:mnd // Constants for MB conversion
	logrus.Infof("  🧠 Peak Memory Usage: %dMB", stats.PeakMemoryUsage/(1024*1024))
	logrus.Infof("  Total Files Processed: %d", stats.TotalFilesProcessed)
	//nolint:mnd // Constants for MB conversion
	logrus.Infof("  Total File Size: %dMB", stats.TotalFileSize/(1024*1024))
	logrus.Infof("  🧹 GC Triggered: %d times", stats.GCTriggered)
	logrus.Infof("  Warnings Issued: %d", stats.WarningsIssued)
	logrus.Infof("  Runtime: %v", time.Since(stats.StartTime))

	if !stats.LastGC.IsZero() {
		logrus.Infof("  🧹 Last GC: %v ago", time.Since(stats.LastGC))
	}
}

// ResetStats resets resource statistics
func (rl *ResourceLimits) ResetStats() {
	rl.monitoringMutex.Lock()
	defer rl.monitoringMutex.Unlock()

	rl.stats = ResourceStats{
		StartTime: time.Now(),
	}
	rl.currentFileSize = 0
	rl.stats.TotalFilesProcessed = 0
	rl.stats.TotalFileSize = 0

	logrus.Info("Resource statistics reset")
}

// IsMonitoringEnabled returns whether monitoring is enabled
func (rl *ResourceLimits) IsMonitoringEnabled() bool {
	return rl.monitoringEnabled
}

// SetGCThreshold sets the garbage collection threshold
func (rl *ResourceLimits) SetGCThreshold(threshold int) {
	if threshold < 1 || threshold > 100 {
		threshold = DefaultGCThreshold
	}

	rl.monitoringMutex.Lock()
	defer rl.monitoringMutex.Unlock()

	rl.GCThreshold = threshold
	logrus.Infof("GC threshold set to %d%%", threshold)
}

// SetMonitoringInterval sets the monitoring interval
func (rl *ResourceLimits) SetMonitoringInterval(interval time.Duration) {
	if interval < time.Second {
		interval = DefaultMonitoringInterval
	}

	rl.monitoringMutex.Lock()
	defer rl.monitoringMutex.Unlock()

	rl.MonitoringInterval = interval
	logrus.Infof("Monitoring interval set to %v", interval)
}

// GetCurrentMemoryUsage returns current memory usage
func (rl *ResourceLimits) GetCurrentMemoryUsage() int64 {
	rl.monitoringMutex.RLock()
	defer rl.monitoringMutex.RUnlock()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	// #nosec G115 - Memory stats conversion is safe
	return int64(m.Alloc)
}

// GetCurrentFileSize returns current total file size
func (rl *ResourceLimits) GetCurrentFileSize() int64 {
	rl.monitoringMutex.RLock()
	defer rl.monitoringMutex.RUnlock()

	return rl.stats.TotalFileSize
}

// GetTotalFilesProcessed returns total files processed
func (rl *ResourceLimits) GetTotalFilesProcessed() int64 {
	rl.monitoringMutex.RLock()
	defer rl.monitoringMutex.RUnlock()

	return rl.stats.TotalFilesProcessed
}
