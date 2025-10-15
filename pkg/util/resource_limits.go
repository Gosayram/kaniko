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
	"runtime"
	"sync"
	"time"
)

// ResourceLimits provides global resource management
type ResourceLimits struct {
	MaxMemoryUsage   int64         // Maximum memory usage in bytes
	MaxFileSize      int64         // Maximum file size in bytes
	MaxTotalFileSize int64         // Maximum total file size in bytes
	MaxExecutionTime time.Duration // Maximum execution time
	MaxConcurrency   int           // Maximum number of concurrent operations
	CheckInterval    time.Duration // How often to check resource usage
	mu               sync.RWMutex
	startTime        time.Time
	totalFileSize    int64
	concurrentOps    int
	stopChan         chan struct{}
	checkTicker      *time.Ticker
}

// ResourceStats provides current resource usage statistics
type ResourceStats struct {
	MemoryUsage      uint64        `json:"memory_usage"`
	MemoryLimit      int64         `json:"memory_limit"`
	FileSize         int64         `json:"file_size"`
	FileSizeLimit    int64         `json:"file_size_limit"`
	TotalFileSize    int64         `json:"total_file_size"`
	TotalFileLimit   int64         `json:"total_file_limit"`
	ExecutionTime    time.Duration `json:"execution_time"`
	ExecutionLimit   time.Duration `json:"execution_limit"`
	ConcurrentOps    int           `json:"concurrent_ops"`
	ConcurrencyLimit int           `json:"concurrency_limit"`
	GCs              int64         `json:"gc_cycles"`
}

// NewResourceLimits creates a new resource limits manager
func NewResourceLimits() *ResourceLimits {
	limits := &ResourceLimits{
		MaxMemoryUsage:   2 * 1024 * 1024 * 1024,  // 2GB default
		MaxFileSize:      500 * 1024 * 1024,       // 500MB default
		MaxTotalFileSize: 10 * 1024 * 1024 * 1024, // 10GB default
		MaxExecutionTime: 30 * time.Minute,        // 30 minutes default
		MaxConcurrency:   10,                      // 10 concurrent operations default
		CheckInterval:    5 * time.Second,         // Check every 5 seconds
		startTime:        time.Now(),
		stopChan:         make(chan struct{}),
	}

	// Start monitoring goroutine
	limits.startMonitoring()

	return limits
}

// SetLimits sets resource limits
func (rl *ResourceLimits) SetLimits(memory, fileSize, totalFileSize int64, executionTime time.Duration, concurrency int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.MaxMemoryUsage = memory
	rl.MaxFileSize = fileSize
	rl.MaxTotalFileSize = totalFileSize
	rl.MaxExecutionTime = executionTime
	rl.MaxConcurrency = concurrency
}

// CheckMemoryUsage checks if memory usage is within limits
func (rl *ResourceLimits) CheckMemoryUsage() error {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	rl.mu.RLock()
	limit := rl.MaxMemoryUsage
	rl.mu.RUnlock()

	if m.Alloc > uint64(limit) {
		return fmt.Errorf("memory limit exceeded: %d bytes (limit: %d bytes)", m.Alloc, limit)
	}

	return nil
}

// CheckFileSize checks if file size is within limits
func (rl *ResourceLimits) CheckFileSize(fileSize int64) error {
	rl.mu.RLock()
	limit := rl.MaxFileSize
	rl.mu.RUnlock()

	if fileSize > limit {
		return fmt.Errorf("file size limit exceeded: %d bytes (limit: %d bytes)", fileSize, limit)
	}

	return nil
}

// CheckTotalFileSize checks if total file size is within limits
func (rl *ResourceLimits) CheckTotalFileSize(additionalSize int64) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	newTotal := rl.totalFileSize + additionalSize
	if newTotal > rl.MaxTotalFileSize {
		return fmt.Errorf("total file size limit exceeded: %d bytes (limit: %d bytes)", newTotal, rl.MaxTotalFileSize)
	}

	rl.totalFileSize = newTotal
	return nil
}

// CheckExecutionTime checks if execution time is within limits
func (rl *ResourceLimits) CheckExecutionTime() error {
	rl.mu.RLock()
	limit := rl.MaxExecutionTime
	rl.mu.RUnlock()

	elapsed := time.Since(rl.startTime)
	if elapsed > limit {
		return fmt.Errorf("execution time limit exceeded: %v (limit: %v)", elapsed, limit)
	}

	return nil
}

// CheckConcurrency checks if concurrency is within limits
func (rl *ResourceLimits) CheckConcurrency() error {
	rl.mu.RLock()
	limit := rl.MaxConcurrency
	current := rl.concurrentOps
	rl.mu.RUnlock()

	if current >= limit {
		return fmt.Errorf("concurrency limit exceeded: %d (limit: %d)", current, limit)
	}

	return nil
}

// AcquireConcurrencySlot acquires a concurrency slot
func (rl *ResourceLimits) AcquireConcurrencySlot() error {
	if err := rl.CheckConcurrency(); err != nil {
		return err
	}

	rl.mu.Lock()
	rl.concurrentOps++
	rl.mu.Unlock()

	return nil
}

// ReleaseConcurrencySlot releases a concurrency slot
func (rl *ResourceLimits) ReleaseConcurrencySlot() {
	rl.mu.Lock()
	if rl.concurrentOps > 0 {
		rl.concurrentOps--
	}
	rl.mu.Unlock()
}

// CheckAllLimits checks all resource limits
func (rl *ResourceLimits) CheckAllLimits() error {
	// Check memory usage
	if err := rl.CheckMemoryUsage(); err != nil {
		return fmt.Errorf("memory check failed: %w", err)
	}

	// Check execution time
	if err := rl.CheckExecutionTime(); err != nil {
		return fmt.Errorf("execution time check failed: %w", err)
	}

	// Check concurrency
	if err := rl.CheckConcurrency(); err != nil {
		return fmt.Errorf("concurrency check failed: %w", err)
	}

	return nil
}

// GetStats returns current resource usage statistics
func (rl *ResourceLimits) GetStats() ResourceStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	rl.mu.RLock()
	defer rl.mu.RUnlock()

	return ResourceStats{
		MemoryUsage:      m.Alloc,
		MemoryLimit:      rl.MaxMemoryUsage,
		FileSize:         0, // Would be set by caller
		FileSizeLimit:    rl.MaxFileSize,
		TotalFileSize:    rl.totalFileSize,
		TotalFileLimit:   rl.MaxTotalFileSize,
		ExecutionTime:    time.Since(rl.startTime),
		ExecutionLimit:   rl.MaxExecutionTime,
		ConcurrentOps:    rl.concurrentOps,
		ConcurrencyLimit: rl.MaxConcurrency,
		GCs:              int64(m.NumGC),
	}
}

// startMonitoring starts the resource monitoring goroutine
func (rl *ResourceLimits) startMonitoring() {
	rl.checkTicker = time.NewTicker(rl.CheckInterval)

	go func() {
		for {
			select {
			case <-rl.checkTicker.C:
				rl.monitorResources()
			case <-rl.stopChan:
				return
			}
		}
	}()
}

// monitorResources monitors resource usage and takes action if needed
func (rl *ResourceLimits) monitorResources() {
	// Check all limits
	if err := rl.CheckAllLimits(); err != nil {
		// Log warning but don't fail - this is just monitoring
		// In a real implementation, you might want to take action
		// like triggering garbage collection or reducing concurrency
	}

	// Force garbage collection if memory usage is high
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	rl.mu.RLock()
	memoryLimit := rl.MaxMemoryUsage
	rl.mu.RUnlock()

	if m.Alloc > uint64(memoryLimit)*3/4 { // If using more than 75% of limit
		runtime.GC()
	}
}

// Reset resets resource limits to initial state
func (rl *ResourceLimits) Reset() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.startTime = time.Now()
	rl.totalFileSize = 0
	rl.concurrentOps = 0
}

// Close stops the resource monitoring
func (rl *ResourceLimits) Close() {
	if rl.checkTicker != nil {
		rl.checkTicker.Stop()
	}
	close(rl.stopChan)
}

// Global resource limits instance
var (
	globalResourceLimits *ResourceLimits
	resourceLimitsOnce   sync.Once
)

// GetGlobalResourceLimits returns the global resource limits
func GetGlobalResourceLimits() *ResourceLimits {
	resourceLimitsOnce.Do(func() {
		globalResourceLimits = NewResourceLimits()
	})
	return globalResourceLimits
}

// CheckGlobalMemoryUsage is a convenience function that uses the global limits
func CheckGlobalMemoryUsage() error {
	return GetGlobalResourceLimits().CheckMemoryUsage()
}

// CheckGlobalFileSize is a convenience function that uses the global limits
func CheckGlobalFileSize(fileSize int64) error {
	return GetGlobalResourceLimits().CheckFileSize(fileSize)
}

// CheckGlobalTotalFileSize is a convenience function that uses the global limits
func CheckGlobalTotalFileSize(additionalSize int64) error {
	return GetGlobalResourceLimits().CheckTotalFileSize(additionalSize)
}

// CheckGlobalExecutionTime is a convenience function that uses the global limits
func CheckGlobalExecutionTime() error {
	return GetGlobalResourceLimits().CheckExecutionTime()
}

// AcquireGlobalConcurrencySlot is a convenience function that uses the global limits
func AcquireGlobalConcurrencySlot() error {
	return GetGlobalResourceLimits().AcquireConcurrencySlot()
}

// ReleaseGlobalConcurrencySlot is a convenience function that uses the global limits
func ReleaseGlobalConcurrencySlot() {
	GetGlobalResourceLimits().ReleaseConcurrencySlot()
}
