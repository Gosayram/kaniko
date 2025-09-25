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
	"fmt"
	"runtime"
	"sync"
	"time"
)

// PerformanceTracker tracks performance metrics and memory snapshots during execution
type PerformanceTracker struct {
	mu           sync.Mutex
	startTime    time.Time
	metrics      map[string]interface{}
	memoryPoints []MemorySnapshot
}

// MemorySnapshot captures memory statistics at a specific point in time
type MemorySnapshot struct {
	Timestamp  time.Time
	Alloc      uint64
	TotalAlloc uint64
	Sys        uint64
	NumGC      uint32
}

var (
	globalTracker *PerformanceTracker
)

// InitPerformanceTracker creates and initializes a new performance tracker
func InitPerformanceTracker() *PerformanceTracker {
	pt := &PerformanceTracker{
		startTime: time.Now(),
		metrics:   make(map[string]interface{}),
	}
	globalTracker = pt
	return pt
}

// RecordMemorySnapshot captures current memory statistics
func (pt *PerformanceTracker) RecordMemorySnapshot() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	pt.mu.Lock()
	defer pt.mu.Unlock()

	pt.memoryPoints = append(pt.memoryPoints, MemorySnapshot{
		Timestamp:  time.Now(),
		Alloc:      m.Alloc,
		TotalAlloc: m.TotalAlloc,
		Sys:        m.Sys,
		NumGC:      m.NumGC,
	})
}

// RecordMetric records a custom metric with the given name and value
func (pt *PerformanceTracker) RecordMetric(name string, value interface{}) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	pt.metrics[name] = value
}

// GenerateReport creates a formatted report of all tracked performance metrics
func (pt *PerformanceTracker) GenerateReport() string {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	report := "=== Performance Report ===\n"
	report += fmt.Sprintf("Total execution time: %v\n", time.Since(pt.startTime))

	if len(pt.memoryPoints) > 0 {
		lastPoint := pt.memoryPoints[len(pt.memoryPoints)-1]
		report += fmt.Sprintf("Final memory allocation: %d bytes\n", lastPoint.Alloc)
		report += fmt.Sprintf("Total memory allocated: %d bytes\n", lastPoint.TotalAlloc)
		report += fmt.Sprintf("Number of GC cycles: %d\n", lastPoint.NumGC)
	}

	for name, value := range pt.metrics {
		report += fmt.Sprintf("%s: %v\n", name, value)
	}

	return report
}

// GetExecutionTime returns the elapsed time since the tracker was initialized
func (pt *PerformanceTracker) GetExecutionTime() time.Duration {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	return time.Since(pt.startTime)
}

// RecordMemorySnapshot records a memory snapshot using the global tracker
func RecordMemorySnapshot() {
	if globalTracker != nil {
		globalTracker.RecordMemorySnapshot()
	}
}

// RecordMetric records a metric using the global tracker
func RecordMetric(name string, value interface{}) {
	if globalTracker != nil {
		globalTracker.RecordMetric(name, value)
	}
}

// GenerateReport generates a performance report using the global tracker
func GenerateReport() string {
	if globalTracker != nil {
		return globalTracker.GenerateReport()
	}
	return "No performance tracker initialized"
}

// GetExecutionTime returns execution time using the global tracker
func GetExecutionTime() time.Duration {
	if globalTracker != nil {
		return globalTracker.GetExecutionTime()
	}
	return 0
}
