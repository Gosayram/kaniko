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

type PerformanceTracker struct {
	mu           sync.Mutex
	startTime    time.Time
	metrics      map[string]interface{}
	memoryPoints []MemorySnapshot
}

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

func InitPerformanceTracker() *PerformanceTracker {
	pt := &PerformanceTracker{
		startTime: time.Now(),
		metrics:   make(map[string]interface{}),
	}
	globalTracker = pt
	return pt
}

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

func (pt *PerformanceTracker) RecordMetric(name string, value interface{}) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	pt.metrics[name] = value
}

func (pt *PerformanceTracker) GenerateReport() string {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	report := fmt.Sprintf("=== Performance Report ===\n")
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

func (pt *PerformanceTracker) GetExecutionTime() time.Duration {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	return time.Since(pt.startTime)
}

// Global functions for convenience
func RecordMemorySnapshot() {
	if globalTracker != nil {
		globalTracker.RecordMemorySnapshot()
	}
}

func RecordMetric(name string, value interface{}) {
	if globalTracker != nil {
		globalTracker.RecordMetric(name, value)
	}
}

func GenerateReport() string {
	if globalTracker != nil {
		return globalTracker.GenerateReport()
	}
	return "No performance tracker initialized"
}

func GetExecutionTime() time.Duration {
	if globalTracker != nil {
		return globalTracker.GetExecutionTime()
	}
	return 0
}
