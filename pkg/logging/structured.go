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
	"encoding/json"
	"fmt"
	"math"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Constants for calculations
const (
	percentageMultiplier = 100
	averageDivisor       = 2
)

// StructuredLogger provides enhanced structured logging with context and performance tracking
type StructuredLogger struct {
	// Core logging
	logger       *logrus.Logger
	context      map[string]interface{}
	contextMutex sync.RWMutex

	// Performance tracking
	performanceTracker *PerformanceTracker
	metricsCollector   *MetricsCollector

	// Configuration
	enableStructured  bool
	enablePerformance bool
	enableMetrics     bool
	logLevel          string
	outputFormat      string
}

// PerformanceTracker tracks performance metrics
type PerformanceTracker struct {
	operations map[string]*OperationMetrics
	mutex      sync.RWMutex
	startTime  time.Time
}

// OperationMetrics tracks metrics for a specific operation
type OperationMetrics struct {
	Name        string        `json:"name"`
	Count       int64         `json:"count"`
	TotalTime   time.Duration `json:"total_time"`
	AverageTime time.Duration `json:"average_time"`
	MinTime     time.Duration `json:"min_time"`
	MaxTime     time.Duration `json:"max_time"`
	LastTime    time.Time     `json:"last_time"`
	Errors      int64         `json:"errors"`
	SuccessRate float64       `json:"success_rate"`
}

// MetricsCollector collects and aggregates metrics
type MetricsCollector struct {
	metrics   map[string]interface{}
	mutex     sync.RWMutex
	startTime time.Time
}

// LogContext represents a logging context
type LogContext struct {
	BuildID     string                 `json:"build_id"`
	Stage       string                 `json:"stage"`
	Command     string                 `json:"command"`
	File        string                 `json:"file"`
	Line        int                    `json:"line"`
	Function    string                 `json:"function"`
	Timestamp   time.Time              `json:"timestamp"`
	Level       string                 `json:"level"`
	Message     string                 `json:"message"`
	Fields      map[string]interface{} `json:"fields"`
	Performance *PerformanceData       `json:"performance,omitempty"`
	Memory      *MemoryData            `json:"memory,omitempty"`
	Error       *ErrorData             `json:"error,omitempty"`
}

// PerformanceData contains performance information
type PerformanceData struct {
	Operation   string        `json:"operation"`
	Duration    time.Duration `json:"duration"`
	StartTime   time.Time     `json:"start_time"`
	EndTime     time.Time     `json:"end_time"`
	CPUUsage    float64       `json:"cpu_usage"`
	MemoryUsage int64         `json:"memory_usage"`
	Throughput  float64       `json:"throughput"`
}

// MemoryData contains memory information
type MemoryData struct {
	Allocated  int64   `json:"allocated"`
	Used       int64   `json:"used"`
	Free       int64   `json:"free"`
	Percentage float64 `json:"percentage"`
	GC         int64   `json:"gc_count"`
	HeapSize   int64   `json:"heap_size"`
	StackSize  int64   `json:"stack_size"`
}

// ErrorData contains error information
type ErrorData struct {
	Type        string                 `json:"type"`
	Message     string                 `json:"message"`
	Stack       string                 `json:"stack"`
	Context     map[string]interface{} `json:"context"`
	Recoverable bool                   `json:"recoverable"`
	Severity    string                 `json:"severity"`
}

// NewStructuredLogger creates a new structured logger
func NewStructuredLogger(
	enableStructured, enablePerformance, enableMetrics bool,
	logLevel, outputFormat string) *StructuredLogger {
	logger := logrus.New()

	// Configure logger
	switch outputFormat {
	case "json":
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339Nano,
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "timestamp",
				logrus.FieldKeyLevel: "level",
				logrus.FieldKeyMsg:   "message",
			},
		})
	case "text":
		logger.SetFormatter(&logrus.TextFormatter{
			TimestampFormat: time.RFC3339Nano,
			FullTimestamp:   true,
		})
	default:
		logger.SetFormatter(&logrus.TextFormatter{
			TimestampFormat: time.RFC3339Nano,
			FullTimestamp:   true,
		})
	}

	// Set log level
	const defaultLevel = "info"
	switch logLevel {
	case "trace":
		logger.SetLevel(logrus.TraceLevel)
	case "debug":
		logger.SetLevel(logrus.DebugLevel)
	case defaultLevel:
		logger.SetLevel(logrus.InfoLevel)
	case "warn":
		logger.SetLevel(logrus.WarnLevel)
	case LevelError:
		logger.SetLevel(logrus.ErrorLevel)
	default:
		logger.SetLevel(logrus.InfoLevel)
	}

	// Set output
	logger.SetOutput(os.Stdout)

	sl := &StructuredLogger{
		logger:             logger,
		context:            make(map[string]interface{}),
		performanceTracker: NewPerformanceTracker(),
		metricsCollector:   NewMetricsCollector(),
		enableStructured:   enableStructured,
		enablePerformance:  enablePerformance,
		enableMetrics:      enableMetrics,
		logLevel:           logLevel,
		outputFormat:       outputFormat,
	}

	// Add default context
	sl.SetContext("logger", "structured")
	sl.SetContext("version", "1.0.0")
	sl.SetContext("go_version", runtime.Version())

	return sl
}

// NewPerformanceTracker creates a new performance tracker
func NewPerformanceTracker() *PerformanceTracker {
	return &PerformanceTracker{
		operations: make(map[string]*OperationMetrics),
		startTime:  time.Now(),
	}
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		metrics:   make(map[string]interface{}),
		startTime: time.Now(),
	}
}

// SetContext sets a context value
func (sl *StructuredLogger) SetContext(key string, value interface{}) {
	sl.contextMutex.Lock()
	defer sl.contextMutex.Unlock()

	sl.context[key] = value
}

// GetContext gets a context value
func (sl *StructuredLogger) GetContext(key string) (interface{}, bool) {
	sl.contextMutex.RLock()
	defer sl.contextMutex.RUnlock()

	value, exists := sl.context[key]
	return value, exists
}

// RemoveContext removes a context value
func (sl *StructuredLogger) RemoveContext(key string) {
	sl.contextMutex.Lock()
	defer sl.contextMutex.Unlock()

	delete(sl.context, key)
}

// ClearContext clears all context
func (sl *StructuredLogger) ClearContext() {
	sl.contextMutex.Lock()
	defer sl.contextMutex.Unlock()

	sl.context = make(map[string]interface{})
}

// WithContext creates a new logger with additional context
func (sl *StructuredLogger) WithContext(ctx map[string]interface{}) *StructuredLogger {
	newLogger := &StructuredLogger{
		logger:             sl.logger,
		context:            make(map[string]interface{}),
		performanceTracker: sl.performanceTracker,
		metricsCollector:   sl.metricsCollector,
		enableStructured:   sl.enableStructured,
		enablePerformance:  sl.enablePerformance,
		enableMetrics:      sl.enableMetrics,
		logLevel:           sl.logLevel,
		outputFormat:       sl.outputFormat,
	}

	// Copy existing context
	sl.contextMutex.RLock()
	for k, v := range sl.context {
		newLogger.context[k] = v
	}
	sl.contextMutex.RUnlock()

	// Add new context
	for k, v := range ctx {
		newLogger.context[k] = v
	}

	return newLogger
}

// StartOperation starts tracking an operation
func (sl *StructuredLogger) StartOperation(operation string) *OperationTracker {
	if !sl.enablePerformance {
		return &OperationTracker{logger: sl, operation: operation}
	}

	tracker := &OperationTracker{
		logger:    sl,
		operation: operation,
		startTime: time.Now(),
	}

	// Get memory stats
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	tracker.startMemory = m.Alloc

	return tracker
}

// OperationTracker tracks a single operation
type OperationTracker struct {
	logger      *StructuredLogger
	operation   string
	startTime   time.Time
	startMemory uint64
}

// Finish finishes tracking the operation
func (ot *OperationTracker) Finish() {
	if !ot.logger.enablePerformance {
		return
	}

	duration := time.Since(ot.startTime)

	// Get memory stats
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	var memoryUsed int64
	// Safe conversion to prevent overflow
	if m.Alloc >= ot.startMemory {
		// Safe conversion to prevent overflow
		if m.Alloc >= ot.startMemory {
			diff := m.Alloc - ot.startMemory
			if diff <= math.MaxInt64 {
				memoryUsed = int64(diff)
			} else {
				memoryUsed = math.MaxInt64
			}
		} else {
			memoryUsed = 0
		}
	} else {
		memoryUsed = 0
	}

	// Update performance tracker
	ot.logger.performanceTracker.RecordOperation(ot.operation, duration, memoryUsed)

	// Log performance data
	ot.logger.logWithPerformance(ot.operation, duration, memoryUsed)
}

// FinishWithError finishes tracking with an error
func (ot *OperationTracker) FinishWithError(err error) {
	if !ot.logger.enablePerformance {
		return
	}

	duration := time.Since(ot.startTime)

	// Get memory stats
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	var memoryUsed int64
	// Safe conversion to prevent overflow
	if m.Alloc >= ot.startMemory {
		// Safe conversion to prevent overflow
		if m.Alloc >= ot.startMemory {
			diff := m.Alloc - ot.startMemory
			if diff <= math.MaxInt64 {
				memoryUsed = int64(diff)
			} else {
				memoryUsed = math.MaxInt64
			}
		} else {
			memoryUsed = 0
		}
	} else {
		memoryUsed = 0
	}

	// Update performance tracker
	ot.logger.performanceTracker.RecordOperationWithError(ot.operation, duration, memoryUsed)

	// Log with error
	ot.logger.logWithError(ot.operation, err, duration, memoryUsed)
}

// RecordOperation records an operation in the performance tracker
func (pt *PerformanceTracker) RecordOperation(operation string, duration time.Duration, _ int64) {
	pt.mutex.Lock()
	defer pt.mutex.Unlock()

	metrics, exists := pt.operations[operation]
	if !exists {
		metrics = &OperationMetrics{
			Name:     operation,
			MinTime:  duration,
			MaxTime:  duration,
			LastTime: time.Now(),
		}
		pt.operations[operation] = metrics
	}

	metrics.Count++
	metrics.TotalTime += duration
	metrics.AverageTime = metrics.TotalTime / time.Duration(metrics.Count)
	metrics.LastTime = time.Now()

	if duration < metrics.MinTime {
		metrics.MinTime = duration
	}
	if duration > metrics.MaxTime {
		metrics.MaxTime = duration
	}

	// Calculate success rate
	if metrics.Count > 0 {
		metrics.SuccessRate = float64(metrics.Count-metrics.Errors) / float64(metrics.Count) * percentageMultiplier
	}
}

// RecordOperationWithError records an operation with an error
func (pt *PerformanceTracker) RecordOperationWithError(operation string, duration time.Duration, _ int64) {
	pt.mutex.Lock()
	defer pt.mutex.Unlock()

	metrics, exists := pt.operations[operation]
	if !exists {
		metrics = &OperationMetrics{
			Name:     operation,
			MinTime:  duration,
			MaxTime:  duration,
			LastTime: time.Now(),
		}
		pt.operations[operation] = metrics
	}

	metrics.Count++
	metrics.TotalTime += duration
	metrics.AverageTime = metrics.TotalTime / time.Duration(metrics.Count)
	metrics.Errors++
	metrics.LastTime = time.Now()

	if duration < metrics.MinTime {
		metrics.MinTime = duration
	}
	if duration > metrics.MaxTime {
		metrics.MaxTime = duration
	}

	// Calculate success rate
	if metrics.Count > 0 {
		metrics.SuccessRate = float64(metrics.Count-metrics.Errors) / float64(metrics.Count) * percentageMultiplier
	}
}

// GetOperationMetrics returns metrics for an operation
func (pt *PerformanceTracker) GetOperationMetrics(operation string) *OperationMetrics {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()

	metrics, exists := pt.operations[operation]
	if !exists {
		return nil
	}

	// Return a copy to avoid race conditions
	return &OperationMetrics{
		Name:        metrics.Name,
		Count:       metrics.Count,
		TotalTime:   metrics.TotalTime,
		AverageTime: metrics.AverageTime,
		MinTime:     metrics.MinTime,
		MaxTime:     metrics.MaxTime,
		LastTime:    metrics.LastTime,
		Errors:      metrics.Errors,
		SuccessRate: metrics.SuccessRate,
	}
}

// GetAllMetrics returns all operation metrics
func (pt *PerformanceTracker) GetAllMetrics() map[string]*OperationMetrics {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()

	// Return a copy to avoid race conditions
	metrics := make(map[string]*OperationMetrics)
	for k, v := range pt.operations {
		metrics[k] = &OperationMetrics{
			Name:        v.Name,
			Count:       v.Count,
			TotalTime:   v.TotalTime,
			AverageTime: v.AverageTime,
			MinTime:     v.MinTime,
			MaxTime:     v.MaxTime,
			LastTime:    v.LastTime,
			Errors:      v.Errors,
			SuccessRate: v.SuccessRate,
		}
	}
	return metrics
}

// RecordMetric records a metric
func (mc *MetricsCollector) RecordMetric(name string, value interface{}) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	mc.metrics[name] = value
}

// GetMetric gets a metric value
func (mc *MetricsCollector) GetMetric(name string) (interface{}, bool) {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()

	value, exists := mc.metrics[name]
	return value, exists
}

// GetAllMetrics returns all metrics
func (mc *MetricsCollector) GetAllMetrics() map[string]interface{} {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()

	// Return a copy to avoid race conditions
	metrics := make(map[string]interface{})
	for k, v := range mc.metrics {
		metrics[k] = v
	}
	return metrics
}

// Trace logs a trace level message with structured fields
func (sl *StructuredLogger) Trace(msg string, fields ...map[string]interface{}) {
	sl.log(logrus.TraceLevel, msg, fields...)
}

// Debug logs a debug level message with structured fields
func (sl *StructuredLogger) Debug(msg string, fields ...map[string]interface{}) {
	sl.log(logrus.DebugLevel, msg, fields...)
}

// Info logs an info level message with structured fields
func (sl *StructuredLogger) Info(msg string, fields ...map[string]interface{}) {
	sl.log(logrus.InfoLevel, msg, fields...)
}

// Warn logs a warning level message with structured fields
func (sl *StructuredLogger) Warn(msg string, fields ...map[string]interface{}) {
	sl.log(logrus.WarnLevel, msg, fields...)
}

// Error logs an error level message with structured fields
func (sl *StructuredLogger) Error(msg string, fields ...map[string]interface{}) {
	sl.log(logrus.ErrorLevel, msg, fields...)
}

// Fatal logs a fatal level message with structured fields
func (sl *StructuredLogger) Fatal(msg string, fields ...map[string]interface{}) {
	sl.log(logrus.FatalLevel, msg, fields...)
}

// log performs the actual logging
func (sl *StructuredLogger) log(level logrus.Level, msg string, fields ...map[string]interface{}) {
	entry := sl.logger.WithFields(logrus.Fields{})

	// Add context
	sl.contextMutex.RLock()
	for k, v := range sl.context {
		entry = entry.WithField(k, v)
	}
	sl.contextMutex.RUnlock()

	// Add fields
	for _, fieldMap := range fields {
		for k, v := range fieldMap {
			entry = entry.WithField(k, v)
		}
	}

	// Add performance data if enabled
	if sl.enablePerformance {
		entry = entry.WithField("performance", sl.getPerformanceData())
	}

	// Add memory data if enabled
	if sl.enableMetrics {
		entry = entry.WithField("memory", sl.getMemoryData())
	}

	// Log the message
	switch level {
	case logrus.TraceLevel:
		entry.Trace(msg)
	case logrus.DebugLevel:
		entry.Debug(msg)
	case logrus.InfoLevel:
		entry.Info(msg)
	case logrus.WarnLevel:
		entry.Warn(msg)
	case logrus.ErrorLevel:
		entry.Error(msg)
	case logrus.FatalLevel:
		entry.Fatal(msg)
	}
}

// logWithPerformance logs with performance data
func (sl *StructuredLogger) logWithPerformance(operation string, duration time.Duration, memoryUsed int64) {
	entry := sl.logger.WithFields(logrus.Fields{
		"operation":   operation,
		"duration":    duration.String(),
		"memory_used": memoryUsed,
		"performance": true,
	})

	// Add context
	sl.contextMutex.RLock()
	for k, v := range sl.context {
		entry = entry.WithField(k, v)
	}
	sl.contextMutex.RUnlock()

	entry.Info(fmt.Sprintf("Operation %s completed", operation))
}

// logWithError logs with error data
func (sl *StructuredLogger) logWithError(operation string, err error, duration time.Duration, memoryUsed int64) {
	entry := sl.logger.WithFields(logrus.Fields{
		"operation":   operation,
		"duration":    duration.String(),
		"memory_used": memoryUsed,
		"error":       err.Error(),
		"performance": true,
	})

	// Add context
	sl.contextMutex.RLock()
	for k, v := range sl.context {
		entry = entry.WithField(k, v)
	}
	sl.contextMutex.RUnlock()

	entry.Error(fmt.Sprintf("Operation %s failed", operation))
}

// getPerformanceData gets current performance data
func (sl *StructuredLogger) getPerformanceData() map[string]interface{} {
	if !sl.enablePerformance {
		return nil
	}

	// Get current memory stats
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return map[string]interface{}{
		"goroutines":   runtime.NumGoroutine(),
		"memory_alloc": m.Alloc,
		"memory_total": m.TotalAlloc,
		"gc_count":     m.NumGC,
		"gc_pause":     m.PauseTotalNs,
	}
}

// getMemoryData gets current memory data
func (sl *StructuredLogger) getMemoryData() *MemoryData {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Safe conversion to prevent overflow
	var allocated, used, free, heapSize, stackSize int64
	if m.Alloc <= math.MaxInt64 {
		allocated = int64(m.Alloc)
	}
	if m.Sys <= math.MaxInt64 {
		used = int64(m.Sys)
	}
	if m.Sys >= m.Alloc {
		diff := m.Sys - m.Alloc
		if diff <= math.MaxInt64 {
			free = int64(diff)
		} else {
			free = math.MaxInt64
		}
	}
	if m.HeapSys <= math.MaxInt64 {
		heapSize = int64(m.HeapSys)
	}
	if m.StackSys <= math.MaxInt64 {
		stackSize = int64(m.StackSys)
	}

	return &MemoryData{
		Allocated:  allocated,
		Used:       used,
		Free:       free,
		Percentage: float64(m.Alloc) / float64(m.Sys) * percentageMultiplier,
		GC:         int64(m.NumGC),
		HeapSize:   heapSize,
		StackSize:  stackSize,
	}
}

// GetPerformanceReport returns a performance report
func (sl *StructuredLogger) GetPerformanceReport() (string, error) {
	if !sl.enablePerformance {
		return "", fmt.Errorf("performance tracking not enabled")
	}

	metrics := sl.performanceTracker.GetAllMetrics()

	report := map[string]interface{}{
		"timestamp":  time.Now().Format(time.RFC3339),
		"operations": metrics,
		"summary": map[string]interface{}{
			"total_operations": len(metrics),
			"uptime":           time.Since(sl.performanceTracker.startTime).String(),
		},
	}

	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}

	return string(jsonData), nil
}

// GetMetricsReport returns a metrics report
func (sl *StructuredLogger) GetMetricsReport() (string, error) {
	if !sl.enableMetrics {
		return "", fmt.Errorf("metrics collection not enabled")
	}

	metrics := sl.metricsCollector.GetAllMetrics()

	report := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"metrics":   metrics,
		"memory":    sl.getMemoryData(),
	}

	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}

	return string(jsonData), nil
}

// Close closes the structured logger
func (sl *StructuredLogger) Close() {
	// Log final performance report
	if sl.enablePerformance {
		report, err := sl.GetPerformanceReport()
		if err == nil {
			sl.Info("Final performance report", map[string]interface{}{
				"report": report,
			})
		}
	}

	// Log final metrics report
	if sl.enableMetrics {
		report, err := sl.GetMetricsReport()
		if err == nil {
			sl.Info("Final metrics report", map[string]interface{}{
				"report": report,
			})
		}
	}
}
