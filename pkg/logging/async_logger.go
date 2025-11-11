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
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	// DefaultAsyncLogBufferSize is the default buffer size for async logging channel
	DefaultAsyncLogBufferSize = 1000
	// DefaultAsyncLogFlushInterval is the default interval for flushing logs
	DefaultAsyncLogFlushInterval = 2 * time.Second
	// MaxSyncFallbackRetries is the maximum number of retries for sync fallback
	MaxSyncFallbackRetries = 3
	// DefaultAsyncLogBatchSize is the default batch size for flushing logs
	DefaultAsyncLogBatchSize = 100
)

// LogEntry represents a single log entry for async processing
type LogEntry struct {
	Level   logrus.Level
	Message string
	Fields  logrus.Fields
	Time    time.Time
}

// AsyncLogger provides asynchronous logging for non-critical log levels
// to reduce CPU usage and allocations in hot paths
type AsyncLogger struct {
	// Configuration
	bufferSize    int
	flushInterval time.Duration
	enabled       bool

	// Channels
	logChan chan LogEntry
	ctx     context.Context
	cancel  context.CancelFunc

	// Worker synchronization
	wg sync.WaitGroup

	// Statistics
	droppedLogs   int64 // Number of logs dropped due to buffer overflow
	flushedLogs   int64 // Number of logs flushed
	syncFallbacks int64 // Number of sync fallbacks used

	// State
	started int32 // Atomic flag to track if started
	stopped int32 // Atomic flag to track if stopped
}

var (
	globalAsyncLogger *AsyncLogger
	asyncLoggerOnce   sync.Once
)

// GetAsyncLogger returns the singleton async logger instance
func GetAsyncLogger() *AsyncLogger {
	asyncLoggerOnce.Do(func() {
		globalAsyncLogger = NewAsyncLogger(DefaultAsyncLogBufferSize, DefaultAsyncLogFlushInterval)
	})
	return globalAsyncLogger
}

// NewAsyncLogger creates a new async logger with specified buffer size and flush interval
func NewAsyncLogger(bufferSize int, flushInterval time.Duration) *AsyncLogger {
	if bufferSize <= 0 {
		bufferSize = DefaultAsyncLogBufferSize
	}
	if flushInterval <= 0 {
		flushInterval = DefaultAsyncLogFlushInterval
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &AsyncLogger{
		bufferSize:    bufferSize,
		flushInterval: flushInterval,
		enabled:       true,
		logChan:       make(chan LogEntry, bufferSize),
		ctx:           ctx,
		cancel:        cancel,
	}
}

// Start starts the async logger worker goroutine
func (al *AsyncLogger) Start() {
	if !atomic.CompareAndSwapInt32(&al.started, 0, 1) {
		// Already started
		return
	}

	al.wg.Add(1)
	go al.worker()
}

// Stop stops the async logger and flushes all pending logs
func (al *AsyncLogger) Stop() {
	if !atomic.CompareAndSwapInt32(&al.stopped, 0, 1) {
		// Already stopped
		return
	}

	// Cancel context to stop worker
	al.cancel()

	// Close channel to signal no more entries
	close(al.logChan)

	// Wait for worker to finish
	al.wg.Wait()
}

// Log logs a message asynchronously (only for Debug, Trace, Info levels)
// Error, Fatal, Panic are always logged synchronously for safety
func (al *AsyncLogger) Log(level logrus.Level, message string, fields logrus.Fields) {
	// Auto-start if not already started (safe for concurrent access)
	if atomic.LoadInt32(&al.started) == 0 {
		al.Start()
	}

	// Critical levels are always logged synchronously
	if level >= logrus.ErrorLevel {
		al.logSynchronously(level, message, fields)
		return
	}

	// Check if async logging is enabled
	if !al.enabled {
		// Fallback to synchronous logging
		al.logSynchronously(level, message, fields)
		return
	}

	// Try to send to async channel (non-blocking)
	select {
	case al.logChan <- LogEntry{
		Level:   level,
		Message: message,
		Fields:  fields,
		Time:    time.Now(),
	}:
		// Successfully queued
	default:
		// Channel is full, fallback to synchronous logging
		atomic.AddInt64(&al.syncFallbacks, 1)
		al.logSynchronously(level, message, fields)
	}
}

// logSynchronously logs a message synchronously (used for critical levels and fallback)
func (al *AsyncLogger) logSynchronously(level logrus.Level, message string, fields logrus.Fields) {
	entry := logrus.WithFields(fields)
	switch level {
	case logrus.DebugLevel:
		entry.Debug(message)
	case logrus.TraceLevel:
		entry.Trace(message)
	case logrus.InfoLevel:
		entry.Info(message)
	case logrus.WarnLevel:
		entry.Warn(message)
	case logrus.ErrorLevel:
		entry.Error(message)
	case logrus.FatalLevel:
		entry.Fatal(message)
	case logrus.PanicLevel:
		entry.Panic(message)
	}
}

// worker is the background goroutine that processes log entries
func (al *AsyncLogger) worker() {
	defer al.wg.Done()

	ticker := time.NewTicker(al.flushInterval)
	defer ticker.Stop()

	batch := make([]LogEntry, 0, DefaultAsyncLogBatchSize) // Pre-allocate batch

	for {
		select {
		case <-al.ctx.Done():
			// Flush remaining logs before exit
			al.flushBatch(batch)
			return

		case entry, ok := <-al.logChan:
			if !ok {
				// Channel closed, flush and exit
				al.flushBatch(batch)
				return
			}

			batch = append(batch, entry)

			// Flush if batch is full
			if len(batch) >= DefaultAsyncLogBatchSize {
				al.flushBatch(batch)
				batch = batch[:0] // Reset batch
			}

		case <-ticker.C:
			// Periodic flush
			if len(batch) > 0 {
				al.flushBatch(batch)
				batch = batch[:0] // Reset batch
			}
		}
	}
}

// flushBatch flushes a batch of log entries synchronously
func (al *AsyncLogger) flushBatch(batch []LogEntry) {
	if len(batch) == 0 {
		return
	}

	for _, entry := range batch {
		logEntry := logrus.WithFields(entry.Fields)
		switch entry.Level {
		case logrus.DebugLevel:
			logEntry.Debug(entry.Message)
		case logrus.TraceLevel:
			logEntry.Trace(entry.Message)
		case logrus.InfoLevel:
			logEntry.Info(entry.Message)
		case logrus.WarnLevel:
			logEntry.Warn(entry.Message)
		}
	}

	atomic.AddInt64(&al.flushedLogs, int64(len(batch)))
}

// Enable enables async logging
func (al *AsyncLogger) Enable() {
	al.enabled = true
}

// Disable disables async logging (falls back to synchronous)
func (al *AsyncLogger) Disable() {
	al.enabled = false
}

// GetStats returns statistics about async logging
func (al *AsyncLogger) GetStats() map[string]int64 {
	return map[string]int64{
		"dropped_logs":   atomic.LoadInt64(&al.droppedLogs),
		"flushed_logs":   atomic.LoadInt64(&al.flushedLogs),
		"sync_fallbacks": atomic.LoadInt64(&al.syncFallbacks),
		"buffer_size":    int64(al.bufferSize),
		"queue_length":   int64(len(al.logChan)),
	}
}

// IsEnabled returns whether async logging is enabled
func (al *AsyncLogger) IsEnabled() bool {
	return al.enabled
}
