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

package snapshot

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// Constants for worker pool
const (
	// Conservative defaults for CPU usage optimization
	// Changed from 2.0 to 1.0 to avoid excessive CPU usage, especially with multiple parallel builds
	ioIntensiveMultiplier = 1.0
	queueBufferMultiplier = 2
	adjustmentCooldownSec = 5
	sleepIntervalMs       = 10
	mixedTaskMultiplier   = 1.5
	// Maximum absolute limit for workers - increased for better CPU utilization
	// min(32, GOMAXPROCS * 4) for adaptive worker pool
	maxWorkersAbsoluteLimit = 32
)

// AdaptiveWorkerPool provides an adaptive worker pool that adjusts size based on workload
type AdaptiveWorkerPool struct {
	// Configuration
	minWorkers     int
	maxWorkers     int
	currentWorkers int32

	// Worker management
	workers      chan struct{}
	taskQueue    chan Task
	workerWg     sync.WaitGroup
	shutdownChan chan struct{}

	// Statistics
	stats      *WorkerPoolStats
	statsMutex sync.RWMutex

	// Adaptive behavior
	lastAdjustment     time.Time
	adjustmentCooldown time.Duration
}

// Task represents a task to be executed by a worker
type Task struct {
	ID       string
	Function func() error
	Priority int // Higher number = higher priority
}

// WorkerPoolStats tracks worker pool performance
type WorkerPoolStats struct {
	TasksProcessed    int64         `json:"tasks_processed"`
	TasksFailed       int64         `json:"tasks_failed"`
	AverageTaskTime   time.Duration `json:"average_task_time"`
	WorkerUtilization float64       `json:"worker_utilization"`
	QueueLength       int64         `json:"queue_length"`
	StartTime         time.Time     `json:"start_time"`
	LastActivity      time.Time     `json:"last_activity"`
}

// NewAdaptiveWorkerPool creates a new adaptive worker pool
// Uses conservative defaults to avoid excessive CPU usage, especially with multiple parallel builds
func NewAdaptiveWorkerPool(minWorkers, maxWorkers int) *AdaptiveWorkerPool {
	if minWorkers <= 0 {
		minWorkers = 1
	}
	if maxWorkers <= 0 {
		// Use GOMAXPROCS for better resource utilization
		gomaxprocs := runtime.GOMAXPROCS(0)
		const concurrencyMultiplier = 4
		maxWorkers = gomaxprocs * concurrencyMultiplier
		if maxWorkers > maxWorkersAbsoluteLimit {
			maxWorkers = maxWorkersAbsoluteLimit
		}
	}
	// Apply absolute limit to prevent excessive CPU usage
	if maxWorkers > maxWorkersAbsoluteLimit {
		maxWorkers = maxWorkersAbsoluteLimit
	}
	if minWorkers > maxWorkers {
		minWorkers = maxWorkers
	}

	// Ensure minWorkers doesn't overflow int32
	if minWorkers > int(^uint32(0)>>1) {
		minWorkers = int(^uint32(0) >> 1)
	}

	// Safe conversion to int32
	var currentWorkers int32
	switch {
	case minWorkers <= int(^uint32(0)>>1) && minWorkers >= int(^uint32(0)>>1)*-1:
		currentWorkers = int32(minWorkers)
	case minWorkers > int(^uint32(0)>>1):
		currentWorkers = ^int32(0) // Max int32 value
	default:
		currentWorkers = ^int32(0) + 1 // Min int32 value
	}

	pool := &AdaptiveWorkerPool{
		minWorkers:         minWorkers,
		maxWorkers:         maxWorkers,
		currentWorkers:     currentWorkers,
		workers:            make(chan struct{}, maxWorkers),
		taskQueue:          make(chan Task, maxWorkers*queueBufferMultiplier), // Buffer for queue
		shutdownChan:       make(chan struct{}),
		adjustmentCooldown: adjustmentCooldownSec * time.Second,
		stats: &WorkerPoolStats{
			StartTime: time.Now(),
		},
	}

	// Initialize workers
	for i := 0; i < minWorkers; i++ {
		pool.startWorker()
	}

	return pool
}

// Submit submits a task to the worker pool
func (awp *AdaptiveWorkerPool) Submit(task Task) error {
	select {
	case awp.taskQueue <- task:
		awp.updateQueueLength(1)
		awp.considerScaling()
		return nil
	case <-awp.shutdownChan:
		return ErrWorkerPoolShutdown
	default:
		// Queue is full, consider scaling up
		awp.considerScaling()
		return ErrQueueFull
	}
}

// SubmitFunc submits a function as a task
func (awp *AdaptiveWorkerPool) SubmitFunc(id string, fn func() error) error {
	return awp.Submit(Task{
		ID:       id,
		Function: fn,
		Priority: 0,
	})
}

// startWorker starts a new worker
func (awp *AdaptiveWorkerPool) startWorker() {
	awp.workers <- struct{}{}
	atomic.AddInt32(&awp.currentWorkers, 1)

	awp.workerWg.Add(1)
	go func() {
		defer awp.workerWg.Done()
		defer func() { <-awp.workers }()
		defer atomic.AddInt32(&awp.currentWorkers, -1)

		for {
			select {
			case task := <-awp.taskQueue:
				awp.executeTask(task)
				awp.updateQueueLength(-1)
			case <-awp.shutdownChan:
				return
			}
		}
	}()
}

// executeTask executes a task and records statistics
func (awp *AdaptiveWorkerPool) executeTask(task Task) {
	start := time.Now()

	var err error
	if task.Function == nil {
		err = fmt.Errorf("task function is nil for task ID: %s", task.ID)
	} else {
		err = task.Function()
	}

	duration := time.Since(start)
	awp.updateStats(duration, err == nil)
}

// considerScaling considers whether to scale the worker pool
func (awp *AdaptiveWorkerPool) considerScaling() {
	now := time.Now()
	if now.Sub(awp.lastAdjustment) < awp.adjustmentCooldown {
		return
	}

	awp.lastAdjustment = now
	currentWorkers := int(atomic.LoadInt32(&awp.currentWorkers))
	queueLength := len(awp.taskQueue)

	// Scale up if queue is getting full
	if queueLength > currentWorkers && currentWorkers < awp.maxWorkers {
		awp.scaleUp()
	}

	// Scale down if queue is empty and we have excess workers
	if queueLength == 0 && currentWorkers > awp.minWorkers {
		awp.scaleDown()
	}
}

// scaleUp adds more workers
func (awp *AdaptiveWorkerPool) scaleUp() {
	currentWorkers := int(atomic.LoadInt32(&awp.currentWorkers))
	if currentWorkers >= awp.maxWorkers {
		return
	}

	// Add one worker at a time
	awp.startWorker()
}

// scaleDown removes excess workers
func (awp *AdaptiveWorkerPool) scaleDown() {
	currentWorkers := int(atomic.LoadInt32(&awp.currentWorkers))
	if currentWorkers <= awp.minWorkers {
		return
	}

	// Send shutdown signal to one worker
	select {
	case awp.shutdownChan <- struct{}{}:
	default:
		// No workers available to shutdown
	}
}

// updateStats updates worker pool statistics
func (awp *AdaptiveWorkerPool) updateStats(duration time.Duration, success bool) {
	awp.statsMutex.Lock()
	defer awp.statsMutex.Unlock()

	awp.stats.LastActivity = time.Now()
	awp.stats.TasksProcessed++

	if !success {
		awp.stats.TasksFailed++
	}

	// Update average task time
	if awp.stats.TasksProcessed == 1 {
		awp.stats.AverageTaskTime = duration
	} else {
		awp.stats.AverageTaskTime = (awp.stats.AverageTaskTime + duration) / averageDivisor
	}

	// Calculate utilization
	currentWorkers := int(atomic.LoadInt32(&awp.currentWorkers))
	if currentWorkers > 0 {
		awp.stats.WorkerUtilization = float64(len(awp.taskQueue)) / float64(currentWorkers)
	}
}

// updateQueueLength updates the queue length statistic
func (awp *AdaptiveWorkerPool) updateQueueLength(delta int) {
	awp.statsMutex.Lock()
	defer awp.statsMutex.Unlock()

	awp.stats.QueueLength += int64(delta)
	if awp.stats.QueueLength < 0 {
		awp.stats.QueueLength = 0
	}
}

// GetStats returns worker pool statistics
func (awp *AdaptiveWorkerPool) GetStats() *WorkerPoolStats {
	awp.statsMutex.RLock()
	defer awp.statsMutex.RUnlock()

	// Return a copy to avoid race conditions
	stats := *awp.stats
	return &stats
}

// GetCurrentWorkers returns the current number of workers
func (awp *AdaptiveWorkerPool) GetCurrentWorkers() int {
	return int(atomic.LoadInt32(&awp.currentWorkers))
}

// Shutdown gracefully shuts down the worker pool
func (awp *AdaptiveWorkerPool) Shutdown() {
	close(awp.shutdownChan)
	awp.workerWg.Wait()
	close(awp.taskQueue)
}

// WaitForCompletion waits for all tasks to complete
func (awp *AdaptiveWorkerPool) WaitForCompletion() {
	for len(awp.taskQueue) > 0 {
		time.Sleep(sleepIntervalMs * time.Millisecond)
	}
}

// GetOptimalWorkerCount calculates the optimal number of workers based on system resources
// Uses GOMAXPROCS for better resource utilization
func GetOptimalWorkerCount(taskType string) int {
	gomaxprocs := runtime.GOMAXPROCS(0)
	var optimal int

	switch taskType {
	case "cpu_intensive":
		optimal = gomaxprocs
	case "io_intensive":
		optimal = int(float64(gomaxprocs) * ioIntensiveMultiplier)
	case "mixed":
		optimal = int(float64(gomaxprocs) * mixedTaskMultiplier)
	default:
		optimal = gomaxprocs
	}

	// Apply absolute limit
	if optimal > maxWorkersAbsoluteLimit {
		optimal = maxWorkersAbsoluteLimit
	}
	return optimal
}

// Errors
var (
	ErrWorkerPoolShutdown = errors.New("worker pool is shutting down")
	ErrQueueFull          = errors.New("task queue is full")
)
