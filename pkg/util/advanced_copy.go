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

package util

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Constants for file operations
const (
	defaultBufferSizeKB = 128
	kbToBytes           = 1024
	mbToBytes           = 1024 * 1024
	percentageBase      = 100
	directoryPerms      = 0o750
	// Increased max workers limit for I/O-bound operations
	// min(8, GOMAXPROCS * 2) for better I/O throughput
	maxWorkersLimit = 8
	// Small file threshold for batching optimization (per performance plan)
	smallFileThreshold = 1 * mbToBytes // 1MB
	// Batch size for small files (per performance plan: optimize I/O operations)
	smallFileBatchSize = 10 // Process up to 10 small files in a batch
)

// AdvancedCopy provides high-performance file copying with sendfile() and parallel processing
type AdvancedCopy struct {
	// Configuration
	MaxWorkers       int                        // Maximum number of parallel workers
	BufferSize       int                        // Buffer size for copying
	UseSendfile      bool                       // Whether to use sendfile() system call
	ProgressCallback func(string, int64, int64) // Progress callback (file, copied, total)

	// State
	workers    chan struct{}
	stats      *CopyStatistics
	statsMutex sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
}

// CopyStatistics tracks copy operation statistics
type CopyStatistics struct {
	FilesCopied     int64         `json:"files_copied"`
	BytesCopied     int64         `json:"bytes_copied"`
	TotalFiles      int64         `json:"total_files"`
	TotalBytes      int64         `json:"total_bytes"`
	StartTime       time.Time     `json:"start_time"`
	EndTime         time.Time     `json:"end_time"`
	Duration        time.Duration `json:"duration"`
	AverageSpeed    float64       `json:"average_speed"` // MB/s
	SendfileCount   int64         `json:"sendfile_count"`
	BufferCopyCount int64         `json:"buffer_copy_count"`
	Errors          int64         `json:"errors"`
}

// CopyTask represents a single copy operation
type CopyTask struct {
	Src         string
	Dst         string
	Size        int64
	Permissions os.FileMode
	UID         int
	GID         int
	ModTime     time.Time
}

// NewAdvancedCopy creates a new advanced copy instance
// Uses conservative defaults to avoid excessive CPU usage
func NewAdvancedCopy(maxWorkers, bufferSize int, useSendfile bool) *AdvancedCopy {
	if maxWorkers <= 0 {
		// Use GOMAXPROCS for better resource utilization
		// Copy operations are I/O bound, so we can use more workers
		gomaxprocs := runtime.GOMAXPROCS(0)
		const concurrencyMultiplier = 2
		maxWorkers = gomaxprocs * concurrencyMultiplier
		if maxWorkers > maxWorkersLimit {
			maxWorkers = maxWorkersLimit
		}
	}
	if bufferSize <= 0 {
		bufferSize = defaultBufferSizeKB * kbToBytes // Optimized for large files
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &AdvancedCopy{
		MaxWorkers:  maxWorkers,
		BufferSize:  bufferSize,
		UseSendfile: useSendfile,
		workers:     make(chan struct{}, maxWorkers),
		stats: &CopyStatistics{
			StartTime: time.Now(),
		},
		ctx:    ctx,
		cancel: cancel,
	}
}

// CopyFiles copies multiple files in parallel
// Per performance plan: optimizes I/O operations with batching for small files
func (ac *AdvancedCopy) CopyFiles(tasks []CopyTask) error {
	// Reduced logging - only log summary statistics, not start/completion for each operation

	ac.stats.TotalFiles = int64(len(tasks))

	// Calculate total size
	for _, task := range tasks {
		ac.stats.TotalBytes += task.Size
	}

	// Separate small and large files for optimized processing (per performance plan)
	smallFiles := make([]CopyTask, 0)
	largeFiles := make([]CopyTask, 0)
	for _, task := range tasks {
		if task.Size < smallFileThreshold {
			smallFiles = append(smallFiles, task)
		} else {
			largeFiles = append(largeFiles, task)
		}
	}

	// Process small files in batches for better I/O efficiency
	if len(smallFiles) > 0 {
		if err := ac.copySmallFilesBatched(smallFiles); err != nil {
			return err
		}
	}

	// Process large files individually (already optimized with sendfile)
	if len(largeFiles) == 0 {
		// All files were small, update stats and return
		ac.updateFinalStats()
		return nil
	}

	if err := ac.copyLargeFiles(largeFiles); err != nil {
		return err
	}

	// Update final statistics
	ac.updateFinalStats()
	return nil
}

// copyLargeFiles processes large files in parallel using worker pool
func (ac *AdvancedCopy) copyLargeFiles(largeFiles []CopyTask) error {
	var wg sync.WaitGroup
	errorChan := make(chan error, len(largeFiles))

	for i := range largeFiles {
		wg.Add(1)
		go ac.copyLargeFileWorker(&wg, &largeFiles[i], errorChan)
	}

	wg.Wait()
	close(errorChan)

	var errors []error
	for err := range errorChan {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return fmt.Errorf("copy completed with %d errors: %v", len(errors), errors[0])
	}

	return nil
}

// copyLargeFileWorker handles copying a single large file in a worker goroutine
func (ac *AdvancedCopy) copyLargeFileWorker(wg *sync.WaitGroup, task *CopyTask, errorChan chan<- error) {
	defer wg.Done()

	if ac.ctx.Err() != nil {
		return
	}

	// Acquire worker
	select {
	case ac.workers <- struct{}{}:
	case <-ac.ctx.Done():
		return
	}
	defer func() {
		select {
		case <-ac.workers:
		case <-ac.ctx.Done():
		}
	}()

	if ac.ctx.Err() != nil {
		return
	}

	// Copy file
	if err := ac.copySingleFile(task); err != nil {
		select {
		case errorChan <- fmt.Errorf("failed to copy %s to %s: %w", task.Src, task.Dst, err):
			ac.recordError()
		case <-ac.ctx.Done():
		}
	} else {
		ac.recordSuccess(task.Size)
	}
}

// updateFinalStats updates final statistics and logs them
func (ac *AdvancedCopy) updateFinalStats() {
	ac.stats.EndTime = time.Now()
	ac.stats.Duration = ac.stats.EndTime.Sub(ac.stats.StartTime)
	if ac.stats.Duration > 0 {
		ac.stats.AverageSpeed = float64(ac.stats.BytesCopied) / ac.stats.Duration.Seconds() / mbToBytes
	}

	// Log statistics
	ac.logStatistics()
}

// copySmallFilesBatched copies small files in batches for better I/O efficiency
// Per performance plan: optimize I/O operations with batching
func (ac *AdvancedCopy) copySmallFilesBatched(tasks []CopyTask) error {
	// Process small files in batches
	for i := 0; i < len(tasks); i += smallFileBatchSize {
		end := i + smallFileBatchSize
		if end > len(tasks) {
			end = len(tasks)
		}
		batch := tasks[i:end]

		// Process batch in parallel
		var wg sync.WaitGroup
		errorChan := make(chan error, len(batch))

		for _, task := range batch {
			wg.Add(1)
			go func(t CopyTask) {
				defer wg.Done()

				// Check context
				select {
				case <-ac.ctx.Done():
					return
				default:
				}

				// Acquire worker
				select {
				case ac.workers <- struct{}{}:
				case <-ac.ctx.Done():
					return
				}
				defer func() {
					select {
					case <-ac.workers:
					case <-ac.ctx.Done():
					}
				}()

				// Copy file (small files use buffer copy for consistency)
				if err := ac.copyWithBuffer(&t); err != nil {
					select {
					case errorChan <- fmt.Errorf("failed to copy %s to %s: %w", t.Src, t.Dst, err):
						ac.recordError()
					case <-ac.ctx.Done():
						return
					}
				} else {
					ac.recordSuccess(t.Size)
					ac.recordBufferCopy()
				}
			}(task)
		}

		// Wait for batch to complete
		wg.Wait()
		close(errorChan)

		// Check for errors in batch
		var errors []error
		for err := range errorChan {
			errors = append(errors, err)
		}

		if len(errors) > 0 {
			return fmt.Errorf("batch copy failed with %d errors: %v", len(errors), errors[0])
		}
	}

	return nil
}

// copySingleFile copies a single file using the most efficient method
func (ac *AdvancedCopy) copySingleFile(task *CopyTask) error {
	// Check if context is canceled
	select {
	case <-ac.ctx.Done():
		return ac.ctx.Err()
	default:
	}

	// Try sendfile() first if enabled and supported
	if ac.UseSendfile && ac.isSendfileSupported(task.Src, task.Dst) {
		if err := ac.copyWithSendfile(task); err == nil {
			ac.recordSendfile()
			return nil
		}
		// Fall back to buffer copy if sendfile fails
		logrus.Debugf("sendfile() failed for %s, falling back to buffer copy", task.Src)
	}

	// Use buffer copy
	if err := ac.copyWithBuffer(task); err != nil {
		return err
	}

	ac.recordBufferCopy()
	return nil
}

// copyWithSendfile copies a file using the sendfile() system call
func (ac *AdvancedCopy) copyWithSendfile(task *CopyTask) error {
	// Open source file
	srcFile, err := os.Open(task.Src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	// Create destination directory if needed
	if mkdirErr := os.MkdirAll(filepath.Dir(task.Dst), directoryPerms); mkdirErr != nil {
		return mkdirErr
	}

	// Create destination file
	dstFile, err := os.Create(task.Dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	// Get file descriptors
	srcFd := int(srcFile.Fd())
	dstFd := int(dstFile.Fd())

	// Use sendfile() system call
	bytesCopied, err := ac.sendfile(dstFd, srcFd, task.Size)
	if err != nil {
		return err
	}

	// Set file permissions and ownership
	if err := ac.setFileAttributes(task.Dst, task.Permissions, task.UID, task.GID, task.ModTime); err != nil {
		return err
	}

	// Update progress
	if ac.ProgressCallback != nil {
		ac.ProgressCallback(task.Src, bytesCopied, task.Size)
	}

	// Removed per-file logging - too verbose for thousands of files
	return nil
}

// copyWithBuffer copies a file using buffered I/O
func (ac *AdvancedCopy) copyWithBuffer(task *CopyTask) error {
	// Open source file
	srcFile, err := os.Open(task.Src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	// Create destination directory if needed
	if mkdirErr := os.MkdirAll(filepath.Dir(task.Dst), directoryPerms); mkdirErr != nil {
		return mkdirErr
	}

	// Create destination file
	dstFile, err := os.Create(task.Dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	// Copy using buffer
	buffer := make([]byte, ac.BufferSize)
	bytesCopied, err := io.CopyBuffer(dstFile, srcFile, buffer)
	if err != nil {
		return err
	}

	// Set file permissions and ownership
	if err := ac.setFileAttributes(task.Dst, task.Permissions, task.UID, task.GID, task.ModTime); err != nil {
		return err
	}

	// Update progress
	if ac.ProgressCallback != nil {
		ac.ProgressCallback(task.Src, bytesCopied, task.Size)
	}

	// Removed per-file logging - too verbose for thousands of files
	return nil
}

// sendfile performs the sendfile() system call
func (ac *AdvancedCopy) sendfile(dstFd, srcFd int, size int64) (int64, error) {
	// Use platform-specific implementation
	return sendfilePlatform(dstFd, srcFd, size)
}

// isSendfileSupported checks if sendfile() is supported for the given files
func (ac *AdvancedCopy) isSendfileSupported(src, dst string) bool {
	// Check if source is a regular file
	srcInfo, err := os.Stat(src)
	if err != nil || !srcInfo.Mode().IsRegular() {
		return false
	}

	// Check if destination is on the same filesystem
	// (sendfile() works best when both files are on the same filesystem)
	return isSameFilesystemPlatform(src, dst)
}

// setFileAttributes sets file permissions, ownership, and timestamps
func (ac *AdvancedCopy) setFileAttributes(path string, mode os.FileMode, uid, gid int, modTime time.Time) error {
	// Set permissions
	if err := os.Chmod(path, mode); err != nil {
		return err
	}

	// Set ownership (if not root)
	if uid >= 0 && gid >= 0 {
		if err := os.Chown(path, uid, gid); err != nil {
			logrus.Debugf("Failed to set ownership for %s: %v", path, err)
			// Don't fail the copy for ownership errors
		}
	}

	// Set timestamps
	if err := os.Chtimes(path, modTime, modTime); err != nil {
		return err
	}

	return nil
}

// recordSuccess records a successful copy operation
func (ac *AdvancedCopy) recordSuccess(bytes int64) {
	ac.statsMutex.Lock()
	defer ac.statsMutex.Unlock()

	ac.stats.FilesCopied++
	ac.stats.BytesCopied += bytes
}

// recordError records a copy error
func (ac *AdvancedCopy) recordError() {
	ac.statsMutex.Lock()
	defer ac.statsMutex.Unlock()

	ac.stats.Errors++
}

// recordSendfile records a sendfile() operation
func (ac *AdvancedCopy) recordSendfile() {
	ac.statsMutex.Lock()
	defer ac.statsMutex.Unlock()

	ac.stats.SendfileCount++
}

// recordBufferCopy records a buffer copy operation
func (ac *AdvancedCopy) recordBufferCopy() {
	ac.statsMutex.Lock()
	defer ac.statsMutex.Unlock()

	ac.stats.BufferCopyCount++
}

// logStatistics logs copy statistics
func (ac *AdvancedCopy) logStatistics() {
	ac.statsMutex.RLock()
	defer ac.statsMutex.RUnlock()

	logrus.Infof("Copy Statistics:")
	logrus.Infof("   Files: %d/%d (%.1f%%)",
		ac.stats.FilesCopied, ac.stats.TotalFiles,
		float64(ac.stats.FilesCopied)/float64(ac.stats.TotalFiles)*percentageBase)
	logrus.Infof("   Bytes: %d/%d (%.1f%%)",
		ac.stats.BytesCopied, ac.stats.TotalBytes,
		float64(ac.stats.BytesCopied)/float64(ac.stats.TotalBytes)*percentageBase)
	logrus.Infof("   Duration: %v", ac.stats.Duration)
	logrus.Infof("   Speed: %.2f MB/s", ac.stats.AverageSpeed)
	logrus.Infof("   Sendfile: %d, Buffer: %d", ac.stats.SendfileCount, ac.stats.BufferCopyCount)
	if ac.stats.Errors > 0 {
		logrus.Warnf("   Errors: %d", ac.stats.Errors)
	}
}

// GetStatistics returns copy statistics
func (ac *AdvancedCopy) GetStatistics() *CopyStatistics {
	ac.statsMutex.RLock()
	defer ac.statsMutex.RUnlock()

	// Return a copy to avoid race conditions
	stats := *ac.stats
	return &stats
}

// Cancel cancels all ongoing copy operations
func (ac *AdvancedCopy) Cancel() {
	ac.cancel()
}

// Close cleans up resources
func (ac *AdvancedCopy) Close() {
	ac.cancel()
	close(ac.workers)
}
