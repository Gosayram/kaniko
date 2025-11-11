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
	"sync"

	"github.com/sirupsen/logrus"
)

// Constants for buffer pool
const (
	// Default buffer sizes
	DefaultSmallBufferSize  = 4 * 1024    // 4KB
	DefaultMediumBufferSize = 64 * 1024   // 64KB
	DefaultLargeBufferSize  = 1024 * 1024 // 1MB

	// Buffer pool limits
	MaxSmallBuffers  = 100
	MaxMediumBuffers = 50
	MaxLargeBuffers  = 20
)

// BufferPool provides efficient buffer management with different sizes
type BufferPool struct {
	// Small buffers (4KB) - for small file operations
	smallPool sync.Pool

	// Medium buffers (64KB) - for medium file operations
	mediumPool sync.Pool

	// Large buffers (1MB) - for large file operations
	largePool sync.Pool

	// Configuration
	smallSize  int
	mediumSize int
	largeSize  int

	// Statistics
	stats BufferPoolStats

	// Mutex for thread-safe access to stats
	statsMutex sync.RWMutex
}

// BufferPoolStats holds statistics about buffer pool usage
type BufferPoolStats struct {
	SmallBuffersAllocated  int64
	MediumBuffersAllocated int64
	LargeBuffersAllocated  int64
	SmallBuffersReturned   int64
	MediumBuffersReturned  int64
	LargeBuffersReturned   int64
	TotalAllocations       int64
	TotalReturns           int64
}

// NewBufferPool creates a new buffer pool with default sizes
func NewBufferPool() *BufferPool {
	return NewBufferPoolWithSizes(DefaultSmallBufferSize, DefaultMediumBufferSize, DefaultLargeBufferSize)
}

// NewBufferPoolWithSizes creates a new buffer pool with custom sizes
func NewBufferPoolWithSizes(smallSize, mediumSize, largeSize int) *BufferPool {
	if smallSize <= 0 {
		smallSize = DefaultSmallBufferSize
	}
	if mediumSize <= 0 {
		mediumSize = DefaultMediumBufferSize
	}
	if largeSize <= 0 {
		largeSize = DefaultLargeBufferSize
	}

	bp := &BufferPool{
		smallSize:  smallSize,
		mediumSize: mediumSize,
		largeSize:  largeSize,
		stats:      BufferPoolStats{},
	}

	// Initialize pools with factory functions
	bp.smallPool = sync.Pool{
		New: func() interface{} {
			bp.statsMutex.Lock()
			bp.stats.SmallBuffersAllocated++
			bp.stats.TotalAllocations++
			bp.statsMutex.Unlock()

			return make([]byte, smallSize)
		},
	}

	bp.mediumPool = sync.Pool{
		New: func() interface{} {
			bp.statsMutex.Lock()
			bp.stats.MediumBuffersAllocated++
			bp.stats.TotalAllocations++
			bp.statsMutex.Unlock()

			return make([]byte, mediumSize)
		},
	}

	bp.largePool = sync.Pool{
		New: func() interface{} {
			bp.statsMutex.Lock()
			bp.stats.LargeBuffersAllocated++
			bp.stats.TotalAllocations++
			bp.statsMutex.Unlock()

			return make([]byte, largeSize)
		},
	}

	//nolint:mnd // Constants for KB conversion
	logrus.Debugf("Buffer pool initialized: Small=%dKB, Medium=%dKB, Large=%dKB",
		smallSize/1024, mediumSize/1024, largeSize/1024)

	return bp
}

// GetSmallBuffer returns a small buffer from the pool
func (bp *BufferPool) GetSmallBuffer() []byte {
	buffer := bp.smallPool.Get().([]byte)

	// Optimized: use fast zeroing for small buffers (small enough that loop is fine)
	// For small buffers, explicit loop is faster than runtime.memclrNoHeapPointers overhead
	for i := range buffer {
		buffer[i] = 0
	}

	return buffer
}

// GetMediumBuffer returns a medium buffer from the pool
func (bp *BufferPool) GetMediumBuffer() []byte {
	buffer := bp.mediumPool.Get().([]byte)

	// Optimized: use fast zeroing for medium buffers
	// For 64KB buffers, explicit loop is still efficient
	for i := range buffer {
		buffer[i] = 0
	}

	return buffer
}

// GetLargeBuffer returns a large buffer from the pool
func (bp *BufferPool) GetLargeBuffer() []byte {
	buffer := bp.largePool.Get().([]byte)

	// Optimized: for large buffers (1MB+), we could skip zeroing if security allows
	// However, for safety we still zero to prevent data leakage
	// Note: For very large buffers, consider using runtime.memclrNoHeapPointers
	// but explicit loop is fine for 1MB buffers
	for i := range buffer {
		buffer[i] = 0
	}

	return buffer
}

// GetBuffer returns a buffer of appropriate size based on the requested size
//
//nolint:gocritic // if-else chain is more readable than switch for size comparisons
func (bp *BufferPool) GetBuffer(size int) []byte {
	if size <= bp.smallSize {
		return bp.GetSmallBuffer()
	} else if size <= bp.mediumSize {
		return bp.GetMediumBuffer()
	} else if size <= bp.largeSize {
		return bp.GetLargeBuffer()
	}

	// For sizes larger than our largest buffer, allocate directly
	// This should be rare and indicates a need for larger buffer sizes
	logrus.Warnf("Requested buffer size %d exceeds maximum pool size %d, allocating directly",
		size, bp.largeSize)

	bp.statsMutex.Lock()
	bp.stats.TotalAllocations++
	bp.statsMutex.Unlock()

	return make([]byte, size)
}

// PutSmallBuffer returns a small buffer to the pool
func (bp *BufferPool) PutSmallBuffer(buffer []byte) {
	if len(buffer) != bp.smallSize {
		logrus.Warnf("Attempted to return buffer of size %d to small pool (expected %d)",
			len(buffer), bp.smallSize)
		return
	}

	bp.statsMutex.Lock()
	bp.stats.SmallBuffersReturned++
	bp.stats.TotalReturns++
	bp.statsMutex.Unlock()

	//nolint:staticcheck // sync.Pool requires interface{} type
	bp.smallPool.Put(buffer)
}

// PutMediumBuffer returns a medium buffer to the pool
func (bp *BufferPool) PutMediumBuffer(buffer []byte) {
	if len(buffer) != bp.mediumSize {
		logrus.Warnf("Attempted to return buffer of size %d to medium pool (expected %d)",
			len(buffer), bp.mediumSize)
		return
	}

	bp.statsMutex.Lock()
	bp.stats.MediumBuffersReturned++
	bp.stats.TotalReturns++
	bp.statsMutex.Unlock()

	//nolint:staticcheck // sync.Pool requires interface{} type
	bp.mediumPool.Put(buffer)
}

// PutLargeBuffer returns a large buffer to the pool
func (bp *BufferPool) PutLargeBuffer(buffer []byte) {
	if len(buffer) != bp.largeSize {
		logrus.Warnf("Attempted to return buffer of size %d to large pool (expected %d)",
			len(buffer), bp.largeSize)
		return
	}

	bp.statsMutex.Lock()
	bp.stats.LargeBuffersReturned++
	bp.stats.TotalReturns++
	bp.statsMutex.Unlock()

	//nolint:staticcheck // sync.Pool requires interface{} type
	bp.largePool.Put(buffer)
}

// PutBuffer returns a buffer to the appropriate pool based on its size
//
//nolint:gocritic,staticcheck // if-else chain is more readable than switch for size comparisons
func (bp *BufferPool) PutBuffer(buffer []byte) {
	size := len(buffer)

	if size == bp.smallSize {
		bp.PutSmallBuffer(buffer)
	} else if size == bp.mediumSize {
		bp.PutMediumBuffer(buffer)
	} else if size == bp.largeSize {
		bp.PutLargeBuffer(buffer)
	} else {
		// For custom-sized buffers, we don't return them to the pool
		// This is expected for buffers allocated directly for large sizes
		logrus.Debugf("Custom-sized buffer (%d bytes) not returned to pool", size)
	}
}

// GetStats returns current buffer pool statistics
func (bp *BufferPool) GetStats() BufferPoolStats {
	bp.statsMutex.RLock()
	defer bp.statsMutex.RUnlock()

	return bp.stats
}

// LogStats logs current buffer pool statistics
func (bp *BufferPool) LogStats() {
	stats := bp.GetStats()

	logrus.Infof("Buffer Pool Statistics:")
	logrus.Infof("  Small Buffers: Allocated=%d, Returned=%d",
		stats.SmallBuffersAllocated, stats.SmallBuffersReturned)
	logrus.Infof("  Medium Buffers: Allocated=%d, Returned=%d",
		stats.MediumBuffersAllocated, stats.MediumBuffersReturned)
	logrus.Infof("  Large Buffers: Allocated=%d, Returned=%d",
		stats.LargeBuffersAllocated, stats.LargeBuffersReturned)
	logrus.Infof("  Total: Allocated=%d, Returned=%d",
		stats.TotalAllocations, stats.TotalReturns)

	// Calculate efficiency
	if stats.TotalAllocations > 0 {
		//nolint:mnd // Percentage calculation
		efficiency := float64(stats.TotalReturns) / float64(stats.TotalAllocations) * 100
		logrus.Infof("  Efficiency: %.1f%%", efficiency)
	}
}

// ResetStats resets buffer pool statistics
func (bp *BufferPool) ResetStats() {
	bp.statsMutex.Lock()
	defer bp.statsMutex.Unlock()

	bp.stats = BufferPoolStats{}
	logrus.Info("Buffer pool statistics reset")
}

// GetSmallBufferSize returns the size of small buffers
func (bp *BufferPool) GetSmallBufferSize() int {
	return bp.smallSize
}

// GetMediumBufferSize returns the size of medium buffers
func (bp *BufferPool) GetMediumBufferSize() int {
	return bp.mediumSize
}

// GetLargeBufferSize returns the size of large buffers
func (bp *BufferPool) GetLargeBufferSize() int {
	return bp.largeSize
}

// IsBufferFromPool checks if a buffer was allocated from the pool
func (bp *BufferPool) IsBufferFromPool(buffer []byte) bool {
	size := len(buffer)
	return size == bp.smallSize || size == bp.mediumSize || size == bp.largeSize
}

// GetOptimalBufferSize returns the optimal buffer size for a given operation size
//
//nolint:gocritic // if-else chain is more readable than switch for size comparisons
func (bp *BufferPool) GetOptimalBufferSize(operationSize int) int {
	if operationSize <= bp.smallSize {
		return bp.smallSize
	} else if operationSize <= bp.mediumSize {
		return bp.mediumSize
	} else if operationSize <= bp.largeSize {
		return bp.largeSize
	}

	// For operations larger than our largest buffer, return the operation size
	return operationSize
}

// PreallocateBuffers pre-allocates a number of buffers to warm up the pool
func (bp *BufferPool) PreallocateBuffers(smallCount, mediumCount, largeCount int) {
	logrus.Debugf("Pre-allocating buffers: Small=%d, Medium=%d, Large=%d",
		smallCount, mediumCount, largeCount)

	// Pre-allocate small buffers
	for i := 0; i < smallCount && i < MaxSmallBuffers; i++ {
		buffer := bp.GetSmallBuffer()
		bp.PutSmallBuffer(buffer)
	}

	// Pre-allocate medium buffers
	for i := 0; i < mediumCount && i < MaxMediumBuffers; i++ {
		buffer := bp.GetMediumBuffer()
		bp.PutMediumBuffer(buffer)
	}

	// Pre-allocate large buffers
	for i := 0; i < largeCount && i < MaxLargeBuffers; i++ {
		buffer := bp.GetLargeBuffer()
		bp.PutLargeBuffer(buffer)
	}

	logrus.Debugf("Buffer pre-allocation completed")
}

// Global buffer pool instance
var (
	globalBufferPool *BufferPool
	bufferPoolOnce   sync.Once
)

// GetGlobalBufferPool returns the global buffer pool instance
func GetGlobalBufferPool() *BufferPool {
	bufferPoolOnce.Do(func() {
		globalBufferPool = NewBufferPool()
		logrus.Info("Global buffer pool initialized")
	})
	return globalBufferPool
}

// SetGlobalBufferPool sets the global buffer pool instance
func SetGlobalBufferPool(pool *BufferPool) {
	globalBufferPool = pool
	logrus.Info("Global buffer pool updated")
}
