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
	"testing"
)

func TestNewBufferPool(t *testing.T) {
	bp := NewBufferPool()

	if bp == nil {
		t.Fatal("Expected non-nil buffer pool")
	}

	if bp.GetSmallBufferSize() != DefaultSmallBufferSize {
		t.Errorf("Expected small buffer size %d, got %d", DefaultSmallBufferSize, bp.GetSmallBufferSize())
	}

	if bp.GetMediumBufferSize() != DefaultMediumBufferSize {
		t.Errorf("Expected medium buffer size %d, got %d", DefaultMediumBufferSize, bp.GetMediumBufferSize())
	}

	if bp.GetLargeBufferSize() != DefaultLargeBufferSize {
		t.Errorf("Expected large buffer size %d, got %d", DefaultLargeBufferSize, bp.GetLargeBufferSize())
	}
}

func TestNewBufferPoolWithSizes(t *testing.T) {
	smallSize := 8 * 1024        // 8KB
	mediumSize := 128 * 1024     // 128KB
	largeSize := 2 * 1024 * 1024 // 2MB

	bp := NewBufferPoolWithSizes(smallSize, mediumSize, largeSize)

	if bp.GetSmallBufferSize() != smallSize {
		t.Errorf("Expected small buffer size %d, got %d", smallSize, bp.GetSmallBufferSize())
	}

	if bp.GetMediumBufferSize() != mediumSize {
		t.Errorf("Expected medium buffer size %d, got %d", mediumSize, bp.GetMediumBufferSize())
	}

	if bp.GetLargeBufferSize() != largeSize {
		t.Errorf("Expected large buffer size %d, got %d", largeSize, bp.GetLargeBufferSize())
	}
}

func TestNewBufferPoolWithInvalidSizes(t *testing.T) {
	// Test with invalid sizes (should use defaults)
	bp := NewBufferPoolWithSizes(-1, 0, -100)

	if bp.GetSmallBufferSize() != DefaultSmallBufferSize {
		t.Errorf("Expected default small buffer size %d, got %d", DefaultSmallBufferSize, bp.GetSmallBufferSize())
	}

	if bp.GetMediumBufferSize() != DefaultMediumBufferSize {
		t.Errorf("Expected default medium buffer size %d, got %d", DefaultMediumBufferSize, bp.GetMediumBufferSize())
	}

	if bp.GetLargeBufferSize() != DefaultLargeBufferSize {
		t.Errorf("Expected default large buffer size %d, got %d", DefaultLargeBufferSize, bp.GetLargeBufferSize())
	}
}

func TestGetSmallBuffer(t *testing.T) {
	bp := NewBufferPool()

	buffer := bp.GetSmallBuffer()

	if len(buffer) != bp.GetSmallBufferSize() {
		t.Errorf("Expected buffer size %d, got %d", bp.GetSmallBufferSize(), len(buffer))
	}

	// Check that buffer is cleared
	for i, b := range buffer {
		if b != 0 {
			t.Errorf("Expected buffer[%d] to be 0, got %d", i, b)
		}
	}
}

func TestGetMediumBuffer(t *testing.T) {
	bp := NewBufferPool()

	buffer := bp.GetMediumBuffer()

	if len(buffer) != bp.GetMediumBufferSize() {
		t.Errorf("Expected buffer size %d, got %d", bp.GetMediumBufferSize(), len(buffer))
	}

	// Check that buffer is cleared
	for i, b := range buffer {
		if b != 0 {
			t.Errorf("Expected buffer[%d] to be 0, got %d", i, b)
		}
	}
}

func TestGetLargeBuffer(t *testing.T) {
	bp := NewBufferPool()

	buffer := bp.GetLargeBuffer()

	if len(buffer) != bp.GetLargeBufferSize() {
		t.Errorf("Expected buffer size %d, got %d", bp.GetLargeBufferSize(), len(buffer))
	}

	// Check that buffer is cleared
	for i, b := range buffer {
		if b != 0 {
			t.Errorf("Expected buffer[%d] to be 0, got %d", i, b)
		}
	}
}

func TestGetBuffer(t *testing.T) {
	bp := NewBufferPool()

	// Test small buffer request
	buffer := bp.GetBuffer(1000)
	if len(buffer) != bp.GetSmallBufferSize() {
		t.Errorf("Expected small buffer size %d, got %d", bp.GetSmallBufferSize(), len(buffer))
	}

	// Test medium buffer request
	buffer = bp.GetBuffer(50000)
	if len(buffer) != bp.GetMediumBufferSize() {
		t.Errorf("Expected medium buffer size %d, got %d", bp.GetMediumBufferSize(), len(buffer))
	}

	// Test large buffer request
	buffer = bp.GetBuffer(500000)
	if len(buffer) != bp.GetLargeBufferSize() {
		t.Errorf("Expected large buffer size %d, got %d", bp.GetLargeBufferSize(), len(buffer))
	}

	// Test very large buffer request (should allocate directly)
	buffer = bp.GetBuffer(2 * 1024 * 1024) // 2MB
	if len(buffer) != 2*1024*1024 {
		t.Errorf("Expected buffer size %d, got %d", 2*1024*1024, len(buffer))
	}
}

func TestPutSmallBuffer(t *testing.T) {
	bp := NewBufferPool()

	// Get and return a buffer
	buffer := bp.GetSmallBuffer()
	bp.PutSmallBuffer(buffer)

	// Get another buffer - should reuse the returned one
	buffer2 := bp.GetSmallBuffer()

	// The buffer should be cleared
	for i, b := range buffer2 {
		if b != 0 {
			t.Errorf("Expected buffer[%d] to be 0, got %d", i, b)
		}
	}
}

func TestPutMediumBuffer(t *testing.T) {
	bp := NewBufferPool()

	// Get and return a buffer
	buffer := bp.GetMediumBuffer()
	bp.PutMediumBuffer(buffer)

	// Get another buffer - should reuse the returned one
	buffer2 := bp.GetMediumBuffer()

	// The buffer should be cleared
	for i, b := range buffer2 {
		if b != 0 {
			t.Errorf("Expected buffer[%d] to be 0, got %d", i, b)
		}
	}
}

func TestPutLargeBuffer(t *testing.T) {
	bp := NewBufferPool()

	// Get and return a buffer
	buffer := bp.GetLargeBuffer()
	bp.PutLargeBuffer(buffer)

	// Get another buffer - should reuse the returned one
	buffer2 := bp.GetLargeBuffer()

	// The buffer should be cleared
	for i, b := range buffer2 {
		if b != 0 {
			t.Errorf("Expected buffer[%d] to be 0, got %d", i, b)
		}
	}
}

func TestPutBuffer(t *testing.T) {
	bp := NewBufferPool()

	// Test putting buffers of different sizes
	smallBuffer := bp.GetSmallBuffer()
	bp.PutBuffer(smallBuffer)

	mediumBuffer := bp.GetMediumBuffer()
	bp.PutBuffer(mediumBuffer)

	largeBuffer := bp.GetLargeBuffer()
	bp.PutBuffer(largeBuffer)

	// Test putting a custom-sized buffer (should not be returned to pool)
	customBuffer := make([]byte, 1000)
	bp.PutBuffer(customBuffer)
}

func TestGetStats(t *testing.T) {
	bp := NewBufferPool()

	// Initial stats should be zero
	stats := bp.GetStats()
	if stats.TotalAllocations != 0 {
		t.Errorf("Expected initial total allocations 0, got %d", stats.TotalAllocations)
	}

	// Get some buffers
	bp.GetSmallBuffer()
	bp.GetMediumBuffer()
	bp.GetLargeBuffer()

	stats = bp.GetStats()
	if stats.TotalAllocations != 3 {
		t.Errorf("Expected total allocations 3, got %d", stats.TotalAllocations)
	}

	if stats.SmallBuffersAllocated != 1 {
		t.Errorf("Expected small buffers allocated 1, got %d", stats.SmallBuffersAllocated)
	}

	if stats.MediumBuffersAllocated != 1 {
		t.Errorf("Expected medium buffers allocated 1, got %d", stats.MediumBuffersAllocated)
	}

	if stats.LargeBuffersAllocated != 1 {
		t.Errorf("Expected large buffers allocated 1, got %d", stats.LargeBuffersAllocated)
	}
}

func TestBufferPoolResetStats(t *testing.T) {
	bp := NewBufferPool()

	// Get some buffers to generate stats
	bp.GetSmallBuffer()
	bp.GetMediumBuffer()

	// Reset stats
	bp.ResetStats()

	stats := bp.GetStats()
	if stats.TotalAllocations != 0 {
		t.Errorf("Expected stats to be reset, got total allocations %d", stats.TotalAllocations)
	}
}

func TestIsBufferFromPool(t *testing.T) {
	bp := NewBufferPool()

	// Test buffers from pool
	smallBuffer := bp.GetSmallBuffer()
	if !bp.IsBufferFromPool(smallBuffer) {
		t.Error("Expected small buffer to be from pool")
	}

	mediumBuffer := bp.GetMediumBuffer()
	if !bp.IsBufferFromPool(mediumBuffer) {
		t.Error("Expected medium buffer to be from pool")
	}

	largeBuffer := bp.GetLargeBuffer()
	if !bp.IsBufferFromPool(largeBuffer) {
		t.Error("Expected large buffer to be from pool")
	}

	// Test custom buffer
	customBuffer := make([]byte, 1000)
	if bp.IsBufferFromPool(customBuffer) {
		t.Error("Expected custom buffer not to be from pool")
	}
}

func TestGetOptimalBufferSize(t *testing.T) {
	bp := NewBufferPool()

	// Test small operation
	size := bp.GetOptimalBufferSize(1000)
	if size != bp.GetSmallBufferSize() {
		t.Errorf("Expected optimal size %d for small operation, got %d", bp.GetSmallBufferSize(), size)
	}

	// Test medium operation
	size = bp.GetOptimalBufferSize(50000)
	if size != bp.GetMediumBufferSize() {
		t.Errorf("Expected optimal size %d for medium operation, got %d", bp.GetMediumBufferSize(), size)
	}

	// Test large operation
	size = bp.GetOptimalBufferSize(500000)
	if size != bp.GetLargeBufferSize() {
		t.Errorf("Expected optimal size %d for large operation, got %d", bp.GetLargeBufferSize(), size)
	}

	// Test very large operation
	size = bp.GetOptimalBufferSize(2 * 1024 * 1024)
	if size != 2*1024*1024 {
		t.Errorf("Expected optimal size %d for very large operation, got %d", 2*1024*1024, size)
	}
}

func TestPreallocateBuffers(t *testing.T) {
	bp := NewBufferPool()

	// Pre-allocate some buffers
	bp.PreallocateBuffers(5, 3, 2)

	// Check that buffers are available
	smallBuffer := bp.GetSmallBuffer()
	if len(smallBuffer) != bp.GetSmallBufferSize() {
		t.Errorf("Expected small buffer size %d, got %d", bp.GetSmallBufferSize(), len(smallBuffer))
	}

	mediumBuffer := bp.GetMediumBuffer()
	if len(mediumBuffer) != bp.GetMediumBufferSize() {
		t.Errorf("Expected medium buffer size %d, got %d", bp.GetMediumBufferSize(), len(mediumBuffer))
	}

	largeBuffer := bp.GetLargeBuffer()
	if len(largeBuffer) != bp.GetLargeBufferSize() {
		t.Errorf("Expected large buffer size %d, got %d", bp.GetLargeBufferSize(), len(largeBuffer))
	}
}

func TestGlobalBufferPool(t *testing.T) {
	// Test getting global buffer pool
	bp1 := GetGlobalBufferPool()
	if bp1 == nil {
		t.Fatal("Expected non-nil global buffer pool")
	}

	// Test that it's the same instance
	bp2 := GetGlobalBufferPool()
	if bp1 != bp2 {
		t.Error("Expected same global buffer pool instance")
	}

	// Test setting global buffer pool
	newBP := NewBufferPool()
	SetGlobalBufferPool(newBP)

	bp3 := GetGlobalBufferPool()
	if bp3 != newBP {
		t.Error("Expected updated global buffer pool instance")
	}
}

func TestBufferPoolConcurrency(t *testing.T) {
	bp := NewBufferPool()

	// Test concurrent access
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- true }()

			// Get and return buffers
			for j := 0; j < 10; j++ {
				smallBuffer := bp.GetSmallBuffer()
				bp.PutSmallBuffer(smallBuffer)

				mediumBuffer := bp.GetMediumBuffer()
				bp.PutMediumBuffer(mediumBuffer)

				largeBuffer := bp.GetLargeBuffer()
				bp.PutLargeBuffer(largeBuffer)
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Check that stats are reasonable
	stats := bp.GetStats()
	if stats.TotalAllocations == 0 {
		t.Error("Expected some allocations to have occurred")
	}
}

func TestBufferPoolEfficiency(t *testing.T) {
	bp := NewBufferPool()

	// Get and return buffers multiple times
	for i := 0; i < 100; i++ {
		smallBuffer := bp.GetSmallBuffer()
		bp.PutSmallBuffer(smallBuffer)

		mediumBuffer := bp.GetMediumBuffer()
		bp.PutMediumBuffer(mediumBuffer)

		largeBuffer := bp.GetLargeBuffer()
		bp.PutLargeBuffer(largeBuffer)
	}

	stats := bp.GetStats()

	// Should have high efficiency (many returns vs allocations)
	if stats.TotalReturns < stats.TotalAllocations {
		t.Errorf("Expected high efficiency, got returns=%d, allocations=%d",
			stats.TotalReturns, stats.TotalAllocations)
	}
}
