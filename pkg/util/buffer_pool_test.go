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
	"bytes"
	"strings"
	"testing"
)

func TestBufferPool(t *testing.T) {
	pool := NewBufferPool(1024)

	// Test getting and putting buffers
	buf1 := pool.Get()
	if len(*buf1) != 1024 {
		t.Errorf("Expected buffer size 1024, got %d", len(*buf1))
	}

	// Modify the buffer
	*buf1 = (*buf1)[:100] // Resize to 100 bytes
	copy(*buf1, []byte("test data"))

	// Put it back
	pool.Put(buf1)

	// Get it again - should be reset
	buf2 := pool.Get()
	if len(*buf2) != 1024 {
		t.Errorf("Expected buffer size 1024 after reset, got %d", len(*buf2))
	}

	// Put it back
	pool.Put(buf2)
}

func TestBytesBufferPool(t *testing.T) {
	pool := NewBytesBufferPool()

	// Test getting and putting buffers
	buf1 := pool.Get()
	if buf1.Cap() < 1024 {
		t.Errorf("Expected buffer capacity >= 1024, got %d", buf1.Cap())
	}

	// Write some data
	buf1.WriteString("test data")
	if buf1.String() != "test data" {
		t.Errorf("Expected 'test data', got '%s'", buf1.String())
	}

	// Put it back
	pool.Put(buf1)

	// Get it again - should be reset
	buf2 := pool.Get()
	if buf2.Len() != 0 {
		t.Errorf("Expected empty buffer after reset, got length %d", buf2.Len())
	}

	// Put it back
	pool.Put(buf2)
}

func TestCopyWithBuffer(t *testing.T) {
	// Test data
	testData := "Hello, World! This is a test string for buffer pooling."
	src := strings.NewReader(testData)

	var dst bytes.Buffer

	// Test copying with buffer pool
	written, err := CopyWithBuffer(&dst, src, SmallBufferPool)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if written != int64(len(testData)) {
		t.Errorf("Expected written %d, got %d", len(testData), written)
	}

	if dst.String() != testData {
		t.Errorf("Expected '%s', got '%s'", testData, dst.String())
	}
}

func TestCopyFileWithBuffer(t *testing.T) {
	// Test data
	testData := "This is test data for file copying with buffer pooling."
	src := strings.NewReader(testData)

	var dst bytes.Buffer

	// Test copying with default buffer pool
	written, err := CopyFileWithBuffer(&dst, src)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if written != int64(len(testData)) {
		t.Errorf("Expected written %d, got %d", len(testData), written)
	}

	if dst.String() != testData {
		t.Errorf("Expected '%s', got '%s'", testData, dst.String())
	}
}

func TestGetBuffer(t *testing.T) {
	tests := []struct {
		name     string
		size     int
		expected string
	}{
		{
			name:     "Small buffer",
			size:     1024,
			expected: "small",
		},
		{
			name:     "Medium buffer",
			size:     16 * 1024,
			expected: "medium",
		},
		{
			name:     "Large buffer",
			size:     128 * 1024,
			expected: "large",
		},
		{
			name:     "Very large buffer",
			size:     512 * 1024,
			expected: "new",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := GetBuffer(tt.size)
			if buf == nil {
				t.Errorf("Expected non-nil buffer")
			}

			// Test that we can write to the buffer
			*buf = (*buf)[:tt.size]
			copy(*buf, []byte("test"))

			// Return the buffer
			PutBuffer(buf)
		})
	}
}

func TestGlobalPools(t *testing.T) {
	// Test that global pools are initialized
	if SmallBufferPool == nil {
		t.Error("SmallBufferPool should be initialized")
	}

	if MediumBufferPool == nil {
		t.Error("MediumBufferPool should be initialized")
	}

	if LargeBufferPool == nil {
		t.Error("LargeBufferPool should be initialized")
	}

	if GlobalBytesBufferPool == nil {
		t.Error("GlobalBytesBufferPool should be initialized")
	}
}

func TestBufferPoolConcurrency(t *testing.T) {
	pool := NewBufferPool(1024)

	// Test concurrent access
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				buf := pool.Get()
				// Simulate some work
				*buf = (*buf)[:100]
				copy(*buf, []byte("test"))
				pool.Put(buf)
			}
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestBytesBufferPoolLargeBuffer(t *testing.T) {
	pool := NewBytesBufferPool()

	// Create a large buffer that should not be returned to pool
	buf := pool.Get()

	// Write a lot of data to make it large
	for i := 0; i < 1000; i++ {
		buf.WriteString("This is a long string that will make the buffer large. ")
	}

	// Put it back - should not be returned to pool due to size
	pool.Put(buf)

	// Get a new buffer - should be small
	newBuf := pool.Get()
	if newBuf.Cap() > 64*1024 {
		t.Errorf("Expected small buffer capacity, got %d", newBuf.Cap())
	}

	pool.Put(newBuf)
}
