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

// Package benchmark provides performance benchmarks for Kaniko components.
package benchmark

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/Gosayram/kaniko/pkg/snapshot"
	"github.com/Gosayram/kaniko/pkg/util"
)

// Constants for benchmark tests
const (
	MB1          = 1024 * 1024
	KB1          = 1024
	KB64         = 64 * 1024
	MaxCacheSize = 1000
	MaxFiles     = 100
	ByteMod256   = 256
	DefaultTTL   = 5 * time.Minute
	FilePerm750  = 0o750
	FilePerm600  = 0o600
)

// SnapshotPerformance benchmarks snapshot performance
func SnapshotPerformance(b *testing.B) {
	// Create test directory
	testDir := createTestDirectory(b)
	defer os.RemoveAll(testDir)

	// Create snapshotter
	snapshotter := snapshot.NewSnapshotter(&snapshot.LayeredMap{}, testDir)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := snapshotter.TakeSnapshotFS()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// IncrementalSnapshot benchmarks incremental snapshot performance
func IncrementalSnapshot(b *testing.B) {
	// Create test directory
	testDir := createTestDirectory(b)
	defer os.RemoveAll(testDir)

	// Create incremental snapshotter
	incrementalSnapshotter := snapshot.NewIncrementalSnapshotter(testDir, []string{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := incrementalSnapshotter.TakeIncrementalSnapshot()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// FileCopy benchmarks file copying performance
func FileCopy(b *testing.B) {
	// Create test file
	src := createTestFile(b, MB1) // 1MB file
	defer os.Remove(src)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst := fmt.Sprintf("/tmp/copy_%d", i)
		err := util.CopyFileOrSymlinkOptimized(src, dst, "")
		if err != nil {
			b.Fatal(err)
		}
		_ = os.Remove(dst)
	}
}

// OptimizedFileCopy benchmarks optimized file copying
func OptimizedFileCopy(b *testing.B) {
	// Create test file
	src := createTestFile(b, MB1) // 1MB file
	defer os.Remove(src)

	// Create optimized file copy instance
	ofc := util.NewOptimizedFileCopy()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst := fmt.Sprintf("/tmp/optimized_copy_%d", i)
		err := ofc.CopyFileWithOptimization(src, dst)
		if err != nil {
			b.Fatal(err)
		}
		_ = os.Remove(dst)
	}
}

// FileSystemCache benchmarks filesystem cache performance
func FileSystemCache(b *testing.B) {
	// Create test directory
	testDir := createTestDirectory(b)
	defer os.RemoveAll(testDir)

	// Create filesystem cache
	fsCache := util.NewFileSystemCache(MaxCacheSize, DefaultTTL)
	defer fsCache.Close()

	// Create test files
	for i := 0; i < 100; i++ {
		filePath := filepath.Join(testDir, fmt.Sprintf("file_%d.txt", i))
		createTestFileAtPath(b, filePath, KB1) // 1KB files
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filePath := filepath.Join(testDir, fmt.Sprintf("file_%d.txt", i%MaxFiles))
		_, err := fsCache.CachedStat(filePath)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BufferPool benchmarks buffer pool performance
func BufferPool(b *testing.B) {
	// Create test data
	data := make([]byte, KB64) // 64KB
	for i := range data {
		data[i] = byte(i % ByteMod256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Get buffer from pool
		buf := util.GetBuffer(KB64)

		// Use buffer
		copy(*buf, data)

		// Return buffer to pool
		util.PutBuffer(buf)
	}
}

// ResourceLimits benchmarks resource limits checking
func ResourceLimits(b *testing.B) {
	// Create resource limits
	limits := util.NewResourceLimits()
	defer limits.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := limits.CheckAllLimits()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// MemoryUsage benchmarks memory usage patterns
func MemoryUsage(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Allocate memory
		data := make([]byte, MB1) // 1MB

		// Use memory
		for j := range data {
			data[j] = byte(i + j)
		}

		// Force garbage collection periodically
		if i%100 == 0 {
			runtime.GC()
		}
	}
}

// ConcurrentOperations benchmarks concurrent operations
func ConcurrentOperations(b *testing.B) {
	// Create test directory
	testDir := createTestDirectory(b)
	defer os.RemoveAll(testDir)

	// Create test files
	for i := 0; i < 100; i++ {
		filePath := filepath.Join(testDir, fmt.Sprintf("file_%d.txt", i))
		createTestFileAtPath(b, filePath, KB1)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Simulate concurrent file operations
			filePath := filepath.Join(testDir, fmt.Sprintf("file_%d.txt", runtime.NumGoroutine()%MaxFiles))
			_, err := os.Stat(filePath)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// PathOperations benchmarks path operations
func PathOperations(b *testing.B) {
	paths := []string{
		"/tmp/test/file1.txt",
		"/tmp/test/file2.txt",
		"/tmp/test/subdir/file3.txt",
		"/tmp/test/subdir/file4.txt",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		path := paths[i%len(paths)]

		// Test various path operations
		_ = filepath.Base(path)
		_ = filepath.Dir(path)
		_ = filepath.Ext(path)
		_ = filepath.Join(path, "..", "parent")
	}
}

// StringOperations benchmarks string operations
func StringOperations(b *testing.B) {
	strings := []string{
		"hello world",
		"test string",
		"another test",
		"more strings",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		str := strings[i%len(strings)]

		// Test various string operations
		_ = len(str)
		_ = str + " suffix"
		_ = "prefix " + str
	}
}

// Helper functions

// createTestDirectory creates a test directory with files
func createTestDirectory(b *testing.B) string {
	dir, err := os.MkdirTemp("", "kaniko_benchmark_*")
	if err != nil {
		b.Fatal(err)
	}

	// Create subdirectories and files
	for i := 0; i < 10; i++ {
		subdir := filepath.Join(dir, fmt.Sprintf("subdir_%d", i))
		if err := os.Mkdir(subdir, FilePerm750); err != nil {
			b.Fatal(err)
		}

		for j := 0; j < 10; j++ {
			filePath := filepath.Join(subdir, fmt.Sprintf("file_%d.txt", j))
			createTestFileAtPath(b, filePath, KB1) // 1KB files
		}
	}

	return dir
}

// createTestFile creates a test file with specified size
func createTestFile(b *testing.B, size int64) string {
	file, err := os.CreateTemp("", "kaniko_benchmark_*.txt")
	if err != nil {
		b.Fatal(err)
	}
	defer file.Close()

	// Write test data
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % ByteMod256)
	}

	if _, err := file.Write(data); err != nil {
		b.Fatal(err)
	}

	return file.Name()
}

// createTestFileAtPath creates a test file at specified path
func createTestFileAtPath(b *testing.B, path string, size int64) {
	file, err := os.Create(filepath.Clean(path))
	if err != nil {
		b.Fatal(err)
	}
	defer file.Close()

	// Write test data
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % ByteMod256)
	}

	if _, err := file.Write(data); err != nil {
		b.Fatal(err)
	}
}

// MemoryAllocation benchmarks memory allocation patterns
func MemoryAllocation(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Allocate different sizes
		sizes := []int{1024, 4096, 16384, 65536} // 1KB, 4KB, 16KB, 64KB
		size := sizes[i%len(sizes)]

		// Allocate memory
		data := make([]byte, size)

		// Use memory
		for j := range data {
			data[j] = byte(i + j)
		}

		// Force garbage collection periodically
		if i%1000 == 0 {
			runtime.GC()
		}
	}
}

// GoroutineCreation benchmarks goroutine creation
func GoroutineCreation(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		done := make(chan struct{})
		go func() {
			// Simulate work
			time.Sleep(time.Microsecond)
			close(done)
		}()
		<-done
	}
}

// ChannelOperations benchmarks channel operations
func ChannelOperations(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ch := make(chan int, 1)
		go func() {
			ch <- i
		}()
		<-ch
		close(ch)
	}
}

// MutexOperations benchmarks mutex operations
func MutexOperations(b *testing.B) {
	var mu sync.Mutex
	var counter int

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mu.Lock()
		counter++
		mu.Unlock()
	}
}

// RWMutexOperations benchmarks read-write mutex operations
func RWMutexOperations(b *testing.B) {
	var mu sync.RWMutex
	var counter int

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mu.RLock()
		_ = counter
		mu.RUnlock()
	}
}
