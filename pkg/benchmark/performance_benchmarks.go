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

// BenchmarkSnapshotPerformance benchmarks snapshot performance
func BenchmarkSnapshotPerformance(b *testing.B) {
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

// BenchmarkIncrementalSnapshot benchmarks incremental snapshot performance
func BenchmarkIncrementalSnapshot(b *testing.B) {
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

// BenchmarkFileCopy benchmarks file copying performance
func BenchmarkFileCopy(b *testing.B) {
	// Create test file
	src := createTestFile(b, 1024*1024) // 1MB file
	defer os.Remove(src)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst := fmt.Sprintf("/tmp/copy_%d", i)
		err := util.CopyFileOrSymlinkOptimized(src, dst, "")
		if err != nil {
			b.Fatal(err)
		}
		os.Remove(dst)
	}
}

// BenchmarkOptimizedFileCopy benchmarks optimized file copying
func BenchmarkOptimizedFileCopy(b *testing.B) {
	// Create test file
	src := createTestFile(b, 1024*1024) // 1MB file
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
		os.Remove(dst)
	}
}

// BenchmarkFileSystemCache benchmarks filesystem cache performance
func BenchmarkFileSystemCache(b *testing.B) {
	// Create test directory
	testDir := createTestDirectory(b)
	defer os.RemoveAll(testDir)

	// Create filesystem cache
	fsCache := util.NewFileSystemCache(1000, 5*time.Minute)
	defer fsCache.Close()

	// Create test files
	for i := 0; i < 100; i++ {
		filePath := filepath.Join(testDir, fmt.Sprintf("file_%d.txt", i))
		createTestFileAtPath(b, filePath, 1024) // 1KB files
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filePath := filepath.Join(testDir, fmt.Sprintf("file_%d.txt", i%100))
		_, err := fsCache.CachedStat(filePath)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkBufferPool benchmarks buffer pool performance
func BenchmarkBufferPool(b *testing.B) {
	// Create test data
	data := make([]byte, 64*1024) // 64KB
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Get buffer from pool
		buf := util.GetBuffer(64 * 1024)

		// Use buffer
		copy(*buf, data)

		// Return buffer to pool
		util.PutBuffer(buf)
	}
}

// BenchmarkResourceLimits benchmarks resource limits checking
func BenchmarkResourceLimits(b *testing.B) {
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

// BenchmarkMemoryUsage benchmarks memory usage patterns
func BenchmarkMemoryUsage(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Allocate memory
		data := make([]byte, 1024*1024) // 1MB

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

// BenchmarkConcurrentOperations benchmarks concurrent operations
func BenchmarkConcurrentOperations(b *testing.B) {
	// Create test directory
	testDir := createTestDirectory(b)
	defer os.RemoveAll(testDir)

	// Create test files
	for i := 0; i < 100; i++ {
		filePath := filepath.Join(testDir, fmt.Sprintf("file_%d.txt", i))
		createTestFileAtPath(b, filePath, 1024)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Simulate concurrent file operations
			filePath := filepath.Join(testDir, fmt.Sprintf("file_%d.txt", runtime.NumGoroutine()%100))
			_, err := os.Stat(filePath)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkPathOperations benchmarks path operations
func BenchmarkPathOperations(b *testing.B) {
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

// BenchmarkStringOperations benchmarks string operations
func BenchmarkStringOperations(b *testing.B) {
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
		if err := os.Mkdir(subdir, 0755); err != nil {
			b.Fatal(err)
		}

		for j := 0; j < 10; j++ {
			filePath := filepath.Join(subdir, fmt.Sprintf("file_%d.txt", j))
			createTestFileAtPath(b, filePath, 1024) // 1KB files
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
		data[i] = byte(i % 256)
	}

	if _, err := file.Write(data); err != nil {
		b.Fatal(err)
	}

	return file.Name()
}

// createTestFileAtPath creates a test file at specified path
func createTestFileAtPath(b *testing.B, path string, size int64) {
	file, err := os.Create(path)
	if err != nil {
		b.Fatal(err)
	}
	defer file.Close()

	// Write test data
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 256)
	}

	if _, err := file.Write(data); err != nil {
		b.Fatal(err)
	}
}

// BenchmarkMemoryAllocation benchmarks memory allocation patterns
func BenchmarkMemoryAllocation(b *testing.B) {
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

// BenchmarkGoroutineCreation benchmarks goroutine creation
func BenchmarkGoroutineCreation(b *testing.B) {
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

// BenchmarkChannelOperations benchmarks channel operations
func BenchmarkChannelOperations(b *testing.B) {
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

// BenchmarkMutexOperations benchmarks mutex operations
func BenchmarkMutexOperations(b *testing.B) {
	var mu sync.Mutex
	var counter int

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mu.Lock()
		counter++
		mu.Unlock()
	}
}

// BenchmarkRWMutexOperations benchmarks read-write mutex operations
func BenchmarkRWMutexOperations(b *testing.B) {
	var mu sync.RWMutex
	var counter int

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mu.RLock()
		_ = counter
		mu.RUnlock()
	}
}
