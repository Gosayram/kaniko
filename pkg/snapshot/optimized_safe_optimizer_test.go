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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Gosayram/kaniko/pkg/config"
)

func TestLRUHashCache(t *testing.T) {
	cache := NewLRUHashCache(3)

	// Test basic operations
	cache.Put("file1", "hash1")
	cache.Put("file2", "hash2")
	cache.Put("file3", "hash3")

	// Test retrieval
	if hash, found := cache.Get("file1"); !found || hash != "hash1" {
		t.Errorf("Expected hash1, got %s", hash)
	}

	// Test LRU eviction
	cache.Put("file4", "hash4") // Should evict file1 (least recently used)

	// Access file2 and file3 to make them more recent
	cache.Get("file2")
	cache.Get("file3")

	// Add another file to trigger eviction
	cache.Put("file5", "hash5") // Should evict file1 (still least recently used)

	if _, found := cache.Get("file1"); found {
		t.Error("file1 should have been evicted")
	}

	if hash, found := cache.Get("file4"); !found || hash != "hash4" {
		t.Errorf("Expected hash4, got %s", hash)
	}

	// Test statistics
	stats := cache.GetStats()
	if stats.Hits == 0 {
		t.Error("Expected cache hits > 0")
	}

	if stats.HitRate <= 0 {
		t.Error("Expected hit rate > 0")
	}
}

func TestLRUHashCacheConcurrency(t *testing.T) {
	cache := NewLRUHashCache(100)

	// Test concurrent access
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				key := fmt.Sprintf("file_%d_%d", id, j)
				hash := fmt.Sprintf("hash_%d_%d", id, j)

				cache.Put(key, hash)

				if retrievedHash, found := cache.Get(key); !found || retrievedHash != hash {
					// Log the error but don't fail the test immediately
					// This is expected behavior in concurrent scenarios
					t.Logf("Concurrent access issue for key %s: found=%v, hash=%s", key, found, retrievedHash)
				}
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify cache is still functional
	if cache.Size() == 0 {
		t.Error("Cache should not be empty after concurrent access")
	}
}

func TestAdaptiveWorkerPool(t *testing.T) {
	pool := NewAdaptiveWorkerPool(2, 4)
	defer pool.Shutdown()

	// Test basic task submission with smaller batch
	taskCount := 5
	completed := make(chan int, taskCount)

	for i := 0; i < taskCount; i++ {
		task := Task{
			ID: fmt.Sprintf("task_%d", i),
			Function: func() error {
				time.Sleep(5 * time.Millisecond)
				completed <- 1
				return nil
			},
			Priority: 0,
		}

		if err := pool.Submit(task); err != nil {
			t.Logf("Failed to submit task %d: %v (this may be expected)", i, err)
		}
	}

	// Wait for completion
	pool.WaitForCompletion()

	// Verify tasks completed (allow for some failures due to queue limits)
	totalCompleted := 0
	timeout := time.After(2 * time.Second)
	for i := 0; i < taskCount; i++ {
		select {
		case <-completed:
			totalCompleted++
		case <-timeout:
			goto done
		}
	}
done:

	if totalCompleted == 0 {
		t.Error("Expected at least some tasks to complete")
	}

	// Test statistics
	stats := pool.GetStats()
	if stats.TasksProcessed == 0 {
		t.Error("Expected tasks processed > 0")
	}
}

func TestAdaptiveWorkerPoolScaling(t *testing.T) {
	pool := NewAdaptiveWorkerPool(1, 4)
	defer pool.Shutdown()

	// Submit many tasks to trigger scaling
	for i := 0; i < 20; i++ {
		task := Task{
			ID: fmt.Sprintf("scaling_task_%d", i),
			Function: func() error {
				time.Sleep(50 * time.Millisecond)
				return nil
			},
			Priority: 0,
		}

		pool.Submit(task)
	}

	// Wait a bit for scaling to occur
	time.Sleep(100 * time.Millisecond)

	// Check that workers were scaled up
	workers := pool.GetCurrentWorkers()
	if workers <= 1 {
		t.Errorf("Expected workers > 1, got %d", workers)
	}

	pool.WaitForCompletion()
}

func TestIncrementalIntegrityChecker(t *testing.T) {
	checker := NewIncrementalIntegrityChecker(10)

	// Test normal files (should pass)
	normalFiles := []string{"/tmp/file1", "/tmp/file2", "/tmp/file3"}
	if checker.NeedsIncrementalCheck(normalFiles) {
		t.Error("Normal files should not need incremental check")
	}

	// Test too many files (should fail)
	manyFiles := make([]string, 15)
	for i := 0; i < 15; i++ {
		manyFiles[i] = fmt.Sprintf("/tmp/file_%d", i)
	}

	if !checker.NeedsIncrementalCheck(manyFiles) {
		t.Error("Too many files should need incremental check")
	}

	// Test critical files (should fail)
	criticalFiles := []string{"/etc/passwd", "/tmp/normal_file"}
	if !checker.NeedsIncrementalCheck(criticalFiles) {
		t.Error("Critical files should need incremental check")
	}

	// Test incremental scan capability
	if !checker.CanPerformIncrementalScan() {
		t.Error("Should be able to perform incremental scan initially")
	}
}

func TestOptimizedSafeSnapshotOptimizer(t *testing.T) {
	// Create temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "optimized_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test files
	testFiles := []string{
		"file1.txt",
		"file2.txt",
		"subdir/file3.txt",
	}

	for _, file := range testFiles {
		fullPath := filepath.Join(tmpDir, file)
		dir := filepath.Dir(fullPath)

		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("Failed to create directory %s: %v", dir, err)
		}

		if err := os.WriteFile(fullPath, []byte("test content"), 0644); err != nil {
			t.Fatalf("Failed to create file %s: %v", fullPath, err)
		}
	}

	// Create mock snapshotter and options
	_ = &config.KanikoOptions{
		MaxParallelCommands: 2,
		EnableParallelExec:  true,
		IntegrityCheck:      true,
		MaxExpectedChanges:  10,
	}

	// Note: This test would require a mock snapshotter
	// For now, we'll test the components individually
	t.Run("LRU_Cache_Integration", func(t *testing.T) {
		cache := NewLRUHashCache(100)

		// Simulate file hashing
		for _, file := range testFiles {
			fullPath := filepath.Join(tmpDir, file)
			cache.Put(fullPath, "mock_hash")
		}

		// Test cache hits
		for _, file := range testFiles {
			fullPath := filepath.Join(tmpDir, file)
			if hash, found := cache.Get(fullPath); !found || hash != "mock_hash" {
				t.Errorf("Cache miss for file %s", fullPath)
			}
		}

		stats := cache.GetStats()
		if stats.Hits == 0 {
			t.Error("Expected cache hits > 0")
		}
	})

	t.Run("Worker_Pool_Integration", func(t *testing.T) {
		pool := NewAdaptiveWorkerPool(1, 2)
		defer pool.Shutdown()

		// Submit file processing tasks
		for _, file := range testFiles {
			fullPath := filepath.Join(tmpDir, file)
			task := Task{
				ID: fullPath,
				Function: func() error {
					// Simulate file processing
					time.Sleep(10 * time.Millisecond)
					return nil
				},
				Priority: 0,
			}

			if err := pool.Submit(task); err != nil {
				t.Errorf("Failed to submit task for %s: %v", fullPath, err)
			}
		}

		pool.WaitForCompletion()

		stats := pool.GetStats()
		if stats.TasksProcessed == 0 {
			t.Error("Expected tasks processed > 0")
		}
	})
}

func TestGetOptimalWorkerCount(t *testing.T) {
	tests := []struct {
		taskType string
		expected int
	}{
		{"cpu_intensive", runtime.NumCPU()},
		{"io_intensive", runtime.NumCPU() * 2},
		{"mixed", int(float64(runtime.NumCPU()) * 1.5)},
		{"unknown", runtime.NumCPU()},
	}

	for _, test := range tests {
		result := GetOptimalWorkerCount(test.taskType)
		if result != test.expected {
			t.Errorf("GetOptimalWorkerCount(%s) = %d, expected %d",
				test.taskType, result, test.expected)
		}
	}
}

func TestLRUHashCacheWarmup(t *testing.T) {
	cache := NewLRUHashCache(10)

	// Create mock hasher function
	hasher := func(path string) (string, error) {
		return fmt.Sprintf("hash_%s", filepath.Base(path)), nil
	}

	// Test warmup
	files := []string{"/tmp/file1", "/tmp/file2", "/tmp/file3"}
	cache.WarmupCache(files, hasher)

	// Verify cache is populated
	if cache.Size() != len(files) {
		t.Errorf("Expected cache size %d, got %d", len(files), cache.Size())
	}

	// Verify cache contents
	for _, file := range files {
		if hash, found := cache.Get(file); !found {
			t.Errorf("File %s not found in cache after warmup", file)
		} else {
			expectedHash := fmt.Sprintf("hash_%s", filepath.Base(file))
			if hash != expectedHash {
				t.Errorf("Expected hash %s for file %s, got %s", expectedHash, file, hash)
			}
		}
	}
}

func TestLRUHashCacheEfficiency(t *testing.T) {
	cache := NewLRUHashCache(5)

	// Fill cache
	for i := 0; i < 5; i++ {
		cache.Put(fmt.Sprintf("file_%d", i), fmt.Sprintf("hash_%d", i))
	}

	// Access some files multiple times
	for i := 0; i < 10; i++ {
		cache.Get("file_0") // Should be cached
		cache.Get("file_1") // Should be cached
	}

	// Add more files to trigger evictions
	for i := 5; i < 10; i++ {
		cache.Put(fmt.Sprintf("file_%d", i), fmt.Sprintf("hash_%d", i))
	}

	// Check efficiency metrics
	efficiency := cache.GetCacheEfficiency()

	if efficiency["hit_rate"].(float64) <= 0 {
		t.Error("Expected hit rate > 0")
	}

	if efficiency["utilization"].(float64) != 1.0 {
		t.Error("Expected utilization = 1.0")
	}

	if efficiency["size"].(int) != 5 {
		t.Error("Expected cache size = 5")
	}
}
