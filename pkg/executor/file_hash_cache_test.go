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

package executor

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/util"
)

func TestFileHashCache_GetSet(t *testing.T) {
	cache := NewFileHashCache(100, 10)

	// Create a test file
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(filePath, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Compute hash
	hash, err := util.CacheHasher()(filePath)
	if err != nil {
		t.Fatalf("Failed to compute hash: %v", err)
	}

	// Set in cache
	if err := cache.Set(filePath, hash); err != nil {
		t.Fatalf("Failed to set cache: %v", err)
	}

	// Get from cache
	cachedHash, found := cache.Get(filePath)
	if !found {
		t.Error("Expected to find cached hash, but didn't")
	}
	if cachedHash != hash {
		t.Errorf("Expected cached hash to match, got %s, want %s", cachedHash, hash)
	}
}

func TestFileHashCache_Invalidation_Mtime(t *testing.T) {
	cache := NewFileHashCache(100, 10)

	// Create a test file
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(filePath, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Compute and cache hash
	hash1, err := util.CacheHasher()(filePath)
	if err != nil {
		t.Fatalf("Failed to compute hash: %v", err)
	}
	if err := cache.Set(filePath, hash1); err != nil {
		t.Fatalf("Failed to set cache: %v", err)
	}

	// Verify cache hit
	_, found := cache.Get(filePath)
	if !found {
		t.Error("Expected to find cached hash before modification")
	}

	// Modify file mtime (touch the file)
	time.Sleep(100 * time.Millisecond) // Ensure different mtime
	if err := os.Chtimes(filePath, time.Now(), time.Now()); err != nil {
		t.Fatalf("Failed to change mtime: %v", err)
	}

	// Cache should be invalidated
	_, found = cache.Get(filePath)
	if found {
		t.Error("Expected cache to be invalidated after mtime change")
	}
}

func TestFileHashCache_Invalidation_Size(t *testing.T) {
	cache := NewFileHashCache(100, 10)

	// Create a test file
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(filePath, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Compute and cache hash
	hash1, err := util.CacheHasher()(filePath)
	if err != nil {
		t.Fatalf("Failed to compute hash: %v", err)
	}
	if err := cache.Set(filePath, hash1); err != nil {
		t.Fatalf("Failed to set cache: %v", err)
	}

	// Verify cache hit
	_, found := cache.Get(filePath)
	if !found {
		t.Error("Expected to find cached hash before modification")
	}

	// Modify file size
	if err := os.WriteFile(filePath, []byte("modified content with different size"), 0644); err != nil {
		t.Fatalf("Failed to modify file: %v", err)
	}

	// Cache should be invalidated
	_, found = cache.Get(filePath)
	if found {
		t.Error("Expected cache to be invalidated after size change")
	}
}

func TestFileHashCache_Invalidation_Mode(t *testing.T) {
	cache := NewFileHashCache(100, 10)

	// Create a test file
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(filePath, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Compute and cache hash
	hash1, err := util.CacheHasher()(filePath)
	if err != nil {
		t.Fatalf("Failed to compute hash: %v", err)
	}
	if err := cache.Set(filePath, hash1); err != nil {
		t.Fatalf("Failed to set cache: %v", err)
	}

	// Verify cache hit
	_, found := cache.Get(filePath)
	if !found {
		t.Error("Expected to find cached hash before modification")
	}

	// Modify file mode
	if err := os.Chmod(filePath, 0755); err != nil {
		t.Fatalf("Failed to change mode: %v", err)
	}

	// Cache should be invalidated
	_, found = cache.Get(filePath)
	if found {
		t.Error("Expected cache to be invalidated after mode change")
	}
}

func TestFileHashCache_MaxEntries(t *testing.T) {
	maxEntries := 5
	cache := NewFileHashCache(maxEntries, 100)

	tmpDir := t.TempDir()

	// Add more entries than max
	for i := 0; i < maxEntries+3; i++ {
		filePath := filepath.Join(tmpDir, "test", fmt.Sprintf("file%d.txt", i))
		if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
			t.Fatalf("Failed to create dir: %v", err)
		}
		if err := os.WriteFile(filePath, []byte("content"), 0644); err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}

		hash, err := util.CacheHasher()(filePath)
		if err != nil {
			t.Fatalf("Failed to compute hash: %v", err)
		}
		if err := cache.Set(filePath, hash); err != nil {
			t.Fatalf("Failed to set cache: %v", err)
		}
	}

	// Check that we don't exceed max entries
	stats := cache.GetStats()
	entries := stats["entries"].(int)
	if entries > maxEntries {
		t.Errorf("Expected at most %d entries, got %d", maxEntries, entries)
	}
}

func TestFileHashCache_MaxMemory(t *testing.T) {
	// Use small memory limit (1 MB)
	maxMemoryMB := 1
	cache := NewFileHashCache(1000, maxMemoryMB)

	tmpDir := t.TempDir()

	// Add entries until memory limit is reached
	for i := 0; i < 100; i++ {
		filePath := filepath.Join(tmpDir, "test", fmt.Sprintf("file%d.txt", i))
		if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
			t.Fatalf("Failed to create dir: %v", err)
		}
		if err := os.WriteFile(filePath, []byte("content"), 0644); err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}

		hash, err := util.CacheHasher()(filePath)
		if err != nil {
			t.Fatalf("Failed to compute hash: %v", err)
		}
		if err := cache.Set(filePath, hash); err != nil {
			t.Fatalf("Failed to set cache: %v", err)
		}
	}

	// Check memory usage
	stats := cache.GetStats()
	memoryBytes := stats["memory_bytes"].(int64)
	maxMemoryBytes := int64(maxMemoryMB) * 1024 * 1024

	if memoryBytes > maxMemoryBytes {
		t.Errorf("Expected memory usage (%d) to be <= max (%d)", memoryBytes, maxMemoryBytes)
	}

	// Verify that some entries are still present
	stats = cache.GetStats()
	entries := stats["entries"].(int)
	if entries == 0 {
		t.Error("Expected some entries to be present")
	}
}

func TestFileHashCache_Clear(t *testing.T) {
	cache := NewFileHashCache(100, 10)

	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(filePath, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	hash, err := util.CacheHasher()(filePath)
	if err != nil {
		t.Fatalf("Failed to compute hash: %v", err)
	}

	// Set in cache
	if err := cache.Set(filePath, hash); err != nil {
		t.Fatalf("Failed to set cache: %v", err)
	}

	// Verify entry is present
	stats := cache.GetStats()
	if stats["entries"].(int) != 1 {
		t.Errorf("Expected 1 entry, got %d", stats["entries"].(int))
	}

	// Clear cache
	cache.Clear()

	// Verify cache is empty
	stats = cache.GetStats()
	if stats["entries"].(int) != 0 {
		t.Errorf("Expected 0 entries after clear, got %d", stats["entries"].(int))
	}
	if stats["memory_bytes"].(int64) != 0 {
		t.Errorf("Expected 0 memory after clear, got %d", stats["memory_bytes"].(int64))
	}
}

func TestGetFileHashWithCache(t *testing.T) {
	// Set global opts
	opts := &config.KanikoOptions{
		FileHashCacheMaxEntries:  100,
		FileHashCacheMaxMemoryMB: 10,
	}
	SetGlobalFileHashCacheOpts(opts)

	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(filePath, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	context := util.FileContext{Root: tmpDir}

	// First call - should compute hash
	hash1, err := getFileHashWithCache(filePath, context, opts)
	if err != nil {
		t.Fatalf("Failed to get hash: %v", err)
	}

	// Second call - should use cache
	hash2, err := getFileHashWithCache(filePath, context, opts)
	if err != nil {
		t.Fatalf("Failed to get hash: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("Expected same hash, got %s and %s", hash1, hash2)
	}
}

func TestFileHashCache_ConcurrentAccess(t *testing.T) {
	cache := NewFileHashCache(100, 10)

	tmpDir := t.TempDir()

	// Concurrent writes
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(idx int) {
			filePath := filepath.Join(tmpDir, fmt.Sprintf("file%d.txt", idx))
			if err := os.WriteFile(filePath, []byte("content"), 0644); err != nil {
				t.Errorf("Failed to create file: %v", err)
				done <- false
				return
			}

			hash, err := util.CacheHasher()(filePath)
			if err != nil {
				t.Errorf("Failed to compute hash: %v", err)
				done <- false
				return
			}

			if err := cache.Set(filePath, hash); err != nil {
				t.Errorf("Failed to set cache: %v", err)
				done <- false
				return
			}
			done <- true
		}(i)
	}

	// Wait for all writes
	for i := 0; i < 10; i++ {
		<-done
	}

	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func(idx int) {
			filePath := filepath.Join(tmpDir, fmt.Sprintf("file%d.txt", idx))
			_, _ = cache.Get(filePath)
			done <- true
		}(i)
	}

	// Wait for all reads
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify no panic occurred and cache is in valid state
	stats := cache.GetStats()
	if stats["entries"].(int) < 0 {
		t.Error("Expected non-negative entry count")
	}
}
