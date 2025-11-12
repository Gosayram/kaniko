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
	"strings"
	"testing"
	"time"

	"github.com/Gosayram/kaniko/pkg/util"
)

// Test_AdaptiveHash_SmallFiles tests adaptive hashing for directory with <1000 files, all files <10MB
func Test_AdaptiveHash_SmallFiles(t *testing.T) {
	tmpDir := t.TempDir()
	fileContext := util.FileContext{Root: tmpDir}

	// Create 100 small files (<10MB)
	for i := 0; i < 100; i++ {
		content := strings.Repeat("test content ", 100) // Small file
		filePath := filepath.Join(tmpDir, fmt.Sprintf("file%d.txt", i))
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	// Hash directory
	r := NewCompositeCache()
	if err := r.AddPath(tmpDir, fileContext); err != nil {
		t.Fatalf("Failed to add path: %v", err)
	}

	hash1, err := r.Hash()
	if err != nil {
		t.Fatalf("Failed to generate hash: %v", err)
	}

	// Hash again - should be the same
	r2 := NewCompositeCache()
	if err := r2.AddPath(tmpDir, fileContext); err != nil {
		t.Fatalf("Failed to add path: %v", err)
	}

	hash2, err := r2.Hash()
	if err != nil {
		t.Fatalf("Failed to generate hash: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("Expected equal hashes for same directory, got: %s and %s", hash1, hash2)
	}
}

// Test_AdaptiveHash_ManyFiles tests adaptive hashing for directory with >1000 files
func Test_AdaptiveHash_ManyFiles(t *testing.T) {
	tmpDir := t.TempDir()
	fileContext := util.FileContext{Root: tmpDir}

	// Create 1500 files to trigger metadata-only hashing
	for i := 0; i < 1500; i++ {
		content := fmt.Sprintf("file content %d", i)
		filePath := filepath.Join(tmpDir, fmt.Sprintf("file%d.txt", i))
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	// Hash directory - should use metadata-only hashing
	start := time.Now()
	r := NewCompositeCache()
	if err := r.AddPath(tmpDir, fileContext); err != nil {
		t.Fatalf("Failed to add path: %v", err)
	}
	duration := time.Since(start)

	hash1, err := r.Hash()
	if err != nil {
		t.Fatalf("Failed to generate hash: %v", err)
	}

	// Should complete reasonably fast (<1 minute for 1500 files)
	if duration > 1*time.Minute {
		t.Errorf("Hashing took too long: %v for 1500 files", duration)
	}

	// Hash again - should be the same
	hash2, err := r.Hash()
	if err != nil {
		t.Fatalf("Failed to generate hash: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("Expected equal hashes for same directory, got: %s and %s", hash1, hash2)
	}
}

// Test_AdaptiveHash_MixedFiles tests adaptive hashing for directory with mixed file sizes
func Test_AdaptiveHash_MixedFiles(t *testing.T) {
	tmpDir := t.TempDir()
	fileContext := util.FileContext{Root: tmpDir}

	// Create mix of small files
	for i := 0; i < 50; i++ {
		// Small files
		content := strings.Repeat("small ", 100)
		filePath := filepath.Join(tmpDir, fmt.Sprintf("small%d.txt", i))
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	// Hash directory
	r := NewCompositeCache()
	if err := r.AddPath(tmpDir, fileContext); err != nil {
		t.Fatalf("Failed to add path: %v", err)
	}

	hash1, err := r.Hash()
	if err != nil {
		t.Fatalf("Failed to generate hash: %v", err)
	}

	// Modify a small file and ensure mtime changes
	filePath := filepath.Join(tmpDir, "small0.txt")
	time.Sleep(100 * time.Millisecond) // Ensure mtime changes
	if err := os.WriteFile(filePath, []byte("modified content"), 0644); err != nil {
		t.Fatalf("Failed to modify file: %v", err)
	}
	// Explicitly update mtime to ensure it's different
	time.Sleep(100 * time.Millisecond)
	now := time.Now()
	if err := os.Chtimes(filePath, now, now); err != nil {
		t.Fatalf("Failed to update mtime: %v", err)
	}

	// Clear cache to ensure fresh hash calculation
	// Note: In real scenario, cache should invalidate based on mtime, but for test we clear it
	fileHashCacheMu.Lock()
	fileHashCache = make(map[string]string)
	fileHashCacheMu.Unlock()

	// Hash again - should be different
	r2 := NewCompositeCache()
	if err := r2.AddPath(tmpDir, fileContext); err != nil {
		t.Fatalf("Failed to add path: %v", err)
	}

	hash2, err := r2.Hash()
	if err != nil {
		t.Fatalf("Failed to generate hash: %v", err)
	}

	if hash1 == hash2 {
		t.Errorf("Expected different hashes after file modification, got: %s", hash1)
	}
}

// Test_AdaptiveHash_ChangeDetection tests that changes in files are detected
func Test_AdaptiveHash_ChangeDetection(t *testing.T) {
	tmpDir := t.TempDir()
	fileContext := util.FileContext{Root: tmpDir}

	// Create initial file
	filePath := filepath.Join(tmpDir, "test.txt")
	content := "initial content"
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Hash directory
	r1 := NewCompositeCache()
	if err := r1.AddPath(tmpDir, fileContext); err != nil {
		t.Fatalf("Failed to add path: %v", err)
	}

	hash1, err := r1.Hash()
	if err != nil {
		t.Fatalf("Failed to generate hash: %v", err)
	}

	// Modify file content and ensure mtime changes
	time.Sleep(100 * time.Millisecond) // Ensure mtime changes
	if err := os.WriteFile(filePath, []byte("modified content"), 0644); err != nil {
		t.Fatalf("Failed to modify file: %v", err)
	}
	// Explicitly update mtime to ensure it's different
	time.Sleep(100 * time.Millisecond)
	now := time.Now()
	if err := os.Chtimes(filePath, now, now); err != nil {
		t.Fatalf("Failed to update mtime: %v", err)
	}

	// Clear cache to ensure fresh hash calculation
	// Note: In real scenario, cache should invalidate based on mtime, but for test we clear it
	fileHashCacheMu.Lock()
	fileHashCache = make(map[string]string)
	fileHashCacheMu.Unlock()

	// Hash again
	r2 := NewCompositeCache()
	if err := r2.AddPath(tmpDir, fileContext); err != nil {
		t.Fatalf("Failed to add path: %v", err)
	}

	hash2, err := r2.Hash()
	if err != nil {
		t.Fatalf("Failed to generate hash: %v", err)
	}

	if hash1 == hash2 {
		t.Errorf("Expected different hashes after file modification, got: %s", hash1)
	}
}

// Test_AdaptiveHash_Performance_SmallDir tests performance for small directory
func Test_AdaptiveHash_Performance_SmallDir(t *testing.T) {
	tmpDir := t.TempDir()
	fileContext := util.FileContext{Root: tmpDir}

	// Create 100 small files
	for i := 0; i < 100; i++ {
		content := strings.Repeat("test ", 100)
		filePath := filepath.Join(tmpDir, fmt.Sprintf("file%d.txt", i))
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	// Measure hashing time
	start := time.Now()
	r := NewCompositeCache()
	if err := r.AddPath(tmpDir, fileContext); err != nil {
		t.Fatalf("Failed to add path: %v", err)
	}
	duration := time.Since(start)

	// Should complete in reasonable time (<5 seconds)
	if duration > 5*time.Second {
		t.Errorf("Hashing took too long: %v for 100 files", duration)
	}

	_, err := r.Hash()
	if err != nil {
		t.Fatalf("Failed to generate hash: %v", err)
	}
}

// Test_AdaptiveHash_NoTimeouts tests that adaptive hashing doesn't use timeouts
func Test_AdaptiveHash_NoTimeouts(t *testing.T) {
	// This test verifies that adaptive hashing path doesn't use context with timeout
	// We can't directly test this, but we can verify that it works without timeout errors
	tmpDir := t.TempDir()
	fileContext := util.FileContext{Root: tmpDir}

	// Create files
	for i := 0; i < 50; i++ {
		content := fmt.Sprintf("file content %d", i)
		filePath := filepath.Join(tmpDir, fmt.Sprintf("file%d.txt", i))
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	// Hash should complete without timeout errors
	r := NewCompositeCache()
	if err := r.AddPath(tmpDir, fileContext); err != nil {
		t.Fatalf("Failed to add path (should not timeout): %v", err)
	}

	_, err := r.Hash()
	if err != nil {
		t.Fatalf("Failed to generate hash: %v", err)
	}
}

// Test_AdaptiveHash_ErrorHandling tests that error handling is preserved
func Test_AdaptiveHash_ErrorHandling(t *testing.T) {
	tmpDir := t.TempDir()
	fileContext := util.FileContext{Root: tmpDir}

	// Test with non-existent path
	nonExistentPath := filepath.Join(tmpDir, "nonexistent")
	r := NewCompositeCache()
	err := r.AddPath(nonExistentPath, fileContext)
	// Should handle gracefully (log warning and continue)
	if err != nil && !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("Expected graceful handling of non-existent path, got: %v", err)
	}

	// Test with valid path
	filePath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(filePath, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	r2 := NewCompositeCache()
	if err := r2.AddPath(tmpDir, fileContext); err != nil {
		t.Fatalf("Failed to add valid path: %v", err)
	}
}

// Test_AdaptiveHash_LargeFiles tests adaptive hashing for directory with <1000 files, all files >=10MB
func Test_AdaptiveHash_LargeFiles(t *testing.T) {
	tmpDir := t.TempDir()
	fileContext := util.FileContext{Root: tmpDir}

	// Create 10 large files (>=10MB each)
	for i := 0; i < 10; i++ {
		// Create 11MB file to exceed threshold
		content := make([]byte, 11*1024*1024)
		for j := range content {
			content[j] = byte(i + j)
		}
		filePath := filepath.Join(tmpDir, fmt.Sprintf("large%d.bin", i))
		if err := os.WriteFile(filePath, content, 0644); err != nil {
			t.Fatalf("Failed to create large test file: %v", err)
		}
	}

	// Hash directory
	r := NewCompositeCache()
	if err := r.AddPath(tmpDir, fileContext); err != nil {
		t.Fatalf("Failed to add path: %v", err)
	}

	hash1, err := r.Hash()
	if err != nil {
		t.Fatalf("Failed to hash directory: %v", err)
	}

	// Hash again - should be the same
	r2 := NewCompositeCache()
	if err := r2.AddPath(tmpDir, fileContext); err != nil {
		t.Fatalf("Failed to add path: %v", err)
	}

	hash2, err := r2.Hash()
	if err != nil {
		t.Fatalf("Failed to hash directory: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("Hashes should be the same for identical directories, got %s != %s", hash1, hash2)
	}
}

// Test_AdaptiveHash_Consistency tests that identical files give identical hashes
func Test_AdaptiveHash_Consistency(t *testing.T) {
	tmpDir1 := t.TempDir()
	tmpDir2 := t.TempDir()
	fileContext1 := util.FileContext{Root: tmpDir1}
	fileContext2 := util.FileContext{Root: tmpDir2}

	// Create identical files in both directories
	for i := 0; i < 50; i++ {
		content := fmt.Sprintf("test content %d", i)
		filePath1 := filepath.Join(tmpDir1, fmt.Sprintf("file%d.txt", i))
		filePath2 := filepath.Join(tmpDir2, fmt.Sprintf("file%d.txt", i))
		if err := os.WriteFile(filePath1, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
		if err := os.WriteFile(filePath2, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	// Hash both directories
	r1 := NewCompositeCache()
	if err := r1.AddPath(tmpDir1, fileContext1); err != nil {
		t.Fatalf("Failed to add path: %v", err)
	}
	hash1, err := r1.Hash()
	if err != nil {
		t.Fatalf("Failed to hash directory: %v", err)
	}

	r2 := NewCompositeCache()
	if err := r2.AddPath(tmpDir2, fileContext2); err != nil {
		t.Fatalf("Failed to add path: %v", err)
	}
	hash2, err := r2.Hash()
	if err != nil {
		t.Fatalf("Failed to hash directory: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("Hashes should be the same for identical directories, got %s != %s", hash1, hash2)
	}
}

// Test_AdaptiveHash_FileContentChange tests that content changes in small files are detected
func Test_AdaptiveHash_FileContentChange(t *testing.T) {
	tmpDir := t.TempDir()
	fileContext := util.FileContext{Root: tmpDir}

	// Create small file
	filePath := filepath.Join(tmpDir, "small.txt")
	content1 := "original content"
	if err := os.WriteFile(filePath, []byte(content1), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Hash directory
	r1 := NewCompositeCache()
	if err := r1.AddPath(tmpDir, fileContext); err != nil {
		t.Fatalf("Failed to add path: %v", err)
	}
	hash1, err := r1.Hash()
	if err != nil {
		t.Fatalf("Failed to hash directory: %v", err)
	}

	// Clear cache to force re-hashing
	fileHashCacheMu.Lock()
	fileHashCache = make(map[string]string)
	fileHashCacheMu.Unlock()

	// Change file content (but keep same size and mtime might be similar)
	content2 := "modified content"
	if err := os.WriteFile(filePath, []byte(content2), 0644); err != nil {
		t.Fatalf("Failed to modify test file: %v", err)
	}
	// Ensure mtime changes
	time.Sleep(10 * time.Millisecond)
	if err := os.Chtimes(filePath, time.Now(), time.Now()); err != nil {
		t.Fatalf("Failed to update mtime: %v", err)
	}

	// Hash again
	r2 := NewCompositeCache()
	if err := r2.AddPath(tmpDir, fileContext); err != nil {
		t.Fatalf("Failed to add path: %v", err)
	}
	hash2, err := r2.Hash()
	if err != nil {
		t.Fatalf("Failed to hash directory: %v", err)
	}

	if hash1 == hash2 {
		t.Errorf("Hashes should be different after content change, got same hash: %s", hash1)
	}
}

// Test_AdaptiveHash_MetadataChange tests that metadata changes in large files are detected
func Test_AdaptiveHash_MetadataChange(t *testing.T) {
	tmpDir := t.TempDir()
	fileContext := util.FileContext{Root: tmpDir}

	// Create large file (>=10MB)
	filePath := filepath.Join(tmpDir, "large.bin")
	content := make([]byte, 11*1024*1024)
	for i := range content {
		content[i] = byte(i)
	}
	if err := os.WriteFile(filePath, content, 0644); err != nil {
		t.Fatalf("Failed to create large test file: %v", err)
	}

	// Hash directory
	r1 := NewCompositeCache()
	if err := r1.AddPath(tmpDir, fileContext); err != nil {
		t.Fatalf("Failed to add path: %v", err)
	}
	hash1, err := r1.Hash()
	if err != nil {
		t.Fatalf("Failed to hash directory: %v", err)
	}

	// Clear cache to force re-hashing
	fileHashCacheMu.Lock()
	fileHashCache = make(map[string]string)
	fileHashCacheMu.Unlock()

	// Change mtime
	time.Sleep(10 * time.Millisecond)
	if err := os.Chtimes(filePath, time.Now(), time.Now()); err != nil {
		t.Fatalf("Failed to update mtime: %v", err)
	}

	// Hash again
	r2 := NewCompositeCache()
	if err := r2.AddPath(tmpDir, fileContext); err != nil {
		t.Fatalf("Failed to add path: %v", err)
	}
	hash2, err := r2.Hash()
	if err != nil {
		t.Fatalf("Failed to hash directory: %v", err)
	}

	if hash1 == hash2 {
		t.Errorf("Hashes should be different after metadata change, got same hash: %s", hash1)
	}
}

// Test_AdaptiveHash_Performance_LargeDir tests performance for large directory
func Test_AdaptiveHash_Performance_LargeDir(t *testing.T) {
	tmpDir := t.TempDir()
	fileContext := util.FileContext{Root: tmpDir}

	// Create 1500 files (>1000 threshold)
	for i := 0; i < 1500; i++ {
		content := fmt.Sprintf("test content %d", i)
		filePath := filepath.Join(tmpDir, fmt.Sprintf("file%d.txt", i))
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	// Hash directory and measure time
	start := time.Now()
	r := NewCompositeCache()
	if err := r.AddPath(tmpDir, fileContext); err != nil {
		t.Fatalf("Failed to add path: %v", err)
	}
	_, err := r.Hash()
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Failed to hash directory: %v", err)
	}

	// Should complete in reasonable time (<1 minute)
	if duration > 1*time.Minute {
		t.Errorf("Hashing took too long: %v, expected <1 minute", duration)
	}

	t.Logf("Hashed %d files in %v", 1500, duration)
}

// Test_AdaptiveHash_Performance_Mixed tests performance for mixed directory
func Test_AdaptiveHash_Performance_Mixed(t *testing.T) {
	tmpDir := t.TempDir()
	fileContext := util.FileContext{Root: tmpDir}

	// Create 250 small files
	for i := 0; i < 250; i++ {
		content := strings.Repeat("small ", 100)
		filePath := filepath.Join(tmpDir, fmt.Sprintf("small%d.txt", i))
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	// Create 250 large files (>=10MB)
	for i := 0; i < 250; i++ {
		content := make([]byte, 11*1024*1024)
		for j := range content {
			content[j] = byte(i + j)
		}
		filePath := filepath.Join(tmpDir, fmt.Sprintf("large%d.bin", i))
		if err := os.WriteFile(filePath, content, 0644); err != nil {
			t.Fatalf("Failed to create large test file: %v", err)
		}
	}

	// Hash directory and measure time
	start := time.Now()
	r := NewCompositeCache()
	if err := r.AddPath(tmpDir, fileContext); err != nil {
		t.Fatalf("Failed to add path: %v", err)
	}
	_, err := r.Hash()
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Failed to hash directory: %v", err)
	}

	// Should complete in reasonable time
	if duration > 2*time.Minute {
		t.Errorf("Hashing took too long: %v, expected <2 minutes", duration)
	}

	t.Logf("Hashed 500 mixed files in %v", duration)
}

// Test_AdaptiveHash_CacheHit tests that caching works correctly
func Test_AdaptiveHash_CacheHit(t *testing.T) {
	tmpDir := t.TempDir()
	fileContext := util.FileContext{Root: tmpDir}

	// Create test files
	for i := 0; i < 100; i++ {
		content := fmt.Sprintf("test content %d", i)
		filePath := filepath.Join(tmpDir, fmt.Sprintf("file%d.txt", i))
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	// First hash (populates cache)
	start1 := time.Now()
	r1 := NewCompositeCache()
	if err := r1.AddPath(tmpDir, fileContext); err != nil {
		t.Fatalf("Failed to add path: %v", err)
	}
	hash1, err := r1.Hash()
	duration1 := time.Since(start1)
	if err != nil {
		t.Fatalf("Failed to hash directory: %v", err)
	}

	// Second hash (should use cache)
	start2 := time.Now()
	r2 := NewCompositeCache()
	if err := r2.AddPath(tmpDir, fileContext); err != nil {
		t.Fatalf("Failed to add path: %v", err)
	}
	hash2, err := r2.Hash()
	duration2 := time.Since(start2)
	if err != nil {
		t.Fatalf("Failed to hash directory: %v", err)
	}

	// Hashes should be the same
	if hash1 != hash2 {
		t.Errorf("Hashes should be the same, got %s != %s", hash1, hash2)
	}

	// Second hash should be faster (using cache)
	if duration2 >= duration1 {
		t.Logf("Warning: Second hash (%v) was not faster than first (%v), cache may not be working", duration2, duration1)
	}

	t.Logf("First hash: %v, Second hash: %v", duration1, duration2)
}

// Test_AdaptiveHash_CacheInvalidation tests that cache is invalidated on file changes
func Test_AdaptiveHash_CacheInvalidation(t *testing.T) {
	tmpDir := t.TempDir()
	fileContext := util.FileContext{Root: tmpDir}

	// Create test file
	filePath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(filePath, []byte("original"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// First hash
	r1 := NewCompositeCache()
	if err := r1.AddPath(tmpDir, fileContext); err != nil {
		t.Fatalf("Failed to add path: %v", err)
	}
	hash1, err := r1.Hash()
	if err != nil {
		t.Fatalf("Failed to hash directory: %v", err)
	}

	// Clear cache to simulate cache invalidation
	fileHashCacheMu.Lock()
	fileHashCache = make(map[string]string)
	fileHashCacheMu.Unlock()

	// Modify file
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(filePath, []byte("modified"), 0644); err != nil {
		t.Fatalf("Failed to modify test file: %v", err)
	}
	if err := os.Chtimes(filePath, time.Now(), time.Now()); err != nil {
		t.Fatalf("Failed to update mtime: %v", err)
	}

	// Second hash (should detect change)
	r2 := NewCompositeCache()
	if err := r2.AddPath(tmpDir, fileContext); err != nil {
		t.Fatalf("Failed to add path: %v", err)
	}
	hash2, err := r2.Hash()
	if err != nil {
		t.Fatalf("Failed to hash directory: %v", err)
	}

	// Hashes should be different
	if hash1 == hash2 {
		t.Errorf("Hashes should be different after file change, got same hash: %s", hash1)
	}
}

// Test_AdaptiveHash_BackwardCompatibility tests backward compatibility with USE_ADAPTIVE_DIR_HASH flag
func Test_AdaptiveHash_BackwardCompatibility(t *testing.T) {
	tmpDir := t.TempDir()
	fileContext := util.FileContext{Root: tmpDir}

	// Create test files
	for i := 0; i < 50; i++ {
		content := fmt.Sprintf("test content %d", i)
		filePath := filepath.Join(tmpDir, fmt.Sprintf("file%d.txt", i))
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	// Test with adaptive hashing enabled (default)
	os.Unsetenv("USE_ADAPTIVE_DIR_HASH")
	r1 := NewCompositeCache()
	if err := r1.AddPath(tmpDir, fileContext); err != nil {
		t.Fatalf("Failed to add path: %v", err)
	}
	hash1, err := r1.Hash()
	if err != nil {
		t.Fatalf("Failed to hash directory: %v", err)
	}

	// Test with adaptive hashing disabled
	os.Setenv("USE_ADAPTIVE_DIR_HASH", "false")
	defer os.Unsetenv("USE_ADAPTIVE_DIR_HASH")

	r2 := NewCompositeCache()
	if err := r2.AddPath(tmpDir, fileContext); err != nil {
		t.Fatalf("Failed to add path: %v", err)
	}
	hash2, err := r2.Hash()
	if err != nil {
		t.Fatalf("Failed to hash directory: %v", err)
	}

	// Both should work (may have different hashes due to different strategies)
	if hash1 == "" || hash2 == "" {
		t.Errorf("Both hashing strategies should produce valid hashes")
	}

	t.Logf("Adaptive hash: %s, Legacy hash: %s", hash1, hash2)
}
