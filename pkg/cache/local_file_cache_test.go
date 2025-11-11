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

package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Gosayram/kaniko/pkg/config"
)

// TestLocalFileCache_index tests that index is built and used for fast lookup
func TestLocalFileCache_index(t *testing.T) {
	tmpDir := t.TempDir()

	opts := &config.CacheOptions{
		CacheDir: tmpDir,
		CacheTTL: 1 * time.Hour,
	}

	lfc := NewLocalFileCache(opts)

	// Create a test cache file
	cacheKey := "test-key"
	cachePath := filepath.Join(tmpDir, cacheKey)
	testFile, err := os.Create(cachePath)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	testFile.WriteString("test content")
	testFile.Close()

	// Build index
	err = lfc.buildIndex()
	if err != nil {
		t.Fatalf("Failed to build index: %v", err)
	}

	// Check that index was built
	lfc.mu.RLock()
	indexed := lfc.indexed
	entryCount := len(lfc.index)
	lfc.mu.RUnlock()

	if !indexed {
		t.Error("Expected index to be built")
	}

	if entryCount == 0 {
		t.Error("Expected index to contain entries")
	}

	// Check that entry exists in index
	entry, exists := lfc.getIndexEntry(cacheKey)
	if !exists {
		t.Error("Expected entry to exist in index")
	}

	if entry == nil {
		t.Fatal("Expected entry to be non-nil")
	}

	if entry.FilePath != cachePath {
		t.Errorf("Expected file path %s, got %s", cachePath, entry.FilePath)
	}
}

// TestLocalFileCache_indexExpiration tests that expired entries are removed from index
func TestLocalFileCache_indexExpiration(t *testing.T) {
	tmpDir := t.TempDir()

	opts := &config.CacheOptions{
		CacheDir: tmpDir,
		CacheTTL: 1 * time.Hour,
	}

	lfc := NewLocalFileCache(opts)

	// Create a test cache file with old modification time
	cacheKey := "expired-key"
	cachePath := filepath.Join(tmpDir, cacheKey)
	testFile, err := os.Create(cachePath)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	testFile.WriteString("test content")
	testFile.Close()

	// Set old modification time (expired)
	oldTime := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(cachePath, oldTime, oldTime); err != nil {
		t.Fatalf("Failed to set file time: %v", err)
	}

	// Build index
	err = lfc.buildIndex()
	if err != nil {
		t.Fatalf("Failed to build index: %v", err)
	}

	// Entry should be in index initially
	entry, exists := lfc.getIndexEntry(cacheKey)
	if exists {
		// But should be expired
		if !time.Now().After(entry.ExpiresAt) {
			t.Error("Expected entry to be expired")
		}
		// getIndexEntry should remove expired entries
		_, existsAfter := lfc.getIndexEntry(cacheKey)
		if existsAfter {
			t.Error("Expected expired entry to be removed from index")
		}
	}
}

// TestLocalFileCache_indexUpdate tests that index is updated when new files are added
func TestLocalFileCache_indexUpdate(t *testing.T) {
	tmpDir := t.TempDir()

	opts := &config.CacheOptions{
		CacheDir: tmpDir,
		CacheTTL: 1 * time.Hour,
	}

	lfc := NewLocalFileCache(opts)

	// Build initial index (should be empty)
	err := lfc.buildIndex()
	if err != nil {
		t.Fatalf("Failed to build index: %v", err)
	}

	lfc.mu.RLock()
	initialCount := len(lfc.index)
	lfc.mu.RUnlock()

	// Create a new cache file
	cacheKey := "new-key"
	cachePath := filepath.Join(tmpDir, cacheKey)
	testFile, err := os.Create(cachePath)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	testFile.WriteString("test content")
	testFile.Close()

	// Index should not automatically update (lazy)
	// But RetrieveLayer should add it to index
	// For now, just verify that buildIndex can be called again
	// (it should skip if already indexed)
	err = lfc.buildIndex()
	if err != nil {
		t.Fatalf("Failed to rebuild index: %v", err)
	}

	// Reset indexed flag to allow rebuilding
	lfc.mu.Lock()
	lfc.indexed = false
	lfc.mu.Unlock()

	// Rebuild index
	err = lfc.buildIndex()
	if err != nil {
		t.Fatalf("Failed to rebuild index: %v", err)
	}

	lfc.mu.RLock()
	finalCount := len(lfc.index)
	lfc.mu.RUnlock()

	if finalCount <= initialCount {
		t.Errorf("Expected index count to increase, got %d (was %d)", finalCount, initialCount)
	}
}
