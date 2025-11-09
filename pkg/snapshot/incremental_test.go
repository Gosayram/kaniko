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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Gosayram/kaniko/pkg/util"
)

func TestIncrementalSnapshotter(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "kaniko-incremental-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a mock layered map
	l := NewLayeredMap(util.Hasher())

	// Create base snapshotter
	baseSnapshotter := NewSnapshotter(l, tempDir)

	// Create incremental snapshotter
	incremental := NewIncrementalSnapshotter(baseSnapshotter)

	// Test basic functionality
	t.Run("BasicInitialization", func(t *testing.T) {
		if incremental.baseSnapshotter == nil {
			t.Error("Base snapshotter should not be nil")
		}
		if incremental.fileCache == nil {
			t.Error("File cache should be initialized")
		}
		if !incremental.integrityCheck {
			t.Error("Integrity check should be enabled by default")
		}
		if !incremental.fullScanBackup {
			t.Error("Full scan backup should be enabled by default")
		}
	})

	// Test cache stats
	t.Run("CacheStats", func(t *testing.T) {
		stats := incremental.GetCacheStats()
		if stats["cached_files"].(int) != 0 {
			t.Errorf("Expected 0 cached files, got %d", stats["cached_files"])
		}
		if stats["scan_count"].(int) != 0 {
			t.Errorf("Expected 0 scan count, got %d", stats["scan_count"])
		}
	})

	// Test critical system file detection
	t.Run("CriticalSystemFileDetection", func(t *testing.T) {
		criticalFiles := []string{
			"/etc/passwd",
			"/etc/group",
			"/etc/shadow",
			"/proc/something",
			"/sys/something",
			"/dev/something",
		}

		for _, file := range criticalFiles {
			if !incremental.isCriticalSystemFile(file) {
				t.Errorf("File %s should be detected as critical", file)
			}
		}

		// Test non-critical files
		nonCriticalFiles := []string{
			"/tmp/something",
			"/home/user/file",
			"/app/data.txt",
		}

		for _, file := range nonCriticalFiles {
			if incremental.isCriticalSystemFile(file) {
				t.Errorf("File %s should not be detected as critical", file)
			}
		}
	})

	// Test integrity check logic
	t.Run("IntegrityCheckLogic", func(t *testing.T) {
		// Test with too many changes
		tooManyChanges := make([]string, 2000) // More than maxExpectedChanges (1000)
		for i := range tooManyChanges {
			tooManyChanges[i] = "/tmp/file" + string(rune(i))
		}

		if !incremental.needsIntegrityCheck(tooManyChanges) {
			t.Error("Should need integrity check for too many changes")
		}

		// Test with critical system files
		criticalChanges := []string{"/etc/passwd", "/tmp/normal"}
		if !incremental.needsIntegrityCheck(criticalChanges) {
			t.Error("Should need integrity check for critical system file changes")
		}

		// Test with normal changes
		normalChanges := []string{"/tmp/file1", "/tmp/file2", "/app/data.txt"}
		if incremental.needsIntegrityCheck(normalChanges) {
			t.Error("Should not need integrity check for normal changes")
		}
	})

	// Test cache clearing
	t.Run("CacheClearing", func(t *testing.T) {
		incremental.ClearCache()
		stats := incremental.GetCacheStats()
		if stats["cached_files"].(int) != 0 {
			t.Errorf("Expected 0 cached files after clearing, got %d", stats["cached_files"])
		}
		if stats["scan_count"].(int) != 0 {
			t.Errorf("Expected 0 scan count after clearing, got %d", stats["scan_count"])
		}
	})
}

func TestIncrementalSnapshotterIntegration(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "kaniko-incremental-integration-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test files
	testFiles := []string{
		filepath.Join(tempDir, "file1.txt"),
		filepath.Join(tempDir, "file2.txt"),
		filepath.Join(tempDir, "subdir", "file3.txt"),
	}

	for _, file := range testFiles {
		dir := filepath.Dir(file)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("Failed to create directory %s: %v", dir, err)
		}
		if err := os.WriteFile(file, []byte("test content"), 0644); err != nil {
			t.Fatalf("Failed to create file %s: %v", file, err)
		}
	}

	// Create a mock layered map
	l := NewLayeredMap(util.Hasher())

	// Create base snapshotter
	baseSnapshotter := NewSnapshotter(l, tempDir)

	// Create incremental snapshotter
	incremental := NewIncrementalSnapshotter(baseSnapshotter)

	// Test incremental change detection
	t.Run("IncrementalChangeDetection", func(t *testing.T) {
		// First, populate cache with initial files
		incremental.updateFileCache(testFiles)

		// Modify a file
		modifiedFile := testFiles[0]
		if err := os.WriteFile(modifiedFile, []byte("modified content"), 0644); err != nil {
			t.Fatalf("Failed to modify file: %v", err)
		}

		// Wait a bit to ensure different mtime
		time.Sleep(10 * time.Millisecond)

		// Detect changes
		changes := incremental.detectIncrementalChanges()

		// Should detect the modified file
		found := false
		for _, change := range changes {
			if change == modifiedFile {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Should have detected change in %s", modifiedFile)
		}
	})
}
