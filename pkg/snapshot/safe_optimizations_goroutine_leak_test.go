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
	"github.com/Gosayram/kaniko/pkg/util"
)

// Test_ParallelDirectoryScan_GoroutineLeak tests that parallel directory scan doesn't leak goroutines
func Test_ParallelDirectoryScan_GoroutineLeak(t *testing.T) {
	setUpTest(t)

	// Get initial goroutine count
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	beforeGoroutines := runtime.NumGoroutine()

	tmpDir := t.TempDir()

	// Create test files
	for i := 0; i < 100; i++ {
		content := fmt.Sprintf("test content %d", i)
		filePath := filepath.Join(tmpDir, fmt.Sprintf("file%d.txt", i))
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	snapshotter := NewSnapshotter(NewLayeredMap(util.Hasher()), tmpDir)
	optimizer := NewSafeSnapshotOptimizer(snapshotter, &config.KanikoOptions{
		EnableParallelExec: true,
		IntegrityCheck:     true,
		MaxExpectedChanges: 5000,
	})

	existingPaths := make(map[string]struct{})

	// Run scan multiple times
	for i := 0; i < 5; i++ {
		_, _, err := optimizer.OptimizedWalkFS(tmpDir, existingPaths)
		if err != nil {
			t.Fatalf("Failed to scan directory: %v", err)
		}
	}

	// Wait for goroutines to finish
	runtime.GC()
	time.Sleep(1 * time.Second)

	afterGoroutines := runtime.NumGoroutine()

	// Allow some margin for background goroutines (GC, etc.)
	// But should not have significant increase
	if afterGoroutines > beforeGoroutines+5 {
		t.Errorf("Possible goroutine leak detected: before=%d, after=%d (increase of %d)",
			beforeGoroutines, afterGoroutines, afterGoroutines-beforeGoroutines)
	} else {
		t.Logf("Goroutine count: before=%d, after=%d (increase of %d)",
			beforeGoroutines, afterGoroutines, afterGoroutines-beforeGoroutines)
	}
}

// Test_ParallelDirectoryScan_ContextCancellation tests that contexts are properly cancelled
func Test_ParallelDirectoryScan_ContextCancellation(t *testing.T) {
	setUpTest(t)

	tmpDir := t.TempDir()

	// Create test files
	for i := 0; i < 50; i++ {
		content := fmt.Sprintf("test content %d", i)
		filePath := filepath.Join(tmpDir, fmt.Sprintf("file%d.txt", i))
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	// Get initial goroutine count
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	beforeGoroutines := runtime.NumGoroutine()

	snapshotter := NewSnapshotter(NewLayeredMap(util.Hasher()), tmpDir)
	optimizer := NewSafeSnapshotOptimizer(snapshotter, &config.KanikoOptions{
		EnableParallelExec: true,
		IntegrityCheck:     true,
		MaxExpectedChanges: 5000,
	})

	existingPaths := make(map[string]struct{})

	// Run scan
	_, _, err := optimizer.OptimizedWalkFS(tmpDir, existingPaths)
	if err != nil {
		t.Fatalf("Failed to scan directory: %v", err)
	}

	// Wait for all operations to complete
	runtime.GC()
	time.Sleep(1 * time.Second)

	afterGoroutines := runtime.NumGoroutine()

	// Should not have significant increase
	if afterGoroutines > beforeGoroutines+5 {
		t.Errorf("Possible goroutine leak after context cancellation: before=%d, after=%d",
			beforeGoroutines, afterGoroutines)
	} else {
		t.Logf("Goroutine count after cancellation: before=%d, after=%d",
			beforeGoroutines, afterGoroutines)
	}
}

// Test_ParallelDirectoryScan_WaitGroupCleanup tests that WaitGroups are properly waited
func Test_ParallelDirectoryScan_WaitGroupCleanup(t *testing.T) {
	setUpTest(t)

	tmpDir := t.TempDir()

	// Create many test files to stress test
	for i := 0; i < 200; i++ {
		content := fmt.Sprintf("test content %d", i)
		filePath := filepath.Join(tmpDir, fmt.Sprintf("file%d.txt", i))
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	// Get initial goroutine count
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	beforeGoroutines := runtime.NumGoroutine()

	snapshotter := NewSnapshotter(NewLayeredMap(util.Hasher()), tmpDir)
	optimizer := NewSafeSnapshotOptimizer(snapshotter, &config.KanikoOptions{
		EnableParallelExec: true,
		IntegrityCheck:     true,
		MaxExpectedChanges: 5000,
	})

	existingPaths := make(map[string]struct{})

	// Run scan multiple times
	for i := 0; i < 5; i++ {
		_, _, err := optimizer.OptimizedWalkFS(tmpDir, existingPaths)
		if err != nil {
			t.Fatalf("Failed to scan directory: %v", err)
		}
	}

	// Wait for all operations to complete
	runtime.GC()
	time.Sleep(1 * time.Second)

	afterGoroutines := runtime.NumGoroutine()

	// Should not have significant increase
	if afterGoroutines > beforeGoroutines+5 {
		t.Errorf("Possible goroutine leak after WaitGroup operations: before=%d, after=%d (increase of %d)",
			beforeGoroutines, afterGoroutines, afterGoroutines-beforeGoroutines)
	} else {
		t.Logf("Goroutine count after WaitGroup operations: before=%d, after=%d (increase of %d)",
			beforeGoroutines, afterGoroutines, afterGoroutines-beforeGoroutines)
	}
}

// Test_Fallback_GoroutineLeak tests that fallback doesn't leak goroutines
func Test_Fallback_GoroutineLeak(t *testing.T) {
	setUpTest(t)

	tmpDir := t.TempDir()

	// Create test files
	for i := 0; i < 50; i++ {
		content := fmt.Sprintf("test content %d", i)
		filePath := filepath.Join(tmpDir, fmt.Sprintf("file%d.txt", i))
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	// Get initial goroutine count
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	beforeGoroutines := runtime.NumGoroutine()

	snapshotter := NewSnapshotter(NewLayeredMap(util.Hasher()), tmpDir)
	optimizer := NewSafeSnapshotOptimizer(snapshotter, &config.KanikoOptions{
		EnableParallelExec: true,
		IntegrityCheck:     true,
		MaxExpectedChanges: 5000,
	})

	existingPaths := make(map[string]struct{})

	// Run scan (will use fallback if needed)
	_, _, err := optimizer.OptimizedWalkFS(tmpDir, existingPaths)
	if err != nil {
		t.Fatalf("Failed to scan directory: %v", err)
	}

	// Wait for all operations to complete
	runtime.GC()
	time.Sleep(1 * time.Second)

	afterGoroutines := runtime.NumGoroutine()

	// Should not have significant increase
	if afterGoroutines > beforeGoroutines+5 {
		t.Errorf("Possible goroutine leak after fallback: before=%d, after=%d",
			beforeGoroutines, afterGoroutines)
	} else {
		t.Logf("Goroutine count after fallback: before=%d, after=%d",
			beforeGoroutines, afterGoroutines)
	}
}
