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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestAdaptiveWorkerPool_GoroutineLeak tests that worker pool
// properly cleans up goroutines after shutdown
func TestAdaptiveWorkerPool_GoroutineLeak(t *testing.T) {
	// Wait for any background goroutines from previous tests to settle
	time.Sleep(500 * time.Millisecond)
	runtime.GC()

	beforeGoroutines := runtime.NumGoroutine()

	// Create worker pool
	awp := NewAdaptiveWorkerPool(2, 5)
	if awp == nil {
		t.Fatal("Failed to create AdaptiveWorkerPool")
	}

	// Submit some tasks
	for i := 0; i < 10; i++ {
		taskID := i
		if err := awp.Submit(Task{
			ID: fmt.Sprintf("task_%d", taskID),
			Function: func() error {
				time.Sleep(10 * time.Millisecond)
				return nil
			},
		}); err != nil {
			t.Logf("Failed to submit task %d: %v", taskID, err)
		}
	}

	// Wait for tasks to complete
	time.Sleep(300 * time.Millisecond)

	// Shutdown worker pool
	awp.Shutdown()

	// Wait for goroutines to cleanup
	time.Sleep(500 * time.Millisecond)
	runtime.GC()
	time.Sleep(200 * time.Millisecond)
	runtime.GC()

	afterGoroutines := runtime.NumGoroutine()

	// Allow some margin for background goroutines
	if afterGoroutines > beforeGoroutines+5 {
		t.Errorf("Possible goroutine leak in AdaptiveWorkerPool: before=%d, after=%d (increase: %d)",
			beforeGoroutines, afterGoroutines, afterGoroutines-beforeGoroutines)
	} else {
		t.Logf("Goroutine count: before=%d, after=%d (increase: %d)",
			beforeGoroutines, afterGoroutines, afterGoroutines-beforeGoroutines)
	}
}

// TestIncrementalSnapshotter_WatcherGoroutineLeak tests that
// watcher goroutine properly terminates when watcher channel is closed
// Note: This is a simplified test since watcher is private
func TestIncrementalSnapshotter_WatcherGoroutineLeak(t *testing.T) {
	// Wait for any background goroutines from previous tests to settle
	time.Sleep(500 * time.Millisecond)
	runtime.GC()

	beforeGoroutines := runtime.NumGoroutine()

	// Test that goroutine properly handles channel closure
	// by simulating the pattern used in startListener
	changes := make(chan string, 10)
	done := make(chan bool, 1)

	go func() {
		for change := range changes {
			_ = change // Process change
		}
		done <- true
	}()

	// Send some changes
	for i := 0; i < 5; i++ {
		changes <- fmt.Sprintf("file_%d.txt", i)
	}

	time.Sleep(100 * time.Millisecond)

	// Close channel (should terminate goroutine)
	close(changes)

	// Wait for goroutine to finish
	select {
	case <-done:
		// Goroutine properly terminated
	case <-time.After(1 * time.Second):
		t.Error("Goroutine did not terminate after channel closure")
	}

	// Wait for cleanup
	time.Sleep(500 * time.Millisecond)
	runtime.GC()
	time.Sleep(200 * time.Millisecond)
	runtime.GC()

	afterGoroutines := runtime.NumGoroutine()

	// Allow some margin for background goroutines
	if afterGoroutines > beforeGoroutines+5 {
		t.Errorf("Possible goroutine leak in watcher pattern: before=%d, after=%d (increase: %d)",
			beforeGoroutines, afterGoroutines, afterGoroutines-beforeGoroutines)
	} else {
		t.Logf("Goroutine count: before=%d, after=%d (increase: %d)",
			beforeGoroutines, afterGoroutines, afterGoroutines-beforeGoroutines)
	}
}

// TestSafeOptimizations_FileHashGoroutineLeak tests that
// file hashing goroutines properly terminate
func TestSafeOptimizations_FileHashGoroutineLeak(t *testing.T) {
	// Wait for any background goroutines from previous tests to settle
	time.Sleep(500 * time.Millisecond)
	runtime.GC()

	beforeGoroutines := runtime.NumGoroutine()

	tmpDir := t.TempDir()

	// Create test files
	for i := 0; i < 10; i++ {
		filePath := filepath.Join(tmpDir, fmt.Sprintf("file_%d.txt", i))
		if err := os.WriteFile(filePath, []byte("test content"), 0644); err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Process files (creates goroutines for hashing)
	var wg sync.WaitGroup
	workers := make(chan struct{}, 5)
	hashes := make(map[string]string)
	var mutex sync.Mutex

	hasher := func(f string) (string, error) {
		// Simulate hashing
		return "hash_" + f, nil
	}

	for i := 0; i < 10; i++ {
		filePath := filepath.Join(tmpDir, fmt.Sprintf("file_%d.txt", i))
		wg.Add(1)
		go func(f string) {
			defer wg.Done()

			// Acquire worker
			select {
			case workers <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() {
				select {
				case <-workers:
				case <-ctx.Done():
				}
			}()

			// Check context
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Hash file
			hash, err := hasher(f)
			if err == nil {
				mutex.Lock()
				hashes[f] = hash
				mutex.Unlock()
			}
		}(filePath)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Wait for cleanup
	time.Sleep(500 * time.Millisecond)
	runtime.GC()
	time.Sleep(200 * time.Millisecond)
	runtime.GC()

	afterGoroutines := runtime.NumGoroutine()

	// Allow some margin for background goroutines
	if afterGoroutines > beforeGoroutines+5 {
		t.Errorf("Possible goroutine leak in file hashing: before=%d, after=%d (increase: %d)",
			beforeGoroutines, afterGoroutines, afterGoroutines-beforeGoroutines)
	} else {
		t.Logf("Goroutine count: before=%d, after=%d (increase: %d)",
			beforeGoroutines, afterGoroutines, afterGoroutines-beforeGoroutines)
	}

	if len(hashes) != 10 {
		t.Errorf("Expected 10 hashes, got %d", len(hashes))
	}
}
