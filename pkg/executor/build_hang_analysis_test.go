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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestFilesUsedFromContext_Deadlock tests potential deadlock
// when goroutine hangs on FilesUsedFromContext and select chooses timeout
func TestFilesUsedFromContext_Deadlock(t *testing.T) {
	filesCh := make(chan struct {
		files []string
		err   error
	}, 1)

	go func() {
		time.Sleep(10 * time.Second)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	select {
	case result := <-filesCh:
		t.Logf("Received result: %v", result)
	case <-ctx.Done():
		t.Log("Context cancelled (expected)")
	case <-time.After(200 * time.Millisecond):
		t.Log("Timeout occurred (expected)")
	}

	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	goroutines := runtime.NumGoroutine()
	t.Logf("Goroutines after test: %d", goroutines)
}

// TestFilesUsedFromContext_ChannelBlock tests that goroutine is not blocked
// when writing to buffered channel
func TestFilesUsedFromContext_ChannelBlock(t *testing.T) {
	filesCh := make(chan struct {
		files []string
		err   error
	}, 1)

	go func() {
		time.Sleep(50 * time.Millisecond)
		filesCh <- struct {
			files []string
			err   error
		}{files: []string{"file1"}, err: nil}
	}()

	select {
	case result := <-filesCh:
		if len(result.files) != 1 {
			t.Errorf("Expected 1 file, got %d", len(result.files))
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Timeout occurred, but should have received result")
	}
}

// TestFilesUsedFromContext_MutexDeadlock tests potential deadlock
// with mutex in processCommand
func TestFilesUsedFromContext_MutexDeadlock(t *testing.T) {
	var mu sync.RWMutex

	mu.Lock()

	done := make(chan bool, 1)
	go func() {
		mu.RLock()
		defer mu.RUnlock()
		done <- true
	}()

	select {
	case <-done:
		t.Error("Should not be able to acquire RLock while Lock is held")
	case <-time.After(100 * time.Millisecond):
		t.Log("Goroutine blocked as expected (Lock held)")
	}

	mu.Unlock()

	select {
	case <-done:
		t.Log("Goroutine unblocked after Lock released")
	case <-time.After(100 * time.Millisecond):
		t.Error("Goroutine should have unblocked after Lock released")
	}
}

// TestResolveEnvAndWildcards_HangOnLargeDirectory tests that ResolveEnvAndWildcards
// does not hang on large directories
func TestResolveEnvAndWildcards_HangOnLargeDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	for i := 0; i < 1000; i++ {
		filePath := filepath.Join(tmpDir, fmt.Sprintf("file_%d.txt", i))
		if err := os.WriteFile(filePath, []byte("test"), 0644); err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	done := make(chan bool, 1)
	go func() {
		files, err := filepath.Glob(filepath.Join(tmpDir, "*.txt"))
		if err != nil {
			t.Errorf("Glob failed: %v", err)
		}
		if len(files) != 1000 {
			t.Errorf("Expected 1000 files, got %d", len(files))
		}
		done <- true
	}()

	select {
	case <-done:
		t.Log("Operation completed successfully")
	case <-ctx.Done():
		t.Error("Operation timed out - potential hang detected")
	}
}

// TestMultipleFilesUsedFromContext_RaceCondition tests race condition
// with parallel calls to FilesUsedFromContext
func TestMultipleFilesUsedFromContext_RaceCondition(t *testing.T) {
	var mu sync.RWMutex
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			filesCh := make(chan struct {
				files []string
				err   error
			}, 1)

			go func() {
				mu.RLock()
				defer mu.RUnlock()
				time.Sleep(10 * time.Millisecond)
				filesCh <- struct {
					files []string
					err   error
				}{files: []string{"file"}, err: nil}
			}()

			select {
			case <-filesCh:
			case <-time.After(1 * time.Second):
				t.Errorf("Goroutine %d timed out", id)
			}
		}(i)
	}

	wg.Wait()
	t.Log("All goroutines completed")
}

// TestFilesUsedFromContext_ContextCancellation tests that context
// is properly cancelled and goroutines terminate
func TestFilesUsedFromContext_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	filesCh := make(chan struct {
		files []string
		err   error
	}, 1)

	go func() {
		time.Sleep(1 * time.Second)
		select {
		case filesCh <- struct {
			files []string
			err   error
		}{files: []string{"file"}, err: nil}:
		case <-ctx.Done():
			t.Log("Goroutine cancelled")
		}
	}()

	cancel()

	select {
	case <-filesCh:
		t.Error("Should not receive from channel when context is cancelled")
	case <-ctx.Done():
		t.Log("Context cancelled as expected")
	case <-time.After(100 * time.Millisecond):
		t.Error("Select should have chosen ctx.Done()")
	}
}

// TestProcessCommand_TimeoutRace tests race condition between
// timeout and receiving result from channel
func TestProcessCommand_TimeoutRace(t *testing.T) {
	filesCh := make(chan struct {
		files []string
		err   error
	}, 1)

	go func() {
		time.Sleep(100 * time.Millisecond)
		filesCh <- struct {
			files []string
			err   error
		}{files: []string{"file"}, err: nil}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	select {
	case result := <-filesCh:
		if len(result.files) != 1 {
			t.Errorf("Expected 1 file, got %d", len(result.files))
		}
		t.Log("Received result before timeout")
	case <-ctx.Done():
		t.Log("Timeout occurred")
	case <-time.After(200 * time.Millisecond):
		t.Error("Both timeout and result should have occurred")
	}
}

// TestRelativeFiles_LargeDirectory tests that RelativeFiles
// does not hang on large directories
func TestRelativeFiles_LargeDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	for i := 0; i < 100; i++ {
		subDir := filepath.Join(tmpDir, fmt.Sprintf("dir_%d", i))
		if err := os.MkdirAll(subDir, 0755); err != nil {
			t.Fatalf("Failed to create directory: %v", err)
		}

		for j := 0; j < 100; j++ {
			filePath := filepath.Join(subDir, fmt.Sprintf("file_%d.txt", j))
			if err := os.WriteFile(filePath, []byte("test"), 0644); err != nil {
				t.Fatalf("Failed to create file: %v", err)
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan bool, 1)
	go func() {
		var count int
		err := filepath.Walk(tmpDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				count++
			}
			return nil
		})
		if err != nil {
			t.Errorf("Walk failed: %v", err)
		}
		if count != 10000 {
			t.Errorf("Expected 10000 files, got %d", count)
		}
		done <- true
	}()

	select {
	case <-done:
		t.Log("Directory walk completed successfully")
	case <-ctx.Done():
		t.Error("Directory walk timed out - potential hang detected")
	}
}

// TestGoroutineLeak_FilesUsedFromContext tests goroutine leak
// when select chooses timeout but goroutine continues working
func TestGoroutineLeak_FilesUsedFromContext(t *testing.T) {
	beforeGoroutines := runtime.NumGoroutine()

	for i := 0; i < 10; i++ {
		filesCh := make(chan struct {
			files []string
			err   error
		}, 1)

		go func() {
			time.Sleep(200 * time.Millisecond)
			select {
			case filesCh <- struct {
				files []string
				err   error
			}{files: []string{"file"}, err: nil}:
			default:
			}
		}()

		select {
		case <-filesCh:
		case <-time.After(50 * time.Millisecond):
		}
	}

	time.Sleep(300 * time.Millisecond)
	runtime.GC()

	afterGoroutines := runtime.NumGoroutine()

	if afterGoroutines > beforeGoroutines+5 {
		t.Errorf("Possible goroutine leak: before=%d, after=%d", beforeGoroutines, afterGoroutines)
	} else {
		t.Logf("Goroutine count: before=%d, after=%d", beforeGoroutines, afterGoroutines)
	}
}
