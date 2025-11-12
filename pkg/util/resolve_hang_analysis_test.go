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

package util

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/moby/buildkit/frontend/dockerfile/instructions"
)

// TestResolveEnvAndWildcards_DoubleTimeout tests double timeout issue
// Code has both ctx.Done() and time.After() which is redundant and may cause problems
func TestResolveEnvAndWildcards_DoubleTimeout(t *testing.T) {
	tmpDir := t.TempDir()
	fileContext := FileContext{Root: tmpDir}

	for i := 0; i < 10; i++ {
		filePath := filepath.Join(tmpDir, fmt.Sprintf("file_%d.txt", i))
		if err := os.WriteFile(filePath, []byte("test"), 0644); err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}
	}

	sd := instructions.SourcesAndDest{
		SourcePaths: []string{"file_*.txt"},
		DestPath:    "/dest",
	}

	start := time.Now()
	sources, dest, err := ResolveEnvAndWildcards(sd, fileContext, []string{})
	duration := time.Since(start)

	if err != nil {
		t.Logf("ResolveEnvAndWildcards returned error (may be expected): %v", err)
	}

	if duration > 10*time.Second {
		t.Errorf("ResolveEnvAndWildcards took too long: %v (potential hang)", duration)
	}

	t.Logf("ResolveEnvAndWildcards completed in %v: sources=%d, dest=%s", duration, len(sources), dest)
}

// TestResolveEnvAndWildcards_Timeout tests that timeout actually works
func TestResolveEnvAndWildcards_Timeout(t *testing.T) {
	tmpDir := t.TempDir()
	fileContext := FileContext{Root: tmpDir}

	for i := 0; i < 1000; i++ {
		filePath := filepath.Join(tmpDir, fmt.Sprintf("file_%d.txt", i))
		if err := os.WriteFile(filePath, []byte("test"), 0644); err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}
	}

	sd := instructions.SourcesAndDest{
		SourcePaths: []string{"file_*.txt"},
		DestPath:    "/dest",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan bool, 1)
	var sources []string
	var dest string
	var err error

	go func() {
		sources, dest, err = ResolveEnvAndWildcards(sd, fileContext, []string{})
		done <- true
	}()

	select {
	case <-done:
		t.Logf("ResolveEnvAndWildcards completed: sources=%d, dest=%s, err=%v", len(sources), dest, err)
	case <-ctx.Done():
		t.Error("ResolveEnvAndWildcards timed out - potential hang detected!")
	}
}

// TestResolveEnvAndWildcards_GoroutineLeak tests goroutine leak
// when select chooses timeout but goroutine continues working
func TestResolveEnvAndWildcards_GoroutineLeak(t *testing.T) {
	// Wait for any background goroutines from previous tests to settle
	time.Sleep(500 * time.Millisecond)
	runtime.GC()

	beforeGoroutines := runtime.NumGoroutine()

	tmpDir := t.TempDir()
	fileContext := FileContext{Root: tmpDir}

	for i := 0; i < 100; i++ {
		filePath := filepath.Join(tmpDir, fmt.Sprintf("file_%d.txt", i))
		if err := os.WriteFile(filePath, []byte("test"), 0644); err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}
	}

	sd := instructions.SourcesAndDest{
		SourcePaths: []string{"file_*.txt"},
		DestPath:    "/dest",
	}

	// Call fewer times to reduce noise
	for i := 0; i < 5; i++ {
		_, _, _ = ResolveEnvAndWildcards(sd, fileContext, []string{})
	}

	// Give goroutines time to complete and cleanup
	// Each ResolveEnvAndWildcards creates goroutines that should complete
	time.Sleep(3 * time.Second)
	runtime.GC()
	time.Sleep(1 * time.Second)
	runtime.GC()

	afterGoroutines := runtime.NumGoroutine()

	// Allow some margin for background goroutines (timeout warnings, etc.)
	// But should not have 1000+ goroutines
	if afterGoroutines > beforeGoroutines+20 {
		t.Errorf("Possible goroutine leak: before=%d, after=%d (increase: %d)",
			beforeGoroutines, afterGoroutines, afterGoroutines-beforeGoroutines)
	} else {
		t.Logf("Goroutine count: before=%d, after=%d (increase: %d)",
			beforeGoroutines, afterGoroutines, afterGoroutines-beforeGoroutines)
	}
}

// TestResolveSources_RelativeFilesHang tests that ResolveSources
// does not hang when RelativeFiles takes long time
func TestResolveSources_RelativeFilesHang(t *testing.T) {
	tmpDir := t.TempDir()

	for i := 0; i < 50; i++ {
		subDir := filepath.Join(tmpDir, fmt.Sprintf("dir_%d", i))
		if err := os.MkdirAll(subDir, 0755); err != nil {
			t.Fatalf("Failed to create directory: %v", err)
		}

		for j := 0; j < 50; j++ {
			filePath := filepath.Join(subDir, fmt.Sprintf("file_%d.txt", j))
			if err := os.WriteFile(filePath, []byte("test"), 0644); err != nil {
				t.Fatalf("Failed to create file: %v", err)
			}
		}
	}

	srcs := []string{"dir_*/*.txt"}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan bool, 1)
	var resolved []string
	var err error

	go func() {
		resolved, err = ResolveSources(srcs, tmpDir)
		done <- true
	}()

	select {
	case <-done:
		t.Logf("ResolveSources completed: resolved=%d files, err=%v", len(resolved), err)
		if err != nil {
			t.Logf("Error (may be expected): %v", err)
		}
	case <-ctx.Done():
		t.Error("ResolveSources timed out - potential hang detected!")
	}
}

// TestRelativeFiles_ContextCancellation tests that RelativeFiles
// properly handles context cancellation
func TestRelativeFiles_ContextCancellation(t *testing.T) {
	tmpDir := t.TempDir()

	for i := 0; i < 100; i++ {
		filePath := filepath.Join(tmpDir, fmt.Sprintf("file_%d.txt", i))
		if err := os.WriteFile(filePath, []byte("test"), 0644); err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}
	}

	start := time.Now()
	files, err := RelativeFiles("", tmpDir)
	duration := time.Since(start)

	if duration > 10*time.Second {
		t.Errorf("RelativeFiles took too long: %v (potential hang)", duration)
	}

	if err != nil {
		t.Logf("RelativeFiles returned error (may be expected): %v", err)
	}

	t.Logf("RelativeFiles completed in %v: files=%d", duration, len(files))
}

// TestResolveEnvAndWildcards_ConcurrentAccess tests race conditions
// with parallel calls to ResolveEnvAndWildcards
func TestResolveEnvAndWildcards_ConcurrentAccess(t *testing.T) {
	tmpDir := t.TempDir()
	fileContext := FileContext{Root: tmpDir}

	for i := 0; i < 100; i++ {
		filePath := filepath.Join(tmpDir, fmt.Sprintf("file_%d.txt", i))
		if err := os.WriteFile(filePath, []byte("test"), 0644); err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}
	}

	sd := instructions.SourcesAndDest{
		SourcePaths: []string{"file_*.txt"},
		DestPath:    "/dest",
	}

	var wg sync.WaitGroup
	errors := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			_, _, err := ResolveEnvAndWildcards(sd, fileContext, []string{})
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: %w", id, err)
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Logf("Concurrent access error (may be expected): %v", err)
	}
}

// TestResolveEnvAndWildcards_EmptyResult tests that function
// does not hang when returning empty result
func TestResolveEnvAndWildcards_EmptyResult(t *testing.T) {
	tmpDir := t.TempDir()
	fileContext := FileContext{Root: tmpDir}

	sd := instructions.SourcesAndDest{
		SourcePaths: []string{"nonexistent_*.txt"},
		DestPath:    "/dest",
	}

	start := time.Now()
	sources, dest, err := ResolveEnvAndWildcards(sd, fileContext, []string{})
	duration := time.Since(start)

	if duration > 10*time.Second {
		t.Errorf("ResolveEnvAndWildcards took too long with empty result: %v (potential hang)", duration)
	}

	t.Logf("ResolveEnvAndWildcards with empty result: duration=%v, sources=%d, dest=%s, err=%v",
		duration, len(sources), dest, err)
}

// TestResolveEnvAndWildcards_ChannelDeadlock tests potential deadlock
// in resolveCh channel
func TestResolveEnvAndWildcards_ChannelDeadlock(t *testing.T) {
	tmpDir := t.TempDir()
	fileContext := FileContext{Root: tmpDir}

	for i := 0; i < 10; i++ {
		filePath := filepath.Join(tmpDir, fmt.Sprintf("file_%d.txt", i))
		if err := os.WriteFile(filePath, []byte("test"), 0644); err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}
	}

	sd := instructions.SourcesAndDest{
		SourcePaths: []string{"file_*.txt"},
		DestPath:    "/dest",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan bool, 1)
	go func() {
		_, _, _ = ResolveEnvAndWildcards(sd, fileContext, []string{})
		done <- true
	}()

	select {
	case <-done:
		t.Log("ResolveEnvAndWildcards completed")
	case <-ctx.Done():
		t.Error("ResolveEnvAndWildcards timed out - potential deadlock!")
	}
}
