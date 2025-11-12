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
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/Gosayram/kaniko/pkg/commands"
	"github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/dockerfile"
)

// TestBuildContext_HangSimulation simulates the real scenario from pipeline log
// where build hangs after "Context files: [/builds/finservice/halyk-market-mono]"
// This happens right after "Starting stage" and before command execution
func TestBuildContext_HangSimulation(t *testing.T) {
	tmpDir := t.TempDir()

	// Simulate large monorepo structure (like halyk-market-mono)
	// Create nested directory structure with many files
	for i := 0; i < 50; i++ {
		appDir := filepath.Join(tmpDir, fmt.Sprintf("app_%d", i))
		if err := os.MkdirAll(appDir, 0755); err != nil {
			t.Fatalf("Failed to create app directory: %v", err)
		}

		// Create subdirectories
		for j := 0; j < 20; j++ {
			subDir := filepath.Join(appDir, fmt.Sprintf("sub_%d", j))
			if err := os.MkdirAll(subDir, 0755); err != nil {
				t.Fatalf("Failed to create subdirectory: %v", err)
			}

			// Create files in each subdirectory
			for k := 0; k < 50; k++ {
				filePath := filepath.Join(subDir, fmt.Sprintf("file_%d.txt", k))
				if err := os.WriteFile(filePath, []byte("test content"), 0644); err != nil {
					t.Fatalf("Failed to create file: %v", err)
				}
			}
		}
	}

	// Create mock COPY command that would trigger "Context files" log
	// This simulates what happens when COPY command calls FilesUsedFromContext
	mockCmd := MockDockerCommand{
		command:      "COPY * /app",
		contextFiles: []string{"app_0", "app_1"}, // Simulated files
	}

	sb := &stageBuilder{
		cmds:             []commands.DockerCommand{mockCmd},
		args:             dockerfile.NewBuildArgs(nil),
		opts:             &config.KanikoOptions{Cache: true},
		digestToCacheKey: make(map[string]string),
		cf:               &v1.ConfigFile{Config: v1.Config{}},
	}

	cfg := &v1.Config{}

	// Simulate computeCacheKeys which is called before processCommand
	// This is where "Context files" would be logged
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	done := make(chan bool, 1)
	var results []*cacheCheckResult
	var computeErr error

	go func() {
		compositeKey := *NewCompositeCache()
		results, computeErr = sb.computeCacheKeys(compositeKey, cfg)
		done <- true
	}()

	select {
	case <-done:
		if computeErr != nil {
			t.Logf("computeCacheKeys returned error (may be expected): %v", computeErr)
		}
		t.Logf("computeCacheKeys completed: results=%d", len(results))
	case <-ctx.Done():
		t.Error("computeCacheKeys timed out - this simulates the hang from pipeline log!")
	}

	// Now simulate processCommand which would be called after computeCacheKeys
	// This is where the actual hang might occur
	if len(results) > 0 {
		ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel2()

		done2 := make(chan bool, 1)
		var processErr error

		go func() {
			compositeKey := NewCompositeCache()
			processErr = sb.processCommand(mockCmd, 0, compositeKey, nil, false)
			done2 <- true
		}()

		select {
		case <-done2:
			if processErr != nil {
				t.Logf("processCommand returned error (may be expected): %v", processErr)
			}
			t.Log("processCommand completed")
		case <-ctx2.Done():
			t.Error("processCommand timed out - potential hang point!")
		}
	}
}

// TestBuildContext_LargeDirectoryStructure tests the scenario
// where build context has very large directory structure
// that could cause FilesUsedFromContext to hang
func TestBuildContext_LargeDirectoryStructure(t *testing.T) {
	tmpDir := t.TempDir()

	// Create very large directory structure (simulating real monorepo)
	// This could cause RelativeFiles to take very long time
	for i := 0; i < 100; i++ {
		dir := filepath.Join(tmpDir, fmt.Sprintf("dir_%d", i))
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("Failed to create directory: %v", err)
		}

		for j := 0; j < 100; j++ {
			filePath := filepath.Join(dir, fmt.Sprintf("file_%d.txt", j))
			if err := os.WriteFile(filePath, []byte("test"), 0644); err != nil {
				t.Fatalf("Failed to create file: %v", err)
			}
		}
	}

	// Test that computeCacheKeys doesn't hang even with large structure
	mockCmd := MockDockerCommand{
		command:      "COPY dir_* /dest",
		contextFiles: []string{"dir_0", "dir_1"},
	}

	sb := &stageBuilder{
		cmds:             []commands.DockerCommand{mockCmd},
		args:             dockerfile.NewBuildArgs(nil),
		opts:             &config.KanikoOptions{Cache: false},
		digestToCacheKey: make(map[string]string),
	}

	cfg := &v1.Config{}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan bool, 1)
	var results []*cacheCheckResult
	var computeErr error

	go func() {
		compositeKey := *NewCompositeCache()
		results, computeErr = sb.computeCacheKeys(compositeKey, cfg)
		done <- true
	}()

	select {
	case <-done:
		if computeErr != nil {
			t.Logf("computeCacheKeys returned error (may be expected): %v", computeErr)
		}
		t.Logf("computeCacheKeys completed: results=%d", len(results))
	case <-ctx.Done():
		t.Error("computeCacheKeys timed out - potential hang with large directory structure!")
	}
}
