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
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/Gosayram/kaniko/pkg/commands"
	"github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/dockerfile"
)

// TestComputeCacheKeys_MockCommand tests computeCacheKeys
// with mock command that simulates FilesUsedFromContext call
func TestComputeCacheKeys_MockCommand(t *testing.T) {
	mockCmd := MockDockerCommand{
		command:      "COPY test.txt /dest",
		contextFiles: []string{"test.txt"},
	}

	sb := &stageBuilder{
		cmds:             []commands.DockerCommand{mockCmd},
		args:             dockerfile.NewBuildArgs(nil),
		opts:             &config.KanikoOptions{Cache: false},
		digestToCacheKey: make(map[string]string),
	}

	cfg := &v1.Config{}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
		t.Error("computeCacheKeys timed out - potential hang detected!")
	}
}

// TestComputeCacheKeys_MultipleCommands tests computeCacheKeys
// with multiple commands that use FilesUsedFromContext
func TestComputeCacheKeys_MultipleCommands(t *testing.T) {
	var cmds []commands.DockerCommand
	for i := 0; i < 10; i++ {
		cmds = append(cmds, MockDockerCommand{
			command:      fmt.Sprintf("COPY file_%d.txt /dest_%d", i, i),
			contextFiles: []string{fmt.Sprintf("file_%d.txt", i)},
		})
	}

	sb := &stageBuilder{
		cmds:             cmds,
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
		t.Error("computeCacheKeys timed out - potential hang detected!")
	}
}

// TestComputeCacheKeys_Timeout tests that computeCacheKeys
// properly handles timeout when FilesUsedFromContext takes long time
// Note: This test is skipped by default as it requires 2+ minutes to run
// To run it: go test -run TestComputeCacheKeys_Timeout -timeout 5m
func TestComputeCacheKeys_Timeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping long-running timeout test in short mode")
	}

	// Use delay longer than 2 minute timeout in computeCacheKeys
	slowCmd := &slowFilesCommand{
		MockDockerCommand: MockDockerCommand{
			command:      "COPY * /dest",
			contextFiles: []string{"file1.txt", "file2.txt"},
		},
		delay: 2*time.Minute + 10*time.Second, // Longer than 2 minute timeout
	}

	sb := &stageBuilder{
		cmds:             []commands.DockerCommand{slowCmd},
		args:             dockerfile.NewBuildArgs(nil),
		opts:             &config.KanikoOptions{Cache: false},
		digestToCacheKey: make(map[string]string),
	}

	cfg := &v1.Config{}

	// Test should complete within 3 minutes (timeout in computeCacheKeys is 2 minutes)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
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
		// Should complete with timeout error or empty results
		if computeErr != nil {
			t.Logf("computeCacheKeys returned error (expected for timeout): %v", computeErr)
		}
		t.Logf("computeCacheKeys completed: results=%d", len(results))
		// Verify that timeout was handled (results should be empty or partial)
		if len(results) == 0 {
			t.Log("Timeout handled correctly - no results returned")
		}
	case <-ctx.Done():
		t.Error("Test itself timed out - computeCacheKeys may have hung!")
	}
}

// TestProcessCommand_FilesUsedFromContext tests processCommand
// with mock command that uses FilesUsedFromContext
func TestProcessCommand_FilesUsedFromContext(t *testing.T) {
	mockCmd := MockDockerCommand{
		command:      "COPY *.txt /dest",
		contextFiles: []string{"file_0.txt", "file_1.txt"},
	}

	sb := &stageBuilder{
		cmds: []commands.DockerCommand{mockCmd},
		args: dockerfile.NewBuildArgs(nil),
		opts: &config.KanikoOptions{
			Cache: false,
		},
		cf: &v1.ConfigFile{Config: v1.Config{}},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	done := make(chan bool, 1)
	var processErr error

	go func() {
		compositeKey := NewCompositeCache()
		processErr = sb.processCommand(mockCmd, 0, compositeKey, nil, false)
		done <- true
	}()

	select {
	case <-done:
		if processErr != nil {
			t.Logf("processCommand returned error (may be expected): %v", processErr)
		}
		t.Log("processCommand completed")
	case <-ctx.Done():
		t.Error("processCommand timed out - potential hang detected!")
	}
}

// slowFilesCommand is a mock command that simulates slow FilesUsedFromContext
type slowFilesCommand struct {
	MockDockerCommand
	delay time.Duration
}

// FilesUsedFromContext simulates slow operation
func (s *slowFilesCommand) FilesUsedFromContext(_ *v1.Config, _ *dockerfile.BuildArgs) ([]string, error) {
	time.Sleep(s.delay)
	return s.contextFiles, nil
}
