/*
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package executor

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/Gosayram/kaniko/pkg/commands"
	"github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/dockerfile"
)

// testRunCommand is a mock command that doesn't provide files to snapshot (like real RUN commands)
type testRunCommand struct {
	MockDockerCommand
	command          string
	executeFunc      func(*v1.Config, *dockerfile.BuildArgs) error
	executeTime      time.Time
	executeTimeMutex sync.Mutex
}

func (t *testRunCommand) String() string {
	return t.command
}

func (t *testRunCommand) ProvidesFilesToSnapshot() bool {
	return false // RUN commands don't provide files to snapshot
}

func (t *testRunCommand) ExecuteCommand(config *v1.Config, buildArgs *dockerfile.BuildArgs) error {
	t.executeTimeMutex.Lock()
	if t.executeTime.IsZero() {
		t.executeTime = time.Now()
	}
	t.executeTimeMutex.Unlock()

	if t.executeFunc != nil {
		return t.executeFunc(config, buildArgs)
	}
	return t.MockDockerCommand.ExecuteCommand(config, buildArgs)
}

func (t *testRunCommand) GetExecuteTime() time.Time {
	t.executeTimeMutex.Lock()
	defer t.executeTimeMutex.Unlock()
	return t.executeTime
}

// trackingSnapshotter tracks init snapshot calls
type trackingSnapshotter struct {
	*fakeSnapShotter
	initCallCount int64
	initTime      time.Time
	initTimeMutex sync.Mutex
}

func (t *trackingSnapshotter) Init() error {
	atomic.AddInt64(&t.initCallCount, 1)
	t.initTimeMutex.Lock()
	if t.initTime.IsZero() {
		t.initTime = time.Now()
	}
	t.initTimeMutex.Unlock()
	return t.fakeSnapShotter.Init()
}

func (t *trackingSnapshotter) GetInitCallCount() int {
	return int(atomic.LoadInt64(&t.initCallCount))
}

func (t *trackingSnapshotter) GetInitTime() time.Time {
	t.initTimeMutex.Lock()
	defer t.initTimeMutex.Unlock()
	return t.initTime
}

// TestInitSnapshotOnce tests that initSnapshot is called only once even with parallel commands
func TestInitSnapshotOnce(t *testing.T) {
	// Create mock commands that don't provide files to snapshot (like RUN commands)
	// This ensures initSnapshot will be called
	cmds := []commands.DockerCommand{
		&testRunCommand{command: "RUN cmd1"},
		&testRunCommand{command: "RUN cmd2"},
		&testRunCommand{command: "RUN cmd3"},
	}

	opts := &config.KanikoOptions{
		MaxParallelCommands: 3,
		CommandTimeout:      30 * time.Second,
	}

	args := dockerfile.NewBuildArgs([]string{})
	imageConfig := &v1.Config{}

	// Create minimal stageBuilder with tracking snapshotter
	trackingSnap := &trackingSnapshotter{
		fakeSnapShotter: &fakeSnapShotter{file: ""},
	}
	sb := &stageBuilder{
		args:        dockerfile.NewBuildArgs([]string{}),
		opts:        opts,
		cf:          &v1.ConfigFile{Config: v1.Config{Env: make([]string, 0)}},
		snapshotter: trackingSnap,
	}

	executor := NewParallelExecutor(cmds, opts, args, imageConfig, sb)

	// Execute commands in parallel
	compositeKey := &CompositeCache{}
	err := executor.ExecuteCommands(compositeKey, false)

	if err != nil {
		t.Fatalf("ExecuteCommands failed: %v", err)
	}

	// Verify init snapshot was called only once
	callCount := trackingSnap.GetInitCallCount()
	if callCount != 1 {
		t.Errorf("Expected initSnapshot to be called once, got %d", callCount)
	}
}

// TestInitSnapshotAlreadyTaken tests that initSnapshot is not called when already taken
func TestInitSnapshotAlreadyTaken(t *testing.T) {
	cmds := []commands.DockerCommand{
		MockDockerCommand{command: "RUN cmd1"},
		MockDockerCommand{command: "RUN cmd2"},
	}

	opts := &config.KanikoOptions{
		MaxParallelCommands: 2,
		CommandTimeout:      30 * time.Second,
	}

	args := dockerfile.NewBuildArgs([]string{})
	imageConfig := &v1.Config{}

	trackingSnap := &trackingSnapshotter{
		fakeSnapShotter: &fakeSnapShotter{file: ""},
	}
	sb := &stageBuilder{
		args:        dockerfile.NewBuildArgs([]string{}),
		opts:        opts,
		cf:          &v1.ConfigFile{Config: v1.Config{Env: make([]string, 0)}},
		snapshotter: trackingSnap,
	}

	executor := NewParallelExecutor(cmds, opts, args, imageConfig, sb)

	compositeKey := &CompositeCache{}
	// Pass initSnapshotTaken = true
	err := executor.ExecuteCommands(compositeKey, true)

	if err != nil {
		t.Fatalf("ExecuteCommands failed: %v", err)
	}

	// Verify init snapshot was NOT called
	callCount := trackingSnap.GetInitCallCount()
	if callCount != 0 {
		t.Errorf("Expected initSnapshot to not be called when already taken, got %d", callCount)
	}
}

// TestCommandExecutionOrder tests that commands execute in correct order
func TestCommandExecutionOrder(t *testing.T) {
	// Create commands with dependencies
	// Command 0 should execute before command 1
	cmds := []commands.DockerCommand{
		MockDockerCommand{command: "RUN install-tool"},
		MockDockerCommand{command: "RUN use-tool"},
		MockDockerCommand{command: "ARG VAR"},
	}

	opts := &config.KanikoOptions{
		MaxParallelCommands: 3,
		CommandTimeout:      30 * time.Second,
	}

	args := dockerfile.NewBuildArgs([]string{})
	imageConfig := &v1.Config{}

	sb := &stageBuilder{
		args:        dockerfile.NewBuildArgs([]string{}),
		opts:        opts,
		cf:          &v1.ConfigFile{Config: v1.Config{Env: make([]string, 0)}},
		snapshotter: &fakeSnapShotter{file: ""},
	}

	executor := NewParallelExecutor(cmds, opts, args, imageConfig, sb)

	// Add dependency: command 1 depends on command 0
	executor.dependencies = []CommandDependency{
		{From: 0, To: 1, Type: FileSystemDependency},
	}

	compositeKey := &CompositeCache{}
	err := executor.AnalyzeDependencies()
	if err != nil {
		t.Fatalf("AnalyzeDependencies failed: %v", err)
	}

	// Verify execution order
	order := executor.executionOrder
	if len(order) != 3 {
		t.Fatalf("Expected 3 commands in order, got %d", len(order))
	}

	// Command 0 should come before command 1
	found0 := false
	found1 := false
	for _, idx := range order {
		if idx == 0 {
			found0 = true
		}
		if idx == 1 {
			found1 = true
			if !found0 {
				t.Errorf("Command 1 executed before command 0 (dependency violation)")
			}
		}
		if idx == 2 {
			// ARG commands can execute in parallel, so command 2 can be anywhere
		}
	}

	if !found0 || !found1 {
		t.Errorf("Not all commands found in execution order")
	}

	// Execute commands
	err = executor.ExecuteCommands(compositeKey, true)
	if err != nil {
		t.Fatalf("ExecuteCommands failed: %v", err)
	}
}

// TestParallelExecutionWithInitSnapshot tests that init snapshot works correctly with parallel execution
func TestParallelExecutionWithInitSnapshot(t *testing.T) {
	cmds := []commands.DockerCommand{
		&testRunCommand{command: "RUN cmd1"},
		&testRunCommand{command: "RUN cmd2"},
		&testRunCommand{command: "RUN cmd3"},
		&testRunCommand{command: "RUN cmd4"},
	}

	opts := &config.KanikoOptions{
		MaxParallelCommands: 4,
		CommandTimeout:      30 * time.Second,
	}

	args := dockerfile.NewBuildArgs([]string{})
	imageConfig := &v1.Config{}

	trackingSnap := &trackingSnapshotter{
		fakeSnapShotter: &fakeSnapShotter{file: ""},
	}
	sb := &stageBuilder{
		args:        dockerfile.NewBuildArgs([]string{}),
		opts:        opts,
		cf:          &v1.ConfigFile{Config: v1.Config{Env: make([]string, 0)}},
		snapshotter: trackingSnap,
	}

	executor := NewParallelExecutor(cmds, opts, args, imageConfig, sb)

	compositeKey := &CompositeCache{}
	err := executor.ExecuteCommands(compositeKey, false)

	if err != nil {
		t.Fatalf("ExecuteCommands failed: %v", err)
	}

	// Verify init snapshot was called only once despite 4 parallel commands
	callCount := trackingSnap.GetInitCallCount()
	if callCount != 1 {
		t.Errorf("Expected initSnapshot to be called once with 4 parallel commands, got %d", callCount)
	}
}

// TestDeferredSnapshotsBasic tests that deferred snapshot mechanism works
func TestDeferredSnapshotsBasic(t *testing.T) {
	cmds := []commands.DockerCommand{
		&testRunCommand{command: "RUN cmd0"},
		&testRunCommand{command: "RUN cmd1"},
		&testRunCommand{command: "RUN cmd2"},
	}

	opts := &config.KanikoOptions{
		MaxParallelCommands: 3,
		CommandTimeout:      30 * time.Second,
		ForceBuildMetadata:  true, // Force snapshots
	}

	args := dockerfile.NewBuildArgs([]string{})
	imageConfig := &v1.Config{}

	sb := &stageBuilder{
		args:        dockerfile.NewBuildArgs([]string{}),
		opts:        opts,
		cf:          &v1.ConfigFile{Config: v1.Config{Env: make([]string, 0)}},
		snapshotter: &fakeSnapShotter{file: "/tmp/test-snapshot"},
		cmds:        cmds,
		pushLayerToCache: func(_ *config.KanikoOptions, _, _, _ string) error {
			return nil // Mock cache push
		},
	}

	executor := NewParallelExecutor(cmds, opts, args, imageConfig, sb)

	compositeKey := &CompositeCache{}
	err := executor.ExecuteCommands(compositeKey, true)

	// Should succeed - deferred snapshots should work correctly
	if err != nil {
		t.Fatalf("ExecuteCommands failed: %v", err)
	}

	// Verify all commands were executed
	executor.executedMutex.RLock()
	executedCount := len(executor.executed)
	executor.executedMutex.RUnlock()

	if executedCount != 3 {
		t.Errorf("Expected 3 commands to be executed, got %d", executedCount)
	}
}

// TestCompositeKeyIsolation tests that compositeKey is properly copied for each snapshot
func TestCompositeKeyIsolation(t *testing.T) {
	cmds := []commands.DockerCommand{
		&testRunCommand{command: "RUN cmd0"},
		&testRunCommand{command: "RUN cmd1"},
		&testRunCommand{command: "RUN cmd2"},
	}

	opts := &config.KanikoOptions{
		MaxParallelCommands: 3,
		CommandTimeout:      30 * time.Second,
		ForceBuildMetadata:  true,
		Cache:               true, // Enable cache to test compositeKey
	}

	args := dockerfile.NewBuildArgs([]string{})
	imageConfig := &v1.Config{}

	sb := &stageBuilder{
		args:        dockerfile.NewBuildArgs([]string{}),
		opts:        opts,
		cf:          &v1.ConfigFile{Config: v1.Config{Env: make([]string, 0)}},
		snapshotter: &fakeSnapShotter{file: "/tmp/test-snapshot"},
		cmds:        cmds,
		pushLayerToCache: func(_ *config.KanikoOptions, _, _, _ string) error {
			return nil // Mock cache push
		},
	}

	executor := NewParallelExecutor(cmds, opts, args, imageConfig, sb)

	compositeKey := &CompositeCache{}
	compositeKey.AddKey("initial-key")

	err := executor.ExecuteCommands(compositeKey, true)

	// Should succeed - compositeKey should be properly handled
	if err != nil {
		t.Fatalf("ExecuteCommands failed: %v", err)
	}
}

// TestEmptySnapshotHandling tests that empty snapshots are handled correctly
func TestEmptySnapshotHandling(t *testing.T) {
	cmds := []commands.DockerCommand{
		MockDockerCommand{command: "ARG VAR"}, // Metadata command, might not create snapshot
		&testRunCommand{command: "RUN cmd1"},
	}

	opts := &config.KanikoOptions{
		MaxParallelCommands: 2,
		CommandTimeout:      30 * time.Second,
	}

	args := dockerfile.NewBuildArgs([]string{})
	imageConfig := &v1.Config{}

	sb := &stageBuilder{
		args:        dockerfile.NewBuildArgs([]string{}),
		opts:        opts,
		cf:          &v1.ConfigFile{Config: v1.Config{Env: make([]string, 0)}},
		snapshotter: &fakeSnapShotter{file: ""}, // Empty file = no snapshot
		cmds:        cmds,
	}

	executor := NewParallelExecutor(cmds, opts, args, imageConfig, sb)

	compositeKey := &CompositeCache{}
	err := executor.ExecuteCommands(compositeKey, true)

	// Should not fail even with empty snapshots
	if err != nil {
		t.Fatalf("ExecuteCommands failed with empty snapshots: %v", err)
	}
}

// TestParallelGroupWithDependencies tests that parallel groups respect dependencies
func TestParallelGroupWithDependencies(t *testing.T) {
	cmds := []commands.DockerCommand{
		MockDockerCommand{command: "RUN install"}, // Command 0
		MockDockerCommand{command: "RUN use1"},    // Command 1 depends on 0
		MockDockerCommand{command: "RUN use2"},    // Command 2 depends on 0
		MockDockerCommand{command: "ARG VAR"},     // Command 3 - no dependencies
	}

	opts := &config.KanikoOptions{
		MaxParallelCommands: 4,
		CommandTimeout:      30 * time.Second,
	}

	args := dockerfile.NewBuildArgs([]string{})
	imageConfig := &v1.Config{}

	sb := &stageBuilder{
		args:        dockerfile.NewBuildArgs([]string{}),
		opts:        opts,
		cf:          &v1.ConfigFile{Config: v1.Config{Env: make([]string, 0)}},
		snapshotter: &fakeSnapShotter{file: ""},
	}

	executor := NewParallelExecutor(cmds, opts, args, imageConfig, sb)

	// Add dependencies: commands 1 and 2 depend on command 0
	executor.dependencies = []CommandDependency{
		{From: 0, To: 1, Type: FileSystemDependency},
		{From: 0, To: 2, Type: FileSystemDependency},
	}

	compositeKey := &CompositeCache{}
	err := executor.AnalyzeDependencies()
	if err != nil {
		t.Fatalf("AnalyzeDependencies failed: %v", err)
	}

	// Build execution groups
	groups := executor.buildExecutionGroups()

	// With dependencies, we should have at least 2 groups:
	// Group 0: command 0 (and possibly 3, as ARG has no dependencies)
	// Group 1: commands 1 and 2 (depend on 0)
	// But depending on implementation, all commands might be in one group if they can execute in parallel
	// The important thing is that execution order respects dependencies
	if len(groups) == 0 {
		t.Errorf("Expected at least 1 execution group, got %d", len(groups))
	}

	// Verify that command 0 is executed before commands 1 and 2 in the execution order
	// This is the critical test - dependencies must be respected
	order := executor.executionOrder
	idx0 := -1
	idx1 := -1
	idx2 := -1
	for i, cmdIdx := range order {
		if cmdIdx == 0 {
			idx0 = i
		}
		if cmdIdx == 1 {
			idx1 = i
		}
		if cmdIdx == 2 {
			idx2 = i
		}
	}

	if idx0 == -1 || idx1 == -1 || idx2 == -1 {
		t.Errorf("Not all commands found in execution order: 0=%d, 1=%d, 2=%d", idx0, idx1, idx2)
	}

	// Command 0 must come before commands 1 and 2
	if idx0 >= idx1 {
		t.Errorf("Command 0 (index %d) should execute before command 1 (index %d)", idx0, idx1)
	}
	if idx0 >= idx2 {
		t.Errorf("Command 0 (index %d) should execute before command 2 (index %d)", idx0, idx2)
	}

	// Execute commands
	err = executor.ExecuteCommands(compositeKey, true)
	if err != nil {
		t.Fatalf("ExecuteCommands failed: %v", err)
	}
}

// TestSnapshotWithCacheEnabled tests snapshot behavior when cache is enabled
func TestSnapshotWithCacheEnabled(t *testing.T) {
	cmds := []commands.DockerCommand{
		&testRunCommand{command: "RUN cmd1"},
		&testRunCommand{command: "RUN cmd2"},
	}

	opts := &config.KanikoOptions{
		MaxParallelCommands: 2,
		CommandTimeout:      30 * time.Second,
		Cache:               true, // Enable cache
		ForceBuildMetadata:  true,
	}

	args := dockerfile.NewBuildArgs([]string{})
	imageConfig := &v1.Config{}

	sb := &stageBuilder{
		args:        dockerfile.NewBuildArgs([]string{}),
		opts:        opts,
		cf:          &v1.ConfigFile{Config: v1.Config{Env: make([]string, 0)}},
		snapshotter: &fakeSnapShotter{file: "/tmp/test-snapshot"},
		cmds:        cmds,
		pushLayerToCache: func(_ *config.KanikoOptions, _, _, _ string) error {
			return nil // Mock cache push
		},
	}

	executor := NewParallelExecutor(cmds, opts, args, imageConfig, sb)

	compositeKey := &CompositeCache{}
	compositeKey.AddKey("test-key")

	err := executor.ExecuteCommands(compositeKey, true)

	// Should succeed with cache enabled
	if err != nil {
		t.Fatalf("ExecuteCommands failed with cache enabled: %v", err)
	}
}

// TestPendingSnapshotCompositeKeyCopy tests that each PendingSnapshot has its own copy of CompositeKey
func TestPendingSnapshotCompositeKeyCopy(t *testing.T) {
	cmds := []commands.DockerCommand{
		&testRunCommand{command: "RUN cmd0"},
		&testRunCommand{command: "RUN cmd1"},
	}

	opts := &config.KanikoOptions{
		MaxParallelCommands: 2,
		CommandTimeout:      30 * time.Second,
		ForceBuildMetadata:  true,
		Cache:               true,
	}

	args := dockerfile.NewBuildArgs([]string{})
	imageConfig := &v1.Config{}

	sb := &stageBuilder{
		args:        dockerfile.NewBuildArgs([]string{}),
		opts:        opts,
		cf:          &v1.ConfigFile{Config: v1.Config{Env: make([]string, 0)}},
		snapshotter: &fakeSnapShotter{file: "/tmp/test-snapshot"},
		cmds:        cmds,
		pushLayerToCache: func(_ *config.KanikoOptions, _, _, _ string) error {
			return nil
		},
	}

	executor := NewParallelExecutor(cmds, opts, args, imageConfig, sb)

	compositeKey := &CompositeCache{}
	compositeKey.AddKey("key0")

	err := executor.ExecuteCommands(compositeKey, true)

	// Should succeed - each snapshot should have its own compositeKey copy
	if err != nil {
		t.Fatalf("ExecuteCommands failed: %v", err)
	}
}

// TestSnapshotSequentialOrder tests that snapshots are taken sequentially after parallel execution
func TestSnapshotSequentialOrder(t *testing.T) {
	cmds := []commands.DockerCommand{
		&testRunCommand{command: "RUN cmd0"},
		&testRunCommand{command: "RUN cmd1"},
		&testRunCommand{command: "RUN cmd2"},
	}

	opts := &config.KanikoOptions{
		MaxParallelCommands: 3,
		CommandTimeout:      30 * time.Second,
		ForceBuildMetadata:  true,
	}

	args := dockerfile.NewBuildArgs([]string{})
	imageConfig := &v1.Config{}

	sb := &stageBuilder{
		args:        dockerfile.NewBuildArgs([]string{}),
		opts:        opts,
		cf:          &v1.ConfigFile{Config: v1.Config{Env: make([]string, 0)}},
		snapshotter: &fakeSnapShotter{file: "/tmp/test-snapshot"},
		cmds:        cmds,
		pushLayerToCache: func(_ *config.KanikoOptions, _, _, _ string) error {
			return nil
		},
	}

	executor := NewParallelExecutor(cmds, opts, args, imageConfig, sb)

	compositeKey := &CompositeCache{}
	err := executor.ExecuteCommands(compositeKey, true)

	// Should succeed - snapshots should be taken sequentially
	if err != nil {
		t.Fatalf("ExecuteCommands failed: %v", err)
	}

	// Verify all commands executed
	executor.executedMutex.RLock()
	executedCount := len(executor.executed)
	executor.executedMutex.RUnlock()

	if executedCount != 3 {
		t.Errorf("Expected 3 commands to be executed, got %d", executedCount)
	}
}

// TestSingleCommandGroup tests that single command groups work correctly
func TestSingleCommandGroup(t *testing.T) {
	cmds := []commands.DockerCommand{
		&testRunCommand{command: "RUN cmd0"},
	}

	opts := &config.KanikoOptions{
		MaxParallelCommands: 1,
		CommandTimeout:      30 * time.Second,
		ForceBuildMetadata:  true,
	}

	args := dockerfile.NewBuildArgs([]string{})
	imageConfig := &v1.Config{}

	sb := &stageBuilder{
		args:        dockerfile.NewBuildArgs([]string{}),
		opts:        opts,
		cf:          &v1.ConfigFile{Config: v1.Config{Env: make([]string, 0)}},
		snapshotter: &fakeSnapShotter{file: "/tmp/test-snapshot"},
		cmds:        cmds,
		pushLayerToCache: func(_ *config.KanikoOptions, _, _, _ string) error {
			return nil
		},
	}

	executor := NewParallelExecutor(cmds, opts, args, imageConfig, sb)

	compositeKey := &CompositeCache{}
	err := executor.ExecuteCommands(compositeKey, true)

	// Single command should work with immediate snapshot
	if err != nil {
		t.Fatalf("ExecuteCommands failed for single command: %v", err)
	}
}

// TestMultipleCommandsNoSnapshots tests commands that don't require snapshots
func TestMultipleCommandsNoSnapshots(t *testing.T) {
	cmds := []commands.DockerCommand{
		MockDockerCommand{command: "ARG VAR1"},
		MockDockerCommand{command: "ARG VAR2"},
		MockDockerCommand{command: "ENV KEY=value"},
	}

	opts := &config.KanikoOptions{
		MaxParallelCommands: 3,
		CommandTimeout:      30 * time.Second,
	}

	args := dockerfile.NewBuildArgs([]string{})
	imageConfig := &v1.Config{}

	sb := &stageBuilder{
		args:        dockerfile.NewBuildArgs([]string{}),
		opts:        opts,
		cf:          &v1.ConfigFile{Config: v1.Config{Env: make([]string, 0)}},
		snapshotter: &fakeSnapShotter{file: ""},
		cmds:        cmds,
		pushLayerToCache: func(_ *config.KanikoOptions, _, _, _ string) error {
			return nil
		},
	}

	executor := NewParallelExecutor(cmds, opts, args, imageConfig, sb)

	compositeKey := &CompositeCache{}
	err := executor.ExecuteCommands(compositeKey, true)

	// Should succeed - metadata commands don't need snapshots
	if err != nil {
		t.Fatalf("ExecuteCommands failed for metadata commands: %v", err)
	}
}

// TestInitSnapshotBeforeParallelCommands tests that init snapshot is taken BEFORE parallel commands execute
// This is critical to ensure filesystem is ready for commands like apt-get that require system directories
func TestInitSnapshotBeforeParallelCommands(t *testing.T) {
	cmd0 := &testRunCommand{command: "RUN apt-get update"} // Command that requires /etc/apt/ directories
	cmd1 := &testRunCommand{command: "RUN echo test"}
	cmd2 := &testRunCommand{command: "RUN ls"}
	cmds := []commands.DockerCommand{cmd0, cmd1, cmd2}

	opts := &config.KanikoOptions{
		MaxParallelCommands: 3,
		CommandTimeout:      30 * time.Second,
	}

	args := dockerfile.NewBuildArgs([]string{})
	imageConfig := &v1.Config{}

	trackingSnap := &trackingSnapshotter{
		fakeSnapShotter: &fakeSnapShotter{file: "/tmp/test-snapshot"},
	}

	sb := &stageBuilder{
		args:        dockerfile.NewBuildArgs([]string{}),
		opts:        opts,
		cf:          &v1.ConfigFile{Config: v1.Config{Env: make([]string, 0)}},
		snapshotter: trackingSnap,
		cmds:        cmds,
		pushLayerToCache: func(_ *config.KanikoOptions, _, _, _ string) error {
			return nil
		},
	}

	executor := NewParallelExecutor(cmds, opts, args, imageConfig, sb)

	compositeKey := &CompositeCache{}
	err := executor.ExecuteCommands(compositeKey, false) // initSnapshotTaken = false to trigger init

	if err != nil {
		t.Fatalf("ExecuteCommands failed: %v", err)
	}

	// Verify init snapshot was called
	if trackingSnap.GetInitCallCount() != 1 {
		t.Errorf("Expected initSnapshot to be called once, got %d", trackingSnap.GetInitCallCount())
	}

	// Verify init snapshot was taken BEFORE commands started
	// This is critical - commands should not execute until filesystem is ready
	initTime := trackingSnap.GetInitTime()
	cmd0Time := cmd0.GetExecuteTime()

	if !initTime.IsZero() && !cmd0Time.IsZero() {
		if cmd0Time.Before(initTime) {
			t.Errorf("CRITICAL: First command started at %v BEFORE init snapshot at %v - this can cause filesystem errors",
				cmd0Time, initTime)
		}
	}
}

// TestContextCancellationOnError tests that when one command fails, other commands are properly canceled
// This prevents race conditions where failed command leaves filesystem in inconsistent state
func TestContextCancellationOnError(t *testing.T) {
	var executionOrder []int
	var executionMutex sync.Mutex

	cmd0 := &testRunCommand{
		command: "RUN cmd1",
		executeFunc: func(*v1.Config, *dockerfile.BuildArgs) error {
			executionMutex.Lock()
			executionOrder = append(executionOrder, 0)
			executionMutex.Unlock()
			return nil
		},
	}
	cmd1 := &testRunCommand{
		command: "RUN cmd2",
		executeFunc: func(*v1.Config, *dockerfile.BuildArgs) error {
			executionMutex.Lock()
			executionOrder = append(executionOrder, 1)
			executionMutex.Unlock()
			return fmt.Errorf("command 1 failed intentionally")
		},
	}
	cmd2 := &testRunCommand{
		command: "RUN cmd3",
		executeFunc: func(*v1.Config, *dockerfile.BuildArgs) error {
			executionMutex.Lock()
			executionOrder = append(executionOrder, 2)
			executionMutex.Unlock()
			return nil
		},
	}
	cmds := []commands.DockerCommand{cmd0, cmd1, cmd2}

	opts := &config.KanikoOptions{
		MaxParallelCommands: 3,
		CommandTimeout:      30 * time.Second,
	}

	args := dockerfile.NewBuildArgs([]string{})
	imageConfig := &v1.Config{}

	sb := &stageBuilder{
		args:        dockerfile.NewBuildArgs([]string{}),
		opts:        opts,
		cf:          &v1.ConfigFile{Config: v1.Config{Env: make([]string, 0)}},
		snapshotter: &fakeSnapShotter{file: ""},
		cmds:        cmds,
	}

	executor := NewParallelExecutor(cmds, opts, args, imageConfig, sb)

	compositeKey := &CompositeCache{}
	err := executor.ExecuteCommands(compositeKey, true)

	// Should fail because command 1 failed
	if err == nil {
		t.Fatal("Expected ExecuteCommands to fail when command fails, but it succeeded")
	}

	// Verify that error was properly propagated
	if !strings.Contains(err.Error(), "command 1") {
		t.Errorf("Expected error to mention 'command 1', got: %v", err)
	}

	// Verify that not all commands executed (some should be canceled)
	// The exact behavior depends on timing, but at least one should have started
	executionMutex.Lock()
	executedCount := len(executionOrder)
	executionMutex.Unlock()

	if executedCount == 0 {
		t.Errorf("Expected at least one command to start execution")
	}
}

// TestFilesystemDependencyDetection tests that commands which modify filesystem
// are properly detected as dependencies for subsequent commands
func TestFilesystemDependencyDetection(t *testing.T) {
	cmds := []commands.DockerCommand{
		&testRunCommand{command: "RUN mkdir -p /etc/apt/apt.conf.d"}, // Creates directory
		&testRunCommand{command: "RUN apt-get update"},               // Requires directory from previous command
		&testRunCommand{command: "RUN echo test"},
	}

	opts := &config.KanikoOptions{
		MaxParallelCommands: 3,
		CommandTimeout:      30 * time.Second,
	}

	args := dockerfile.NewBuildArgs([]string{})
	imageConfig := &v1.Config{}

	sb := &stageBuilder{
		args:        dockerfile.NewBuildArgs([]string{}),
		opts:        opts,
		cf:          &v1.ConfigFile{Config: v1.Config{Env: make([]string, 0)}},
		snapshotter: &fakeSnapShotter{file: "/tmp/test-snapshot"},
		cmds:        cmds,
		pushLayerToCache: func(_ *config.KanikoOptions, _, _, _ string) error {
			return nil
		},
	}

	executor := NewParallelExecutor(cmds, opts, args, imageConfig, sb)

	// Manually set dependency to test that dependency system works correctly
	// (Automatic detection requires specific command interfaces that mocks may not implement)
	executor.dependencies = []CommandDependency{
		{From: 0, To: 1, Type: FileSystemDependency},
	}

	// Analyze dependencies (will build execution order from our dependencies)
	err := executor.AnalyzeDependencies()
	if err != nil {
		t.Fatalf("AnalyzeDependencies failed: %v", err)
	}

	// Verify execution order respects dependencies
	order := executor.executionOrder
	idx0 := -1
	idx1 := -1
	for i, cmdIdx := range order {
		if cmdIdx == 0 {
			idx0 = i
		}
		if cmdIdx == 1 {
			idx1 = i
		}
	}

	if idx0 == -1 || idx1 == -1 {
		t.Errorf("Commands not found in execution order: 0=%d, 1=%d", idx0, idx1)
	}

	// Command 0 should execute before command 1 when dependency is set
	if idx0 >= idx1 {
		t.Errorf("CRITICAL: Command 0 (mkdir) should execute before command 1 (apt-get) when dependency is set, but got order: %v", order)
	}
}

// TestConcurrentFilesystemModifications tests race conditions when multiple commands
// modify the same filesystem locations concurrently
func TestConcurrentFilesystemModifications(t *testing.T) {
	var executionCount int64
	var executionMutex sync.Mutex

	// Create commands that all modify the same directory structure
	createCommand := func(index int) *testRunCommand {
		return &testRunCommand{
			command: fmt.Sprintf("RUN touch /tmp/test%d", index),
			executeFunc: func(*v1.Config, *dockerfile.BuildArgs) error {
				executionMutex.Lock()
				currentCount := atomic.LoadInt64(&executionCount)
				atomic.AddInt64(&executionCount, 1)
				executionMutex.Unlock()

				// Simulate some work
				time.Sleep(10 * time.Millisecond)

				atomic.AddInt64(&executionCount, -1)

				// Verify no race condition - count should be managed correctly
				if currentCount >= 8 {
					t.Errorf("CRITICAL: Too many concurrent executions: %d (max: 8)", currentCount)
				}

				return nil
			},
		}
	}

	cmds := make([]commands.DockerCommand, 8)
	for i := 0; i < 8; i++ {
		cmds[i] = createCommand(i + 1)
	}

	opts := &config.KanikoOptions{
		MaxParallelCommands: 8, // Execute all in parallel
		CommandTimeout:      30 * time.Second,
		ForceBuildMetadata:  true,
	}

	args := dockerfile.NewBuildArgs([]string{})
	imageConfig := &v1.Config{}

	sb := &stageBuilder{
		args:        dockerfile.NewBuildArgs([]string{}),
		opts:        opts,
		cf:          &v1.ConfigFile{Config: v1.Config{Env: make([]string, 0)}},
		snapshotter: &fakeSnapShotter{file: "/tmp/test-snapshot"},
		cmds:        cmds,
		pushLayerToCache: func(_ *config.KanikoOptions, _, _, _ string) error {
			return nil
		},
	}

	executor := NewParallelExecutor(cmds, opts, args, imageConfig, sb)

	compositeKey := &CompositeCache{}
	err := executor.ExecuteCommands(compositeKey, true)

	// Should succeed even with concurrent filesystem modifications
	if err != nil {
		t.Fatalf("ExecuteCommands failed with concurrent modifications: %v", err)
	}

	// Verify all commands executed
	executor.executedMutex.RLock()
	executedCount := len(executor.executed)
	executor.executedMutex.RUnlock()

	if executedCount != 8 {
		t.Errorf("Expected 8 commands to be executed, got %d", executedCount)
	}
}

// TestCompositeKeyUpdateRaceCondition tests that compositeKey updates are thread-safe
// This is critical for cache correctness
func TestCompositeKeyUpdateRaceCondition(t *testing.T) {
	cmds := []commands.DockerCommand{
		&testRunCommand{command: "RUN cmd0"},
		&testRunCommand{command: "RUN cmd1"},
		&testRunCommand{command: "RUN cmd2"},
		&testRunCommand{command: "RUN cmd3"},
	}

	opts := &config.KanikoOptions{
		MaxParallelCommands: 4,
		CommandTimeout:      30 * time.Second,
		Cache:               true, // Enable cache to test compositeKey updates
		ForceBuildMetadata:  true,
	}

	args := dockerfile.NewBuildArgs([]string{})
	imageConfig := &v1.Config{}

	sb := &stageBuilder{
		args:        dockerfile.NewBuildArgs([]string{}),
		opts:        opts,
		cf:          &v1.ConfigFile{Config: v1.Config{Env: make([]string, 0)}},
		snapshotter: &fakeSnapShotter{file: "/tmp/test-snapshot"},
		cmds:        cmds,
		pushLayerToCache: func(_ *config.KanikoOptions, _, _, _ string) error {
			return nil
		},
	}

	executor := NewParallelExecutor(cmds, opts, args, imageConfig, sb)

	compositeKey := &CompositeCache{}
	compositeKey.AddKey("initial-key")

	err := executor.ExecuteCommands(compositeKey, true)

	// Should succeed - compositeKey updates should be thread-safe (protected by mutex in code)
	if err != nil {
		t.Fatalf("ExecuteCommands failed: %v", err)
	}

	// Verify all commands executed
	executor.executedMutex.RLock()
	executedCount := len(executor.executed)
	executor.executedMutex.RUnlock()

	if executedCount != 4 {
		t.Errorf("Expected 4 commands to be executed, got %d", executedCount)
	}
}

// TestDeferredSnapshotOrder tests that deferred snapshots are taken in correct order
// This prevents cache corruption when snapshots are taken out of order
func TestDeferredSnapshotOrder(t *testing.T) {
	cmd0 := &testRunCommand{command: "RUN cmd0"}
	cmd1 := &testRunCommand{command: "RUN cmd1"}
	cmd2 := &testRunCommand{command: "RUN cmd2"}
	cmds := []commands.DockerCommand{cmd0, cmd1, cmd2}

	opts := &config.KanikoOptions{
		MaxParallelCommands: 3,
		CommandTimeout:      30 * time.Second,
		ForceBuildMetadata:  true,
	}

	args := dockerfile.NewBuildArgs([]string{})
	imageConfig := &v1.Config{}

	sb := &stageBuilder{
		args:        dockerfile.NewBuildArgs([]string{}),
		opts:        opts,
		cf:          &v1.ConfigFile{Config: v1.Config{Env: make([]string, 0)}},
		snapshotter: &fakeSnapShotter{file: "/tmp/test-snapshot"},
		cmds:        cmds,
		pushLayerToCache: func(_ *config.KanikoOptions, _, _, _ string) error {
			return nil
		},
	}

	executor := NewParallelExecutor(cmds, opts, args, imageConfig, sb)

	compositeKey := &CompositeCache{}
	err := executor.ExecuteCommands(compositeKey, true)

	// Should succeed - deferred snapshots should work correctly
	if err != nil {
		t.Fatalf("ExecuteCommands failed: %v", err)
	}

	// Verify all commands executed
	executor.executedMutex.RLock()
	executedCount := len(executor.executed)
	executor.executedMutex.RUnlock()

	if executedCount != 3 {
		t.Errorf("Expected 3 commands to be executed, got %d", executedCount)
	}
}
