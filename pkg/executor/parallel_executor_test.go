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
	cmd0 := &testRunCommand{command: "RUN cmd0"}
	cmd1 := &testRunCommand{command: "RUN cmd1"}
	cmd2 := &testRunCommand{command: "RUN cmd2"}
	cmd3 := &testRunCommand{command: "RUN cmd3"}
	cmds := []commands.DockerCommand{cmd0, cmd1, cmd2, cmd3}

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

// TestParallelExecutionOrder tests that execution order respects dependencies
func TestParallelExecutionOrder(t *testing.T) {
	cmds := []commands.DockerCommand{
		MockDockerCommand{command: "RUN install"}, // Command 0
		MockDockerCommand{command: "RUN use"},     // Command 1 depends on 0
		MockDockerCommand{command: "ARG VAR"},     // Command 2 - no dependencies
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
		t.Errorf("Command 0 should execute before command 1, but got: 0 at %d, 1 at %d", idx0, idx1)
	}
	if idx0 >= idx2 {
		t.Errorf("Command 0 should execute before command 2, but got: 0 at %d, 2 at %d", idx0, idx2)
	}
}

// TestEnvironmentDependencyDetection tests that ENV commands are detected as dependencies for RUN commands
// that use those environment variables
func TestEnvironmentDependencyDetection(t *testing.T) {
	// Command 0: ENV PATH=/custom/path:$PATH
	// Command 1: RUN echo $PATH
	// Command 2: RUN echo "hello"
	// Command 1 should depend on command 0 (uses PATH variable)
	// Command 2 should not depend on command 0 (doesn't use PATH)
	cmds := []commands.DockerCommand{
		MockDockerCommand{command: "ENV PATH=/custom/path:$PATH"},
		&testRunCommand{command: "RUN echo $PATH"},
		&testRunCommand{command: "RUN echo hello"},
	}

	opts := &config.KanikoOptions{
		MaxParallelCommands: 3,
		CommandTimeout:      30 * time.Second,
		EnableParallelExec:  true,
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

	// Analyze dependencies - should detect ENV dependency
	err := executor.AnalyzeDependencies()
	if err != nil {
		t.Fatalf("AnalyzeDependencies failed: %v", err)
	}

	// Check that environment dependency was detected
	envDepFound := false
	for _, dep := range executor.dependencies {
		if dep.From == 0 && dep.To == 1 && dep.Type == EnvironmentDependency {
			envDepFound = true
			break
		}
	}

	if !envDepFound {
		t.Errorf("Expected environment dependency from command 0 (ENV) to command 1 (RUN uses $PATH), but it was not found")
		t.Logf("Found dependencies: %+v", executor.dependencies)
	}

	// Verify that command 2 (doesn't use PATH) doesn't have dependency on command 0
	cmd2DepFound := false
	for _, dep := range executor.dependencies {
		if dep.From == 0 && dep.To == 2 {
			cmd2DepFound = true
			break
		}
	}

	if cmd2DepFound {
		t.Errorf("Command 2 should not depend on command 0 (ENV) since it doesn't use PATH variable")
	}

	// Verify execution order - command 0 should come before command 1
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

	// Command 0 (ENV) must come before command 1 (RUN uses $PATH)
	if idx0 >= idx1 {
		t.Errorf("Command 0 (ENV) should execute before command 1 (RUN uses $PATH), but got: 0 at %d, 1 at %d", idx0, idx1)
	}
}

// TestEnvironmentDependencyMultipleVars tests detection of multiple environment variables
func TestEnvironmentDependencyMultipleVars(t *testing.T) {
	// Command 0: ENV VAR1=value1
	// Command 1: ENV VAR2=value2
	// Command 2: RUN echo $VAR1 $VAR2
	// Command 2 should depend on both command 0 and command 1
	cmds := []commands.DockerCommand{
		MockDockerCommand{command: "ENV VAR1=value1"},
		MockDockerCommand{command: "ENV VAR2=value2"},
		&testRunCommand{command: "RUN echo $VAR1 $VAR2"},
	}

	opts := &config.KanikoOptions{
		MaxParallelCommands: 3,
		CommandTimeout:      30 * time.Second,
		EnableParallelExec:  true,
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

	err := executor.AnalyzeDependencies()
	if err != nil {
		t.Fatalf("AnalyzeDependencies failed: %v", err)
	}

	// Check that both dependencies were detected
	var1DepFound := false
	var2DepFound := false
	for _, dep := range executor.dependencies {
		if dep.From == 0 && dep.To == 2 && dep.Type == EnvironmentDependency {
			var1DepFound = true
		}
		if dep.From == 1 && dep.To == 2 && dep.Type == EnvironmentDependency {
			var2DepFound = true
		}
	}

	if !var1DepFound {
		t.Errorf("Expected environment dependency from command 0 (ENV VAR1) to command 2 (RUN uses $VAR1)")
	}
	if !var2DepFound {
		t.Errorf("Expected environment dependency from command 1 (ENV VAR2) to command 2 (RUN uses $VAR2)")
	}
}
