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
	"runtime"
	"sort"
	"sync"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/Gosayram/kaniko/pkg/commands"
	"github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/dockerfile"
	"github.com/Gosayram/kaniko/pkg/logging"
)

// CommandDependency represents a dependency between commands
type CommandDependency struct {
	From int // Source command index
	To   int // Target command index
	Type DependencyType
}

// DependencyType defines the type of dependency between commands
type DependencyType int

const (
	// FileSystemDependency - command depends on filesystem changes from another command
	FileSystemDependency DependencyType = iota
	// EnvironmentDependency - command depends on environment variables from another command
	EnvironmentDependency
	// MetadataDependency - command depends on metadata changes from another command
	MetadataDependency
	// CacheDependency - command depends on cache state from another command
	CacheDependency
)

// ParallelExecutor handles parallel execution of Docker commands with dependency analysis
type ParallelExecutor struct {
	commands     []commands.DockerCommand
	dependencies []CommandDependency
	config       *config.KanikoOptions
	args         *dockerfile.BuildArgs
	imageConfig  *v1.Config
	stageBuilder *stageBuilder

	// Worker pool configuration
	maxWorkers int
	workerPool chan struct{}

	// Execution state
	executionOrder []int
	executed       map[int]bool
	executedMutex  sync.RWMutex

	// Performance monitoring
	executionStats map[int]*CommandExecutionStats
	statsMutex     sync.RWMutex

	// Init snapshot state - ensures init snapshot is taken only once
	initSnapshotOnce     sync.Once
	initSnapshotErr      error
	initSnapshotDone     chan struct{} // Channel to signal when init snapshot is complete
	initSnapshotDoneOnce sync.Once     // Ensure channel is closed only once
}

// CommandExecutionStats tracks execution statistics for a command
type CommandExecutionStats struct {
	StartTime    time.Time
	EndTime      time.Time
	Duration     time.Duration
	Success      bool
	ErrorMessage string
	WorkerID     int
}

// NewParallelExecutor creates a new parallel executor
func NewParallelExecutor(
	cmds []commands.DockerCommand,
	opts *config.KanikoOptions,
	args *dockerfile.BuildArgs,
	imageConfig *v1.Config,
	sb *stageBuilder,
) *ParallelExecutor {
	maxWorkers := opts.MaxParallelCommands
	if maxWorkers <= 0 {
		maxWorkers = runtime.NumCPU()
	}

	return &ParallelExecutor{
		commands:         cmds,
		config:           opts,
		args:             args,
		imageConfig:      imageConfig,
		stageBuilder:     sb,
		maxWorkers:       maxWorkers,
		workerPool:       make(chan struct{}, maxWorkers),
		executed:         make(map[int]bool),
		executionStats:   make(map[int]*CommandExecutionStats),
		initSnapshotDone: make(chan struct{}),
	}
}

// AnalyzeDependencies analyzes command dependencies to determine execution order
func (pe *ParallelExecutor) AnalyzeDependencies() error {
	logrus.Info("🔍 Analyzing command dependencies for parallel execution")

	dependencies := make([]CommandDependency, 0)

	for i, cmd := range pe.commands {
		if cmd == nil {
			continue
		}

		// Analyze dependencies for this command
		cmdDeps := pe.analyzeCommandDependencies(i, cmd)
		dependencies = append(dependencies, cmdDeps...)
	}

	pe.dependencies = dependencies

	// Build execution order based on dependencies
	executionOrder := pe.buildExecutionOrder()

	pe.executionOrder = executionOrder

	logrus.Infof("📊 Found %d dependencies, execution order: %v", len(dependencies), executionOrder)
	return nil
}

// analyzeCommandDependencies analyzes dependencies for a specific command
func (pe *ParallelExecutor) analyzeCommandDependencies(index int, cmd commands.DockerCommand) []CommandDependency {
	dependencies := make([]CommandDependency, 0)

	// Check for filesystem dependencies
	if pe.hasFilesystemDependency(index, cmd) {
		// Find the last command that modifies filesystem
		for i := index - 1; i >= 0; i-- {
			if pe.commands[i] != nil && !pe.commands[i].MetadataOnly() {
				dependencies = append(dependencies, CommandDependency{
					From: i,
					To:   index,
					Type: FileSystemDependency,
				})
				break
			}
		}
	}

	// Check for environment dependencies
	if pe.hasEnvironmentDependency(index, cmd) {
		// Find the last command that modifies environment
		for i := index - 1; i >= 0; i-- {
			if pe.commands[i] != nil && pe.commands[i].MetadataOnly() {
				// Check if it's an environment-related command
				if pe.isEnvironmentCommand(pe.commands[i]) {
					dependencies = append(dependencies, CommandDependency{
						From: i,
						To:   index,
						Type: EnvironmentDependency,
					})
					break
				}
			}
		}
	}

	return dependencies
}

// hasFilesystemDependency checks if a command depends on filesystem changes
func (pe *ParallelExecutor) hasFilesystemDependency(_ int, cmd commands.DockerCommand) bool {
	// Commands that read from filesystem depend on previous filesystem changes
	return !cmd.MetadataOnly() && cmd.RequiresUnpackedFS()
}

// hasEnvironmentDependency checks if a command depends on environment variables
func (pe *ParallelExecutor) hasEnvironmentDependency(_ int, cmd commands.DockerCommand) bool {
	// RUN commands typically depend on environment variables
	return !cmd.MetadataOnly() && cmd.RequiresUnpackedFS()
}

// isEnvironmentCommand checks if a command modifies environment
func (pe *ParallelExecutor) isEnvironmentCommand(cmd commands.DockerCommand) bool {
	// This would need to be implemented based on command type
	// For now, assume metadata commands can affect environment
	return cmd.MetadataOnly()
}

// buildExecutionOrder builds the execution order based on dependencies
// Uses Kahn's algorithm for topological sorting
func (pe *ParallelExecutor) buildExecutionOrder() []int {
	// Build dependency graph: for each command, track how many dependencies it has
	inDegree := make(map[int]int)
	// Build reverse graph: for each command, track which commands depend on it
	dependsOnMe := make(map[int][]int)

	// Initialize inDegree for all commands
	for i := range pe.commands {
		if pe.commands[i] != nil {
			inDegree[i] = 0
		}
	}

	// Build dependency graph
	for _, dep := range pe.dependencies {
		// Command dep.To depends on dep.From, so increment inDegree
		inDegree[dep.To]++
		dependsOnMe[dep.From] = append(dependsOnMe[dep.From], dep.To)
	}

	// Kahn's algorithm: start with commands that have no dependencies
	// Use a sorted slice to ensure stable execution order (commands execute in index order when no dependencies)
	queue := make([]int, 0)
	for i, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, i)
		}
	}
	// Sort queue to ensure stable execution order (earlier commands execute first when no dependencies)
	// This ensures that RUN commands that install tools come before commands that use them
	sort.Ints(queue)

	order := make([]int, 0, len(pe.commands))

	// Process commands in topological order
	for len(queue) > 0 {
		// Get next command with no dependencies (always the smallest index due to sorting)
		current := queue[0]
		queue = queue[1:]
		order = append(order, current)

		// Decrease inDegree for commands that depend on current
		for _, dependent := range dependsOnMe[current] {
			inDegree[dependent]--
			if inDegree[dependent] == 0 {
				queue = append(queue, dependent)
			}
		}
		// Keep queue sorted to ensure stable execution order
		// Commands with smaller indices execute first when dependencies allow
		sort.Ints(queue)
	}

	// Add any remaining commands (shouldn't happen in a valid DAG, but handle gracefully)
	for i, cmd := range pe.commands {
		if cmd == nil {
			continue
		}
		found := false
		for _, idx := range order {
			if idx == i {
				found = true
				break
			}
		}
		if !found {
			logrus.Warnf("Command %d has circular dependency or wasn't processed, adding at end", i)
			order = append(order, i)
		}
	}

	return order
}

// ExecuteCommands executes commands in parallel with dependency resolution
func (pe *ParallelExecutor) ExecuteCommands(compositeKey *CompositeCache, initSnapshotTaken bool) error {
	logrus.Info("🚀 Starting parallel command execution")

	// CRITICAL: If init snapshot was already taken, close the channel immediately
	// to prevent any blocking when commands check for init snapshot
	if initSnapshotTaken {
		pe.initSnapshotDoneOnce.Do(func() {
			close(pe.initSnapshotDone)
		})
	}

	// Analyze dependencies if not already done
	if len(pe.executionOrder) == 0 {
		if err := pe.AnalyzeDependencies(); err != nil {
			return fmt.Errorf("failed to analyze dependencies: %w", err)
		}
	}

	// Create execution groups based on dependencies
	executionGroups := pe.buildExecutionGroups()

	// Execute each group in parallel
	for groupIndex, group := range executionGroups {
		logrus.Infof("📦 Executing group %d with %d commands", groupIndex, len(group))

		if err := pe.executeGroup(group, compositeKey, initSnapshotTaken); err != nil {
			return fmt.Errorf("failed to execute group %d: %w", groupIndex, err)
		}
	}

	// Log execution statistics
	pe.logExecutionStats()

	logrus.Info("✅ Parallel command execution completed")
	return nil
}

// buildExecutionGroups builds groups of commands that can be executed in parallel
func (pe *ParallelExecutor) buildExecutionGroups() [][]int {
	groups := make([][]int, 0)
	executed := make(map[int]bool)

	for _, cmdIndex := range pe.executionOrder {
		if executed[cmdIndex] {
			continue
		}

		// Find all commands that can be executed in parallel with this one
		group := pe.findParallelGroup(cmdIndex, executed)
		groups = append(groups, group)

		// Mark all commands in this group as executed
		for _, cmdIdx := range group {
			executed[cmdIdx] = true
		}
	}

	return groups
}

// findParallelGroup finds commands that can be executed in parallel
// Only includes commands whose ALL dependencies are already executed
func (pe *ParallelExecutor) findParallelGroup(startIndex int, executed map[int]bool) []int {
	group := []int{startIndex}

	// Find commands that can be executed in parallel with startIndex
	// A command can be added if:
	// 1. It's not already executed
	// 2. ALL its dependencies are already executed
	// 3. It doesn't conflict with other commands in the group
	for i, cmd := range pe.commands {
		if cmd == nil || executed[i] || i == startIndex {
			continue
		}

		// Check if ALL dependencies of this command are executed
		allDepsExecuted := true
		for _, dep := range pe.dependencies {
			if dep.To == i && !executed[dep.From] {
				allDepsExecuted = false
				break
			}
		}

		if !allDepsExecuted {
			continue
		}

		// Check if this command can be executed in parallel with startIndex
		if pe.canExecuteInParallel(startIndex, i) {
			// Also check it can be executed in parallel with all commands in the group
			canAdd := true
			for _, groupIdx := range group {
				if !pe.canExecuteInParallel(groupIdx, i) {
					canAdd = false
					break
				}
			}
			if canAdd {
				group = append(group, i)
			}
		}
	}

	return group
}

// canExecuteInParallel checks if two commands can be executed in parallel
func (pe *ParallelExecutor) canExecuteInParallel(cmd1Index, cmd2Index int) bool {
	// Check if cmd2 depends on cmd1
	for _, dep := range pe.dependencies {
		if dep.From == cmd1Index && dep.To == cmd2Index {
			return false
		}
	}

	// Check if cmd1 depends on cmd2
	for _, dep := range pe.dependencies {
		if dep.From == cmd2Index && dep.To == cmd1Index {
			return false
		}
	}

	return true
}

// PendingSnapshot represents a command that needs a snapshot after execution
type PendingSnapshot struct {
	Command      commands.DockerCommand
	Index        int
	Files        []string
	CompositeKey *CompositeCache // Shared compositeKey (updated during command execution)
}

// executeGroup executes a group of commands in parallel
// CRITICAL: Commands execute first, then snapshots are taken sequentially to avoid race conditions
func (pe *ParallelExecutor) executeGroup(group []int, compositeKey *CompositeCache, initSnapshotTaken bool) error {
	if len(group) == 1 {
		// Single command - execute directly with immediate snapshot
		ctx, cancel := context.WithTimeout(context.Background(), pe.config.CommandTimeout)
		defer cancel()
		return pe.executeCommand(ctx, group[0], compositeKey, initSnapshotTaken)
	}

	// Multiple commands - execute in parallel, then take snapshots sequentially
	// Use context to cancel other commands when one fails
	ctx, cancel := context.WithTimeout(context.Background(), pe.config.CommandTimeout)
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)

	// Track pending snapshots - commands that need snapshots after execution
	pendingSnapshots := make([]PendingSnapshot, 0, len(group))
	var snapshotMutex sync.Mutex

	for _, cmdIndex := range group {
		cmdIndex := cmdIndex // Capture for closure
		g.Go(func() error {
			// Check if context is canceled before executing
			select {
			case <-ctx.Done():
				logrus.Debugf("Command %d canceled due to context", cmdIndex)
				return ctx.Err()
			default:
				// Execute command WITHOUT snapshot (to avoid race conditions)
				// Snapshot will be taken after all commands complete
				err := pe.executeCommandWithoutSnapshot(
					ctx, cmdIndex, compositeKey, initSnapshotTaken,
					&pendingSnapshots, &snapshotMutex)
				// Check context again after execution (in case it was canceled during execution)
				select {
				case <-ctx.Done():
					logrus.Debugf("Command %d context canceled during/after execution", cmdIndex)
					if err == nil {
						return ctx.Err()
					}
				default:
				}
				return err
			}
		})
	}

	// Wait for all commands to complete
	if err := g.Wait(); err != nil {
		return err
	}

	// All commands completed successfully - now take snapshots sequentially
	// This prevents race conditions where snapshots are taken while commands are still running
	logrus.Debugf("📸 All commands in group completed, taking snapshots sequentially for %d commands",
		len(pendingSnapshots))

	// Sort snapshots by command index to ensure consistent order
	sort.Slice(pendingSnapshots, func(i, j int) bool {
		return pendingSnapshots[i].Index < pendingSnapshots[j].Index
	})

	cacheGroup := &errgroup.Group{}
	for _, pending := range pendingSnapshots {
		logrus.Debugf("📸 Taking snapshot for command %d: %s", pending.Index, pending.Command.String())
		if err := pe.stageBuilder.handleSnapshot(
			pending.Command, pending.Files, pending.CompositeKey, cacheGroup); err != nil {
			logrus.Errorf("Failed to take snapshot for command %d: %v", pending.Index, err)
			return errors.Wrapf(err, "failed to take snapshot for command %d", pending.Index)
		}
		logrus.Debugf("✅ Snapshot completed for command %d", pending.Index)
	}

	// Wait for cache operations to complete
	if err := cacheGroup.Wait(); err != nil {
		logrus.Warnf("Error in cache operations: %s", err)
		// Cache errors are non-fatal, but we should log them
	}

	return nil
}

// executeCommandWithoutSnapshot executes a command but defers snapshot to avoid race conditions
// It collects snapshot information for later sequential processing
func (pe *ParallelExecutor) executeCommandWithoutSnapshot(
	ctx context.Context,
	cmdIndex int,
	compositeKey *CompositeCache,
	initSnapshotTaken bool,
	pendingSnapshots *[]PendingSnapshot,
	snapshotMutex *sync.Mutex,
) error {
	cmd := pe.commands[cmdIndex]
	if cmd == nil {
		return nil
	}

	// Start timing
	stats := &CommandExecutionStats{
		StartTime: time.Now(),
		WorkerID:  len(pe.workerPool),
	}

	pe.statsMutex.Lock()
	pe.executionStats[cmdIndex] = stats
	pe.statsMutex.Unlock()

	logrus.Infof("🔄 Executing command %d: %s", cmdIndex, cmd.String())

	// Check context before executing command
	select {
	case <-ctx.Done():
		logrus.Debugf("Command %d canceled before execution", cmdIndex)
		return ctx.Err()
	default:
	}

	// Execute command WITHOUT snapshot (processCommand will be modified to skip snapshot)
	// We need to manually call the command execution logic
	err := pe.executeCommandOnly(ctx, cmdIndex, compositeKey, initSnapshotTaken)
	if err != nil {
		stats.EndTime = time.Now()
		stats.Duration = stats.EndTime.Sub(stats.StartTime)
		stats.Success = false
		stats.ErrorMessage = err.Error()
		pe.executedMutex.Lock()
		pe.executed[cmdIndex] = true
		pe.executedMutex.Unlock()
		logrus.Errorf("❌ Command %d failed: %v", cmdIndex, err)
		return fmt.Errorf("command %d (%s) failed: %w", cmdIndex, cmd.String(), err)
	}

	// Check context after execution
	select {
	case <-ctx.Done():
		logrus.Debugf("Command %d context canceled during execution", cmdIndex)
		return ctx.Err()
	default:
	}

	// Update statistics
	stats.EndTime = time.Now()
	stats.Duration = stats.EndTime.Sub(stats.StartTime)
	stats.Success = true

	pe.executedMutex.Lock()
	pe.executed[cmdIndex] = true
	pe.executedMutex.Unlock()

	// Collect snapshot information for later processing
	// Only if command needs a snapshot
	if pe.stageBuilder.shouldTakeSnapshot(cmdIndex, cmd.MetadataOnly()) || pe.config.ForceBuildMetadata {
		files := cmd.FilesToSnapshot()
		// Create a snapshot of compositeKey at this point for this specific command
		// This ensures each command gets the correct cache key state
		cmdCompositeKey := *compositeKey

		snapshotMutex.Lock()
		*pendingSnapshots = append(*pendingSnapshots, PendingSnapshot{
			Command:      cmd,
			Index:        cmdIndex,
			Files:        files,
			CompositeKey: &cmdCompositeKey, // Copy of compositeKey at this point in execution
		})
		snapshotMutex.Unlock()
	}

	logrus.Infof("✅ Command %d completed in %v (snapshot deferred)", cmdIndex, stats.Duration)
	return nil
}

// executeCommandOnly executes a command without taking snapshot
func (pe *ParallelExecutor) executeCommandOnly(
	_ context.Context, cmdIndex int, compositeKey *CompositeCache, initSnapshotTaken bool) error {
	cmd := pe.commands[cmdIndex]
	if cmd == nil {
		return nil
	}

	// Get files used from context (needed for cache key)
	pe.stageBuilder.mutex.RLock()
	files, err := cmd.FilesUsedFromContext(pe.imageConfig, pe.args)
	pe.stageBuilder.mutex.RUnlock()

	if err != nil {
		return errors.Wrap(err, "failed to get files used from context")
	}

	// Update composite key if caching is enabled
	// CRITICAL: Use mutex to protect compositeKey updates during parallel execution
	// Each command needs to update compositeKey sequentially to maintain correct cache key order
	if pe.config.Cache {
		var err error
		var updatedKey CompositeCache
		pe.stageBuilder.mutex.Lock()
		updatedKey, err = pe.stageBuilder.populateCompositeKey(cmd, files, *compositeKey, pe.args, pe.imageConfig.Env)
		if err == nil {
			*compositeKey = updatedKey
		}
		pe.stageBuilder.mutex.Unlock()
		if err != nil {
			return err
		}
	}

	// Log command start
	globalLogger := logging.GetGlobalManager()
	commandStartTime := time.Now()
	globalLogger.LogCommandStart(cmdIndex, cmd.String(), "stage")

	// Handle init snapshot if needed
	// CRITICAL: Use sync.Once to ensure init snapshot is taken only once across all parallel commands
	// AND ensure all commands wait for it to complete before executing
	// Multiple commands may check initSnapshotTaken == false simultaneously, but only one should execute
	// Check if command is a cached command (similar to isCacheCommand in build.go)
	_, isCached := cmd.(commands.Cached)
	if !initSnapshotTaken && !isCached && !cmd.ProvidesFilesToSnapshot() {
		// Only one command will execute init snapshot, but all commands must wait for it
		pe.initSnapshotOnce.Do(func() {
			pe.initSnapshotErr = pe.stageBuilder.initSnapshotWithTimings()
			// Signal that init snapshot is complete (close channel to unblock waiting commands)
			close(pe.initSnapshotDone)
		})

		// CRITICAL: All commands must wait for init snapshot to complete before executing
		// This prevents race conditions where commands start before filesystem is ready
		// Reading from closed channel returns immediately (non-blocking)
		<-pe.initSnapshotDone

		if pe.initSnapshotErr != nil {
			return pe.initSnapshotErr
		}
	}
	// Note: If initSnapshotTaken == true, channel is already closed in ExecuteCommands

	// Execute command (this is safe as it doesn't modify shared state)
	if err := cmd.ExecuteCommand(pe.imageConfig, pe.args); err != nil {
		// Log command failure
		commandDuration := time.Since(commandStartTime).Milliseconds()
		globalLogger.LogCommandComplete(cmdIndex, cmd.String(), commandDuration, false)
		globalLogger.LogError("command", "execute", err, map[string]interface{}{
			"command_index": cmdIndex,
			"command":       cmd.String(),
		})
		return errors.Wrap(err, "failed to execute command")
	}

	// Log command completion
	commandDuration := time.Since(commandStartTime).Milliseconds()
	globalLogger.LogCommandComplete(cmdIndex, cmd.String(), commandDuration, true)

	// NOTE: Snapshot is NOT taken here - it will be taken after all commands in group complete
	return nil
}

// executeCommand executes a single command
func (pe *ParallelExecutor) executeCommand(
	ctx context.Context, cmdIndex int, compositeKey *CompositeCache, initSnapshotTaken bool) error {
	cmd := pe.commands[cmdIndex]
	if cmd == nil {
		return nil
	}

	// Start timing
	stats := &CommandExecutionStats{
		StartTime: time.Now(),
		WorkerID:  len(pe.workerPool),
	}

	pe.statsMutex.Lock()
	pe.executionStats[cmdIndex] = stats
	pe.statsMutex.Unlock()

	logrus.Infof("🔄 Executing command %d: %s", cmdIndex, cmd.String())

	// Check context before executing command
	select {
	case <-ctx.Done():
		logrus.Debugf("Command %d canceled before execution", cmdIndex)
		return ctx.Err()
	default:
	}

	// Execute the command using the existing stageBuilder logic
	err := pe.stageBuilder.processCommand(cmd, cmdIndex, compositeKey, &errgroup.Group{}, initSnapshotTaken)

	// Check context after execution (in case it was canceled during execution)
	select {
	case <-ctx.Done():
		logrus.Debugf("Command %d context canceled during execution", cmdIndex)
		if err == nil {
			// If command succeeded but context was canceled, return context error
			return ctx.Err()
		}
		// If command failed, return the original error (more specific)
	default:
	}

	// Update statistics
	stats.EndTime = time.Now()
	stats.Duration = stats.EndTime.Sub(stats.StartTime)
	stats.Success = err == nil
	if err != nil {
		stats.ErrorMessage = err.Error()
	}

	pe.executedMutex.Lock()
	pe.executed[cmdIndex] = true
	pe.executedMutex.Unlock()

	if err != nil {
		logrus.Errorf("❌ Command %d failed: %v", cmdIndex, err)
		return fmt.Errorf("command %d (%s) failed: %w", cmdIndex, cmd.String(), err)
	}

	logrus.Infof("✅ Command %d completed in %v", cmdIndex, stats.Duration)
	return nil
}

// logExecutionStats logs execution statistics
func (pe *ParallelExecutor) logExecutionStats() {
	pe.statsMutex.RLock()
	defer pe.statsMutex.RUnlock()

	totalDuration := time.Duration(0)
	successCount := 0

	for cmdIndex, stats := range pe.executionStats {
		totalDuration += stats.Duration
		if stats.Success {
			successCount++
		}

		logrus.Infof("📊 Command %d: %v (success: %v, worker: %d)",
			cmdIndex, stats.Duration, stats.Success, stats.WorkerID)
	}

	logrus.Infof("📈 Total execution time: %v, success rate: %d/%d",
		totalDuration, successCount, len(pe.executionStats))
}

// GetExecutionStats returns execution statistics
func (pe *ParallelExecutor) GetExecutionStats() map[int]*CommandExecutionStats {
	pe.statsMutex.RLock()
	defer pe.statsMutex.RUnlock()

	// Return a copy to avoid race conditions
	stats := make(map[int]*CommandExecutionStats)
	for k, v := range pe.executionStats {
		stats[k] = v
	}
	return stats
}
