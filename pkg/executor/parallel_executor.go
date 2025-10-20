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
	"sync"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/Gosayram/kaniko/pkg/commands"
	"github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/dockerfile"
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
		commands:       cmds,
		config:         opts,
		args:           args,
		imageConfig:    imageConfig,
		stageBuilder:   sb,
		maxWorkers:     maxWorkers,
		workerPool:     make(chan struct{}, maxWorkers),
		executed:       make(map[int]bool),
		executionStats: make(map[int]*CommandExecutionStats),
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
func (pe *ParallelExecutor) buildExecutionOrder() []int {
	// Simple topological sort for now
	// In a more sophisticated implementation, we could use Kahn's algorithm

	order := make([]int, 0, len(pe.commands))
	visited := make(map[int]bool)

	// Add commands that have no dependencies first
	for i, cmd := range pe.commands {
		if cmd == nil {
			continue
		}

		hasDependencies := false
		for _, dep := range pe.dependencies {
			if dep.To == i {
				hasDependencies = true
				break
			}
		}

		if !hasDependencies {
			order = append(order, i)
			visited[i] = true
		}
	}

	// Add remaining commands in order
	for i, cmd := range pe.commands {
		if cmd == nil || visited[i] {
			continue
		}
		order = append(order, i)
	}

	return order
}

// ExecuteCommands executes commands in parallel with dependency resolution
func (pe *ParallelExecutor) ExecuteCommands(compositeKey *CompositeCache, initSnapshotTaken bool) error {
	logrus.Info("🚀 Starting parallel command execution")

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
func (pe *ParallelExecutor) findParallelGroup(startIndex int, executed map[int]bool) []int {
	group := []int{startIndex}

	// Find commands that don't depend on the start command
	for i, cmd := range pe.commands {
		if cmd == nil || executed[i] || i == startIndex {
			continue
		}

		// Check if this command can be executed in parallel
		if pe.canExecuteInParallel(startIndex, i) {
			group = append(group, i)
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

// executeGroup executes a group of commands in parallel
func (pe *ParallelExecutor) executeGroup(group []int, compositeKey *CompositeCache, initSnapshotTaken bool) error {
	if len(group) == 1 {
		// Single command - execute directly
		return pe.executeCommand(group[0], compositeKey, initSnapshotTaken)
	}

	// Multiple commands - execute in parallel
	ctx, cancel := context.WithTimeout(context.Background(), pe.config.CommandTimeout)
	defer cancel()

	g, _ := errgroup.WithContext(ctx)

	for _, cmdIndex := range group {
		cmdIndex := cmdIndex // Capture for closure
		g.Go(func() error {
			return pe.executeCommandWithWorker(cmdIndex, compositeKey, initSnapshotTaken)
		})
	}

	return g.Wait()
}

// executeCommandWithWorker executes a command using the worker pool
func (pe *ParallelExecutor) executeCommandWithWorker(
	cmdIndex int, compositeKey *CompositeCache, initSnapshotTaken bool) error {
	// Acquire worker
	pe.workerPool <- struct{}{}
	defer func() { <-pe.workerPool }()

	return pe.executeCommand(cmdIndex, compositeKey, initSnapshotTaken)
}

// executeCommand executes a single command
func (pe *ParallelExecutor) executeCommand(cmdIndex int, compositeKey *CompositeCache, initSnapshotTaken bool) error {
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

	// Execute the command using the existing stageBuilder logic
	err := pe.stageBuilder.processCommand(cmd, cmdIndex, compositeKey, &errgroup.Group{}, initSnapshotTaken)

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
