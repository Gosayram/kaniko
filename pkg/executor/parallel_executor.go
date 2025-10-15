/*
Copyright 2024 Kaniko Contributors

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
	"sync"
	"time"

	"github.com/Gosayram/kaniko/pkg/commands"
	"github.com/sirupsen/logrus"
)

// ParallelExecutor handles parallel execution of Docker commands
type ParallelExecutor struct {
	maxWorkers    int
	timeout       time.Duration
	errorHandler  func(error) error
	progressChan  chan ProgressUpdate
	mu            sync.RWMutex
	executionPlan []ExecutionGroup
}

// ExecutionGroup represents a group of commands that can be executed in parallel
type ExecutionGroup struct {
	Commands []commands.DockerCommand
	Index    int
	Priority int
}

// ProgressUpdate provides information about command execution progress
type ProgressUpdate struct {
	CommandIndex int
	CommandName  string
	Status       string
	Error        error
	Duration     time.Duration
}

// CommandDependency represents a dependency between commands
type CommandDependency struct {
	From int    // Source command index
	To   int    // Target command index
	Type string // "file", "env", "stage"
}

// NewParallelExecutor creates a new parallel executor
func NewParallelExecutor(maxWorkers int, timeout time.Duration) *ParallelExecutor {
	if maxWorkers <= 0 {
		maxWorkers = 4 // Default to 4 workers
	}
	if timeout <= 0 {
		timeout = 30 * time.Minute // Default timeout
	}

	return &ParallelExecutor{
		maxWorkers:   maxWorkers,
		timeout:      timeout,
		progressChan: make(chan ProgressUpdate, 100),
	}
}

// ExecuteCommandsParallel executes commands in parallel where possible
func (pe *ParallelExecutor) ExecuteCommandsParallel(
	cmds []commands.DockerCommand,
	compositeKey *CompositeCache,
	initSnapshotTaken bool,
	stageBuilder *stageBuilder,
) error {
	ctx, cancel := context.WithTimeout(context.Background(), pe.timeout)
	defer cancel()

	// Analyze command dependencies
	dependencies, err := pe.analyzeDependencies(cmds)
	if err != nil {
		return fmt.Errorf("failed to analyze dependencies: %w", err)
	}

	// Create execution plan
	executionPlan, err := pe.createExecutionPlan(cmds, dependencies)
	if err != nil {
		return fmt.Errorf("failed to create execution plan: %w", err)
	}

	pe.mu.Lock()
	pe.executionPlan = executionPlan
	pe.mu.Unlock()

	// Execute plan
	return pe.executePlan(ctx, executionPlan, compositeKey, initSnapshotTaken, stageBuilder)
}

// analyzeDependencies analyzes dependencies between commands
func (pe *ParallelExecutor) analyzeDependencies(cmds []commands.DockerCommand) ([]CommandDependency, error) {
	var dependencies []CommandDependency

	for i, cmd := range cmds {
		if cmd == nil {
			continue
		}

		// Analyze file dependencies
		fileDeps := pe.analyzeFileDependencies(cmd, i, cmds)
		dependencies = append(dependencies, fileDeps...)

		// Analyze environment dependencies
		envDeps := pe.analyzeEnvironmentDependencies(cmd, i, cmds)
		dependencies = append(dependencies, envDeps...)

		// Analyze stage dependencies
		stageDeps := pe.analyzeStageDependencies(cmd, i, cmds)
		dependencies = append(dependencies, stageDeps...)
	}

	return dependencies, nil
}

// analyzeFileDependencies analyzes file-based dependencies
func (pe *ParallelExecutor) analyzeFileDependencies(cmd commands.DockerCommand, index int, allCmds []commands.DockerCommand) []CommandDependency {
	var deps []CommandDependency

	// Check if command reads from files created by previous commands
	if copyCmd, ok := cmd.(*commands.CopyCommand); ok {
		for i := 0; i < index; i++ {
			if prevCmd := allCmds[i]; prevCmd != nil {
				// Check if previous command creates files that this command reads
				if pe.commandsHaveFileDependency(prevCmd, copyCmd) {
					deps = append(deps, CommandDependency{
						From: i,
						To:   index,
						Type: "file",
					})
				}
			}
		}
	}

	return deps
}

// analyzeEnvironmentDependencies analyzes environment variable dependencies
func (pe *ParallelExecutor) analyzeEnvironmentDependencies(cmd commands.DockerCommand, index int, allCmds []commands.DockerCommand) []CommandDependency {
	var deps []CommandDependency

	// Check if command uses environment variables set by previous commands
	if runCmd, ok := cmd.(*commands.RunCommand); ok {
		for i := 0; i < index; i++ {
			if prevCmd := allCmds[i]; prevCmd != nil {
				// Check if previous command sets environment variables used by this command
				if pe.commandsHaveEnvironmentDependency(prevCmd, runCmd) {
					deps = append(deps, CommandDependency{
						From: i,
						To:   index,
						Type: "env",
					})
				}
			}
		}
	}

	return deps
}

// analyzeStageDependencies analyzes cross-stage dependencies
func (pe *ParallelExecutor) analyzeStageDependencies(cmd commands.DockerCommand, index int, allCmds []commands.DockerCommand) []CommandDependency {
	var deps []CommandDependency

	// Check if command depends on previous stage
	if copyCmd, ok := cmd.(*commands.CopyCommand); ok && copyCmd.From() != "" {
		// Find the stage this command depends on
		for i := 0; i < index; i++ {
			if prevCmd := allCmds[i]; prevCmd != nil {
				if pe.isStageDependency(prevCmd, copyCmd) {
					deps = append(deps, CommandDependency{
						From: i,
						To:   index,
						Type: "stage",
					})
				}
			}
		}
	}

	return deps
}

// commandsHaveFileDependency checks if two commands have file dependencies
func (pe *ParallelExecutor) commandsHaveFileDependency(prevCmd, currCmd commands.DockerCommand) bool {
	// This is a simplified check - in reality, you'd need more sophisticated analysis
	// of what files each command creates and what files each command reads

	// For now, assume all commands have potential file dependencies
	// In a real implementation, you'd analyze the actual file operations
	return true
}

// commandsHaveEnvironmentDependency checks if two commands have environment dependencies
func (pe *ParallelExecutor) commandsHaveEnvironmentDependency(prevCmd, currCmd commands.DockerCommand) bool {
	// This is a simplified check - in reality, you'd need to analyze
	// environment variable usage in command strings

	// For now, assume RUN commands might depend on previous commands
	if _, ok := currCmd.(*commands.RunCommand); ok {
		return true
	}
	return false
}

// isStageDependency checks if a command depends on a previous stage
func (pe *ParallelExecutor) isStageDependency(prevCmd, currCmd commands.DockerCommand) bool {
	// Check if current command is a COPY --from command
	if copyCmd, ok := currCmd.(*commands.CopyCommand); ok && copyCmd.From() != "" {
		// This is a simplified check - in reality, you'd need to match
		// the stage name with the actual stage
		return true
	}
	return false
}

// createExecutionPlan creates a plan for parallel execution
func (pe *ParallelExecutor) createExecutionPlan(cmds []commands.DockerCommand, dependencies []CommandDependency) ([]ExecutionGroup, error) {
	var plan []ExecutionGroup
	executed := make(map[int]bool)
	groupIndex := 0

	for len(executed) < len(cmds) {
		var currentGroup []commands.DockerCommand
		var currentIndices []int

		// Find commands that can be executed in parallel
		for i, cmd := range cmds {
			if cmd == nil || executed[i] {
				continue
			}

			// Check if all dependencies are satisfied
			if pe.allDependenciesSatisfied(i, dependencies, executed) {
				currentGroup = append(currentGroup, cmd)
				currentIndices = append(currentIndices, i)
			}
		}

		if len(currentGroup) == 0 {
			return nil, fmt.Errorf("circular dependency detected in commands")
		}

		// Create execution group
		group := ExecutionGroup{
			Commands: currentGroup,
			Index:    groupIndex,
			Priority: groupIndex,
		}

		plan = append(plan, group)

		// Mark commands as executed
		for _, idx := range currentIndices {
			executed[idx] = true
		}

		groupIndex++
	}

	return plan, nil
}

// allDependenciesSatisfied checks if all dependencies for a command are satisfied
func (pe *ParallelExecutor) allDependenciesSatisfied(cmdIndex int, dependencies []CommandDependency, executed map[int]bool) bool {
	for _, dep := range dependencies {
		if dep.To == cmdIndex {
			if !executed[dep.From] {
				return false
			}
		}
	}
	return true
}

// executePlan executes the execution plan
func (pe *ParallelExecutor) executePlan(
	ctx context.Context,
	plan []ExecutionGroup,
	compositeKey *CompositeCache,
	initSnapshotTaken bool,
	stageBuilder *stageBuilder,
) error {
	for _, group := range plan {
		logrus.Infof("Executing group %d with %d commands in parallel", group.Index, len(group.Commands))

		if err := pe.executeGroup(ctx, group, compositeKey, initSnapshotTaken, stageBuilder); err != nil {
			return fmt.Errorf("failed to execute group %d: %w", group.Index, err)
		}
	}

	return nil
}

// executeGroup executes a group of commands in parallel
func (pe *ParallelExecutor) executeGroup(
	ctx context.Context,
	group ExecutionGroup,
	compositeKey *CompositeCache,
	initSnapshotTaken bool,
	stageBuilder *stageBuilder,
) error {
	// Limit number of parallel workers
	maxWorkers := pe.maxWorkers
	if len(group.Commands) < maxWorkers {
		maxWorkers = len(group.Commands)
	}

	// Create worker pool
	workerChan := make(chan int, maxWorkers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errors []error

	// Start workers
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for cmdIndex := range workerChan {
				if err := pe.executeCommand(ctx, cmdIndex, group.Commands[cmdIndex], compositeKey, initSnapshotTaken, stageBuilder); err != nil {
					mu.Lock()
					errors = append(errors, fmt.Errorf("command %d failed: %w", cmdIndex, err))
					mu.Unlock()
				}
			}
		}()
	}

	// Send work to workers
	for i := range group.Commands {
		select {
		case workerChan <- i:
		case <-ctx.Done():
			close(workerChan)
			return ctx.Err()
		}
	}

	close(workerChan)
	wg.Wait()

	// Check for errors
	if len(errors) > 0 {
		return fmt.Errorf("group execution failed: %v", errors)
	}

	return nil
}

// executeCommand executes a single command
func (pe *ParallelExecutor) executeCommand(
	ctx context.Context,
	cmdIndex int,
	cmd commands.DockerCommand,
	compositeKey *CompositeCache,
	initSnapshotTaken bool,
	stageBuilder *stageBuilder,
) error {
	startTime := time.Now()

	// Send progress update
	pe.progressChan <- ProgressUpdate{
		CommandIndex: cmdIndex,
		CommandName:  cmd.String(),
		Status:       "starting",
	}

	// Execute command
	err := stageBuilder.processCommand(cmd, cmdIndex, compositeKey, nil, initSnapshotTaken)

	duration := time.Since(startTime)

	// Send progress update
	pe.progressChan <- ProgressUpdate{
		CommandIndex: cmdIndex,
		CommandName:  cmd.String(),
		Status:       "completed",
		Error:        err,
		Duration:     duration,
	}

	return err
}

// GetProgressChannel returns the progress update channel
func (pe *ParallelExecutor) GetProgressChannel() <-chan ProgressUpdate {
	return pe.progressChan
}

// GetExecutionStats returns statistics about the execution
func (pe *ParallelExecutor) GetExecutionStats() map[string]interface{} {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	return map[string]interface{}{
		"max_workers":      pe.maxWorkers,
		"timeout":          pe.timeout,
		"execution_groups": len(pe.executionPlan),
	}
}
