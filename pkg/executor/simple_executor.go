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

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/Gosayram/kaniko/pkg/commands"
	"github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/dockerfile"
	"github.com/Gosayram/kaniko/pkg/llb"
	"github.com/Gosayram/kaniko/pkg/scheduler"
	"github.com/Gosayram/kaniko/pkg/timing"
)

// SimpleExecutor provides simple sequential command execution
// This is the default executor for reliability and simplicity
// Inspired by the original Kaniko approach
type SimpleExecutor struct {
	commands     []commands.DockerCommand
	stageBuilder *stageBuilder
	opts         *config.KanikoOptions
	args         *dockerfile.BuildArgs

	// Optional dependency graph for execution order optimization
	dependencyGraph *DependencyGraph
	useGraph        bool

	// LLB graph and scheduler for BuildKit-style optimization
	llbGraph  *llb.Graph
	scheduler *scheduler.Scheduler
	useLLB    bool
}

// NewSimpleExecutor creates a new simple sequential executor
func NewSimpleExecutor(
	cmds []commands.DockerCommand,
	sb *stageBuilder,
	opts *config.KanikoOptions,
	args *dockerfile.BuildArgs,
) *SimpleExecutor {
	executor := &SimpleExecutor{
		commands:     cmds,
		stageBuilder: sb,
		opts:         opts,
		args:         args,
	}

	// Build dependency graph for execution order optimization (enabled by default per plan)
	if opts.OptimizeExecutionOrder {
		// Get config and buildArgs from stageBuilder
		var imageConfig *v1.Config
		if sb != nil && sb.cf != nil {
			imageConfig = &sb.cf.Config
		} else {
			imageConfig = &v1.Config{}
		}

		graph, err := BuildDependencyGraph(cmds, imageConfig, args)
		if err != nil {
			logrus.Warnf("Failed to build dependency graph: %v, using default order", err)
		} else {
			executor.dependencyGraph = graph
			executor.useGraph = true
			logrus.Debugf("Using dependency graph for execution order optimization")
		}

		// Build LLB graph for BuildKit-style optimization (edge merging, etc.)
		llbGraph, err := llb.BuildGraphFromCommands(cmds)
		if err != nil {
			logrus.Warnf("Failed to build LLB graph: %v, using dependency graph only", err)
		} else {
			// Optimize LLB graph (edge merging, etc.)
			ctx := context.Background()
			if err := llbGraph.Optimize(ctx); err != nil {
				logrus.Warnf("Failed to optimize LLB graph: %v", err)
			} else {
				executor.llbGraph = llbGraph
				logrus.Debugf("LLB graph optimized: %d operations", len(llbGraph.Operations))

				// Build scheduler from LLB graph
				sched, err := scheduler.BuildFromGraph(llbGraph)
				if err != nil {
					logrus.Warnf("Failed to build scheduler: %v", err)
				} else {
					// Optimize scheduler (edge merging)
					if err := sched.Optimize(ctx); err != nil {
						logrus.Warnf("Failed to optimize scheduler: %v", err)
					} else {
						executor.scheduler = sched
						executor.useLLB = true
						logrus.Debugf("Scheduler optimized with edge merging")
					}
				}
			}
		}
	}

	return executor
}

// ExecuteSequentially executes commands sequentially (default behavior)
// This is simple, reliable, and avoids race conditions
func (e *SimpleExecutor) ExecuteSequentially(compositeKey *CompositeCache, initSnapshotTaken bool) error {
	cacheGroup := errgroup.Group{}
	// Limit concurrent cache push operations to avoid overwhelming registry/network
	// Increased default: min(15, GOMAXPROCS * 2) for better network throughput
	var maxConcurrentPushes int
	if e.opts != nil && e.opts.MaxNetworkConcurrency > 0 {
		maxConcurrentPushes = e.opts.MaxNetworkConcurrency
	} else {
		gomaxprocs := runtime.GOMAXPROCS(0)
		const concurrencyMultiplier = 2
		const maxNetworkConcurrency = 15
		maxConcurrentPushes = gomaxprocs * concurrencyMultiplier
		if maxConcurrentPushes > maxNetworkConcurrency {
			maxConcurrentPushes = maxNetworkConcurrency
		}
		if maxConcurrentPushes < 1 {
			maxConcurrentPushes = 1
		}
	}
	cacheGroup.SetLimit(maxConcurrentPushes)

	var commandErrors []error
	var errorMutex sync.Mutex

	// Determine execution order
	executionOrder := e.getExecutionOrder()

	logrus.Infof("Executing %d commands sequentially", len(e.commands))

	// Execute commands in order
	for _, index := range executionOrder {
		command := e.commands[index]
		if command == nil {
			continue
		}

		func() {
			t := timing.Start("Command: " + command.String())
			defer timing.DefaultRun.Stop(t)

			logrus.Infof("Executing command %d: %s", index, command.String())

			// Execute command
			err := e.stageBuilder.processCommand(command, index, compositeKey, &cacheGroup, initSnapshotTaken)
			if err != nil {
				// Collect errors instead of failing immediately
				errorMutex.Lock()
				commandErrors = append(commandErrors, fmt.Errorf("command %d (%s) failed: %w", index, command.String(), err))
				errorMutex.Unlock()
				logrus.Errorf("Command %d failed: %v", index, err)
			} else {
				logrus.Infof("Command %d completed", index)
			}
		}()
	}

	// Wait for cache operations to complete
	if err := cacheGroup.Wait(); err != nil {
		logrus.Warnf("Error uploading layer to cache: %s", err)
		// Cache errors are non-fatal, but we should log them
	}

	// Return the first command error if any occurred
	if len(commandErrors) > 0 {
		return errors.Wrapf(commandErrors[0], "command execution failed")
	}

	logrus.Infof("All %d commands completed successfully", len(e.commands))
	return nil
}

// ExecuteInParallel executes commands in parallel for explicitly independent commands
// This is an optional optimization that groups commands by dependencies
func (e *SimpleExecutor) ExecuteInParallel(compositeKey *CompositeCache, initSnapshotTaken bool) error {
	// Build dependency graph if not already built
	if e.dependencyGraph == nil {
		// Get config and buildArgs from stageBuilder
		var imageConfig *v1.Config
		if e.stageBuilder != nil && e.stageBuilder.cf != nil {
			e.stageBuilder.mutex.RLock()
			imageConfig = &e.stageBuilder.cf.Config
			e.stageBuilder.mutex.RUnlock()
		} else {
			imageConfig = &v1.Config{}
		}

		graph, err := BuildDependencyGraph(e.commands, imageConfig, e.args)
		if err != nil {
			return errors.Wrap(err, "failed to build dependency graph for parallel execution")
		}
		e.dependencyGraph = graph
		e.useGraph = true
	}

	// Create shared cache group with limit for push operations
	// This ensures all push operations respect the same concurrency limit
	sharedCacheGroup := errgroup.Group{}
	// Increased default: min(15, GOMAXPROCS * 2) for better network throughput
	var maxConcurrentPushes int
	if e.opts != nil && e.opts.MaxNetworkConcurrency > 0 {
		maxConcurrentPushes = e.opts.MaxNetworkConcurrency
	} else {
		gomaxprocs := runtime.GOMAXPROCS(0)
		const concurrencyMultiplier = 2
		const maxNetworkConcurrency = 15
		maxConcurrentPushes = gomaxprocs * concurrencyMultiplier
		if maxConcurrentPushes > maxNetworkConcurrency {
			maxConcurrentPushes = maxNetworkConcurrency
		}
		if maxConcurrentPushes < 1 {
			maxConcurrentPushes = 1
		}
	}
	sharedCacheGroup.SetLimit(maxConcurrentPushes)

	// Group commands by dependencies
	groups := e.groupCommandsByDependencies()

	logrus.Infof("Executing %d commands in %d groups", len(e.commands), len(groups))

	// Execute groups sequentially, commands in group - parallel
	for groupIdx, group := range groups {
		if len(group) == 1 {
			// Single command - execute sequentially
			index := group[0]
			command := e.commands[index]
			if command == nil {
				continue
			}

			logrus.Debugf("Executing single command %d in group %d", index, groupIdx)
			if err := e.stageBuilder.processCommand(
				command, index, compositeKey, &sharedCacheGroup, initSnapshotTaken,
			); err != nil {
				return errors.Wrapf(err, "command %d failed", index)
			}
		} else {
			// Multiple commands - execute in parallel
			logrus.Debugf("Executing %d commands in parallel (group %d)", len(group), groupIdx)
			if err := e.executeGroupParallelWithCacheGroup(
				group, compositeKey, initSnapshotTaken, &sharedCacheGroup,
			); err != nil {
				return errors.Wrapf(err, "group %d execution failed", groupIdx)
			}
		}
	}

	// Wait for all cache operations to complete
	if err := sharedCacheGroup.Wait(); err != nil {
		logrus.Warnf("Error uploading layers to cache: %s", err)
		// Cache errors are non-fatal, but we should log them
	}

	logrus.Infof("All commands completed successfully")
	return nil
}

// getExecutionOrder returns the execution order for commands
// Uses LLB graph if available (BuildKit-style optimization)
// Falls back to dependency graph, then original order
func (e *SimpleExecutor) getExecutionOrder() []int {
	// Use LLB graph if available (most optimized)
	if e.useLLB && e.llbGraph != nil {
		ops, err := e.llbGraph.GetExecutionOrder()
		if err == nil {
			// Convert operations to command indices
			order := make([]int, 0, len(ops))
			for _, op := range ops {
				if op.Index < len(e.commands) {
					order = append(order, op.Index)
				}
			}
			if len(order) == len(e.commands) {
				logrus.Debugf("Using optimized execution order from LLB graph")
				return order
			}
			logrus.Warnf("LLB graph order length mismatch, falling back to dependency graph")
		}
	}

	// Use dependency graph if available (enabled by default)
	if e.useGraph && e.dependencyGraph != nil {
		order := e.dependencyGraph.GetExecutionOrder()
		if len(order) == len(e.commands) {
			logrus.Debugf("Using optimized execution order from dependency graph")
			return order
		}
		logrus.Warnf("Dependency graph order length mismatch, using default order")
	}

	// Fallback: execute in original order (simple and reliable)
	executionOrder := make([]int, len(e.commands))
	for i := range e.commands {
		executionOrder[i] = i
	}
	return executionOrder
}

// groupCommandsByDependencies groups commands that can be executed in parallel
// Commands in the same group have no dependencies on each other
func (e *SimpleExecutor) groupCommandsByDependencies() [][]int {
	if e.dependencyGraph == nil {
		// No graph - each command is its own group (sequential)
		groups := make([][]int, len(e.commands))
		for i := range e.commands {
			groups[i] = []int{i}
		}
		return groups
	}

	groups := [][]int{}
	executed := make(map[int]bool)
	order := e.dependencyGraph.GetExecutionOrder()

	for _, cmdIndex := range order {
		if executed[cmdIndex] {
			continue
		}

		// Find all commands that can be executed in parallel with this one
		group := e.findIndependentCommands(cmdIndex, executed)
		groups = append(groups, group)

		// Mark all commands in this group as executed
		for _, idx := range group {
			executed[idx] = true
		}
	}

	return groups
}

// findIndependentCommands finds commands that can be executed in parallel
// A command can be added if all its dependencies are already executed
func (e *SimpleExecutor) findIndependentCommands(startIndex int, executed map[int]bool) []int {
	group := []int{startIndex}

	if e.dependencyGraph == nil {
		return group
	}

	// Find commands that can be executed in parallel with startIndex
	for i := range e.commands {
		if e.commands[i] == nil || executed[i] || i == startIndex {
			continue
		}

		// Check if all dependencies are executed
		deps := e.dependencyGraph.GetDependencies(i)
		allDepsExecuted := true
		for _, dep := range deps {
			if !executed[dep] {
				allDepsExecuted = false
				break
			}
		}

		if allDepsExecuted {
			// Check if this command doesn't conflict with commands in the group
			// For simplicity, we only add commands that are explicitly independent
			// More sophisticated conflict detection can be added later
			group = append(group, i)
		}
	}

	return group
}

// executeGroupParallelWithCacheGroup executes a group of commands in parallel with shared cache group
func (e *SimpleExecutor) executeGroupParallelWithCacheGroup(
	group []int,
	compositeKey *CompositeCache,
	initSnapshotTaken bool,
	sharedCacheGroup *errgroup.Group,
) error {
	commandGroup := errgroup.Group{}
	var commandErrors []error
	var errorMutex sync.Mutex

	// Limit concurrent commands to avoid excessive CPU usage
	// Use MaxParallelCommands from options if set, otherwise use conservative default
	maxParallelCommands := 4 // Conservative default
	if e.opts.MaxParallelCommands > 0 {
		maxParallelCommands = e.opts.MaxParallelCommands
	}
	commandGroup.SetLimit(maxParallelCommands)

	// Execute all commands in the group in parallel
	for _, index := range group {
		index := index // Capture for closure
		command := e.commands[index]
		if command == nil {
			continue
		}

		commandGroup.Go(func() error {
			t := timing.Start("Command: " + command.String())
			defer timing.DefaultRun.Stop(t)

			logrus.Debugf("Executing command %d in parallel: %s", index, command.String())
			// Use shared cacheGroup for push operations to respect concurrency limit
			err := e.stageBuilder.processCommand(command, index, compositeKey, sharedCacheGroup, initSnapshotTaken)
			if err != nil {
				errorMutex.Lock()
				commandErrors = append(commandErrors, fmt.Errorf("command %d (%s) failed: %w", index, command.String(), err))
				errorMutex.Unlock()
				return err
			}
			return nil
		})
	}

	// Wait for all commands to complete
	if err := commandGroup.Wait(); err != nil {
		if len(commandErrors) > 0 {
			return errors.Wrapf(commandErrors[0], "parallel execution failed")
		}
		return err
	}

	return nil
}
