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
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
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
	"github.com/Gosayram/kaniko/pkg/util"
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

const (
	// goroutineCleanupDelay is the delay to give goroutines time to respond to cancellation
	goroutineCleanupDelay = 10 * time.Millisecond
	// cacheOperationTimeout is the timeout for cache operations to prevent hanging
	cacheOperationTimeout = 30 * time.Second
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

	// Performance optimization: caches for dependency analysis
	commandPathsCache      map[int]map[string]bool // Cache for command paths
	commandPathsCacheMutex sync.RWMutex
	conflictCache          map[string]bool // Cache for conflict checks (key: "cmd1:cmd2")
	conflictCacheMutex     sync.RWMutex
	dependencyIndex        map[int]map[int]bool // Index: dep[from][to] = true
	dependencyIndexMutex   sync.RWMutex
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
		commands:          cmds,
		config:            opts,
		args:              args,
		imageConfig:       imageConfig,
		stageBuilder:      sb,
		maxWorkers:        maxWorkers,
		workerPool:        make(chan struct{}, maxWorkers),
		executed:          make(map[int]bool),
		executionStats:    make(map[int]*CommandExecutionStats),
		initSnapshotDone:  make(chan struct{}),
		commandPathsCache: make(map[int]map[string]bool),
		conflictCache:     make(map[string]bool),
		dependencyIndex:   make(map[int]map[int]bool),
	}
}

// AnalyzeDependencies analyzes command dependencies to determine execution order
func (pe *ParallelExecutor) AnalyzeDependencies() error {
	analysisStartTime := time.Now()
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

	// Build dependency index for fast lookups
	indexStartTime := time.Now()
	pe.buildDependencyIndex()
	indexDuration := time.Since(indexStartTime)

	// Build execution order based on dependencies
	orderStartTime := time.Now()
	executionOrder := pe.buildExecutionOrder()
	orderDuration := time.Since(orderStartTime)

	pe.executionOrder = executionOrder

	totalDuration := time.Since(analysisStartTime)
	logrus.Infof("📊 Dependency analysis completed in %v: found %d dependencies, execution order: %v",
		totalDuration, len(dependencies), executionOrder)
	logrus.Debugf("⏱️  Performance: index build=%v, order build=%v, total=%v",
		indexDuration, orderDuration, totalDuration)
	return nil
}

// buildDependencyIndex builds an index of dependencies for fast lookups
// This optimizes canExecuteInParallel by avoiding linear search through dependencies
func (pe *ParallelExecutor) buildDependencyIndex() {
	pe.dependencyIndexMutex.Lock()
	defer pe.dependencyIndexMutex.Unlock()

	pe.dependencyIndex = make(map[int]map[int]bool)

	for _, dep := range pe.dependencies {
		if pe.dependencyIndex[dep.From] == nil {
			pe.dependencyIndex[dep.From] = make(map[int]bool)
		}
		pe.dependencyIndex[dep.From][dep.To] = true
	}
}

// analyzeCommandDependencies analyzes dependencies for a specific command
// IMPROVED: Now analyzes specific file paths to detect dependencies more accurately
func (pe *ParallelExecutor) analyzeCommandDependencies(index int, cmd commands.DockerCommand) []CommandDependency {
	dependencies := make([]CommandDependency, 0)

	// IMPROVED: Analyze file-based dependencies first (more accurate)
	fileDeps := pe.analyzeFileBasedDependencies(index, cmd)
	dependencies = append(dependencies, fileDeps...)

	// Fallback to general filesystem dependencies if no specific file dependencies found
	if len(fileDeps) == 0 && pe.hasFilesystemDependency(index, cmd) {
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

	// IMPROVED: Analyze environment variable dependencies more accurately
	envDeps := pe.analyzeEnvironmentDependencies(index, cmd)
	dependencies = append(dependencies, envDeps...)

	return dependencies
}

// analyzeFileBasedDependencies analyzes dependencies based on specific file paths
// This is more accurate than general filesystem dependency detection
func (pe *ParallelExecutor) analyzeFileBasedDependencies(index int, cmd commands.DockerCommand) []CommandDependency {
	dependencies := make([]CommandDependency, 0)

	// Get all paths used by this command
	allPathsUsed := pe.getCommandUsedPaths(cmd)

	// Check if any previous command creates files that this command uses
	for i := index - 1; i >= 0; i-- {
		if pe.commands[i] == nil {
			continue
		}

		// Check if this previous command conflicts with current command
		if pe.hasPathConflict(pe.commands[i], allPathsUsed) {
			dependencies = append(dependencies, CommandDependency{
				From: i,
				To:   index,
				Type: FileSystemDependency,
			})
			// Only track the most recent conflicting command to avoid over-dependencies
			break
		}
	}

	return dependencies
}

// getCommandUsedPaths collects all paths that a command might use
func (pe *ParallelExecutor) getCommandUsedPaths(cmd commands.DockerCommand) map[string]bool {
	var filesUsed []string

	// Try to get files used from context (for COPY/ADD commands)
	if pe.config != nil && pe.args != nil {
		if files, err := cmd.FilesUsedFromContext(pe.imageConfig, pe.args); err == nil {
			filesUsed = files
		}
	}

	// Also try to extract paths from RUN command strings (heuristic approach)
	runPaths := pe.extractPathsFromCommand(cmd)

	// Combine all paths this command might use
	allPathsUsed := make(map[string]bool)
	for _, path := range filesUsed {
		allPathsUsed[filepath.Clean(path)] = true
	}
	for _, path := range runPaths {
		allPathsUsed[filepath.Clean(path)] = true
	}

	return allPathsUsed
}

// hasPathConflict checks if a command creates files that conflict with used paths
func (pe *ParallelExecutor) hasPathConflict(prevCmd commands.DockerCommand, usedPaths map[string]bool) bool {
	prevFilesCreated := prevCmd.FilesToSnapshot()

	// Check if any created file matches paths used by current command
	for _, createdPath := range prevFilesCreated {
		cleanCreated := filepath.Clean(createdPath)
		// Check if this path is used by current command
		for usedPath := range usedPaths {
			if pe.pathsOverlap(cleanCreated, usedPath) {
				return true
			}
			// Also check parent directories
			if pe.isParentDirectory(cleanCreated, usedPath) || pe.isParentDirectory(usedPath, cleanCreated) {
				return true
			}
		}
	}

	return false
}

// extractPathsFromCommand extracts file paths from command string (heuristic for RUN commands)
// IMPROVED: More accurate parsing that handles:
// - Quoted paths
// - Absolute paths in any position
// - Paths with spaces
// Uses regex pattern matching without hardcoded command lists
func (pe *ParallelExecutor) extractPathsFromCommand(cmd commands.DockerCommand) []string {
	paths := make(map[string]bool)
	cmdStr := cmd.String()

	if cmdStr == "" {
		return []string{}
	}

	// Remove RUN prefix if present
	cmdStr = strings.TrimPrefix(cmdStr, "RUN ")

	// Extract paths using improved regex - matches both quoted and unquoted paths
	// Pattern matches:
	// - Absolute paths: /path/to/file
	// - Quoted paths: "/path/to/file" or '/path/to/file'
	// - Paths with spaces: "/path with spaces/file"
	// - Paths after any command (no hardcoded list needed)
	// Pattern explanation:
	//   (?:^|\s) - start of string or whitespace
	//   ["']? - optional quote (single or double)
	//   (/(?:[^"'\s|&;()<>$]|\\.)+) - absolute path starts with /, followed by path characters
	//   ["']? - optional closing quote
	pathPattern := regexp.MustCompile(`(?:^|\s)["']?(/(?:[^"'\s|&;()<>$]|\\.)+)["']?`)
	matches := pathPattern.FindAllStringSubmatch(cmdStr, -1)

	for _, match := range matches {
		if len(match) <= 1 {
			continue
		}
		path := match[1]
		// Clean up the path (remove quotes, escape sequences)
		path = strings.Trim(path, `"'`)
		path = filepath.Clean(path)

		// Basic validation - must be a valid absolute path
		// Minimum path length is 2 (e.g., "/a")
		const minPathLength = 2
		if strings.HasPrefix(path, "/") && len(path) >= minPathLength {
			// Filter out shell operators and invalid characters
			if !strings.ContainsAny(path, "|&;()<>") {
				paths[path] = true
			}
		}
	}

	// Convert map to slice
	result := make([]string, 0, len(paths))
	for path := range paths {
		result = append(result, path)
	}

	return result
}

// pathsOverlap checks if two paths overlap (one is a subpath of another)
func (pe *ParallelExecutor) pathsOverlap(path1, path2 string) bool {
	// Normalize paths
	path1 = filepath.Clean(path1)
	path2 = filepath.Clean(path2)

	// Exact match
	if path1 == path2 {
		return true
	}

	// Check if one is a prefix of another
	return strings.HasPrefix(path1+"/", path2+"/") || strings.HasPrefix(path2+"/", path1+"/")
}

// isParentDirectory checks if dir1 is a parent directory of path2
func (pe *ParallelExecutor) isParentDirectory(dir1, path2 string) bool {
	dir1 = filepath.Clean(dir1)
	path2 = filepath.Clean(path2)

	// Check if path2 is under dir1
	rel, err := filepath.Rel(dir1, path2)
	if err != nil {
		return false
	}

	// If relative path doesn't start with "..", then path2 is under dir1
	return !strings.HasPrefix(rel, "..")
}

// hasFilesystemDependency checks if a command depends on filesystem changes
func (pe *ParallelExecutor) hasFilesystemDependency(_ int, cmd commands.DockerCommand) bool {
	// Commands that read from filesystem depend on previous filesystem changes
	return !cmd.MetadataOnly() && cmd.RequiresUnpackedFS()
}

// analyzeEnvironmentDependencies analyzes dependencies based on environment variables
// This checks if RUN commands use environment variables set by ENV commands
func (pe *ParallelExecutor) analyzeEnvironmentDependencies(index int, cmd commands.DockerCommand) []CommandDependency {
	dependencies := make([]CommandDependency, 0)

	// Only analyze RUN commands (commands that require unpacked FS)
	if cmd.MetadataOnly() || !cmd.RequiresUnpackedFS() {
		return dependencies
	}

	// Get environment variables used by this RUN command
	usedEnvVars := pe.getCommandUsedEnvVars(cmd)
	if len(usedEnvVars) == 0 {
		return dependencies
	}

	// Find ENV commands that set these variables
	for i := index - 1; i >= 0; i-- {
		if pe.commands[i] == nil {
			continue
		}

		// Check if this is an ENV command
		envVars := pe.getCommandSetEnvVars(pe.commands[i])
		if len(envVars) == 0 {
			continue
		}

		// Check if any of the used variables are set by this ENV command
		for _, usedVar := range usedEnvVars {
			if envVars[usedVar] {
				dependencies = append(dependencies, CommandDependency{
					From: i,
					To:   index,
					Type: EnvironmentDependency,
				})
				logrus.Debugf("🔗 Environment dependency: command %d (ENV) -> command %d (RUN uses %s)", i, index, usedVar)
				break // Only need one dependency per ENV command
			}
		}
	}

	return dependencies
}

// getCommandUsedEnvVars extracts environment variables used in a RUN command
// It looks for patterns like $VAR or ${VAR} in the command string
func (pe *ParallelExecutor) getCommandUsedEnvVars(cmd commands.DockerCommand) []string {
	usedVars := make(map[string]bool)

	// Get command string representation
	cmdStr := cmd.String()
	if cmdStr == "" {
		return []string{}
	}

	// Extract environment variable references using regex
	// Pattern: $VAR or ${VAR}
	// Note: We don't filter built-in variables because they can be modified by ENV commands
	// (e.g., ENV PATH=/custom/path:$PATH), so we need to track dependencies for all variables
	envVarPattern := regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)
	matches := envVarPattern.FindAllStringSubmatch(cmdStr, -1)

	for _, match := range matches {
		if len(match) > 1 {
			varName := match[1]
			// Include all variables - even built-in ones can be modified by ENV commands
			// This ensures correct dependency tracking for cases like:
			// ENV PATH=/custom/path:$PATH
			// RUN echo $PATH
			usedVars[varName] = true
		}
	}

	// Convert map to slice
	result := make([]string, 0, len(usedVars))
	for varName := range usedVars {
		result = append(result, varName)
	}

	return result
}

// getCommandSetEnvVars extracts environment variables set by an ENV command
// Returns a map of variable names to true if the command sets them
func (pe *ParallelExecutor) getCommandSetEnvVars(cmd commands.DockerCommand) map[string]bool {
	envVars := make(map[string]bool)

	// Try to get environment variables from EnvCommand
	// This requires type assertion to access the internal command
	cmdStr := cmd.String()
	if strings.HasPrefix(cmdStr, "ENV ") {
		// Parse ENV command: ENV KEY=value or ENV KEY value
		// Extract variable names from ENV command string
		envVarPattern := regexp.MustCompile(`ENV\s+([A-Za-z_][A-Za-z0-9_]*)\s*=?\s*`)
		matches := envVarPattern.FindAllStringSubmatch(cmdStr, -1)
		for _, match := range matches {
			if len(match) > 1 {
				varName := match[1]
				envVars[varName] = true
			}
		}
	}

	return envVars
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
	executionStartTime := time.Now()
	logrus.Info("🚀 Starting parallel command execution")

	// CRITICAL: Prepare common system directories writable ONCE before parallel execution
	// This prevents race conditions when multiple commands try to modify the same directories
	// This must be done BEFORE any commands start executing
	util.PrepareCommonSystemDirectoriesWritable()

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
	groupBuildStartTime := time.Now()
	executionGroups := pe.buildExecutionGroups()
	groupBuildDuration := time.Since(groupBuildStartTime)
	logrus.Debugf("⏱️  Built %d execution groups in %v", len(executionGroups), groupBuildDuration)

	// Execute each group in parallel
	for groupIndex, group := range executionGroups {
		groupStartTime := time.Now()
		logrus.Infof("📦 Executing group %d with %d commands", groupIndex, len(group))

		if err := pe.executeGroup(group, compositeKey, initSnapshotTaken); err != nil {
			return fmt.Errorf("failed to execute group %d: %w", groupIndex, err)
		}

		groupDuration := time.Since(groupStartTime)
		logrus.Debugf("⏱️  Group %d completed in %v (avg: %v per command)",
			groupIndex, groupDuration, groupDuration/time.Duration(len(group)))

		// IMPROVED: Sync filesystem after each group completes
		// This is critical for cross-stage dependencies - ensures all files are written
		// before the next stage tries to access them
		if err := util.SyncFilesystem(); err != nil {
			logrus.Warnf("⚠️ Failed to sync filesystem after group %d: %v, continuing anyway", groupIndex, err)
		} else {
			logrus.Debugf("✅ Filesystem synced after group %d completion", groupIndex)
		}
	}

	// IMPROVED: Final filesystem sync before returning
	// This ensures all files are committed to disk before cross-stage dependency search
	logrus.Debugf("🔄 Final filesystem sync after all groups completed")
	if err := util.SyncFilesystem(); err != nil {
		logrus.Warnf("⚠️ Failed to sync filesystem after all groups: %v, continuing anyway", err)
	}

	// Log execution statistics
	pe.logExecutionStats()

	executionDuration := time.Since(executionStartTime)
	logrus.Infof("✅ Parallel command execution completed in %v (%d groups, %d commands)",
		executionDuration, len(executionGroups), len(pe.commands))
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
// IMPROVED: Now also checks for filesystem conflicts between commands
// OPTIMIZED: Uses dependency index for O(1) lookup instead of O(n) linear search
func (pe *ParallelExecutor) canExecuteInParallel(cmd1Index, cmd2Index int) bool {
	// OPTIMIZED: Use dependency index for fast lookup
	pe.dependencyIndexMutex.RLock()
	cmd1Deps := pe.dependencyIndex[cmd1Index]
	cmd2Deps := pe.dependencyIndex[cmd2Index]
	pe.dependencyIndexMutex.RUnlock()

	// Check if cmd2 depends on cmd1 (O(1) lookup)
	if cmd1Deps != nil && cmd1Deps[cmd2Index] {
		return false
	}

	// Check if cmd1 depends on cmd2 (O(1) lookup)
	if cmd2Deps != nil && cmd2Deps[cmd1Index] {
		return false
	}

	// IMPROVED: Check for filesystem conflicts between commands
	// Commands that modify the same files/directories cannot run in parallel
	if pe.hasFilesystemConflict(cmd1Index, cmd2Index) {
		return false
	}

	return true
}

// hasFilesystemConflict checks if two commands conflict on filesystem operations
// This prevents race conditions when commands try to modify the same paths simultaneously
// OPTIMIZED: Uses caching to avoid recomputing paths for the same commands
func (pe *ParallelExecutor) hasFilesystemConflict(cmd1Index, cmd2Index int) bool {
	// Create cache key (order-independent)
	cacheKey := fmt.Sprintf("%d:%d", cmd1Index, cmd2Index)
	if cmd1Index > cmd2Index {
		cacheKey = fmt.Sprintf("%d:%d", cmd2Index, cmd1Index)
	}

	// Check cache first
	pe.conflictCacheMutex.RLock()
	if cached, found := pe.conflictCache[cacheKey]; found {
		pe.conflictCacheMutex.RUnlock()
		return cached
	}
	pe.conflictCacheMutex.RUnlock()

	cmd1 := pe.commands[cmd1Index]
	cmd2 := pe.commands[cmd2Index]

	if cmd1 == nil || cmd2 == nil {
		return false
	}

	// Get all files/paths that each command uses (with caching)
	cmd1Files := pe.getCachedCommandPaths(cmd1Index, cmd1)
	cmd2Files := pe.getCachedCommandPaths(cmd2Index, cmd2)

	// Check for overlapping paths
	result := pe.hasPathOverlap(cmd1Index, cmd1, cmd1Files, cmd2Index, cmd2, cmd2Files)

	// Cache the result
	pe.conflictCacheMutex.Lock()
	pe.conflictCache[cacheKey] = result
	pe.conflictCacheMutex.Unlock()

	return result
}

// getAllCommandPaths collects all paths that a command uses or creates
func (pe *ParallelExecutor) getAllCommandPaths(cmd commands.DockerCommand) map[string]bool {
	files := make(map[string]bool)

	// Get files created by command (if available)
	if cmd.ProvidesFilesToSnapshot() {
		for _, f := range cmd.FilesToSnapshot() {
			files[filepath.Clean(f)] = true
		}
	}

	// Get files used from context (COPY/ADD commands)
	if pe.config != nil && pe.args != nil {
		if filesUsed, err := cmd.FilesUsedFromContext(pe.imageConfig, pe.args); err == nil {
			for _, f := range filesUsed {
				files[filepath.Clean(f)] = true
			}
		}
	}

	// Extract paths from RUN commands (heuristic)
	runPaths := pe.extractPathsFromCommand(cmd)
	for _, path := range runPaths {
		files[filepath.Clean(path)] = true
	}

	return files
}

// getCachedCommandPaths gets command paths with caching to avoid recomputation
func (pe *ParallelExecutor) getCachedCommandPaths(cmdIndex int, cmd commands.DockerCommand) map[string]bool {
	// Check cache first
	pe.commandPathsCacheMutex.RLock()
	if cached, found := pe.commandPathsCache[cmdIndex]; found {
		pe.commandPathsCacheMutex.RUnlock()
		return cached
	}
	pe.commandPathsCacheMutex.RUnlock()

	// Compute paths
	paths := pe.getAllCommandPaths(cmd)

	// Store in cache
	pe.commandPathsCacheMutex.Lock()
	pe.commandPathsCache[cmdIndex] = paths
	pe.commandPathsCacheMutex.Unlock()

	return paths
}

// hasPathOverlap checks if two sets of paths overlap
func (pe *ParallelExecutor) hasPathOverlap(cmd1Index int, cmd1 commands.DockerCommand, cmd1Files map[string]bool,
	cmd2Index int, cmd2 commands.DockerCommand, cmd2Files map[string]bool) bool {
	for path1 := range cmd1Files {
		for path2 := range cmd2Files {
			// Check if paths overlap or one is parent of another
			if pe.pathsOverlap(path1, path2) {
				logrus.Debugf("🔍 Filesystem conflict detected: command %d (%s) and command %d (%s) both use path %s/%s",
					cmd1Index, cmd1.String(), cmd2Index, cmd2.String(), path1, path2)
				return true
			}
		}
	}
	return false
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
	// IMPROVED: Ensure context is always canceled to prevent goroutine leaks
	ctx, cancel := context.WithTimeout(context.Background(), pe.config.CommandTimeout)
	defer func() {
		// Ensure cancel is called to free resources
		cancel()
		// Give goroutines a moment to respond to cancellation
		time.Sleep(goroutineCleanupDelay)
	}()

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
	// IMPROVED: Collect all errors, not just the first one
	// This helps with debugging when multiple commands fail
	if err := g.Wait(); err != nil {
		// IMPROVED: Cleanup pending snapshots for canceled commands when error occurs
		pe.cleanupPendingSnapshotsOnError(ctx, &pendingSnapshots, &snapshotMutex)

		// IMPROVED: Log detailed error information for debugging
		pe.logExecutionStats()
		logrus.Errorf("❌ Group execution failed with error: %v", err)

		// Log which commands failed (if available in stats)
		pe.statsMutex.RLock()
		for idx, stats := range pe.executionStats {
			if !stats.Success && stats.ErrorMessage != "" {
				logrus.Errorf("  Command %d failed: %s", idx, stats.ErrorMessage)
			}
		}
		pe.statsMutex.RUnlock()

		return fmt.Errorf("group execution failed: %w", err)
	}

	// All commands completed successfully - now take snapshots sequentially
	return pe.takeSnapshotsSequentially(pendingSnapshots)
}

// takeSnapshotsSequentially takes snapshots for all commands in deterministic order
func (pe *ParallelExecutor) takeSnapshotsSequentially(pendingSnapshots []PendingSnapshot) error {
	logrus.Debugf("📸 All commands in group completed, taking snapshots sequentially for %d commands",
		len(pendingSnapshots))

	// CRITICAL: Sort snapshots by command index to ensure DETERMINISTIC order
	// This is essential for cache correctness and build reproducibility
	sortedSnapshots := pe.sortSnapshotsByIndex(pendingSnapshots)

	// Take snapshots and collect errors
	cacheGroup := &errgroup.Group{}
	snapshotErrors := pe.executeSnapshots(sortedSnapshots, cacheGroup)

	// Wait for cache operations with timeout
	pe.waitForCacheOperations(cacheGroup)

	// Return error if any snapshots failed
	if len(snapshotErrors) > 0 {
		if len(snapshotErrors) == 1 {
			return snapshotErrors[0]
		}
		return fmt.Errorf("multiple snapshot failures (%d): %v", len(snapshotErrors), snapshotErrors[0])
	}

	return nil
}

// sortSnapshotsByIndex sorts snapshots by command index and validates order
func (pe *ParallelExecutor) sortSnapshotsByIndex(pendingSnapshots []PendingSnapshot) []PendingSnapshot {
	sorted := make([]PendingSnapshot, len(pendingSnapshots))
	copy(sorted, pendingSnapshots)

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Index < sorted[j].Index
	})

	// Validate that snapshots are in correct order (debug check)
	for i := 1; i < len(sorted); i++ {
		if sorted[i].Index <= sorted[i-1].Index {
			logrus.Warnf("⚠️ Snapshot order validation failed: command %d comes before %d",
				sorted[i].Index, sorted[i-1].Index)
		}
	}

	return sorted
}

// executeSnapshots takes snapshots for all commands and collects errors
func (pe *ParallelExecutor) executeSnapshots(pendingSnapshots []PendingSnapshot, cacheGroup *errgroup.Group) []error {
	var snapshotErrors []error

	for _, pending := range pendingSnapshots {
		logrus.Debugf("📸 Taking snapshot for command %d: %s", pending.Index, pending.Command.String())
		if err := pe.stageBuilder.handleSnapshot(
			pending.Command, pending.Files, pending.CompositeKey, cacheGroup); err != nil {
			snapshotErr := fmt.Errorf("failed to take snapshot for command %d (%s): %w",
				pending.Index, pending.Command.String(), err)
			logrus.Errorf("❌ %v", snapshotErr)
			snapshotErrors = append(snapshotErrors, snapshotErr)
			continue
		}
		logrus.Debugf("✅ Snapshot completed for command %d", pending.Index)
	}

	return snapshotErrors
}

// waitForCacheOperations waits for cache operations to complete with timeout
func (pe *ParallelExecutor) waitForCacheOperations(cacheGroup *errgroup.Group) {
	cacheDone := make(chan error, 1)
	go func() {
		cacheDone <- cacheGroup.Wait()
	}()

	select {
	case err := <-cacheDone:
		if err != nil {
			logrus.Warnf("⚠️ Error in cache operations: %s", err)
		}
	case <-time.After(cacheOperationTimeout):
		logrus.Warnf("⚠️ Cache operations timed out after %v, continuing anyway", cacheOperationTimeout)
	}
}

// cleanupPendingSnapshotsOnError cleans up pending snapshots for commands that were canceled
// when an error occurs during parallel execution
func (pe *ParallelExecutor) cleanupPendingSnapshotsOnError(
	ctx context.Context,
	pendingSnapshots *[]PendingSnapshot,
	snapshotMutex *sync.Mutex,
) {
	snapshotMutex.Lock()
	defer snapshotMutex.Unlock()

	// Check if context was canceled - if so, clear all pending snapshots
	select {
	case <-ctx.Done():
		// Context was canceled - all remaining commands were canceled
		// Don't create snapshots for canceled commands
		canceledCount := len(*pendingSnapshots)
		if canceledCount > 0 {
			logrus.Infof("🧹 Cleaning up %d pending snapshots for canceled commands due to context cancellation", canceledCount)
			// Clear all pending snapshots
			*pendingSnapshots = make([]PendingSnapshot, 0)
		}
	default:
		// Context not canceled - snapshots are valid
		// No cleanup needed, snapshots will be processed normally
		logrus.Debugf("No cleanup needed: context not canceled, %d snapshots remain valid", len(*pendingSnapshots))
	}
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
	// IMPROVED: executeCommandOnly updates compositeKey, so we need to capture it AFTER execution
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

		// CRITICAL: Create a snapshot of compositeKey AFTER command execution and compositeKey update
		// This ensures each command gets the correct cache key state that includes its own update
		// The compositeKey was updated in executeCommandOnly, so we capture it here
		// Use mutex to ensure we get a consistent snapshot
		snapshotMutex.Lock()
		// CRITICAL: Copy compositeKey while holding mutex to ensure consistency
		// This snapshot will be used for cache key generation, so order matters
		cmdCompositeKey := CompositeCache{}
		// Deep copy the compositeKey keys to ensure snapshot is independent
		if compositeKey != nil {
			cmdCompositeKey.keys = make([]string, len(compositeKey.keys))
			copy(cmdCompositeKey.keys, compositeKey.keys)
		}

		*pendingSnapshots = append(*pendingSnapshots, PendingSnapshot{
			Command:      cmd,
			Index:        cmdIndex,
			Files:        files,
			CompositeKey: &cmdCompositeKey, // Copy of compositeKey AFTER command execution
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
	// IMPORTANT: While mutex ensures thread safety, the ORDER of updates may vary when commands
	// execute in parallel. However, this is acceptable because:
	// 1. Each command captures its own snapshot of compositeKey AFTER execution (line 770-774)
	// 2. The snapshot includes the command's own update, ensuring correct cache key for that command
	// 3. Snapshots are taken in deterministic order (by command index) after all commands complete
	// This ensures cache correctness while allowing parallel execution
	if pe.config.Cache {
		var err error
		var updatedKey CompositeCache
		pe.stageBuilder.mutex.Lock()
		// Create a copy of current compositeKey to avoid race conditions
		currentKey := *compositeKey
		updatedKey, err = pe.stageBuilder.populateCompositeKey(cmd, files, currentKey, pe.args, pe.imageConfig.Env)
		if err == nil {
			// Update shared compositeKey atomically
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

		// IMPROVED: Better error handling for init snapshot failures
		if pe.initSnapshotErr != nil {
			logrus.Errorf("❌ Init snapshot failed: %v", pe.initSnapshotErr)
			return fmt.Errorf("init snapshot failed (required for command %d): %w", cmdIndex, pe.initSnapshotErr)
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
