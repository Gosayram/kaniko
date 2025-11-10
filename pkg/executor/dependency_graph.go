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
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/Gosayram/kaniko/pkg/commands"
	"github.com/Gosayram/kaniko/pkg/dockerfile"
)

// CommandNode represents a command in the dependency graph
// This provides explicit representation of dependencies between commands
type CommandNode struct {
	Index        int
	Command      commands.DockerCommand
	Dependencies []int // Indices of commands this node depends on
	Dependents   []int // Indices of commands that depend on this node
}

// DependencyGraph represents the dependency graph of commands
// Inspired by BuildKit LLB's explicit dependency representation
type DependencyGraph struct {
	nodes map[int]*CommandNode
	order []int // Topological execution order
	mutex sync.RWMutex
}

// NewDependencyGraph creates a new empty dependency graph
func NewDependencyGraph() *DependencyGraph {
	return &DependencyGraph{
		nodes: make(map[int]*CommandNode),
		order: []int{},
	}
}

// BuildDependencyGraph builds a dependency graph from a list of commands
func BuildDependencyGraph(
	cmds []commands.DockerCommand,
	config *v1.Config,
	buildArgs *dockerfile.BuildArgs,
) (*DependencyGraph, error) {
	graph := NewDependencyGraph()

	// Create nodes for all commands
	for i, cmd := range cmds {
		if cmd == nil {
			continue
		}
		graph.nodes[i] = &CommandNode{
			Index:        i,
			Command:      cmd,
			Dependencies: []int{},
			Dependents:   []int{},
		}
	}

	// Find dependencies for each command
	for i, cmd := range cmds {
		if cmd == nil {
			continue
		}
		node := graph.nodes[i]
		if node == nil {
			continue
		}

		// Analyze dependencies
		deps := findCommandDependencies(i, cmd, cmds, config, buildArgs)
		node.Dependencies = deps

		// Update dependents for each dependency
		for _, dep := range deps {
			if depNode := graph.nodes[dep]; depNode != nil {
				depNode.Dependents = append(depNode.Dependents, i)
			}
		}
	}

	// Perform topological sort to determine execution order
	order, err := graph.topologicalSort()
	if err != nil {
		return nil, errors.Wrap(err, "failed to perform topological sort")
	}
	graph.order = order

	logrus.Debugf("Built dependency graph: %d nodes, execution order: %v", len(graph.nodes), order)
	return graph, nil
}

// findCommandDependencies finds dependencies for a specific command
func findCommandDependencies(
	index int,
	cmd commands.DockerCommand,
	allCommands []commands.DockerCommand,
	config *v1.Config,
	buildArgs *dockerfile.BuildArgs,
) []int {
	dependencies := []int{}

	// Try to get files used by this command for more accurate dependency detection
	var filesUsed []string
	// Use provided config and buildArgs, or create empty ones if not provided
	cfg := config
	if cfg == nil {
		cfg = &v1.Config{}
	}
	if files, err := cmd.FilesUsedFromContext(cfg, buildArgs); err == nil {
		filesUsed = files
	}

	// Find dependencies based on file usage (more accurate)
	if len(filesUsed) > 0 {
		// Check if any previous command creates/modifies files that this command uses
		for i := index - 1; i >= 0; i-- {
			if allCommands[i] == nil {
				continue
			}

			// Check if previous command might affect files used by current command
			if hasFileConflict(allCommands[i], filesUsed) {
				dependencies = append(dependencies, i)
				break // Only track the most recent conflicting command
			}
		}
	}

	// Fallback: Find the last command that modifies filesystem (conservative approach)
	// This ensures proper ordering for filesystem operations
	if len(dependencies) == 0 {
		for i := index - 1; i >= 0; i-- {
			if allCommands[i] == nil {
				continue
			}

			// If previous command modifies filesystem, it's a dependency
			if !allCommands[i].MetadataOnly() {
				dependencies = append(dependencies, i)
				break // Only track the most recent filesystem-modifying command
			}
		}
	}

	return dependencies
}

// hasFileConflict checks if a command might conflict with files used by another command
func hasFileConflict(cmd commands.DockerCommand, filesUsed []string) bool {
	// If command only affects metadata, no filesystem conflict
	if cmd.MetadataOnly() {
		return false
	}

	// Get files that this command creates/modifies
	filesCreated := cmd.FilesToSnapshot()
	if len(filesCreated) == 0 && !cmd.ProvidesFilesToSnapshot() {
		// Command modifies filesystem but doesn't provide file list
		// Conservative approach: assume it might conflict
		return true
	}

	// Check if any created file matches or is in a directory used by other command
	for _, created := range filesCreated {
		cleanCreated := filepath.Clean(created)
		for _, used := range filesUsed {
			cleanUsed := filepath.Clean(used)

			// Direct match
			if cleanCreated == cleanUsed {
				return true
			}

			// Check if created file is in a directory used by other command
			if isParentDirectory(cleanCreated, cleanUsed) {
				return true
			}

			// Check if created directory contains files used by other command
			if isParentDirectory(cleanUsed, cleanCreated) {
				return true
			}
		}
	}

	return false
}

// isParentDirectory checks if path1 is a parent directory of path2
func isParentDirectory(path1, path2 string) bool {
	rel, err := filepath.Rel(path1, path2)
	if err != nil {
		return false
	}
	// If path2 is within path1, Rel will not start with ".."
	return !strings.HasPrefix(rel, "..") && rel != "."
}

// topologicalSort performs topological sorting using Kahn's algorithm
// Returns the execution order and error if cycle is detected
func (g *DependencyGraph) topologicalSort() ([]int, error) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	// Calculate in-degree for each node
	inDegree := make(map[int]int)
	for i := range g.nodes {
		inDegree[i] = 0
	}

	// Build reverse graph and calculate in-degrees
	for i, node := range g.nodes {
		for _, dep := range node.Dependencies {
			inDegree[i]++
			// Update dependents if not already present
			if !contains(g.nodes[dep].Dependents, i) {
				g.nodes[dep].Dependents = append(g.nodes[dep].Dependents, i)
			}
		}
	}

	// Find nodes with no dependencies (in-degree = 0)
	queue := []int{}
	for i, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, i)
		}
	}
	// Sort to ensure stable execution order
	sort.Ints(queue)

	order := []int{}

	// Process nodes in topological order
	for len(queue) > 0 {
		// Get next node with no dependencies
		current := queue[0]
		queue = queue[1:]
		order = append(order, current)

		// Decrease in-degree for dependents
		node := g.nodes[current]
		if node != nil {
			for _, dependent := range node.Dependents {
				inDegree[dependent]--
				if inDegree[dependent] == 0 {
					queue = append(queue, dependent)
				}
			}
		}
		// Keep queue sorted for stable order
		sort.Ints(queue)
	}

	// Check for cycles (nodes not in order)
	if len(order) < len(g.nodes) {
		missing := []int{}
		for i := range g.nodes {
			if !contains(order, i) {
				missing = append(missing, i)
			}
		}
		return nil, fmt.Errorf("circular dependency detected: nodes %v are part of a cycle", missing)
	}

	return order, nil
}

// GetExecutionOrder returns the topological execution order
func (g *DependencyGraph) GetExecutionOrder() []int {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.order
}

// GetNode returns a node by index
func (g *DependencyGraph) GetNode(index int) *CommandNode {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.nodes[index]
}

// GetIndependentCommands returns commands that can be executed in parallel
// (commands with no dependencies or all dependencies already executed)
func (g *DependencyGraph) GetIndependentCommands(executed map[int]bool) []int {
	g.mutex.RLock()
	defer g.mutex.RUnlock()

	independent := []int{}
	for i, node := range g.nodes {
		if executed[i] {
			continue
		}

		// Check if all dependencies are executed
		allDepsExecuted := true
		for _, dep := range node.Dependencies {
			if !executed[dep] {
				allDepsExecuted = false
				break
			}
		}

		if allDepsExecuted {
			independent = append(independent, i)
		}
	}

	// Sort for stable order
	sort.Ints(independent)
	return independent
}

// GetDependencies returns dependencies for a command
func (g *DependencyGraph) GetDependencies(index int) []int {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	if node := g.nodes[index]; node != nil {
		return node.Dependencies
	}
	return []int{}
}

// GetDependents returns commands that depend on this command
func (g *DependencyGraph) GetDependents(index int) []int {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	if node := g.nodes[index]; node != nil {
		return node.Dependents
	}
	return []int{}
}

// String returns a string representation of the graph
func (g *DependencyGraph) String() string {
	g.mutex.RLock()
	defer g.mutex.RUnlock()

	result := fmt.Sprintf("DependencyGraph (%d nodes):\n", len(g.nodes))
	for i, node := range g.nodes {
		result += fmt.Sprintf("  Node %d: deps=%v, dependents=%v\n", i, node.Dependencies, node.Dependents)
	}
	result += fmt.Sprintf("Execution order: %v\n", g.order)
	return result
}

// contains checks if a slice contains a value
func contains(slice []int, value int) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}
