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

// Package llb provides LLB-like intermediate representation for build graph optimization.
// This is inspired by BuildKit's LLB (Low-Level Builder) format, which allows
// for graph optimization before execution, including edge merging and parallelization.
package llb

import (
	"context"
	"fmt"
	"strings"
	"sync"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/Gosayram/kaniko/pkg/commands"
)

// OpType represents the type of operation
type OpType string

const (
	// OpTypeCommand represents a Dockerfile command operation
	OpTypeCommand OpType = "command"
	// OpTypeCopy represents a copy operation
	OpTypeCopy OpType = "copy"
	// OpTypeRun represents a run operation
	OpTypeRun OpType = "run"
	// OpTypeMetadata represents a metadata-only operation
	OpTypeMetadata OpType = "metadata"
	// String builder capacity estimates
	stringBuilderHeaderSize = 128 // Estimated header size in bytes
	stringBuilderOpSize     = 64  // Estimated size per operation in bytes
)

// Operation represents a single operation in the build graph
// Similar to BuildKit's LLB operation, this allows for graph optimization
type Operation struct {
	// ID is a unique identifier for this operation
	ID string

	// Type of operation
	Type OpType

	// Command is the Dockerfile command to execute
	Command commands.DockerCommand

	// Dependencies are operations that must complete before this one
	Dependencies []*Operation

	// Dependents are operations that depend on this one
	Dependents []*Operation

	// CacheKey is the cache key for this operation
	CacheKey string

	// Result holds the result of the operation after execution
	Result *Result

	// Metadata for operation tracking
	Index int

	// Mutex for thread-safe access
	mu sync.RWMutex
}

// Result represents the result of an operation
type Result struct {
	// Image is the resulting image after operation execution
	Image v1.Image

	// Digest is the digest of the resulting layer
	Digest string

	// SnapshotPath is the path to the filesystem snapshot
	SnapshotPath string

	// Error if operation failed
	Error error

	// Completed indicates if operation has completed
	Completed bool

	mu sync.RWMutex
}

// NewResult creates a new result
func NewResult() *Result {
	return &Result{
		Completed: false,
	}
}

// SetImage sets the image result
func (r *Result) SetImage(img v1.Image) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Image = img
}

// SetDigest sets the digest result
func (r *Result) SetDigest(digest string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Digest = digest
}

// SetError sets the error result
func (r *Result) SetError(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Error = err
	r.Completed = true
}

// SetCompleted marks the result as completed
func (r *Result) SetCompleted() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Completed = true
}

// IsCompleted returns whether the result is completed
func (r *Result) IsCompleted() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.Completed
}

// GetImage returns the image result
func (r *Result) GetImage() v1.Image {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.Image
}

// GetError returns the error if any
func (r *Result) GetError() error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.Error
}

// NewOperation creates a new operation
func NewOperation(id string, opType OpType, cmd commands.DockerCommand, index int) *Operation {
	return &Operation{
		ID:           id,
		Type:         opType,
		Command:      cmd,
		Dependencies: []*Operation{},
		Dependents:   []*Operation{},
		Index:        index,
		Result:       NewResult(),
	}
}

// AddDependency adds a dependency to this operation
func (op *Operation) AddDependency(dep *Operation) {
	op.mu.Lock()
	defer op.mu.Unlock()

	// Check if already added
	for _, existing := range op.Dependencies {
		if existing.ID == dep.ID {
			return
		}
	}

	op.Dependencies = append(op.Dependencies, dep)

	// Add this operation as a dependent of the dependency
	dep.mu.Lock()
	defer dep.mu.Unlock()
	for _, existing := range dep.Dependents {
		if existing.ID == op.ID {
			return
		}
	}
	dep.Dependents = append(dep.Dependents, op)
}

// GetDependencies returns a copy of dependencies
func (op *Operation) GetDependencies() []*Operation {
	op.mu.RLock()
	defer op.mu.RUnlock()
	deps := make([]*Operation, len(op.Dependencies))
	copy(deps, op.Dependencies)
	return deps
}

// GetDependents returns a copy of dependents
func (op *Operation) GetDependents() []*Operation {
	op.mu.RLock()
	defer op.mu.RUnlock()
	deps := make([]*Operation, len(op.Dependents))
	copy(deps, op.Dependents)
	return deps
}

// SetCacheKey sets the cache key for this operation
func (op *Operation) SetCacheKey(key string) {
	op.mu.Lock()
	defer op.mu.Unlock()
	op.CacheKey = key
}

// GetCacheKey returns the cache key
func (op *Operation) GetCacheKey() string {
	op.mu.RLock()
	defer op.mu.RUnlock()
	return op.CacheKey
}

// Graph represents the complete build graph
type Graph struct {
	// Operations is the list of all operations
	Operations []*Operation

	// Root is the root operation (if any)
	Root *Operation

	// mu protects graph operations
	mu sync.RWMutex
}

// NewGraph creates a new empty graph
func NewGraph() *Graph {
	return &Graph{
		Operations: []*Operation{},
	}
}

// AddOperation adds an operation to the graph
func (g *Graph) AddOperation(op *Operation) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.Operations = append(g.Operations, op)
}

// BuildGraphFromCommands builds a graph from Dockerfile commands
// This converts the command list into an optimized graph structure
func BuildGraphFromCommands(cmds []commands.DockerCommand) (*Graph, error) {
	graph := NewGraph()
	ops := make([]*Operation, len(cmds))

	// Create operations for all commands
	for i, cmd := range cmds {
		if cmd == nil {
			continue
		}

		opType := determineOpType(cmd)
		op := NewOperation(fmt.Sprintf("op-%d", i), opType, cmd, i)
		ops[i] = op
		graph.AddOperation(op)
	}

	// Build dependencies based on command analysis
	for i, op := range ops {
		if op == nil {
			continue
		}

		// Find dependencies for this operation
		deps := findOperationDependencies(i, op.Command, cmds, ops)
		for _, dep := range deps {
			if dep != nil {
				op.AddDependency(dep)
			}
		}
	}

	// Set root operation (first operation with no dependencies)
	for _, op := range ops {
		if op != nil && len(op.GetDependencies()) == 0 {
			graph.mu.Lock()
			graph.Root = op
			graph.mu.Unlock()
			break
		}
	}

	logrus.Debugf("Built LLB graph: %d operations", len(graph.Operations))
	return graph, nil
}

// determineOpType determines the operation type from a command
func determineOpType(cmd commands.DockerCommand) OpType {
	if cmd.MetadataOnly() {
		return OpTypeMetadata
	}

	cmdStr := cmd.String()
	if len(cmdStr) > 4 && cmdStr[:4] == "COPY" {
		return OpTypeCopy
	}
	if len(cmdStr) > 3 && cmdStr[:3] == "RUN" {
		return OpTypeRun
	}

	return OpTypeCommand
}

// findOperationDependencies finds dependencies for an operation
func findOperationDependencies(
	index int,
	_ commands.DockerCommand,
	allCommands []commands.DockerCommand,
	ops []*Operation,
) []*Operation {
	dependencies := []*Operation{}

	// Find the last operation that modifies filesystem
	for i := index - 1; i >= 0; i-- {
		if allCommands[i] == nil || ops[i] == nil {
			continue
		}

		// If previous command modifies filesystem, it's a dependency
		if !allCommands[i].MetadataOnly() {
			dependencies = append(dependencies, ops[i])
			break // Only track the most recent filesystem-modifying command
		}
	}

	return dependencies
}

// GetExecutionOrder returns operations in topological order
func (g *Graph) GetExecutionOrder() ([]*Operation, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// Use Kahn's algorithm for topological sort
	inDegree := make(map[string]int)
	queue := []*Operation{}

	// Calculate in-degrees
	for _, op := range g.Operations {
		inDegree[op.ID] = 0
	}

	for _, op := range g.Operations {
		deps := op.GetDependencies()
		for range deps {
			inDegree[op.ID]++
		}
	}

	// Find operations with no dependencies
	for _, op := range g.Operations {
		if inDegree[op.ID] == 0 {
			queue = append(queue, op)
		}
	}

	order := []*Operation{}

	// Process queue
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		order = append(order, current)

		// Decrease in-degree for dependents
		dependents := current.GetDependents()
		for _, dependent := range dependents {
			inDegree[dependent.ID]--
			if inDegree[dependent.ID] == 0 {
				queue = append(queue, dependent)
			}
		}
	}

	// Check for cycles
	if len(order) < len(g.Operations) {
		return nil, errors.New("circular dependency detected in graph")
	}

	return order, nil
}

// GetIndependentOperations returns operations that can be executed in parallel
func (g *Graph) GetIndependentOperations(executed map[string]bool) []*Operation {
	g.mu.RLock()
	defer g.mu.RUnlock()

	independent := []*Operation{}
	for _, op := range g.Operations {
		if executed[op.ID] {
			continue
		}

		// Check if all dependencies are executed
		allDepsExecuted := true
		deps := op.GetDependencies()
		for _, dep := range deps {
			if !executed[dep.ID] {
				allDepsExecuted = false
				break
			}
		}

		if allDepsExecuted {
			independent = append(independent, op)
		}
	}

	return independent
}

// Optimize optimizes the graph by merging identical operations
// This is similar to BuildKit's edge merging
func (g *Graph) Optimize(_ context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	logrus.Debugf("Optimizing graph with %d operations", len(g.Operations))

	// Find operations with identical cache keys (potential merges)
	cacheKeyMap := make(map[string][]*Operation)
	for _, op := range g.Operations {
		if op.CacheKey != "" {
			cacheKeyMap[op.CacheKey] = append(cacheKeyMap[op.CacheKey], op)
		}
	}

	// Merge operations with identical cache keys and same command
	merged := make(map[string]bool)
	for _, ops := range cacheKeyMap {
		if len(ops) <= 1 {
			continue
		}

		// Check if operations are truly identical (same command, same dependencies)
		for i := 0; i < len(ops); i++ {
			if merged[ops[i].ID] {
				continue
			}

			for j := i + 1; j < len(ops); j++ {
				if merged[ops[j].ID] {
					continue
				}

				if areOperationsIdentical(ops[i], ops[j]) {
					// Merge operation j into operation i
					g.mergeOperations(ops[i], ops[j])
					merged[ops[j].ID] = true
					logrus.Debugf("Merged operation %s into %s", ops[j].ID, ops[i].ID)
				}
			}
		}
	}

	// Remove merged operations
	newOps := []*Operation{}
	for _, op := range g.Operations {
		if !merged[op.ID] {
			newOps = append(newOps, op)
		}
	}
	g.Operations = newOps

	logrus.Debugf("Optimized graph: %d operations (merged %d)", len(g.Operations), len(merged))
	return nil
}

// areOperationsIdentical checks if two operations are identical
func areOperationsIdentical(op1, op2 *Operation) bool {
	// Same command string
	if op1.Command.String() != op2.Command.String() {
		return false
	}

	// Same type
	if op1.Type != op2.Type {
		return false
	}

	// Same number of dependencies
	deps1 := op1.GetDependencies()
	deps2 := op2.GetDependencies()
	if len(deps1) != len(deps2) {
		return false
	}

	// Check if dependencies are the same
	depSet1 := make(map[string]bool)
	for _, dep := range deps1 {
		depSet1[dep.ID] = true
	}

	for _, dep := range deps2 {
		if !depSet1[dep.ID] {
			return false
		}
	}

	return true
}

// mergeOperations merges op2 into op1
func (g *Graph) mergeOperations(op1, op2 *Operation) {
	// Add op2's dependents to op1
	dependents2 := op2.GetDependents()
	for _, dependent := range dependents2 {
		// Remove op2 from dependent's dependencies
		dependent.mu.Lock()
		newDeps := []*Operation{}
		for _, dep := range dependent.Dependencies {
			if dep.ID != op2.ID {
				newDeps = append(newDeps, dep)
			}
		}
		// Add op1 if not already present
		hasOp1 := false
		for _, dep := range newDeps {
			if dep.ID == op1.ID {
				hasOp1 = true
				break
			}
		}
		if !hasOp1 {
			newDeps = append(newDeps, op1)
		}
		dependent.Dependencies = newDeps
		dependent.mu.Unlock()

		// Update op1's dependents
		op1.mu.Lock()
		hasDependent := false
		for _, dep := range op1.Dependents {
			if dep.ID == dependent.ID {
				hasDependent = true
				break
			}
		}
		if !hasDependent {
			op1.Dependents = append(op1.Dependents, dependent)
		}
		op1.mu.Unlock()
	}
}

// String returns a string representation of the graph
func (g *Graph) String() string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// Optimized: use strings.Builder instead of string concatenation (reduces CPU usage)
	var b strings.Builder
	// Pre-allocate capacity for better performance
	b.Grow(stringBuilderHeaderSize + len(g.Operations)*stringBuilderOpSize)

	b.WriteString(fmt.Sprintf("Graph (%d operations):\n", len(g.Operations)))
	for _, op := range g.Operations {
		deps := op.GetDependencies()
		depIDs := make([]string, len(deps))
		for i, dep := range deps {
			depIDs[i] = dep.ID
		}
		b.WriteString(fmt.Sprintf("  %s: deps=%v\n", op.ID, depIDs))
	}
	return b.String()
}
