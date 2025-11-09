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

// Package scheduler provides a BuildKit-inspired scheduler with edge merging
// for efficient build graph execution.
package scheduler

import (
	"context"
	"fmt"
	"sync"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/Gosayram/kaniko/pkg/llb"
)

// EdgeState represents the state of an edge
type EdgeState int

const (
	// EdgeStatePending means the edge is waiting for dependencies
	EdgeStatePending EdgeState = iota
	// EdgeStateReady means the edge is ready to execute
	EdgeStateReady
	// EdgeStateExecuting means the edge is currently executing
	EdgeStateExecuting
	// EdgeStateCompleted means the edge has completed successfully
	EdgeStateCompleted
	// EdgeStateFailed means the edge has failed
	EdgeStateFailed
)

// Edge represents an edge in the execution graph
// Similar to BuildKit's edge concept, this allows for merging identical operations
type Edge struct {
	// ID is a unique identifier
	ID string

	// Op is the operation this edge represents
	Op *llb.Operation

	// State is the current state of the edge
	State EdgeState

	// Deps are edges that must complete before this one
	Deps []*Edge

	// CacheKey is the cache key for this edge
	CacheKey string

	// mu protects edge state
	mu sync.RWMutex
}

// NewEdge creates a new edge
func NewEdge(id string, op *llb.Operation) *Edge {
	return &Edge{
		ID:    id,
		Op:    op,
		State: EdgeStatePending,
		Deps:  []*Edge{},
	}
}

// SetState sets the edge state
func (e *Edge) SetState(state EdgeState) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.State = state
}

// GetState returns the edge state
func (e *Edge) GetState() EdgeState {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.State
}

// AddDependency adds a dependency edge
func (e *Edge) AddDependency(dep *Edge) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Check if already added
	for _, existing := range e.Deps {
		if existing.ID == dep.ID {
			return
		}
	}

	e.Deps = append(e.Deps, dep)
}

// GetDependencies returns a copy of dependencies
func (e *Edge) GetDependencies() []*Edge {
	e.mu.RLock()
	defer e.mu.RUnlock()
	deps := make([]*Edge, len(e.Deps))
	copy(deps, e.Deps)
	return deps
}

// SetCacheKey sets the cache key
func (e *Edge) SetCacheKey(key string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.CacheKey = key
}

// GetCacheKey returns the cache key
func (e *Edge) GetCacheKey() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.CacheKey
}

// EdgePipe represents a pipe between edges
type EdgePipe struct {
	From *Edge
	To   *Edge
}

// Scheduler manages the execution of a build graph
// Inspired by BuildKit's scheduler, this provides edge merging and efficient execution
type Scheduler struct {
	// edges maps edge ID to edge
	edges map[string]*Edge

	// waitq contains edges waiting for dependencies
	waitq map[*Edge]struct{}

	// incoming maps edge to incoming pipes
	incoming map[*Edge][]*EdgePipe

	// outgoing maps edge to outgoing pipes
	outgoing map[*Edge][]*EdgePipe

	// mu protects scheduler state
	mu sync.RWMutex
}

// NewScheduler creates a new scheduler
func NewScheduler() *Scheduler {
	return &Scheduler{
		edges:    make(map[string]*Edge),
		waitq:    make(map[*Edge]struct{}),
		incoming: make(map[*Edge][]*EdgePipe),
		outgoing: make(map[*Edge][]*EdgePipe),
	}
}

// BuildFromGraph builds a scheduler from an LLB graph
func BuildFromGraph(graph *llb.Graph) (*Scheduler, error) {
	scheduler := NewScheduler()

	// Create edges from operations
	ops := graph.Operations
	for _, op := range ops {
		edgeID := fmt.Sprintf("edge-%s", op.ID)
		edge := NewEdge(edgeID, op)
		edge.SetCacheKey(op.GetCacheKey())
		scheduler.edges[edgeID] = edge
	}

	// Build dependencies
	for _, op := range ops {
		edgeID := fmt.Sprintf("edge-%s", op.ID)
		edge := scheduler.edges[edgeID]
		if edge == nil {
			continue
		}

		deps := op.GetDependencies()
		for _, dep := range deps {
			depEdgeID := fmt.Sprintf("edge-%s", dep.ID)
			depEdge := scheduler.edges[depEdgeID]
			if depEdge != nil {
				edge.AddDependency(depEdge)

				// Create pipe
				pipe := &EdgePipe{
					From: depEdge,
					To:   edge,
				}
				scheduler.incoming[edge] = append(scheduler.incoming[edge], pipe)
				scheduler.outgoing[depEdge] = append(scheduler.outgoing[depEdge], pipe)
			}
		}
	}

	// Initialize wait queue with edges that have dependencies
	for _, edge := range scheduler.edges {
		if len(edge.GetDependencies()) > 0 {
			scheduler.waitq[edge] = struct{}{}
		}
	}

	logrus.Debugf("Built scheduler with %d edges", len(scheduler.edges))
	return scheduler, nil
}

// MergeEdges merges two identical edges
// This is similar to BuildKit's edge merging optimization
func (s *Scheduler) MergeEdges(edge1, edge2 *Edge) (*Edge, error) {
	if err := validateMergeEdges(edge1, edge2); err != nil {
		return nil, err
	}

	if edge1.ID == edge2.ID {
		return edge1, nil
	}

	if !areEdgesIdentical(edge1, edge2) {
		return nil, errors.New("edges are not identical, cannot merge")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	logrus.Debugf("Merging edges %s and %s", edge1.ID, edge2.ID)

	s.mergeIncomingPipes(edge1, edge2)
	s.mergeOutgoingPipes(edge1, edge2)
	s.updateDependentEdges(edge1, edge2)
	s.removeEdge(edge2)

	logrus.Debugf("Merged edge %s into %s", edge2.ID, edge1.ID)
	return edge1, nil
}

func validateMergeEdges(edge1, edge2 *Edge) error {
	if edge1 == nil || edge2 == nil {
		return errors.New("cannot merge nil edges")
	}
	return nil
}

func (s *Scheduler) mergeIncomingPipes(edge1, edge2 *Edge) {
	if pipes, ok := s.incoming[edge2]; ok {
		for _, pipe := range pipes {
			pipe.To = edge1
			s.incoming[edge1] = append(s.incoming[edge1], pipe)
		}
		delete(s.incoming, edge2)
	}
}

func (s *Scheduler) mergeOutgoingPipes(edge1, edge2 *Edge) {
	if pipes, ok := s.outgoing[edge2]; ok {
		for _, pipe := range pipes {
			pipe.From = edge1
			s.outgoing[edge1] = append(s.outgoing[edge1], pipe)
		}
		delete(s.outgoing, edge2)
	}
}

func (s *Scheduler) updateDependentEdges(edge1, edge2 *Edge) {
	for _, edge := range s.edges {
		if s.hasDependency(edge, edge2) {
			s.replaceDependency(edge, edge1, edge2)
		}
	}
}

func (s *Scheduler) hasDependency(edge, dep *Edge) bool {
	deps := edge.GetDependencies()
	for _, d := range deps {
		if d.ID == dep.ID {
			return true
		}
	}
	return false
}

func (s *Scheduler) replaceDependency(edge, edge1, edge2 *Edge) {
	edge.mu.Lock()
	defer edge.mu.Unlock()

	newDeps := []*Edge{}
	hasEdge1 := false
	for _, dep := range edge.Deps {
		if dep.ID == edge2.ID {
			continue
		}
		if dep.ID == edge1.ID {
			hasEdge1 = true
		}
		newDeps = append(newDeps, dep)
	}
	if !hasEdge1 {
		newDeps = append(newDeps, edge1)
	}
	edge.Deps = newDeps
}

func (s *Scheduler) removeEdge(edge2 *Edge) {
	delete(s.edges, edge2.ID)
	delete(s.waitq, edge2)
}

// areEdgesIdentical checks if two edges are identical
func areEdgesIdentical(e1, e2 *Edge) bool {
	// Same operation
	if e1.Op.ID != e2.Op.ID {
		return false
	}

	// Same cache key
	if e1.GetCacheKey() != e2.GetCacheKey() {
		return false
	}

	// Same number of dependencies
	deps1 := e1.GetDependencies()
	deps2 := e2.GetDependencies()
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

// Optimize optimizes the scheduler by merging identical edges
func (s *Scheduler) Optimize(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	logrus.Debugf("Optimizing scheduler with %d edges", len(s.edges))

	// Find edges with identical cache keys
	cacheKeyMap := make(map[string][]*Edge)
	for _, edge := range s.edges {
		cacheKey := edge.GetCacheKey()
		if cacheKey != "" {
			cacheKeyMap[cacheKey] = append(cacheKeyMap[cacheKey], edge)
		}
	}

	// Merge edges with identical cache keys
	merged := make(map[string]bool)
	for cacheKey, edges := range cacheKeyMap {
		if len(edges) <= 1 {
			continue
		}

		logrus.Debugf("Found %d edges with cache key %s", len(edges), cacheKey)

		// Check if edges are truly identical
		for i := 0; i < len(edges); i++ {
			if merged[edges[i].ID] {
				continue
			}

			for j := i + 1; j < len(edges); j++ {
				if merged[edges[j].ID] {
					continue
				}

				if areEdgesIdentical(edges[i], edges[j]) {
					// Merge edge j into edge i
					if _, err := s.MergeEdges(edges[i], edges[j]); err != nil {
						logrus.Warnf("Failed to merge edges: %v", err)
						continue
					}
					merged[edges[j].ID] = true
				}
			}
		}
	}

	logrus.Debugf("Optimized scheduler: %d edges (merged %d)", len(s.edges), len(merged))
	return nil
}

// GetReadyEdges returns edges that are ready to execute
func (s *Scheduler) GetReadyEdges() []*Edge {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ready := []*Edge{}
	for _, edge := range s.edges {
		state := edge.GetState()
		if state != EdgeStatePending && state != EdgeStateReady {
			continue
		}

		// Check if all dependencies are completed
		allDepsCompleted := true
		deps := edge.GetDependencies()
		for _, dep := range deps {
			if dep.GetState() != EdgeStateCompleted {
				allDepsCompleted = false
				break
			}
		}

		if allDepsCompleted && len(deps) > 0 || len(deps) == 0 {
			ready = append(ready, edge)
		}
	}

	return ready
}

// MarkEdgeCompleted marks an edge as completed
func (s *Scheduler) MarkEdgeCompleted(edgeID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	edge := s.edges[edgeID]
	if edge != nil {
		edge.SetState(EdgeStateCompleted)
		delete(s.waitq, edge)
	}
}

// MarkEdgeFailed marks an edge as failed
func (s *Scheduler) MarkEdgeFailed(edgeID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	edge := s.edges[edgeID]
	if edge != nil {
		edge.SetState(EdgeStateFailed)
		delete(s.waitq, edge)
	}
}

// GetEdge returns an edge by ID
func (s *Scheduler) GetEdge(edgeID string) *Edge {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.edges[edgeID]
}

// GetAllEdges returns all edges
func (s *Scheduler) GetAllEdges() []*Edge {
	s.mu.RLock()
	defer s.mu.RUnlock()

	edges := make([]*Edge, 0, len(s.edges))
	for _, edge := range s.edges {
		edges = append(edges, edge)
	}
	return edges
}

// String returns a string representation of the scheduler
func (s *Scheduler) String() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := fmt.Sprintf("Scheduler (%d edges):\n", len(s.edges))
	for _, edge := range s.edges {
		deps := edge.GetDependencies()
		depIDs := make([]string, len(deps))
		for i, dep := range deps {
			depIDs[i] = dep.ID
		}
		result += fmt.Sprintf("  %s [%v]: deps=%v\n", edge.ID, edge.GetState(), depIDs)
	}
	return result
}
