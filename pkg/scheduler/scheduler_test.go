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

package scheduler

import (
	"context"
	"testing"

	"github.com/Gosayram/kaniko/pkg/llb"
)

func TestNewScheduler(t *testing.T) {
	scheduler := NewScheduler()
	if scheduler == nil {
		t.Fatal("Scheduler is nil")
	}

	if scheduler.edges == nil {
		t.Error("Scheduler edges map is nil")
	}

	if scheduler.waitq == nil {
		t.Error("Scheduler waitq map is nil")
	}
}

func TestBuildFromGraph(t *testing.T) {
	// Create a simple LLB graph
	graph := llb.NewGraph()
	op1 := llb.NewOperation("op1", llb.OpTypeCommand, nil, 0)
	op2 := llb.NewOperation("op2", llb.OpTypeCommand, nil, 1)
	op2.AddDependency(op1)

	graph.AddOperation(op1)
	graph.AddOperation(op2)

	scheduler, err := BuildFromGraph(graph)
	if err != nil {
		t.Fatalf("Failed to build scheduler: %v", err)
	}

	if scheduler == nil {
		t.Fatal("Scheduler is nil")
	}

	if len(scheduler.edges) != 2 {
		t.Errorf("Expected 2 edges, got %d", len(scheduler.edges))
	}
}

func TestSchedulerOptimize(t *testing.T) {
	graph := llb.NewGraph()
	op1 := llb.NewOperation("op1", llb.OpTypeCommand, nil, 0)
	op1.SetCacheKey("key1")
	op2 := llb.NewOperation("op2", llb.OpTypeCommand, nil, 1)
	op2.SetCacheKey("key1") // Same cache key for merging

	graph.AddOperation(op1)
	graph.AddOperation(op2)

	scheduler, err := BuildFromGraph(graph)
	if err != nil {
		t.Fatalf("Failed to build scheduler: %v", err)
	}

	initialCount := len(scheduler.edges)

	ctx := context.Background()
	if err := scheduler.Optimize(ctx); err != nil {
		t.Fatalf("Failed to optimize scheduler: %v", err)
	}

	// After optimization, edges with identical cache keys may be merged
	if len(scheduler.edges) > initialCount {
		t.Errorf("Expected edges to be optimized, but count increased")
	}
}

func TestSchedulerGetReadyEdges(t *testing.T) {
	graph := llb.NewGraph()
	op1 := llb.NewOperation("op1", llb.OpTypeCommand, nil, 0)
	op2 := llb.NewOperation("op2", llb.OpTypeCommand, nil, 1)

	graph.AddOperation(op1)
	graph.AddOperation(op2)

	scheduler, err := BuildFromGraph(graph)
	if err != nil {
		t.Fatalf("Failed to build scheduler: %v", err)
	}

	ready := scheduler.GetReadyEdges()
	// Initially, edges with no dependencies should be ready
	if len(ready) == 0 && len(scheduler.edges) > 0 {
		t.Error("Expected at least one ready edge")
	}
}

func TestSchedulerMarkEdgeCompleted(t *testing.T) {
	graph := llb.NewGraph()
	op1 := llb.NewOperation("op1", llb.OpTypeCommand, nil, 0)
	graph.AddOperation(op1)

	scheduler, err := BuildFromGraph(graph)
	if err != nil {
		t.Fatalf("Failed to build scheduler: %v", err)
	}

	// Get an edge
	var edge *Edge
	for _, e := range scheduler.edges {
		edge = e
		break
	}

	if edge == nil {
		t.Fatal("No edge found")
	}

	scheduler.MarkEdgeCompleted(edge.ID)

	if edge.GetState() != EdgeStateCompleted {
		t.Errorf("Expected edge state to be Completed, got %v", edge.GetState())
	}
}

func TestEdgeState(t *testing.T) {
	op := llb.NewOperation("op1", llb.OpTypeCommand, nil, 0)
	edge := NewEdge("edge1", op)

	if edge.GetState() != EdgeStatePending {
		t.Errorf("Expected initial state to be Pending, got %v", edge.GetState())
	}

	edge.SetState(EdgeStateReady)
	if edge.GetState() != EdgeStateReady {
		t.Errorf("Expected state to be Ready, got %v", edge.GetState())
	}
}

func TestEdgeAddDependency(t *testing.T) {
	op1 := llb.NewOperation("op1", llb.OpTypeCommand, nil, 0)
	op2 := llb.NewOperation("op2", llb.OpTypeCommand, nil, 1)

	edge1 := NewEdge("edge1", op1)
	edge2 := NewEdge("edge2", op2)

	edge2.AddDependency(edge1)

	deps := edge2.GetDependencies()
	if len(deps) != 1 {
		t.Errorf("Expected 1 dependency, got %d", len(deps))
	}

	if deps[0].ID != edge1.ID {
		t.Errorf("Expected dependency ID %s, got %s", edge1.ID, deps[0].ID)
	}
}
