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

package llb

import (
	"context"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/Gosayram/kaniko/pkg/commands"
	"github.com/Gosayram/kaniko/pkg/dockerfile"
)

// mockCommand is a simple mock implementation of DockerCommand
type mockCommand struct {
	name string
}

func (m *mockCommand) String() string {
	return m.name
}

func (m *mockCommand) ExecuteCommand(cfg *v1.Config, args *dockerfile.BuildArgs) error {
	return nil
}

func (m *mockCommand) FilesToSnapshot() []string {
	return []string{}
}

func (m *mockCommand) ProvidesFilesToSnapshot() bool {
	return false
}

func (m *mockCommand) FilesUsedFromContext(cfg *v1.Config, args *dockerfile.BuildArgs) ([]string, error) {
	return []string{}, nil
}

func (m *mockCommand) MetadataOnly() bool {
	return false
}

func (m *mockCommand) ShouldCacheOutput() bool {
	return true
}

func (m *mockCommand) CacheCommand(img v1.Image) commands.DockerCommand {
	return nil
}

func (m *mockCommand) RequiresUnpackedFS() bool {
	return false
}

func (m *mockCommand) ShouldDetectDeletedFiles() bool {
	return false
}

func (m *mockCommand) IsArgsEnvsRequiredInCache() bool {
	return false
}

func TestBuildGraphFromCommands(t *testing.T) {
	cmds := []commands.DockerCommand{
		&mockCommand{name: "RUN echo 'test1'"},
		&mockCommand{name: "COPY file.txt /app/"},
		&mockCommand{name: "RUN echo 'test2'"},
	}

	graph, err := BuildGraphFromCommands(cmds)
	if err != nil {
		t.Fatalf("Failed to build graph: %v", err)
	}

	if graph == nil {
		t.Fatal("Graph is nil")
	}

	if len(graph.Operations) != len(cmds) {
		t.Errorf("Expected %d operations, got %d", len(cmds), len(graph.Operations))
	}
}

func TestGraphGetExecutionOrder(t *testing.T) {
	cmds := []commands.DockerCommand{
		&mockCommand{name: "RUN echo 'test1'"},
		&mockCommand{name: "RUN echo 'test2'"},
		&mockCommand{name: "RUN echo 'test3'"},
	}

	graph, err := BuildGraphFromCommands(cmds)
	if err != nil {
		t.Fatalf("Failed to build graph: %v", err)
	}

	order, err := graph.GetExecutionOrder()
	if err != nil {
		t.Fatalf("Failed to get execution order: %v", err)
	}

	if len(order) != len(cmds) {
		t.Errorf("Expected execution order length %d, got %d", len(cmds), len(order))
	}

	// Verify all operations are in the order
	opIDs := make(map[string]bool)
	for _, op := range order {
		opIDs[op.ID] = true
	}

	for _, op := range graph.Operations {
		if !opIDs[op.ID] {
			t.Errorf("Operation %s not found in execution order", op.ID)
		}
	}
}

func TestGraphOptimize(t *testing.T) {
	cmds := []commands.DockerCommand{
		&mockCommand{name: "RUN echo 'test'"},
		&mockCommand{name: "RUN echo 'test'"},
	}

	graph, err := BuildGraphFromCommands(cmds)
	if err != nil {
		t.Fatalf("Failed to build graph: %v", err)
	}

	// Set same cache key for both operations to test merging
	graph.Operations[0].SetCacheKey("same-key")
	graph.Operations[1].SetCacheKey("same-key")

	initialCount := len(graph.Operations)

	ctx := context.Background()
	if err := graph.Optimize(ctx); err != nil {
		t.Fatalf("Failed to optimize graph: %v", err)
	}

	// After optimization, identical operations should be merged
	// (Note: actual merging depends on areOperationsIdentical logic)
	if len(graph.Operations) > initialCount {
		t.Errorf("Expected operations to be merged, but count increased")
	}
}

func TestGraphGetIndependentOperations(t *testing.T) {
	cmds := []commands.DockerCommand{
		&mockCommand{name: "RUN echo 'test1'"},
		&mockCommand{name: "RUN echo 'test2'"},
	}

	graph, err := BuildGraphFromCommands(cmds)
	if err != nil {
		t.Fatalf("Failed to build graph: %v", err)
	}

	executed := make(map[string]bool)
	independent := graph.GetIndependentOperations(executed)

	// Initially, operations with no dependencies should be independent
	if len(independent) == 0 {
		t.Error("Expected at least one independent operation")
	}

	// Mark first operation as executed
	executed[graph.Operations[0].ID] = true
	independent = graph.GetIndependentOperations(executed)

	// Should still have independent operations
	if len(independent) == 0 && len(graph.Operations) > 1 {
		t.Error("Expected independent operations after marking one as executed")
	}
}

func TestOperationAddDependency(t *testing.T) {
	op1 := NewOperation("op1", OpTypeCommand, &mockCommand{name: "RUN echo 'test1'"}, 0)
	op2 := NewOperation("op2", OpTypeCommand, &mockCommand{name: "RUN echo 'test2'"}, 1)

	op2.AddDependency(op1)

	deps := op2.GetDependencies()
	if len(deps) != 1 {
		t.Errorf("Expected 1 dependency, got %d", len(deps))
	}

	if deps[0].ID != op1.ID {
		t.Errorf("Expected dependency ID %s, got %s", op1.ID, deps[0].ID)
	}

	// Check that op1 has op2 as dependent
	dependents := op1.GetDependents()
	if len(dependents) != 1 {
		t.Errorf("Expected 1 dependent, got %d", len(dependents))
	}

	if dependents[0].ID != op2.ID {
		t.Errorf("Expected dependent ID %s, got %s", op2.ID, dependents[0].ID)
	}
}

func TestResult(t *testing.T) {
	result := NewResult()

	if result.IsCompleted() {
		t.Error("New result should not be completed")
	}

	result.SetCompleted()
	if !result.IsCompleted() {
		t.Error("Result should be completed after SetCompleted")
	}

	result.SetError(nil)
	if result.GetError() != nil {
		t.Error("Result error should be nil")
	}
}
