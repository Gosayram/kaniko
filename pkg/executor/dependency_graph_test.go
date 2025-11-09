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
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/Gosayram/kaniko/pkg/commands"
	"github.com/Gosayram/kaniko/pkg/dockerfile"
)

func TestBuildDependencyGraph(t *testing.T) {
	// Create mock commands
	cmds := []commands.DockerCommand{
		&mockCommand{name: "RUN echo 'test1'"},
		&mockCommand{name: "RUN echo 'test2'"},
		&mockCommand{name: "RUN echo 'test3'"},
	}

	graph, err := BuildDependencyGraph(cmds)
	if err != nil {
		t.Fatalf("Failed to build dependency graph: %v", err)
	}

	if graph == nil {
		t.Fatal("Graph is nil")
	}

	order := graph.GetExecutionOrder()
	if len(order) != len(cmds) {
		t.Errorf("Expected execution order length %d, got %d", len(cmds), len(order))
	}

	// Verify all commands are in the order
	for i := range cmds {
		found := false
		for _, idx := range order {
			if idx == i {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Command %d not found in execution order", i)
		}
	}
}

func TestDependencyGraph_GetIndependentCommands(t *testing.T) {
	cmds := []commands.DockerCommand{
		&mockCommand{name: "RUN echo 'test1'"},
		&mockCommand{name: "RUN echo 'test2'"},
		&mockCommand{name: "RUN echo 'test3'"},
	}

	graph, err := BuildDependencyGraph(cmds)
	if err != nil {
		t.Fatalf("Failed to build dependency graph: %v", err)
	}

	// Initially, all commands should be independent (no dependencies)
	executed := make(map[int]bool)
	independent := graph.GetIndependentCommands(executed)

	if len(independent) == 0 {
		t.Error("Expected at least one independent command")
	}
}

func TestDependencyGraph_GetDependencies(t *testing.T) {
	cmds := []commands.DockerCommand{
		&mockCommand{name: "RUN echo 'test1'"},
		&mockCommand{name: "RUN echo 'test2'"},
	}

	graph, err := BuildDependencyGraph(cmds)
	if err != nil {
		t.Fatalf("Failed to build dependency graph: %v", err)
	}

	deps := graph.GetDependencies(1)
	// Command 1 should depend on command 0 (filesystem dependency)
	if len(deps) == 0 {
		t.Error("Expected command 1 to have dependencies")
	}
}

// mockCommand is a simple mock implementation of DockerCommand
type mockCommand struct {
	name string
}

func (m *mockCommand) ExecuteCommand(cfg *v1.Config, args *dockerfile.BuildArgs) error {
	return nil
}

func (m *mockCommand) String() string {
	return m.name
}

func (m *mockCommand) FilesToSnapshot() []string {
	return []string{}
}

func (m *mockCommand) ProvidesFilesToSnapshot() bool {
	return false
}

func (m *mockCommand) ShouldCacheOutput() bool {
	return false
}

func (m *mockCommand) CacheCommand(img v1.Image) commands.DockerCommand {
	return nil
}

func (m *mockCommand) FilesUsedFromContext(cfg *v1.Config, args *dockerfile.BuildArgs) ([]string, error) {
	return []string{}, nil
}

func (m *mockCommand) MetadataOnly() bool {
	return false
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
