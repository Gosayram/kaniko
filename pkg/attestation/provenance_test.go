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

package attestation

import (
	"context"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/Gosayram/kaniko/pkg/config"
)

func TestNewProvenanceGenerator(t *testing.T) {
	opts := &config.KanikoOptions{}
	generator := NewProvenanceGenerator(opts)

	if generator == nil {
		t.Fatal("Provenance generator is nil")
	}

	if generator.opts != opts {
		t.Error("Generator options not set correctly")
	}
}

func TestProvenanceGeneratorGenerate(t *testing.T) {
	opts := &config.KanikoOptions{
		DockerfilePath: "/workspace/Dockerfile",
	}
	generator := NewProvenanceGenerator(opts)

	image := empty.Image
	buildInfo := &BuildInfo{
		SourceURI:    "https://github.com/example/repo",
		SourceDigest: "sha256:abc123",
		BuilderID:    "kaniko",
		BuildType:    "https://github.com/Gosayram/kaniko",
		StartedOn:    time.Now(),
		FinishedOn:   time.Now(),
		Parameters:   make(map[string]interface{}),
		Dependencies: []ResolvedDependency{},
	}

	ctx := context.Background()
	provenance, err := generator.Generate(ctx, image, buildInfo)
	if err != nil {
		t.Fatalf("Failed to generate provenance: %v", err)
	}

	if provenance == nil {
		t.Fatal("Provenance is nil")
	}

	if provenance.PredicateType != "https://slsa.dev/provenance/v1" {
		t.Errorf("Expected predicate type %s, got %s", "https://slsa.dev/provenance/v1", provenance.PredicateType)
	}

	if provenance.Predicate == nil {
		t.Fatal("Provenance predicate is nil")
	}

	if provenance.Predicate.BuildDefinition == nil {
		t.Fatal("Build definition is nil")
	}

	if provenance.Predicate.BuildDefinition.BuildType != buildInfo.BuildType {
		t.Errorf("Expected build type %s, got %s", buildInfo.BuildType, provenance.Predicate.BuildDefinition.BuildType)
	}
}

func TestProvenanceToJSON(t *testing.T) {
	provenance := &Provenance{
		PredicateType: "https://slsa.dev/provenance/v1",
		Predicate: &ProvenancePredicate{
			BuildDefinition: &BuildDefinition{
				BuildType: "https://github.com/Gosayram/kaniko",
			},
			RunDetails: &RunDetails{
				Builder: &Builder{
					ID: "kaniko",
				},
			},
		},
	}

	json, err := provenance.ToJSON()
	if err != nil {
		t.Fatalf("Failed to convert provenance to JSON: %v", err)
	}

	if len(json) == 0 {
		t.Error("JSON output is empty")
	}

	// Verify it's valid JSON by parsing it back
	parsed, err := FromJSON(json)
	if err != nil {
		t.Fatalf("Failed to parse JSON back: %v", err)
	}

	if parsed.PredicateType != provenance.PredicateType {
		t.Errorf("Expected predicate type %s, got %s", provenance.PredicateType, parsed.PredicateType)
	}
}

func TestProvenanceFromJSON(t *testing.T) {
	json := `{
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {
			"buildDefinition": {
				"buildType": "https://github.com/Gosayram/kaniko"
			},
			"runDetails": {
				"builder": {
					"id": "kaniko"
				}
			}
		}
	}`

	provenance, err := FromJSON([]byte(json))
	if err != nil {
		t.Fatalf("Failed to parse provenance from JSON: %v", err)
	}

	if provenance == nil {
		t.Fatal("Provenance is nil")
	}

	if provenance.PredicateType != "https://slsa.dev/provenance/v1" {
		t.Errorf("Expected predicate type %s, got %s", "https://slsa.dev/provenance/v1", provenance.PredicateType)
	}
}

func TestProvenanceGeneratorGenerate_WithDependencies(t *testing.T) {
	opts := &config.KanikoOptions{}
	generator := NewProvenanceGenerator(opts)

	image := empty.Image
	buildInfo := &BuildInfo{
		SourceURI:    "https://github.com/example/repo",
		SourceDigest: "sha256:abc123",
		BuilderID:    "kaniko",
		BuildType:    "https://github.com/Gosayram/kaniko",
		StartedOn:    time.Now(),
		FinishedOn:   time.Now(),
		Parameters:   make(map[string]interface{}),
		Dependencies: []ResolvedDependency{
			{
				URI: "gcr.io/myproject/base:latest",
				Digest: map[string]string{
					"sha256": "def456",
				},
			},
		},
	}

	ctx := context.Background()
	provenance, err := generator.Generate(ctx, image, buildInfo)
	if err != nil {
		t.Fatalf("Failed to generate provenance: %v", err)
	}

	if len(provenance.Predicate.BuildDefinition.ResolvedDependencies) != 1 {
		t.Errorf("Expected 1 dependency, got %d", len(provenance.Predicate.BuildDefinition.ResolvedDependencies))
	}
}

// mockImage is a simple mock implementation of v1.Image for testing
type mockImage struct{}

func (m *mockImage) Digest() (v1.Hash, error) {
	return v1.Hash{
		Algorithm: "sha256",
		Hex:       "abc123",
	}, nil
}

func (m *mockImage) Manifest() (*v1.Manifest, error) {
	return &v1.Manifest{
		SchemaVersion: 2,
		MediaType:     types.DockerManifestSchema2,
	}, nil
}

func (m *mockImage) RawManifest() ([]byte, error) {
	return []byte("{}"), nil
}

func (m *mockImage) ConfigName() (v1.Hash, error) {
	return v1.Hash{Algorithm: "sha256", Hex: "config123"}, nil
}

func (m *mockImage) ConfigFile() (*v1.ConfigFile, error) {
	return &v1.ConfigFile{}, nil
}

func (m *mockImage) RawConfigFile() ([]byte, error) {
	return []byte("{}"), nil
}

func (m *mockImage) MediaType() (types.MediaType, error) {
	return types.DockerManifestSchema2, nil
}

func (m *mockImage) Size() (int64, error) {
	return 1000, nil
}

func (m *mockImage) Layers() ([]v1.Layer, error) {
	return []v1.Layer{}, nil
}

func (m *mockImage) LayerByDigest(h v1.Hash) (v1.Layer, error) {
	return nil, nil
}

func (m *mockImage) LayerByDiffID(h v1.Hash) (v1.Layer, error) {
	return nil, nil
}
