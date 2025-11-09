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

// Package attestation provides SLSA provenance and SBOM generation
// Inspired by BuildKit's attestation capabilities
package attestation

import (
	"context"
	"encoding/json"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/Gosayram/kaniko/pkg/config"
)

// Provenance represents SLSA provenance attestation
type Provenance struct {
	PredicateType string               `json:"predicateType"`
	Predicate     *ProvenancePredicate `json:"predicate"`
}

// ProvenancePredicate contains the actual provenance data
type ProvenancePredicate struct {
	BuildDefinition *BuildDefinition `json:"buildDefinition"`
	RunDetails      *RunDetails      `json:"runDetails"`
}

// BuildDefinition defines how the build was performed
type BuildDefinition struct {
	BuildType            string                 `json:"buildType"`
	ExternalParameters   map[string]interface{} `json:"externalParameters"`
	InternalParameters   map[string]interface{} `json:"internalParameters,omitempty"`
	ResolvedDependencies []ResolvedDependency   `json:"resolvedDependencies,omitempty"`
}

// RunDetails contains information about the build execution
type RunDetails struct {
	Builder    *Builder    `json:"builder"`
	Metadata   *Metadata   `json:"metadata,omitempty"`
	Byproducts []Byproduct `json:"byproducts,omitempty"`
}

// Builder identifies the entity that executed the build
type Builder struct {
	ID string `json:"id"`
}

// Metadata contains additional metadata about the build
type Metadata struct {
	InvocationID string    `json:"invocationId,omitempty"`
	StartedOn    time.Time `json:"startedOn,omitempty"`
	FinishedOn   time.Time `json:"finishedOn,omitempty"`
}

// ResolvedDependency represents a resolved dependency
type ResolvedDependency struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest,omitempty"`
}

// Byproduct represents a byproduct of the build
type Byproduct struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest,omitempty"`
}

// BuildInfo contains information about the build
type BuildInfo struct {
	SourceURI    string
	SourceDigest string
	BuilderID    string
	BuildType    string
	InvocationID string
	StartedOn    time.Time
	FinishedOn   time.Time
	Parameters   map[string]interface{}
	Dependencies []ResolvedDependency
}

// ProvenanceGenerator generates SLSA provenance attestations
type ProvenanceGenerator struct {
	opts *config.KanikoOptions
}

// NewProvenanceGenerator creates a new provenance generator
func NewProvenanceGenerator(opts *config.KanikoOptions) *ProvenanceGenerator {
	return &ProvenanceGenerator{
		opts: opts,
	}
}

// Generate generates SLSA provenance for an image
func (pg *ProvenanceGenerator) Generate(_ context.Context, image v1.Image, buildInfo *BuildInfo) (*Provenance, error) {
	if buildInfo == nil {
		return nil, errors.New("buildInfo is required")
	}

	// Set defaults
	if buildInfo.BuilderID == "" {
		buildInfo.BuilderID = "kaniko"
	}
	if buildInfo.BuildType == "" {
		buildInfo.BuildType = "https://github.com/Gosayram/kaniko"
	}

	// Get image digest
	digest, err := image.Digest()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get image digest")
	}

	// Build external parameters
	externalParams := map[string]interface{}{
		"source": map[string]interface{}{
			"uri":    buildInfo.SourceURI,
			"digest": buildInfo.SourceDigest,
		},
	}
	// Add custom parameters
	for k, v := range buildInfo.Parameters {
		externalParams[k] = v
	}

	// Build resolved dependencies
	resolvedDeps := buildInfo.Dependencies
	// Note: Base image digest would need to be passed via buildInfo.Dependencies
	// or tracked separately in the build process

	provenance := &Provenance{
		PredicateType: "https://slsa.dev/provenance/v1",
		Predicate: &ProvenancePredicate{
			BuildDefinition: &BuildDefinition{
				BuildType:            buildInfo.BuildType,
				ExternalParameters:   externalParams,
				ResolvedDependencies: resolvedDeps,
			},
			RunDetails: &RunDetails{
				Builder: &Builder{
					ID: buildInfo.BuilderID,
				},
				Metadata: &Metadata{
					InvocationID: buildInfo.InvocationID,
					StartedOn:    buildInfo.StartedOn,
					FinishedOn:   buildInfo.FinishedOn,
				},
				Byproducts: []Byproduct{
					{
						URI: digest.String(),
						Digest: map[string]string{
							"sha256": digest.Hex,
						},
					},
				},
			},
		},
	}

	logrus.Debugf("Generated SLSA provenance for image: %s", digest.String())
	return provenance, nil
}

// ToJSON converts provenance to JSON
func (p *Provenance) ToJSON() ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}

// FromJSON parses provenance from JSON
func FromJSON(data []byte) (*Provenance, error) {
	var p Provenance
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, errors.Wrap(err, "failed to parse provenance JSON")
	}
	return &p, nil
}
