/*
Copyright 2019 Google LLC

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

// Package fakes provides mock implementations and test utilities
// for container image interfaces used in Kaniko testing
package fakes

import (
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// FakeImage is a mock implementation of v1.Image interface
// for use in unit tests of container image operations
type FakeImage struct {
	Hash v1.Hash
}

// Layers returns nil layers for testing image layer operations
func (f FakeImage) Layers() ([]v1.Layer, error) {
	return nil, nil
}

// MediaType returns empty media type for testing image media type handling
func (f FakeImage) MediaType() (types.MediaType, error) {
	return "", nil
}

// Size returns zero size for testing image size operations
func (f FakeImage) Size() (int64, error) {
	return 0, nil
}

// ConfigName returns empty hash for testing image config name operations
func (f FakeImage) ConfigName() (v1.Hash, error) {
	return v1.Hash{}, nil
}

// ConfigFile returns empty config file for testing image config operations
func (f FakeImage) ConfigFile() (*v1.ConfigFile, error) {
	return &v1.ConfigFile{}, nil
}

// RawConfigFile returns empty byte slice for testing raw config operations
func (f FakeImage) RawConfigFile() ([]byte, error) {
	return []byte{}, nil
}

// Digest returns the stored hash for testing image digest operations
func (f FakeImage) Digest() (v1.Hash, error) {
	return f.Hash, nil
}

// Manifest returns empty manifest for testing image manifest operations
func (f FakeImage) Manifest() (*v1.Manifest, error) {
	return &v1.Manifest{}, nil
}

// RawManifest returns empty byte slice for testing raw manifest operations
func (f FakeImage) RawManifest() ([]byte, error) {
	return []byte{}, nil
}

// LayerByDigest returns nil for testing layer retrieval by digest
func (f FakeImage) LayerByDigest(v1.Hash) (v1.Layer, error) {
	return nil, nil
}

// LayerByDiffID returns nil for testing layer retrieval by diff ID
func (f FakeImage) LayerByDiffID(v1.Hash) (v1.Layer, error) {
	return nil, nil
}
