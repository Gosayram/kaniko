/*
Copyright 2018 Google LLC

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

// Package executor provides mock implementations and test utilities
// for testing the Kaniko executor functionality
package executor

import (
	"bytes"
	"errors"
	"io"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/Gosayram/kaniko/pkg/commands"
	"github.com/Gosayram/kaniko/pkg/dockerfile"
)

type fakeSnapShotter struct {
	file        string
	tarPath     string
	initialized bool
}

func (f *fakeSnapShotter) Init() error {
	f.initialized = true
	return nil
}
func (f *fakeSnapShotter) TakeSnapshotFS() (string, error) {
	return f.tarPath, nil
}
func (f *fakeSnapShotter) TakeSnapshot(_ []string, _, _ bool) (string, error) {
	return f.tarPath, nil
}

// MockDockerCommand is a mock implementation of DockerCommand interface
// for use in unit tests of the executor package
type MockDockerCommand struct {
	command             string
	contextFiles        []string
	cacheCommand        commands.DockerCommand
	argToCompositeCache bool
}

// ExecuteCommand is a mock implementation that always returns nil
func (m MockDockerCommand) ExecuteCommand(_ *v1.Config, _ *dockerfile.BuildArgs) error { return nil }

// String returns the command string representation for testing
func (m MockDockerCommand) String() string {
	return m.command
}

// FilesToSnapshot returns test file paths for snapshot testing
func (m MockDockerCommand) FilesToSnapshot() []string {
	return []string{"meow-snapshot-no-cache"}
}

// ProvidesFilesToSnapshot indicates that this mock provides files for snapshotting
func (m MockDockerCommand) ProvidesFilesToSnapshot() bool {
	return true
}

// CacheCommand returns the cached command implementation for testing
func (m MockDockerCommand) CacheCommand(_ v1.Image) commands.DockerCommand {
	return m.cacheCommand
}

// FilesUsedFromContext returns mock context files for testing
func (m MockDockerCommand) FilesUsedFromContext(_ *v1.Config, _ *dockerfile.BuildArgs) ([]string, error) {
	return m.contextFiles, nil
}

// MetadataOnly indicates this mock command affects both metadata and filesystem
func (m MockDockerCommand) MetadataOnly() bool {
	return false
}

// RequiresUnpackedFS indicates this mock doesn't require unpacked filesystem
func (m MockDockerCommand) RequiresUnpackedFS() bool {
	return false
}

// ShouldCacheOutput indicates this mock command output should be cached
func (m MockDockerCommand) ShouldCacheOutput() bool {
	return true
}

// ShouldDetectDeletedFiles indicates this mock doesn't detect deleted files
func (m MockDockerCommand) ShouldDetectDeletedFiles() bool {
	return false
}

// IsArgsEnvsRequiredInCache indicates whether args/envs affect cache key for this mock
func (m MockDockerCommand) IsArgsEnvsRequiredInCache() bool {
	return m.argToCompositeCache
}

// MockCachedDockerCommand is a mock implementation for cached Docker commands
// used in executor unit tests
type MockCachedDockerCommand struct {
	contextFiles        []string
	argToCompositeCache bool
}

// ExecuteCommand is a mock implementation that always returns nil
func (m MockCachedDockerCommand) ExecuteCommand(_ *v1.Config, _ *dockerfile.BuildArgs) error {
	return nil
}

// String returns a fixed string representation for testing
func (m MockCachedDockerCommand) String() string {
	return "meow"
}

// FilesToSnapshot returns test file paths for snapshot testing
func (m MockCachedDockerCommand) FilesToSnapshot() []string {
	return []string{"meow-snapshot"}
}

// ProvidesFilesToSnapshot indicates that this mock provides files for snapshotting
func (m MockCachedDockerCommand) ProvidesFilesToSnapshot() bool {
	return true
}

// CacheCommand returns nil since this is already a cached command mock
func (m MockCachedDockerCommand) CacheCommand(_ v1.Image) commands.DockerCommand {
	return nil
}

// ShouldDetectDeletedFiles indicates this mock doesn't detect deleted files
func (m MockCachedDockerCommand) ShouldDetectDeletedFiles() bool {
	return false
}

// FilesUsedFromContext returns mock context files for testing
func (m MockCachedDockerCommand) FilesUsedFromContext(_ *v1.Config, _ *dockerfile.BuildArgs) ([]string, error) {
	return m.contextFiles, nil
}

// MetadataOnly indicates this mock command affects both metadata and filesystem
func (m MockCachedDockerCommand) MetadataOnly() bool {
	return false
}

// RequiresUnpackedFS indicates this mock doesn't require unpacked filesystem
func (m MockCachedDockerCommand) RequiresUnpackedFS() bool {
	return false
}

// ShouldCacheOutput indicates this mock command output should not be cached
func (m MockCachedDockerCommand) ShouldCacheOutput() bool {
	return false
}

// IsArgsEnvsRequiredInCache indicates whether args/envs affect cache key for this mock
func (m MockCachedDockerCommand) IsArgsEnvsRequiredInCache() bool {
	return m.argToCompositeCache
}

type fakeLayerCache struct {
	retrieve     bool
	receivedKeys []string
	img          v1.Image
	keySequence  []string
}

func (f *fakeLayerCache) RetrieveLayer(key string) (v1.Image, error) {
	f.receivedKeys = append(f.receivedKeys, key)
	if len(f.keySequence) > 0 {
		if f.keySequence[0] == key {
			f.keySequence = f.keySequence[1:]
			return f.img, nil
		}
		return f.img, errors.New("could not find layer")
	}

	if !f.retrieve {
		return nil, errors.New("could not find layer")
	}
	return f.img, nil
}

type fakeLayer struct {
	TarContent []byte
	mediaType  types.MediaType
}

func (f fakeLayer) Digest() (v1.Hash, error) {
	return v1.Hash{}, nil
}
func (f fakeLayer) DiffID() (v1.Hash, error) {
	return v1.Hash{}, nil
}
func (f fakeLayer) Compressed() (io.ReadCloser, error) {
	return nil, nil
}
func (f fakeLayer) Uncompressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(f.TarContent)), nil
}
func (f fakeLayer) Size() (int64, error) {
	return 0, nil
}
func (f fakeLayer) MediaType() (types.MediaType, error) {
	return f.mediaType, nil
}

type fakeImage struct {
	ImageLayers []v1.Layer
}

func (f fakeImage) Layers() ([]v1.Layer, error) {
	return f.ImageLayers, nil
}
func (f fakeImage) MediaType() (types.MediaType, error) {
	return "", nil
}
func (f fakeImage) Size() (int64, error) {
	return 0, nil
}
func (f fakeImage) ConfigName() (v1.Hash, error) {
	return v1.Hash{}, nil
}
func (f fakeImage) ConfigFile() (*v1.ConfigFile, error) {
	return &v1.ConfigFile{}, nil
}
func (f fakeImage) RawConfigFile() ([]byte, error) {
	return []byte{}, nil
}
func (f fakeImage) Digest() (v1.Hash, error) {
	return v1.Hash{}, nil
}
func (f fakeImage) Manifest() (*v1.Manifest, error) {
	return &v1.Manifest{}, nil
}
func (f fakeImage) RawManifest() ([]byte, error) {
	return []byte{}, nil
}
func (f fakeImage) LayerByDigest(v1.Hash) (v1.Layer, error) {
	return fakeLayer{}, nil
}
func (f fakeImage) LayerByDiffID(v1.Hash) (v1.Layer, error) {
	return fakeLayer{}, nil
}

type ociFakeImage struct {
	*fakeImage
}

func (f ociFakeImage) MediaType() (types.MediaType, error) {
	return types.OCIManifestSchema1, nil
}

type dockerFakeImage struct {
	*fakeImage
}

func (f dockerFakeImage) MediaType() (types.MediaType, error) {
	return types.DockerManifestSchema2, nil
}
