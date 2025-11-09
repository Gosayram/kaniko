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

// Package oci provides functionality for building, manipulating, and pushing
// OCI image indices and Docker manifest lists in Kaniko.
package oci

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/debug"
	"github.com/Gosayram/kaniko/pkg/retry"
)

const (
	// DefaultIndexPushRetryMaxDelay is the default maximum delay for index push retry operations
	DefaultIndexPushRetryMaxDelay = 30 * time.Second
)

// BuildIndex creates an OCI Image Index or Docker Manifest List from platform digests
func BuildIndex(manifests map[string]string, opts *config.KanikoOptions) (v1.ImageIndex, error) {
	debug.LogComponent("oci-index", "Building image index with %d manifests", len(manifests))
	debug.LogComponent("oci-index", "OCI Mode: %s", opts.OCIMode)
	debug.LogComponent("oci-index", "Legacy Manifest List: %t", opts.LegacyManifestList)

	for platform, digest := range manifests {
		debug.LogComponent("oci-index", "Adding manifest for %s: %s", platform, digest)
	}

	if len(manifests) == 0 {
		return nil, errors.New("no manifests provided for index creation")
	}

	logrus.Info("Building multi-platform image index")

	var index v1.ImageIndex
	var err error

	if opts.LegacyManifestList {
		debug.LogComponent("oci-index", "Creating Docker Manifest List")
		index, err = buildDockerManifestList(manifests, opts)
	} else {
		debug.LogComponent("oci-index", "Creating OCI Image Index")
		index, err = buildOCIImageIndex(manifests, opts)
	}

	if err != nil {
		debug.LogComponent("oci-index", "Failed to build index: %v", err)
		return nil, errors.Wrap(err, "failed to build image index")
	}

	debug.LogComponent("oci-index", "Successfully created image index")
	return index, nil
}

// buildOCIImageIndex creates an OCI Image Index (application/vnd.oci.image.index.v1+json)
func buildOCIImageIndex(manifests map[string]string, opts *config.KanikoOptions) (v1.ImageIndex, error) {
	logrus.Info("Creating OCI Image Index")

	// Create a new simple index with OCI media type
	index := &simpleIndex{
		mediaType:   types.OCIImageIndex,
		manifests:   make([]v1.Descriptor, 0, len(manifests)),
		annotations: make(map[string]string),
	}

	for platform, digestStr := range manifests {
		platformSpec, err := parsePlatform(platform)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid platform format: %s", platform)
		}

		// Fetch the actual manifest to get proper media type and size
		desc, err := fetchManifestDescriptor(digestStr, platformSpec, opts)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to fetch manifest for platform %s", platform)
		}

		index.manifests = append(index.manifests, desc)
	}

	// Add annotations if specified
	if len(opts.IndexAnnotations) > 0 {
		for k, v := range opts.IndexAnnotations {
			index.annotations[k] = v
		}
	}

	// Add OCI-specific annotations for compliance
	index.annotations["org.opencontainers.image.created"] = time.Now().UTC().Format(time.RFC3339)
	index.annotations["org.opencontainers.image.vendor"] = "Kaniko"
	index.annotations["org.opencontainers.image.authors"] = "Kaniko Project"
	index.annotations["org.opencontainers.image.licenses"] = "Apache-2.0"

	return index, nil
}

// buildDockerManifestList creates a Docker Manifest List (application/vnd.docker.distribution.manifest.list.v2+json)
func buildDockerManifestList(manifests map[string]string, opts *config.KanikoOptions) (v1.ImageIndex, error) {
	logrus.Info("Creating Docker Manifest List")

	// Create a new simple index with Docker manifest list media type
	index := &simpleIndex{
		mediaType:   types.DockerManifestList,
		manifests:   make([]v1.Descriptor, 0, len(manifests)),
		annotations: make(map[string]string),
	}

	for platform, digestStr := range manifests {
		platformSpec, err := parsePlatform(platform)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid platform format: %s", platform)
		}

		// Fetch the actual manifest to get proper media type and size
		desc, err := fetchManifestDescriptor(digestStr, platformSpec, opts)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to fetch manifest for platform %s", platform)
		}

		index.manifests = append(index.manifests, desc)
	}

	return index, nil
}

// fetchManifestDescriptor fetches the actual manifest and creates a proper descriptor
func fetchManifestDescriptor(digestStr string, platform *v1.Platform,
	opts *config.KanikoOptions) (v1.Descriptor, error) {
	if len(opts.Destinations) == 0 {
		return v1.Descriptor{}, errors.New("no destinations available to fetch manifest")
	}

	// Use the first destination as reference
	destination := opts.Destinations[0]
	ref, err := name.ParseReference(destination)
	if err != nil {
		return v1.Descriptor{}, errors.Wrapf(err, "invalid destination: %s", destination)
	}

	// Create a reference to the specific manifest digest
	digestRef, err := name.NewDigest(fmt.Sprintf("%s@%s", ref.Context().Name(), digestStr))
	if err != nil {
		return v1.Descriptor{}, errors.Wrapf(err, "invalid digest reference: %s", digestStr)
	}

	// Fetch the manifest
	manifest, err := remote.Get(digestRef, getRemoteOptions(opts)...)
	if err != nil {
		return v1.Descriptor{}, errors.Wrapf(err, "failed to fetch manifest %s", digestStr)
	}

	// Determine proper media type based on OCI mode
	mediaType := manifest.MediaType
	if opts.OCIMode == "oci" {
		// Convert Docker media types to OCI equivalents
		switch mediaType {
		case types.DockerManifestList:
			mediaType = types.OCIImageIndex
		case types.DockerManifestSchema2:
			mediaType = types.OCIManifestSchema1
		case types.DockerManifestSchema1, types.DockerManifestSchema1Signed:
			// Schema 1 doesn't have OCI equivalent, keep as is
		}
	}

	return v1.Descriptor{
		Digest:       manifest.Digest,
		MediaType:    mediaType,
		Size:         manifest.Size,
		Platform:     platform,
		Annotations:  createPlatformAnnotations(platform),
		URLs:         nil,
		Data:         manifest.Manifest,
		ArtifactType: "",
	}, nil
}

// createPlatformAnnotations creates annotations for a specific platform
func createPlatformAnnotations(platform *v1.Platform) map[string]string {
	if platform == nil {
		return nil
	}

	return map[string]string{
		"org.opencontainers.image.ref.platform.os":           platform.OS,
		"org.opencontainers.image.ref.platform.architecture": platform.Architecture,
		"org.opencontainers.image.ref.platform.variant":      platform.Variant,
	}
}

// parsePlatform parses a platform string into v1.Platform
func parsePlatform(platformStr string) (*v1.Platform, error) {
	parts := strings.Split(platformStr, "/")
	const expectedParts = 2
	if len(parts) != expectedParts {
		return nil, fmt.Errorf("invalid platform format: %s (expected os/arch)", platformStr)
	}

	return &v1.Platform{
		OS:           parts[0],
		Architecture: parts[1],
	}, nil
}

// getRemoteOptions returns remote options based on Kaniko configuration
func getRemoteOptions(opts *config.KanikoOptions) []remote.Option {
	// Use anonymous authentication for now - this would be replaced with
	// proper authentication based on KanikoOptions
	return []remote.Option{
		remote.WithAuth(nil), // Anonymous auth
		remote.WithTransport(createTransport(opts)),
	}
}

// simpleIndex is a basic implementation of v1.ImageIndex
type simpleIndex struct {
	mediaType   types.MediaType
	manifests   []v1.Descriptor
	annotations map[string]string
}

func (s *simpleIndex) MediaType() (types.MediaType, error) {
	return s.mediaType, nil
}

func (s *simpleIndex) Digest() (v1.Hash, error) {
	// Compute digest based on the manifests
	manifest, err := s.IndexManifest()
	if err != nil {
		return v1.Hash{}, err
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		return v1.Hash{}, err
	}
	return v1.NewHash(fmt.Sprintf("sha256:%x", data))
}

func (s *simpleIndex) Size() (int64, error) {
	manifest, err := s.IndexManifest()
	if err != nil {
		return 0, err
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		return 0, err
	}
	return int64(len(data)), nil
}

func (s *simpleIndex) IndexManifest() (*v1.IndexManifest, error) {
	const schemaVersion = 2
	manifest := &v1.IndexManifest{
		SchemaVersion: schemaVersion,
		MediaType:     s.mediaType,
		Manifests:     s.manifests,
		Annotations:   s.annotations,
	}
	return manifest, nil
}

func (s *simpleIndex) RawManifest() ([]byte, error) {
	manifest, err := s.IndexManifest()
	if err != nil {
		return nil, err
	}
	return json.Marshal(manifest)
}

func (s *simpleIndex) Image(v1.Hash) (v1.Image, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *simpleIndex) ImageIndex(v1.Hash) (v1.ImageIndex, error) {
	return nil, fmt.Errorf("not implemented")
}

// PushIndex pushes the image index to the registry with retry logic
func PushIndex(index v1.ImageIndex, opts *config.KanikoOptions) error {
	if len(opts.Destinations) == 0 {
		return errors.New("no destinations specified for index push")
	}

	for _, destination := range opts.Destinations {
		destRef, err := name.ParseReference(destination)
		if err != nil {
			return errors.Wrapf(err, "invalid destination: %s", destination)
		}

		logrus.Infof("Pushing image index to %s", destination)

		// Define the push operation with retry logic
		pushOperation := func() error {
			return remote.WriteIndex(destRef, index, getRemoteOptions(opts)...)
		}

		// Use new retry mechanism with exponential backoff
		initialDelay := time.Duration(opts.PushRetryInitialDelay) * time.Millisecond
		if initialDelay <= 0 {
			initialDelay = 1 * time.Second // fallback to 1 second
		}

		maxDelay := time.Duration(opts.PushRetryMaxDelay) * time.Millisecond
		if maxDelay <= 0 {
			maxDelay = DefaultIndexPushRetryMaxDelay
		}

		backoffMultiplier := opts.PushRetryBackoffMultiplier
		const defaultBackoffMultiplier = 2.0
		if backoffMultiplier <= 0 {
			backoffMultiplier = defaultBackoffMultiplier
		}

		retryConfig := retry.NewRetryConfigBuilder().
			WithMaxAttempts(opts.PushRetry + 1). // +1 because first attempt is not a retry
			WithInitialDelay(initialDelay).
			WithMaxDelay(maxDelay).
			WithBackoff(backoffMultiplier).
			WithRetryableErrors(retry.IsRetryableError).
			Build()

		err = retry.Retry(context.Background(), retryConfig, pushOperation)
		if err != nil {
			return errors.Wrapf(err, "failed to push index to %s after %d attempts", destination, opts.PushRetry+1)
		}

		logrus.Infof("Successfully pushed image index to %s", destination)
	}

	return nil
}

// createTransport creates HTTP transport based on Kaniko configuration
func createTransport(_ *config.KanikoOptions) *http.Transport {
	// Create a basic HTTP transport - this would be enhanced with proper configuration
	// based on KanikoOptions (TLS settings, timeouts, etc.)
	return &http.Transport{
		// Basic configuration - would be enhanced with Kaniko-specific settings
	}
}
