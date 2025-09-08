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

package oci

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Gosayram/kaniko/pkg/config"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// BuildIndex creates an OCI Image Index or Docker Manifest List from platform digests
func BuildIndex(manifests map[string]string, opts *config.KanikoOptions) (v1.ImageIndex, error) {
	if len(manifests) == 0 {
		return nil, errors.New("no manifests provided for index creation")
	}

	logrus.Info("Building multi-platform image index")

	var index v1.ImageIndex
	var err error

	if opts.LegacyManifestList {
		index, err = buildDockerManifestList(manifests, opts)
	} else {
		index, err = buildOCIImageIndex(manifests, opts)
	}

	if err != nil {
		return nil, errors.Wrap(err, "failed to build image index")
	}

	return index, nil
}

// buildOCIImageIndex creates an OCI Image Index (application/vnd.oci.image.index.v1+json)
func buildOCIImageIndex(manifests map[string]string, opts *config.KanikoOptions) (v1.ImageIndex, error) {
	logrus.Info("Creating OCI Image Index")
	
	// Create a simple index implementation
	index := &simpleIndex{
		mediaType: types.OCIImageIndex,
		manifests: make([]v1.Descriptor, 0, len(manifests)),
	}

	for platform, digestStr := range manifests {
		platformSpec, err := parsePlatform(platform)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid platform format: %s", platform)
		}

		// Create descriptor for the manifest
		desc, err := createManifestDescriptor(digestStr, platformSpec, opts)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create descriptor for platform %s", platform)
		}

		desc.Platform = platformSpec
		index.manifests = append(index.manifests, desc)
	}

	// Add annotations if specified
	if len(opts.IndexAnnotations) > 0 {
		index.annotations = opts.IndexAnnotations
	}

	return index, nil
}

// buildDockerManifestList creates a Docker Manifest List (application/vnd.docker.distribution.manifest.list.v2+json)
func buildDockerManifestList(manifests map[string]string, opts *config.KanikoOptions) (v1.ImageIndex, error) {
	logrus.Info("Creating Docker Manifest List")
	
	// Create a simple index implementation
	index := &simpleIndex{
		mediaType: types.DockerManifestList,
		manifests: make([]v1.Descriptor, 0, len(manifests)),
	}

	for platform, digestStr := range manifests {
		platformSpec, err := parsePlatform(platform)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid platform format: %s", platform)
		}

		// Create descriptor for the manifest
		desc, err := createManifestDescriptor(digestStr, platformSpec, opts)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create descriptor for platform %s", platform)
		}

		desc.Platform = platformSpec
		index.manifests = append(index.manifests, desc)
	}

	return index, nil
}

// simpleIndex is a basic implementation of v1.ImageIndex
type simpleIndex struct {
	mediaType  types.MediaType
	manifests  []v1.Descriptor
	annotations map[string]string
}

func (s *simpleIndex) MediaType() (types.MediaType, error) {
	return s.mediaType, nil
}

func (s *simpleIndex) Digest() (v1.Hash, error) {
	// This would be computed based on the manifests in a real implementation
	return v1.Hash{}, nil
}

func (s *simpleIndex) Size() (int64, error) {
	// This would be computed based on the manifests in a real implementation
	return 0, nil
}

func (s *simpleIndex) IndexManifest() (*v1.IndexManifest, error) {
	manifest := &v1.IndexManifest{
		SchemaVersion: 2,
		MediaType:      s.mediaType,
		Manifests:      s.manifests,
		Annotations:    s.annotations,
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

// createManifestDescriptor creates a descriptor for a manifest digest
func createManifestDescriptor(digestStr string, platform *v1.Platform, opts *config.KanikoOptions) (v1.Descriptor, error) {
	digest, err := v1.NewHash(digestStr)
	if err != nil {
		return v1.Descriptor{}, errors.Wrapf(err, "invalid digest: %s", digestStr)
	}

	// For now, we create a simple descriptor. In a real implementation,
	// we would fetch the actual manifest to get its media type and size.
	return v1.Descriptor{
		Digest:    digest,
		MediaType: types.DockerManifestSchema2, // Default, would be determined from actual manifest
		Platform:  platform,
	}, nil
}

// parsePlatform parses a platform string into v1.Platform
func parsePlatform(platformStr string) (*v1.Platform, error) {
	parts := strings.Split(platformStr, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid platform format: %s (expected os/arch)", platformStr)
	}

	return &v1.Platform{
		OS:           parts[0],
		Architecture: parts[1],
	}, nil
}

// PushIndex pushes the image index to the registry
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
		
		// This would use the existing kaniko push infrastructure with proper authentication
		// For now, it's a placeholder
		if err := remote.WriteIndex(destRef, index); err != nil {
			return errors.Wrapf(err, "failed to push index to %s", destination)
		}

		logrus.Infof("Successfully pushed image index to %s", destination)
	}

	return nil
}