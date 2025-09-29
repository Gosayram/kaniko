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
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/assert"

	"github.com/Gosayram/kaniko/pkg/config"
)

func TestBuildIndex(t *testing.T) {
	tests := []struct {
		name      string
		manifests map[string]string
		opts      *config.KanikoOptions
		wantErr   bool
	}{
		{
			name:      "empty manifests",
			manifests: map[string]string{},
			opts:      &config.KanikoOptions{},
			wantErr:   true,
		},
		{
			name: "single platform OCI mode",
			manifests: map[string]string{
				"linux/amd64": "sha256:test123",
			},
			opts: &config.KanikoOptions{
				OCIMode: "oci",
			},
			wantErr: false,
		},
		{
			name: "multiple platforms OCI mode",
			manifests: map[string]string{
				"linux/amd64": "sha256:test123",
				"linux/arm64": "sha256:test456",
			},
			opts: &config.KanikoOptions{
				OCIMode: "oci",
			},
			wantErr: false,
		},
		{
			name: "legacy manifest list",
			manifests: map[string]string{
				"linux/amd64": "sha256:test123",
			},
			opts: &config.KanikoOptions{
				LegacyManifestList: true,
			},
			wantErr: false,
		},
		{
			name: "with annotations",
			manifests: map[string]string{
				"linux/amd64": "sha256:test123",
			},
			opts: &config.KanikoOptions{
				OCIMode:          "oci",
				IndexAnnotations: map[string]string{"key": "value"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			index, err := BuildIndex(tt.manifests, tt.opts)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, index)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, index)

				// Verify index media type
				mediaType, err := index.MediaType()
				assert.NoError(t, err)
				if tt.opts.LegacyManifestList {
					assert.Equal(t, types.DockerManifestList, mediaType)
				} else {
					assert.Equal(t, types.OCIImageIndex, mediaType)
				}

				// Verify index manifest structure
				indexManifest, err := index.IndexManifest()
				assert.NoError(t, err)
				assert.Len(t, indexManifest.Manifests, len(tt.manifests))

				// Verify annotations if present
				if len(tt.opts.IndexAnnotations) > 0 {
					assert.NotEmpty(t, indexManifest.Annotations)
				}
			}
		})
	}
}

func TestBuildOCIImageIndex(t *testing.T) {
	tests := []struct {
		name      string
		manifests map[string]string
		opts      *config.KanikoOptions
		wantErr   bool
	}{
		{
			name: "valid single platform",
			manifests: map[string]string{
				"linux/amd64": "sha256:test123",
			},
			opts:    &config.KanikoOptions{},
			wantErr: false,
		},
		{
			name: "valid multiple platforms",
			manifests: map[string]string{
				"linux/amd64": "sha256:test123",
				"linux/arm64": "sha256:test456",
			},
			opts:    &config.KanikoOptions{},
			wantErr: false,
		},
		{
			name: "invalid platform format",
			manifests: map[string]string{
				"invalid": "sha256:test123",
			},
			opts:    &config.KanikoOptions{},
			wantErr: true,
		},
		{
			name: "with annotations",
			manifests: map[string]string{
				"linux/amd64": "sha256:test123",
			},
			opts: &config.KanikoOptions{
				IndexAnnotations: map[string]string{
					"org.opencontainers.image.created": "2023-01-01T00:00:00Z",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			index, err := buildOCIImageIndex(tt.manifests, tt.opts)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, index)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, index)

				mediaType, err := index.MediaType()
				assert.NoError(t, err)
				assert.Equal(t, types.OCIImageIndex, mediaType)

				indexManifest, err := index.IndexManifest()
				assert.NoError(t, err)
				assert.Len(t, indexManifest.Manifests, len(tt.manifests))

				if len(tt.opts.IndexAnnotations) > 0 {
					assert.NotEmpty(t, indexManifest.Annotations)
					for k, v := range tt.opts.IndexAnnotations {
						assert.Equal(t, v, indexManifest.Annotations[k])
					}
				}
			}
		})
	}
}

func TestBuildDockerManifestList(t *testing.T) {
	tests := []struct {
		name      string
		manifests map[string]string
		opts      *config.KanikoOptions
		wantErr   bool
	}{
		{
			name: "valid single platform",
			manifests: map[string]string{
				"linux/amd64": "sha256:test123",
			},
			opts:    &config.KanikoOptions{},
			wantErr: false,
		},
		{
			name: "valid multiple platforms",
			manifests: map[string]string{
				"linux/amd64": "sha256:test123",
				"linux/arm64": "sha256:test456",
			},
			opts:    &config.KanikoOptions{},
			wantErr: false,
		},
		{
			name: "invalid platform format",
			manifests: map[string]string{
				"invalid": "sha256:test123",
			},
			opts:    &config.KanikoOptions{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			index, err := buildDockerManifestList(tt.manifests, tt.opts)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, index)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, index)

				mediaType, err := index.MediaType()
				assert.NoError(t, err)
				assert.Equal(t, types.DockerManifestList, mediaType)

				indexManifest, err := index.IndexManifest()
				assert.NoError(t, err)
				assert.Len(t, indexManifest.Manifests, len(tt.manifests))
			}
		})
	}
}

func TestParsePlatform(t *testing.T) {
	tests := []struct {
		name        string
		platformStr string
		wantErr     bool
	}{
		{
			name:        "valid platform",
			platformStr: "linux/amd64",
			wantErr:     false,
		},
		{
			name:        "valid platform with variant",
			platformStr: "linux/arm64/v8",
			wantErr:     false,
		},
		{
			name:        "invalid format - missing arch",
			platformStr: "linux",
			wantErr:     true,
		},
		{
			name:        "invalid format - empty os",
			platformStr: "/amd64",
			wantErr:     true,
		},
		{
			name:        "invalid format - empty arch",
			platformStr: "linux/",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			platform, err := parsePlatform(tt.platformStr)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, platform)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, platform)
				assert.Equal(t, tt.platformStr, platform.String())
			}
		})
	}
}

func TestCreateManifestDescriptor(t *testing.T) {
	tests := []struct {
		name      string
		digestStr string
		platform  *v1.Platform
		opts      *config.KanikoOptions
		wantErr   bool
	}{
		{
			name:      "valid digest",
			digestStr: "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			platform: &v1.Platform{
				OS:           "linux",
				Architecture: "amd64",
			},
			opts:    &config.KanikoOptions{},
			wantErr: false,
		},
		{
			name:      "invalid digest format",
			digestStr: "invalid",
			platform: &v1.Platform{
				OS:           "linux",
				Architecture: "amd64",
			},
			opts:    &config.KanikoOptions{},
			wantErr: true,
		},
		{
			name:      "empty digest",
			digestStr: "",
			platform: &v1.Platform{
				OS:           "linux",
				Architecture: "amd64",
			},
			opts:    &config.KanikoOptions{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			desc, err := fetchManifestDescriptor(tt.digestStr, tt.platform, tt.opts)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, desc)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, desc)
				assert.Equal(t, tt.platform, desc.Platform)
				assert.Equal(t, tt.digestStr, desc.Digest.String())
			}
		})
	}
}

func TestSimpleIndex(t *testing.T) {
	tests := []struct {
		name        string
		mediaType   types.MediaType
		manifests   []v1.Descriptor
		annotations map[string]string
	}{
		{
			name:      "OCI index with manifests",
			mediaType: types.OCIImageIndex,
			manifests: []v1.Descriptor{
				{
					Digest: v1.Hash{
						Algorithm: "sha256",
						Hex:       "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
					},
					Platform: &v1.Platform{
						OS:           "linux",
						Architecture: "amd64",
					},
				},
			},
		},
		{
			name:        "OCI index with annotations",
			mediaType:   types.OCIImageIndex,
			manifests:   []v1.Descriptor{},
			annotations: map[string]string{"key": "value"},
		},
		{
			name:      "Docker manifest list",
			mediaType: types.DockerManifestList,
			manifests: []v1.Descriptor{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			index := &simpleIndex{
				mediaType:   tt.mediaType,
				manifests:   tt.manifests,
				annotations: tt.annotations,
			}

			// Test MediaType
			mediaType, err := index.MediaType()
			assert.NoError(t, err)
			assert.Equal(t, tt.mediaType, mediaType)

			// Test IndexManifest
			indexManifest, err := index.IndexManifest()
			assert.NoError(t, err)
			assert.Equal(t, tt.mediaType, indexManifest.MediaType)
			assert.Equal(t, tt.manifests, indexManifest.Manifests)
			assert.Equal(t, tt.annotations, indexManifest.Annotations)

			// Test Digest and Size (these would be computed in a real implementation)
			_, err = index.Digest()
			assert.NoError(t, err)
			_, err = index.Size()
			assert.NoError(t, err)
		})
	}
}

func TestOCIModeSelection(t *testing.T) {
	tests := []struct {
		name            string
		opts            *config.KanikoOptions
		expectedOCIMode bool
	}{
		{
			name: "explicit OCI mode",
			opts: &config.KanikoOptions{
				OCIMode: "oci",
			},
			expectedOCIMode: true,
		},
		{
			name: "explicit docker mode",
			opts: &config.KanikoOptions{
				OCIMode: "docker",
			},
			expectedOCIMode: false,
		},
		{
			name: "auto mode with legacy manifest list false",
			opts: &config.KanikoOptions{
				OCIMode:            "auto",
				LegacyManifestList: false,
			},
			expectedOCIMode: true,
		},
		{
			name: "auto mode with legacy manifest list true",
			opts: &config.KanikoOptions{
				OCIMode:            "auto",
				LegacyManifestList: true,
			},
			expectedOCIMode: false,
		},
		{
			name:            "default behavior",
			opts:            &config.KanikoOptions{},
			expectedOCIMode: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifests := map[string]string{
				"linux/amd64": "sha256:test123",
			}

			index, err := BuildIndex(manifests, tt.opts)
			assert.NoError(t, err)
			assert.NotNil(t, index)

			mediaType, err := index.MediaType()
			assert.NoError(t, err)

			if tt.expectedOCIMode {
				assert.Equal(t, types.OCIImageIndex, mediaType)
			} else {
				assert.Equal(t, types.DockerManifestList, mediaType)
			}
		})
	}
}
