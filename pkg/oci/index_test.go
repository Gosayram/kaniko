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

	"github.com/Gosayram/kaniko/pkg/config"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func TestBuildIndex(t *testing.T) {
	tests := []struct {
		name        string
		manifests   map[string]string
		opts        *config.KanikoOptions
		wantErr     bool
		expectedLen int
		expectedMediaType string
	}{
		{
			name:        "empty manifests",
			manifests:   map[string]string{},
			opts:        &config.KanikoOptions{PublishIndex: true},
			wantErr:     true,
			expectedLen: 0,
			expectedMediaType: "",
		},
		{
			name: "single platform OCI",
			manifests: map[string]string{
				"linux/amd64": "sha256:abc123def4567890123456789012345678901234567890123456789012345678",
			},
			opts:        &config.KanikoOptions{PublishIndex: true, LegacyManifestList: false},
			wantErr:     false,
			expectedLen: 1,
			expectedMediaType: string(types.OCIImageIndex),
		},
		{
			name: "multiple platforms OCI",
			manifests: map[string]string{
				"linux/amd64": "sha256:abc123def4567890123456789012345678901234567890123456789012345678",
				"linux/arm64": "sha256:def4567890123456789012345678901234567890123456789012345678901234",
			},
			opts:        &config.KanikoOptions{PublishIndex: true, LegacyManifestList: false},
			wantErr:     false,
			expectedLen: 2,
			expectedMediaType: string(types.OCIImageIndex),
		},
		{
			name: "single platform Docker",
			manifests: map[string]string{
				"linux/amd64": "sha256:abc123def4567890123456789012345678901234567890123456789012345678",
			},
			opts:        &config.KanikoOptions{PublishIndex: true, LegacyManifestList: true},
			wantErr:     false,
			expectedLen: 1,
			expectedMediaType: string(types.DockerManifestList),
		},
		{
			name: "multiple platforms Docker",
			manifests: map[string]string{
				"linux/amd64": "sha256:abc123def4567890123456789012345678901234567890123456789012345678",
				"linux/arm64": "sha256:def4567890123456789012345678901234567890123456789012345678901234",
			},
			opts:        &config.KanikoOptions{PublishIndex: true, LegacyManifestList: true},
			wantErr:     false,
			expectedLen: 2,
			expectedMediaType: string(types.DockerManifestList),
		},
		{
			name: "publish index disabled",
			manifests: map[string]string{
				"linux/amd64": "sha256:abc123def4567890123456789012345678901234567890123456789012345678",
			},
			opts:        &config.KanikoOptions{PublishIndex: false},
			wantErr:     true,
			expectedLen: 0,
			expectedMediaType: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			index, err := BuildIndex(tt.manifests, tt.opts)
			if tt.wantErr {
				if err == nil {
					t.Errorf("BuildIndex() expected error, got nil")
				}
				if index != nil {
					t.Errorf("BuildIndex() expected nil index, got %v", index)
				}
				return
			}

			if err != nil {
				t.Errorf("BuildIndex() unexpected error: %v", err)
				return
			}

			if index == nil {
				t.Errorf("BuildIndex() returned nil index")
				return
			}

			indexManifest, err := index.IndexManifest()
			if err != nil {
				t.Errorf("IndexManifest() error: %v", err)
				return
			}

			if len(indexManifest.Manifests) != tt.expectedLen {
				t.Errorf("BuildIndex() got %d manifests, want %d", len(indexManifest.Manifests), tt.expectedLen)
			}

			mediaType, err := index.MediaType()
			if err != nil {
				t.Errorf("MediaType() error: %v", err)
				return
			}

			if string(mediaType) != tt.expectedMediaType {
				t.Errorf("BuildIndex() got media type %s, want %s", mediaType, tt.expectedMediaType)
			}
		})
	}
}

func TestBuildIndex_Annotations(t *testing.T) {
	manifests := map[string]string{
		"linux/amd64": "sha256:abc123def4567890123456789012345678901234567890123456789012345678",
	}
	opts := &config.KanikoOptions{
		PublishIndex:     true,
		IndexAnnotations: map[string]string{
			"key1": "value1",
			"key2": "value2",
		},
	}

	index, err := BuildIndex(manifests, opts)
	if err != nil {
		t.Fatalf("BuildIndex() error: %v", err)
	}

	indexManifest, err := index.IndexManifest()
	if err != nil {
		t.Fatalf("IndexManifest() error: %v", err)
	}

	if indexManifest.Annotations == nil {
		t.Fatal("Index manifest annotations should not be nil")
	}

	if indexManifest.Annotations["key1"] != "value1" {
		t.Errorf("Expected annotation 'key1' to be 'value1', got %s", indexManifest.Annotations["key1"])
	}

	if indexManifest.Annotations["key2"] != "value2" {
		t.Errorf("Expected annotation 'key2' to be 'value2', got %s", indexManifest.Annotations["key2"])
	}
}

func TestParsePlatform(t *testing.T) {
	tests := []struct {
		name     string
		platform string
		expected *v1.Platform
		wantErr  bool
	}{
		{
			name:     "simple platform",
			platform: "linux/amd64",
			expected: &v1.Platform{
				OS:           "linux",
				Architecture: "amd64",
			},
			wantErr: false,
		},
		{
			name:     "platform with variant",
			platform: "linux/arm64/v8",
			expected: &v1.Platform{
				OS:           "linux",
				Architecture: "arm64",
				Variant:      "v8",
			},
			wantErr: false,
		},
		{
			name:     "invalid platform",
			platform: "linux-amd64",
			expected: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parsePlatform(tt.platform)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parsePlatform() expected error, got nil")
				}
				if result != nil {
					t.Errorf("parsePlatform() expected nil result, got %v", result)
				}
				return
			}

			if err != nil {
				t.Errorf("parsePlatform() unexpected error: %v", err)
				return
			}

			if result == nil {
				t.Errorf("parsePlatform() returned nil platform")
				return
			}

			if result.OS != tt.expected.OS {
				t.Errorf("parsePlatform() OS got %s, want %s", result.OS, tt.expected.OS)
			}

			if result.Architecture != tt.expected.Architecture {
				t.Errorf("parsePlatform() Architecture got %s, want %s", result.Architecture, tt.expected.Architecture)
			}

			if result.Variant != tt.expected.Variant {
				t.Errorf("parsePlatform() Variant got %s, want %s", result.Variant, tt.expected.Variant)
			}
		})
	}
}