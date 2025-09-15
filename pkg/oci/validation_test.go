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

	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/assert"

	"github.com/Gosayram/kaniko/pkg/config"
)

func TestNewValidator(t *testing.T) {
	opts := &config.KanikoOptions{}
	validator := NewValidator(opts)
	assert.NotNil(t, validator)
	assert.Equal(t, opts, validator.opts)
}

func TestValidator_ValidateMediaType(t *testing.T) {
	tests := []struct {
		name      string
		mediaType types.MediaType
		wantErr   bool
	}{
		{
			name:      "valid OCI index",
			mediaType: "application/vnd.oci.image.index.v1+json",
			wantErr:   false,
		},
		{
			name:      "valid OCI manifest",
			mediaType: "application/vnd.oci.image.manifest.v1+json",
			wantErr:   false,
		},
		{
			name:      "valid OCI config",
			mediaType: "application/vnd.oci.image.config.v1+json",
			wantErr:   false,
		},
		{
			name:      "valid OCI layer",
			mediaType: "application/vnd.oci.image.layer.v1.tar",
			wantErr:   false,
		},
		{
			name:      "valid Docker manifest list",
			mediaType: "application/vnd.docker.distribution.manifest.list.v2+json",
			wantErr:   false,
		},
		{
			name:      "valid Docker manifest",
			mediaType: "application/vnd.docker.distribution.manifest.v2+json",
			wantErr:   false,
		},
		{
			name:      "invalid media type",
			mediaType: "application/invalid",
			wantErr:   true,
		},
		{
			name:      "empty media type",
			mediaType: "",
			wantErr:   true,
		},
	}

	validator := NewValidator(&config.KanikoOptions{})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateMediaType(tt.mediaType)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_ValidateSchemaVersion(t *testing.T) {
	tests := []struct {
		name    string
		version int
		wantErr bool
	}{
		{
			name:    "valid version 2",
			version: 2,
			wantErr: false,
		},
		{
			name:    "invalid version 1",
			version: 1,
			wantErr: true,
		},
		{
			name:    "invalid version 3",
			version: 3,
			wantErr: true,
		},
	}

	validator := NewValidator(&config.KanikoOptions{})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateSchemaVersion(tt.version)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_ValidatePlatform(t *testing.T) {
	tests := []struct {
		name     string
		platform v1.Platform
		wantErr  bool
	}{
		{
			name: "valid linux/amd64",
			platform: v1.Platform{
				OS:           "linux",
				Architecture: "amd64",
			},
			wantErr: false,
		},
		{
			name: "valid linux/arm64",
			platform: v1.Platform{
				OS:           "linux",
				Architecture: "arm64",
			},
			wantErr: false,
		},
		{
			name: "valid linux/arm64/v8",
			platform: v1.Platform{
				OS:           "linux",
				Architecture: "arm64",
				Variant:      "v8",
			},
			wantErr: false,
		},
		{
			name: "invalid OS",
			platform: v1.Platform{
				OS:           "invalid",
				Architecture: "amd64",
			},
			wantErr: true,
		},
		{
			name: "invalid architecture",
			platform: v1.Platform{
				OS:           "linux",
				Architecture: "invalid",
			},
			wantErr: true,
		},
		{
			name: "invalid variant",
			platform: v1.Platform{
				OS:           "linux",
				Architecture: "arm64",
				Variant:      "invalid",
			},
			wantErr: true,
		},
		{
			name: "empty OS",
			platform: v1.Platform{
				OS:           "",
				Architecture: "amd64",
			},
			wantErr: true,
		},
		{
			name: "empty architecture",
			platform: v1.Platform{
				OS:           "linux",
				Architecture: "",
			},
			wantErr: true,
		},
	}

	validator := NewValidator(&config.KanikoOptions{})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validatePlatform(tt.platform)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_ValidateAnnotationKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
		wantErr bool
	}{
		{
			name: "valid OCI annotation",
			key:  "org.opencontainers.image.created",
			wantErr: false,
		},
		{
			name: "valid custom annotation",
			key:  "com.example.custom",
			wantErr: false,
		},
		{
			name: "invalid single part",
			key:  "simplekey",
			wantErr: true,
		},
		{
			name: "invalid consecutive dots",
			key:  "com..example",
			wantErr: true,
		},
		{
			name: "invalid starts with dot",
			key:  ".com.example",
			wantErr: true,
		},
		{
			name: "invalid ends with dot",
			key:  "com.example.",
			wantErr: true,
		},
		{
			name: "empty key",
			key:  "",
			wantErr: true,
		},
	}

	validator := NewValidator(&config.KanikoOptions{})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateAnnotationKey(tt.key)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_ValidateAnnotationValue(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
		wantErr bool
	}{
		{
			name:  "valid RFC3339 date",
			key:   "org.opencontainers.image.created",
			value: "2023-01-01T00:00:00Z",
			wantErr: false,
		},
		{
			name:  "invalid RFC3339 date",
			key:   "org.opencontainers.image.created",
			value: "2023-01-01",
			wantErr: true,
		},
		{
			name:  "valid URL",
			key:   "org.opencontainers.image.url",
			value: "https://example.com",
			wantErr: false,
		},
		{
			name:  "invalid URL",
			key:   "org.opencontainers.image.url",
			value: "example.com",
			wantErr: true,
		},
		{
			name:  "empty value",
			key:   "org.opencontainers.image.authors",
			value: "",
			wantErr: true,
		},
		{
			name:  "non-OCI annotation",
			key:   "custom.annotation",
			value: "any value",
			wantErr: false,
		},
	}

	validator := NewValidator(&config.KanikoOptions{})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateAnnotationValue(tt.key, tt.value)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_ValidateCompression(t *testing.T) {
	tests := []struct {
		name       string
		compression config.Compression
		wantErr    bool
	}{
		{
			name:       "valid gzip",
			compression: config.GZip,
			wantErr:    false,
		},
		{
			name:       "valid zstd",
			compression: config.ZStd,
			wantErr:    false,
		},
		{
			name:       "invalid compression",
			compression: config.Compression("invalid"),
			wantErr:    true,
		},
	}

	validator := NewValidator(&config.KanikoOptions{})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateCompression(tt.compression)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_ValidateOCIMode(t *testing.T) {
	tests := []struct {
		name    string
		ociMode string
		wantErr bool
	}{
		{
			name:    "valid oci mode",
			ociMode: "oci",
			wantErr: false,
		},
		{
			name:    "valid docker mode",
			ociMode: "docker",
			wantErr: false,
		},
		{
			name:    "valid auto mode",
			ociMode: "auto",
			wantErr: false,
		},
		{
			name:    "invalid mode",
			ociMode: "invalid",
			wantErr: true,
		},
		{
			name:    "empty mode",
			ociMode: "",
			wantErr: true,
		},
	}

	validator := NewValidator(&config.KanikoOptions{})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateOCIMode(tt.ociMode)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_Contains(t *testing.T) {
	tests := []struct {
		name     string
		slice    []string
		value    string
		expected bool
	}{
		{
			name:     "contains value",
			slice:    []string{"a", "b", "c"},
			value:    "b",
			expected: true,
		},
		{
			name:     "does not contain value",
			slice:    []string{"a", "b", "c"},
			value:    "d",
			expected: false,
		},
		{
			name:     "empty slice",
			slice:    []string{},
			value:    "a",
			expected: false,
		},
		{
			name:     "empty value",
			slice:    []string{"a", "b", "c"},
			value:    "",
			expected: false,
		},
	}

	validator := NewValidator(&config.KanikoOptions{})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.contains(tt.slice, tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidator_IsValidRFC3339Date(t *testing.T) {
	tests := []struct {
		name     string
		date     string
		expected bool
	}{
		{
			name:     "valid RFC3339",
			date:     "2023-01-01T00:00:00Z",
			expected: true,
		},
		{
			name:     "missing T",
			date:     "2023-01-01 00:00:00Z",
			expected: false,
		},
		{
			name:     "missing Z",
			date:     "2023-01-01T00:00:00",
			expected: false,
		},
		{
			name:     "empty date",
			date:     "",
			expected: false,
		},
	}

	validator := NewValidator(&config.KanikoOptions{})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.isValidRFC3339Date(tt.date)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidator_IsValidURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected bool
	}{
		{
			name:     "valid http URL",
			url:      "http://example.com",
			expected: true,
		},
		{
			name:     "valid https URL",
			url:      "https://example.com",
			expected: true,
		},
		{
			name:     "invalid URL",
			url:      "example.com",
			expected: false,
		},
		{
			name:     "empty URL",
			url:      "",
			expected: false,
		},
	}

	validator := NewValidator(&config.KanikoOptions{})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.isValidURL(tt.url)
			assert.Equal(t, tt.expected, result)
		})
	}
}