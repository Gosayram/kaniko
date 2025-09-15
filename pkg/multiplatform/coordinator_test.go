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

package multiplatform

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/Gosayram/kaniko/pkg/config"
)

func TestNewCoordinator(t *testing.T) {
	tests := []struct {
		name    string
		opts    *config.KanikoOptions
		wantErr bool
	}{
		{
			name: "valid local driver",
			opts: &config.KanikoOptions{
				Driver: "local",
			},
			wantErr: false,
		},
		{
			name: "valid k8s driver",
			opts: &config.KanikoOptions{
				Driver: "k8s",
			},
			wantErr: false,
		},
		{
			name: "valid ci driver",
			opts: &config.KanikoOptions{
				Driver: "ci",
			},
			wantErr: false,
		},
		{
			name: "invalid driver",
			opts: &config.KanikoOptions{
				Driver: "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			coordinator, err := NewCoordinator(tt.opts)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, coordinator)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, coordinator)
				assert.Equal(t, tt.opts, coordinator.opts)
			}
		})
	}
}

func TestCoordinator_PreFlightChecks(t *testing.T) {
	tests := []struct {
		name      string
		opts      *config.KanikoOptions
		platforms []string
		wantErr   bool
	}{
		{
			name: "valid platforms",
			opts: &config.KanikoOptions{
				Driver: "local",
			},
			platforms: []string{"linux/amd64", "linux/arm64"},
			wantErr:   false,
		},
		{
			name: "duplicate platforms",
			opts: &config.KanikoOptions{
				Driver: "local",
			},
			platforms: []string{"linux/amd64", "linux/amd64"},
			wantErr:   true,
		},
		{
			name: "invalid platform format",
			opts: &config.KanikoOptions{
				Driver: "local",
			},
			platforms: []string{"linux"},
			wantErr:   true,
		},
		{
			name: "empty platform",
			opts: &config.KanikoOptions{
				Driver: "local",
			},
			platforms: []string{""},
			wantErr:   true,
		},
		{
			name: "ci driver without digests-from",
			opts: &config.KanikoOptions{
				Driver: "ci",
			},
			platforms: []string{"linux/amd64"},
			wantErr:   true,
		},
		{
			name: "publish index without destinations",
			opts: &config.KanikoOptions{
				Driver:       "local",
				PublishIndex: true,
			},
			platforms: []string{"linux/amd64"},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			coordinator := &Coordinator{
				opts: tt.opts,
			}
			err := coordinator.preFlightChecks(tt.platforms)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCoordinator_Execute(t *testing.T) {
	tests := []struct {
		name      string
		opts      *config.KanikoOptions
		platforms []string
		wantErr   bool
	}{
		{
			name: "no platforms specified",
			opts: &config.KanikoOptions{
				Driver: "local",
			},
			platforms: []string{},
			wantErr:   true,
		},
		{
			name: "local driver with single platform",
			opts: &config.KanikoOptions{
				Driver: "local",
			},
			platforms: []string{"linux/amd64"},
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			coordinator := &Coordinator{
				opts: tt.opts,
				driver: &mockDriver{
					validatePlatformsFunc: func(platforms []string) error {
						return nil
					},
					executeBuildsFunc: func(ctx context.Context, platforms []string) (map[string]string, error) {
						return map[string]string{"linux/amd64": "sha256:test"}, nil
					},
				},
			}
			tt.opts.MultiPlatform = tt.platforms

			index, err := coordinator.Execute(context.Background())
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, index)
			} else {
				assert.NoError(t, err)
				if tt.opts.PublishIndex {
					assert.NotNil(t, index)
				} else {
					assert.Nil(t, index)
				}
			}
		})
	}
}

func TestParsePlatforms(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:     "single platform",
			input:    "linux/amd64",
			expected: []string{"linux/amd64"},
		},
		{
			name:     "multiple platforms",
			input:    "linux/amd64,linux/arm64",
			expected: []string{"linux/amd64", "linux/arm64"},
		},
		{
			name:     "multiple platforms with spaces",
			input:    "linux/amd64, linux/arm64",
			expected: []string{"linux/amd64", " linux/arm64"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parsePlatforms(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetDriver(t *testing.T) {
	tests := []struct {
		name    string
		opts    *config.KanikoOptions
		wantErr bool
	}{
		{
			name: "local driver",
			opts: &config.KanikoOptions{
				Driver: "local",
			},
			wantErr: false,
		},
		{
			name: "k8s driver",
			opts: &config.KanikoOptions{
				Driver: "k8s",
			},
			wantErr: false,
		},
		{
			name: "ci driver",
			opts: &config.KanikoOptions{
				Driver: "ci",
			},
			wantErr: false,
		},
		{
			name: "invalid driver",
			opts: &config.KanikoOptions{
				Driver: "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			driver, err := getDriver(tt.opts)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, driver)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, driver)
			}
		})
	}
}

func TestCoordinator_GetDigests(t *testing.T) {
	expectedDigests := map[string]string{
		"linux/amd64": "sha256:test1",
		"linux/arm64": "sha256:test2",
	}

	coordinator := &Coordinator{
		digests: expectedDigests,
	}

	result := coordinator.GetDigests()
	assert.Equal(t, expectedDigests, result)
}

// mockDriver is a mock implementation of the Driver interface for testing
type mockDriver struct {
	validatePlatformsFunc func(platforms []string) error
	executeBuildsFunc     func(ctx context.Context, platforms []string) (map[string]string, error)
	cleanupFunc           func() error
}

func (m *mockDriver) ValidatePlatforms(platforms []string) error {
	if m.validatePlatformsFunc != nil {
		return m.validatePlatformsFunc(platforms)
	}
	return nil
}

func (m *mockDriver) ExecuteBuilds(ctx context.Context, platforms []string) (map[string]string, error) {
	if m.executeBuildsFunc != nil {
		return m.executeBuildsFunc(ctx, platforms)
	}
	return map[string]string{}, nil
}

func (m *mockDriver) Cleanup() error {
	if m.cleanupFunc != nil {
		return m.cleanupFunc()
	}
	return nil
}

func TestCoordinator_LogMultiPlatformConfig(t *testing.T) {
	opts := &config.KanikoOptions{
		Driver:             "local",
		MultiPlatform:      []string{"linux/amd64", "linux/arm64"},
		PublishIndex:       true,
		LegacyManifestList: true,
		RequireNativeNodes: true,
		OCIMode:            "oci",
		IndexAnnotations:   map[string]string{"key": "value"},
	}

	coordinator := &Coordinator{opts: opts}
	// This should not panic and should log the configuration
	coordinator.LogMultiPlatformConfig()
}

func TestValidatePlatformDuplicates(t *testing.T) {
	tests := []struct {
		name      string
		platforms []string
		wantErr   bool
	}{
		{
			name:      "no duplicates",
			platforms: []string{"linux/amd64", "linux/arm64"},
			wantErr:   false,
		},
		{
			name:      "with duplicates",
			platforms: []string{"linux/amd64", "linux/amd64"},
			wantErr:   true,
		},
		{
			name:      "empty platforms",
			platforms: []string{},
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePlatformDuplicates(tt.platforms)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePlatformFormat(t *testing.T) {
	tests := []struct {
		name      string
		platforms []string
		wantErr   bool
	}{
		{
			name:      "valid platforms",
			platforms: []string{"linux/amd64", "linux/arm64"},
			wantErr:   false,
		},
		{
			name:      "invalid format - missing arch",
			platforms: []string{"linux"},
			wantErr:   true,
		},
		{
			name:      "invalid format - empty os",
			platforms: []string{"/amd64"},
			wantErr:   true,
		},
		{
			name:      "invalid format - empty arch",
			platforms: []string{"linux/"},
			wantErr:   true,
		},
		{
			name:      "invalid format - too many parts",
			platforms: []string{"linux/amd64/variant"},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePlatformFormat(tt.platforms)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePublishIndexRequirements(t *testing.T) {
	tests := []struct {
		name    string
		opts    *config.KanikoOptions
		wantErr bool
	}{
		{
			name: "publish index with destinations",
			opts: &config.KanikoOptions{
				PublishIndex: true,
				Destinations: []string{"registry/image:tag"},
			},
			wantErr: false,
		},
		{
			name: "publish index without destinations",
			opts: &config.KanikoOptions{
				PublishIndex: true,
				Destinations: []string{},
			},
			wantErr: true,
		},
		{
			name: "no publish index",
			opts: &config.KanikoOptions{
				PublishIndex: false,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePublishIndexRequirements(tt.opts)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateDriverRequirements(t *testing.T) {
	tests := []struct {
		name      string
		opts      *config.KanikoOptions
		platforms []string
		wantErr   bool
	}{
		{
			name: "local driver with multiple platforms",
			opts: &config.KanikoOptions{
				Driver: "local",
			},
			platforms: []string{"linux/amd64", "linux/arm64"},
			wantErr:   false, // Should only warn, not error
		},
		{
			name: "ci driver without digests-from",
			opts: &config.KanikoOptions{
				Driver: "ci",
			},
			platforms: []string{"linux/amd64"},
			wantErr:   true,
		},
		{
			name: "ci driver with digests-from",
			opts: &config.KanikoOptions{
				Driver:      "ci",
				DigestsFrom: "/path/to/digests",
			},
			platforms: []string{"linux/amd64"},
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDriverRequirements(tt.opts, tt.platforms)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateCacheRepositorySuffix(t *testing.T) {
	tests := []struct {
		name      string
		opts      *config.KanikoOptions
		platforms []string
	}{
		{
			name: "cache with arch suffix and multiple platforms",
			opts: &config.KanikoOptions{
				Cache:               true,
				CacheRepo:           "registry/cache",
				ArchCacheRepoSuffix: "-${ARCH}",
			},
			platforms: []string{"linux/amd64", "linux/arm64"},
		},
		{
			name: "cache without arch suffix",
			opts: &config.KanikoOptions{
				Cache:     true,
				CacheRepo: "registry/cache",
			},
			platforms: []string{"linux/amd64"},
		},
		{
			name: "no cache",
			opts: &config.KanikoOptions{
				Cache: false,
			},
			platforms: []string{"linux/amd64"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This function should not panic and should handle all cases gracefully
			validateCacheRepositorySuffix(tt.opts, tt.platforms)
		})
	}
}
