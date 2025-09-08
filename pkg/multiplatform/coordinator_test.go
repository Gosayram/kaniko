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
	"strings"
	"testing"

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
				if err == nil {
					t.Errorf("NewCoordinator() expected error, got nil")
				}
				if coordinator != nil {
					t.Errorf("NewCoordinator() expected nil coordinator, got %v", coordinator)
				}
			} else {
				if err != nil {
					t.Errorf("NewCoordinator() unexpected error: %v", err)
				}
				if coordinator == nil {
					t.Errorf("NewCoordinator() expected coordinator, got nil")
				}
			}
		})
	}
}

func TestCoordinator_Execute_NoPlatforms(t *testing.T) {
	opts := &config.KanikoOptions{
		Driver:        "local",
		MultiPlatform: []string{},
	}

	coordinator, err := NewCoordinator(opts)
	if err != nil {
		t.Fatalf("NewCoordinator() error: %v", err)
	}

	_, err = coordinator.Execute(context.Background())
	if err == nil {
		t.Errorf("Execute() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "no platforms specified") {
		t.Errorf("Execute() error message should contain 'no platforms specified', got: %v", err)
	}
}

func TestCoordinator_Execute_PreFlightChecks(t *testing.T) {
	tests := []struct {
		name      string
		platforms []string
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "duplicate platforms",
			platforms: []string{"linux/amd64", "linux/amd64"},
			wantErr:   true,
			errMsg:    "duplicate platform",
		},
		{
			name:      "invalid platform format",
			platforms: []string{"linux-amd64"},
			wantErr:   true,
			errMsg:    "invalid platform format",
		},
		{
			name:      "empty os",
			platforms: []string{"/amd64"},
			wantErr:   true,
			errMsg:    "invalid platform format",
		},
		{
			name:      "empty arch",
			platforms: []string{"linux/"},
			wantErr:   true,
			errMsg:    "invalid platform format",
		},
		{
			name:      "valid platforms",
			platforms: []string{"linux/amd64", "linux/arm64"},
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &config.KanikoOptions{
				Driver:        "local",
				MultiPlatform: tt.platforms,
			}

			coordinator, err := NewCoordinator(opts)
			if err != nil {
				t.Fatalf("NewCoordinator() error: %v", err)
			}

			_, err = coordinator.Execute(context.Background())
			if tt.wantErr {
				if err == nil {
					t.Errorf("Execute() expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Execute() error should contain '%s', got: %v", tt.errMsg, err)
				}
			} else {
				// Should pass pre-flight but fail at driver validation
				if err == nil {
					t.Errorf("Execute() expected error from driver validation, got nil")
				}
				if !strings.Contains(err.Error(), "platform validation failed") {
					t.Errorf("Execute() error should contain 'platform validation failed', got: %v", err)
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
			expected: []string{"linux/amd64", "linux/arm64"},
		},
		{
			name:     "trailing comma",
			input:    "linux/amd64,",
			expected: []string{"linux/amd64", ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parsePlatforms(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("parsePlatforms(%q) got %v, want %v", tt.input, result, tt.expected)
				return
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("parsePlatforms(%q) got %v, want %v", tt.input, result, tt.expected)
					break
				}
			}
		})
	}
}

func TestCoordinator_GetDigests(t *testing.T) {
	expectedDigests := map[string]string{
		"linux/amd64": "sha256:abc123",
		"linux/arm64": "sha256:def456",
	}

	coordinator := &Coordinator{
		opts:    &config.KanikoOptions{},
		driver:  nil,
		digests: expectedDigests,
	}

	digests := coordinator.GetDigests()
	if len(digests) != len(expectedDigests) {
		t.Errorf("GetDigests() got %v, want %v", digests, expectedDigests)
		return
	}
	for k, v := range expectedDigests {
		if digests[k] != v {
			t.Errorf("GetDigests()[%s] got %s, want %s", k, digests[k], v)
		}
	}
}

func TestPreFlightChecks_CI_Driver_Requirements(t *testing.T) {
	coordinator := &Coordinator{
		opts: &config.KanikoOptions{
			Driver:        "ci",
			MultiPlatform: []string{"linux/amd64"},
			DigestsFrom:   "", // Missing required field
		},
	}

	err := coordinator.preFlightChecks([]string{"linux/amd64"})
	if err == nil {
		t.Errorf("preFlightChecks() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "CI driver requires --digests-from path") {
		t.Errorf("preFlightChecks() error should contain 'CI driver requires --digests-from path', got: %v", err)
	}
}

func TestPreFlightChecks_PublishIndex_Requirements(t *testing.T) {
	coordinator := &Coordinator{
		opts: &config.KanikoOptions{
			Driver:        "local",
			MultiPlatform: []string{"linux/amd64"},
			PublishIndex:  true,
			Destinations:  []string{}, // No destinations
		},
	}

	err := coordinator.preFlightChecks([]string{"linux/amd64"})
	if err == nil {
		t.Errorf("preFlightChecks() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "cannot publish index without destination registries") {
		t.Errorf("preFlightChecks() error should contain 'cannot publish index without destination registries', got: %v", err)
	}
}

func TestCoordinator_Cleanup(t *testing.T) {
	coordinator := &Coordinator{
		opts:    &config.KanikoOptions{},
		driver:  &LocalDriver{},
		digests: make(map[string]string),
	}

	err := coordinator.Cleanup()
	if err != nil {
		t.Errorf("Cleanup() unexpected error: %v", err)
	}
}

// TestCoordinator_LogMultiPlatformConfig tests that the configuration logging works
// This is a basic test to ensure the function doesn't panic
func TestCoordinator_LogMultiPlatformConfig(t *testing.T) {
	coordinator := &Coordinator{
		opts: &config.KanikoOptions{
			Driver:             "k8s",
			MultiPlatform:      []string{"linux/amd64", "linux/arm64"},
			PublishIndex:       true,
			LegacyManifestList: true,
			RequireNativeNodes: true,
			OCIMode:            "auto",
			IndexAnnotations:   map[string]string{"key": "value"},
		},
	}

	// This should not panic
	coordinator.LogMultiPlatformConfig()
}
