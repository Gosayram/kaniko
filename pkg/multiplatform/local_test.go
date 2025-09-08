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
	"runtime"
	"strings"
	"testing"

	"github.com/Gosayram/kaniko/pkg/config"
)

func TestLocalDriver_ValidatePlatforms(t *testing.T) {
	currentPlatform := runtime.GOOS + "/" + runtime.GOARCH

	tests := []struct {
		name      string
		platforms []string
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "native platform",
			platforms: []string{currentPlatform},
			wantErr:   false,
		},
		{
			name:      "multiple platforms with native",
			platforms: []string{currentPlatform, "linux/amd64"},
			wantErr:   true,
			errMsg:    "local driver only supports single platform",
		},
		{
			name:      "non-native platform with require native",
			platforms: []string{"linux/arm64"},
			wantErr:   true,
			errMsg:    "non-native platform",
		},
		{
			name:      "non-native platform without require native",
			platforms: []string{"linux/arm64"},
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &config.KanikoOptions{
				RequireNativeNodes: strings.Contains(tt.errMsg, "non-native platform"),
			}
			driver := NewLocalDriver(opts)

			err := driver.ValidatePlatforms(tt.platforms)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidatePlatforms() expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidatePlatforms() error should contain '%s', got: %v", tt.errMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("ValidatePlatforms() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestLocalDriver_ExecuteBuilds(t *testing.T) {
	currentPlatform := runtime.GOOS + "/" + runtime.GOARCH

	tests := []struct {
		name      string
		platforms []string
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "native platform",
			platforms: []string{currentPlatform},
			wantErr:   false,
		},
		{
			name:      "multiple platforms",
			platforms: []string{currentPlatform, "linux/amd64"},
			wantErr:   true,
			errMsg:    "local driver only supports single platform",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			driver := NewLocalDriver(&config.KanikoOptions{})

			_, err := driver.ExecuteBuilds(context.Background(), tt.platforms)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ExecuteBuilds() expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ExecuteBuilds() error should contain '%s', got: %v", tt.errMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("ExecuteBuilds() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestLocalDriver_Cleanup(t *testing.T) {
	driver := NewLocalDriver(&config.KanikoOptions{})
	err := driver.Cleanup()
	if err != nil {
		t.Errorf("Cleanup() unexpected error: %v", err)
	}
}

func TestIsPlatformNative(t *testing.T) {
	currentPlatform := runtime.GOOS + "/" + runtime.GOARCH
	nonNativePlatform := "linux/arm64"

	if !isPlatformNative(currentPlatform) {
		t.Errorf("isPlatformNative(%s) should return true", currentPlatform)
	}

	if isPlatformNative(nonNativePlatform) {
		t.Errorf("isPlatformNative(%s) should return false", nonNativePlatform)
	}

	// Test invalid platform formats
	if isPlatformNative("invalid-platform") {
		t.Errorf("isPlatformNative('invalid-platform') should return false")
	}

	if isPlatformNative("linux/") {
		t.Errorf("isPlatformNative('linux/') should return false")
	}

	if isPlatformNative("/amd64") {
		t.Errorf("isPlatformNative('/amd64') should return false")
	}
}
