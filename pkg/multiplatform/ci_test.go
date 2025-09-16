/*
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHWITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package multiplatform

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Gosayram/kaniko/pkg/config"
)

func TestCIDriver_ValidatePlatforms(t *testing.T) {
	tests := []struct {
		name      string
		opts      *config.KanikoOptions
		platforms []string
		wantErr   bool
	}{
		{
			name: "valid platforms with digests-from",
			opts: &config.KanikoOptions{
				DigestsFrom: "/tmp/digests",
			},
			platforms: []string{"linux/amd64", "linux/arm64"},
			wantErr:   false,
		},
		{
			name: "missing digests-from path",
			opts: &config.KanikoOptions{
				DigestsFrom: "",
			},
			platforms: []string{"linux/amd64"},
			wantErr:   true,
		},
		{
			name: "empty platforms",
			opts: &config.KanikoOptions{
				DigestsFrom: "/tmp/digests",
			},
			platforms: []string{},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			driver := &CIDriver{opts: tt.opts}
			err := driver.ValidatePlatforms(tt.platforms)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCIDriver_ExecuteBuilds(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name        string
		setup       func()
		platforms   []string
		wantDigests int
		wantErr     bool
	}{
		{
			name: "successful digest collection",
			setup: func() {
				// Create digest files
				os.WriteFile(filepath.Join(tempDir, "linux-amd64.digest"), []byte("sha256:amd64digest"), 0644)
				os.WriteFile(filepath.Join(tempDir, "linux-arm64.digest"), []byte("sha256:arm64digest"), 0644)
			},
			platforms:   []string{"linux/amd64", "linux/arm64"},
			wantDigests: 2,
			wantErr:     false,
		},
		{
			name: "missing digest file",
			setup: func() {
				// Only create one digest file
				os.WriteFile(filepath.Join(tempDir, "linux-amd64.digest"), []byte("sha256:amd64digest"), 0644)
			},
			platforms: []string{"linux/amd64", "linux/arm64"},
			wantErr:   true,
		},
		{
			name: "invalid digest format",
			setup: func() {
				os.WriteFile(filepath.Join(tempDir, "linux-amd64.digest"), []byte("invalid-digest"), 0644)
			},
			platforms: []string{"linux/amd64"},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up and setup test files
			os.RemoveAll(tempDir)
			os.MkdirAll(tempDir, 0755)
			tt.setup()

			driver := &CIDriver{
				opts: &config.KanikoOptions{
					DigestsFrom: tempDir,
				},
			}

			digests, err := driver.ExecuteBuilds(context.Background(), tt.platforms)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, digests)
			} else {
				assert.NoError(t, err)
				assert.Len(t, digests, tt.wantDigests)
				for platform, digest := range digests {
					assert.Contains(t, digest, "sha256:")
					assert.Contains(t, []string{"linux/amd64", "linux/arm64"}, platform)
				}
			}
		})
	}
}

func TestCIDriver_Cleanup(t *testing.T) {
	t.Run("cleanup should succeed", func(t *testing.T) {
		driver := &CIDriver{opts: &config.KanikoOptions{}}
		err := driver.Cleanup()
		assert.NoError(t, err)
	})
}

func TestNewCIDriver(t *testing.T) {
	t.Run("create new CI driver", func(t *testing.T) {
		opts := &config.KanikoOptions{
			DigestsFrom: "/tmp/digests",
		}
		driver, err := NewCIDriver(opts)
		require.NoError(t, err)
		assert.NotNil(t, driver)
		assert.Equal(t, opts, driver.opts)
	})
}

func TestCIDriver_readDigestFromFile(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name       string
		setup      func()
		platform   string
		wantDigest string
		wantErr    bool
	}{
		{
			name: "valid digest file",
			setup: func() {
				os.WriteFile(filepath.Join(tempDir, "linux-amd64.digest"), []byte("sha256:abc123"), 0644)
			},
			platform:   "linux/amd64",
			wantDigest: "sha256:abc123",
			wantErr:    false,
		},
		{
			name: "file not found",
			setup: func() {
				// No file created
			},
			platform: "linux/amd64",
			wantErr:  true,
		},
		{
			name: "empty file",
			setup: func() {
				os.WriteFile(filepath.Join(tempDir, "linux-amd64.digest"), []byte(""), 0644)
			},
			platform: "linux/amd64",
			wantErr:  true,
		},
		{
			name: "invalid digest format",
			setup: func() {
				os.WriteFile(filepath.Join(tempDir, "linux-amd64.digest"), []byte("invalid"), 0644)
			},
			platform: "linux/amd64",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up and setup test files
			os.RemoveAll(tempDir)
			os.MkdirAll(tempDir, 0755)
			tt.setup()

			driver := &CIDriver{opts: &config.KanikoOptions{DigestsFrom: tempDir}}
			digest, err := driver.readDigestFromFile(tt.platform)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Empty(t, digest)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantDigest, digest)
			}
		})
	}
}

func TestCIDriver_getDigestFilename(t *testing.T) {
	tests := []struct {
		name     string
		platform string
		want     string
	}{
		{
			name:     "linux amd64",
			platform: "linux/amd64",
			want:     "linux-amd64.digest",
		},
		{
			name:     "linux arm64",
			platform: "linux/arm64",
			want:     "linux-arm64.digest",
		},
		{
			name:     "windows amd64",
			platform: "windows/amd64",
			want:     "windows-amd64.digest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			driver := &CIDriver{opts: &config.KanikoOptions{}}
			filename := driver.getDigestFilename(tt.platform)
			assert.Equal(t, tt.want, filename)
		})
	}
}
