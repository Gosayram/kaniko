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
	"github.com/stretchr/testify/require"

	"github.com/Gosayram/kaniko/pkg/config"
)

func TestKubernetesDriver_ValidatePlatforms(t *testing.T) {
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
			name:      "empty platforms",
			platforms: []string{},
			wantErr:   true,
		},
		{
			name:      "invalid platform format",
			platforms: []string{"linux"},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			driver := &KubernetesDriver{opts: &config.KanikoOptions{}}
			err := driver.ValidatePlatforms(tt.platforms)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestKubernetesDriver_ExecuteBuilds(t *testing.T) {
	t.Run("should return error when not running in kubernetes cluster", func(t *testing.T) {
		opts := &config.KanikoOptions{}
		driver, err := NewKubernetesDriver(opts)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create in-cluster config")
		assert.Nil(t, driver)
	})
}

func TestKubernetesDriver_Cleanup(t *testing.T) {
	t.Run("cleanup should handle nil client gracefully", func(t *testing.T) {
		driver := &KubernetesDriver{opts: &config.KanikoOptions{}}
		err := driver.Cleanup()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "kubernetes client not initialized")
	})
}

func TestNewKubernetesDriver(t *testing.T) {
	t.Run("should fail when not running in kubernetes cluster", func(t *testing.T) {
		opts := &config.KanikoOptions{}
		driver, err := NewKubernetesDriver(opts)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create in-cluster config")
		assert.Nil(t, driver)
	})
}

func TestKubernetesDriver_createBuildJob(t *testing.T) {
	t.Run("create build job should succeed", func(t *testing.T) {
		driver := &KubernetesDriver{opts: &config.KanikoOptions{
			SrcContext:     "dir:///workspace",
			DockerfilePath: "Dockerfile",
			Destinations:   []string{"registry/app:tag"},
		}}
		job, err := driver.createBuildJob("linux/amd64")
		assert.NoError(t, err)
		assert.NotNil(t, job)
		assert.Equal(t, "kaniko-build-linux-amd64", job.Name)
	})
}

func TestKubernetesDriver_waitForJobCompletion(t *testing.T) {
	t.Run("wait for job completion should handle nil client gracefully", func(t *testing.T) {
		driver := &KubernetesDriver{opts: &config.KanikoOptions{}}
		_, err := driver.waitForJobCompletion(context.Background(), "non-existent-job", "linux/amd64")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "kubernetes client not initialized")
	})
}

func TestKubernetesDriver_readDigestFromPod(t *testing.T) {
	t.Run("read digest from pod should handle nil client gracefully", func(t *testing.T) {
		driver := &KubernetesDriver{opts: &config.KanikoOptions{}}
		_, err := driver.readDigestFromPod(context.Background(), "non-existent-job", "linux/amd64")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "kubernetes client not initialized")
	})
}
