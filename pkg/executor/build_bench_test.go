/*
Copyright 2024 Google LLC

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

package executor

import (
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"

	"github.com/Gosayram/kaniko/pkg/cache"
	"github.com/Gosayram/kaniko/pkg/commands"
	"github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/dockerfile"
)

// mockLayerCacheForOptimizeBenchmark is a mock layer cache for optimize benchmarking
type mockLayerCacheForOptimizeBenchmark struct {
	images map[string]v1.Image
	delay  time.Duration // Simulate network latency
}

func newMockLayerCacheForOptimizeBenchmark(delay time.Duration) *mockLayerCacheForOptimizeBenchmark {
	return &mockLayerCacheForOptimizeBenchmark{
		images: make(map[string]v1.Image),
		delay:  delay,
	}
}

func (m *mockLayerCacheForOptimizeBenchmark) RetrieveLayer(key string) (v1.Image, error) {
	// Simulate network latency
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	img, exists := m.images[key]
	if !exists {
		return nil, cache.ErrCacheMiss
	}
	return img, nil
}

func (m *mockLayerCacheForOptimizeBenchmark) RetrieveLayersBatch(keys []string) map[string]cache.LayerResult {
	results := make(map[string]cache.LayerResult)
	for _, key := range keys {
		img, err := m.RetrieveLayer(key)
		results[key] = cache.LayerResult{
			Image: img,
			Error: err,
		}
	}
	return results
}

// BenchmarkOptimize_sequentialCacheChecks benchmarks sequential cache checking
// This simulates the old behavior before parallel optimization
func BenchmarkOptimize_sequentialCacheChecks(b *testing.B) {
	// Create mock cache with simulated network latency (2ms per request)
	mockCache := newMockLayerCacheForOptimizeBenchmark(2 * time.Millisecond)

	// Create test images for cache hits
	numCommands := 10
	for i := 0; i < numCommands; i++ {
		key := string(rune('a' + i))
		img, _ := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
			Config: v1.Config{},
		})
		mockCache.images[key] = img
	}

	// Create stage builder with mock cache
	opts := &config.KanikoOptions{
		Cache:                    true,
		MaxConcurrentCacheChecks: 1, // Sequential (old behavior)
	}
	sb := &stageBuilder{
		layerCache:       mockCache,
		opts:             opts,
		cmds:             make([]commands.DockerCommand, numCommands),
		args:             dockerfile.NewBuildArgs(nil),
		digestToCacheKey: make(map[string]string),
	}

	// Create composite key
	compositeKey := CompositeCache{}
	cfg := &v1.Config{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sb.optimize(compositeKey, cfg)
	}
}

// BenchmarkOptimize_parallelCacheChecks benchmarks parallel cache checking
// This simulates the new optimized behavior
func BenchmarkOptimize_parallelCacheChecks(b *testing.B) {
	// Create mock cache with simulated network latency (2ms per request)
	mockCache := newMockLayerCacheForOptimizeBenchmark(2 * time.Millisecond)

	// Create test images for cache hits
	numCommands := 10
	for i := 0; i < numCommands; i++ {
		key := string(rune('a' + i))
		img, _ := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
			Config: v1.Config{},
		})
		mockCache.images[key] = img
	}

	// Create stage builder with mock cache
	opts := &config.KanikoOptions{
		Cache:                    true,
		MaxConcurrentCacheChecks: 5, // Parallel (new behavior)
		LayerLoadMaxConcurrent:   3,
	}
	sb := &stageBuilder{
		layerCache:       mockCache,
		opts:             opts,
		cmds:             make([]commands.DockerCommand, numCommands),
		args:             dockerfile.NewBuildArgs(nil),
		digestToCacheKey: make(map[string]string),
	}

	// Create composite key
	compositeKey := CompositeCache{}
	cfg := &v1.Config{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sb.optimize(compositeKey, cfg)
	}
}

// BenchmarkOptimize_largeDockerfile benchmarks optimize with many commands
func BenchmarkOptimize_largeDockerfile(b *testing.B) {
	// Create mock cache with simulated network latency (1ms per request)
	mockCache := newMockLayerCacheForOptimizeBenchmark(1 * time.Millisecond)

	// Create test images for cache hits (20 commands)
	numCommands := 20
	for i := 0; i < numCommands; i++ {
		key := string(rune('a' + (i % 26)))
		img, _ := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
			Config: v1.Config{},
		})
		mockCache.images[key] = img
	}

	// Create stage builder with parallel cache checking
	opts := &config.KanikoOptions{
		Cache:                    true,
		MaxConcurrentCacheChecks: 5,
		LayerLoadMaxConcurrent:   3,
	}
	sb := &stageBuilder{
		layerCache:       mockCache,
		opts:             opts,
		cmds:             make([]commands.DockerCommand, numCommands),
		args:             dockerfile.NewBuildArgs(nil),
		digestToCacheKey: make(map[string]string),
	}

	// Create composite key
	compositeKey := CompositeCache{}
	cfg := &v1.Config{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sb.optimize(compositeKey, cfg)
	}
}
