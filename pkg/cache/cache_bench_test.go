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

package cache

import (
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"

	"github.com/Gosayram/kaniko/pkg/config"
)

// mockLayerCacheForBenchmark is a mock layer cache for benchmarking
type mockLayerCacheForBenchmark struct {
	images map[string]v1.Image
	delay  time.Duration // Simulate network latency
}

func newMockLayerCacheForBenchmark(delay time.Duration) *mockLayerCacheForBenchmark {
	return &mockLayerCacheForBenchmark{
		images: make(map[string]v1.Image),
		delay:  delay,
	}
}

func (m *mockLayerCacheForBenchmark) RetrieveLayer(key string) (v1.Image, error) {
	// Simulate network latency
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	img, exists := m.images[key]
	if !exists {
		return nil, ErrCacheMiss
	}
	return img, nil
}

func (m *mockLayerCacheForBenchmark) RetrieveLayersBatch(keys []string) map[string]LayerResult {
	results := make(map[string]LayerResult)
	for _, key := range keys {
		img, err := m.RetrieveLayer(key)
		results[key] = LayerResult{
			Image: img,
			Error: err,
		}
	}
	return results
}

// BenchmarkRetrieveLayerSequential benchmarks sequential layer retrieval
func BenchmarkRetrieveLayerSequential(b *testing.B) {
	// Create mock cache with simulated network latency (2ms per request)
	mockCache := newMockLayerCacheForBenchmark(2 * time.Millisecond)

	// Create test images
	numLayers := 10
	keys := make([]string, numLayers)
	for i := 0; i < numLayers; i++ {
		key := string(rune('a' + i))
		keys[i] = key
		img, _ := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
			Config: v1.Config{},
		})
		mockCache.images[key] = img
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, key := range keys {
			_, _ = mockCache.RetrieveLayer(key)
		}
	}
}

// BenchmarkRetrieveLayersBatch benchmarks batch layer retrieval (parallel)
func BenchmarkRetrieveLayersBatch(b *testing.B) {
	// Create mock cache with simulated network latency (2ms per request)
	mockCache := newMockLayerCacheForBenchmark(2 * time.Millisecond)

	// Create test images
	numLayers := 10
	keys := make([]string, numLayers)
	for i := 0; i < numLayers; i++ {
		key := string(rune('a' + i))
		keys[i] = key
		img, _ := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
			Config: v1.Config{},
		})
		mockCache.images[key] = img
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mockCache.RetrieveLayersBatch(keys)
	}
}

// BenchmarkFastCacheManager_Get benchmarks fast cache metadata retrieval
func BenchmarkFastCacheManager_Get(b *testing.B) {
	fcm := NewFastCacheManager()

	// Populate cache with metadata
	numEntries := 1000
	for i := 0; i < numEntries; i++ {
		key := string(rune('a' + (i % 26)))
		record := &CacheRecord{
			Key:     key,
			Digest:  "sha256:test",
			Present: true,
			Metadata: &LayerMetadata{
				Digest:  "sha256:test",
				Size:    1024,
				Created: time.Now(),
				TTL:     time.Now().Add(5 * time.Minute),
			},
		}
		_ = fcm.Set(key, record)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := string(rune('a' + (i % 26)))
		_, _ = fcm.Get(key)
	}
}

// BenchmarkFastCacheManager_Probe benchmarks fast cache probe (existence check)
func BenchmarkFastCacheManager_Probe(b *testing.B) {
	fcm := NewFastCacheManager()

	// Populate cache with metadata
	numEntries := 1000
	for i := 0; i < numEntries; i++ {
		key := string(rune('a' + (i % 26)))
		record := &CacheRecord{
			Key:     key,
			Digest:  "sha256:test",
			Present: true,
			Metadata: &LayerMetadata{
				Digest:  "sha256:test",
				Size:    1024,
				Created: time.Now(),
				TTL:     time.Now().Add(5 * time.Minute),
			},
		}
		_ = fcm.Set(key, record)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := string(rune('a' + (i % 26)))
		_, _ = fcm.Probe(key)
	}
}

// BenchmarkLocalFileCache_index benchmarks local file cache index lookup
func BenchmarkLocalFileCache_index(b *testing.B) {
	opts := &config.CacheOptions{
		CacheDir: "/tmp", // Use temp dir (will fail on miss, but tests index speed)
		CacheTTL: 1 * time.Hour,
	}

	lfc := NewLocalFileCache(opts)

	// Build index (even if empty, tests index structure)
	_ = lfc.buildIndex()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := "test-key"
		_, _ = lfc.getIndexEntry(key)
	}
}

// BenchmarkFastSlowCache_ProbeCache benchmarks fast/slow cache probe
func BenchmarkFastSlowCache_ProbeCache(b *testing.B) {
	// Create mock slow cache
	mockSlowCache := newMockLayerCacheForBenchmark(2 * time.Millisecond)
	mockRemoteCache := newMockLayerCacheForBenchmark(2 * time.Millisecond)

	// Create test images
	numLayers := 10
	for i := 0; i < numLayers; i++ {
		key := string(rune('a' + i))
		img, _ := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
			Config: v1.Config{},
		})
		mockSlowCache.images[key] = img
		mockRemoteCache.images[key] = img
	}

	// Create FastSlowCache
	fsc := NewFastSlowCache(mockSlowCache, mockRemoteCache)

	// Pre-populate fast cache with metadata
	for i := 0; i < numLayers; i++ {
		key := string(rune('a' + i))
		record := &CacheRecord{
			Key:     key,
			Digest:  "sha256:test",
			Present: true,
			Metadata: &LayerMetadata{
				Digest:  "sha256:test",
				Size:    1024,
				Created: time.Now(),
				TTL:     time.Now().Add(5 * time.Minute),
			},
		}
		_ = fsc.fastCache.Set(key, record)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := string(rune('a' + (i % numLayers)))
		_, _ = fsc.ProbeCache(key)
	}
}
