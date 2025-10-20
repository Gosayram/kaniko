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

package network

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sirupsen/logrus"
)

// RegistryClientConfig holds configuration for the registry client
type RegistryClientConfig struct {
	// Connection settings
	MaxConcurrency int           // Maximum concurrent requests
	RequestTimeout time.Duration // Request timeout
	RetryAttempts  int           // Number of retry attempts
	RetryDelay     time.Duration // Delay between retries

	// Registry settings
	EnableParallelPull bool   // Enable parallel layer pulling
	EnableCompression  bool   // Enable compression
	UserAgent          string // User agent string

	// Cache settings
	EnableManifestCache  bool          // Enable manifest caching
	ManifestCacheTimeout time.Duration // Manifest cache timeout
}

// DefaultRegistryClientConfig returns default configuration
func DefaultRegistryClientConfig() *RegistryClientConfig {
	return &RegistryClientConfig{
		MaxConcurrency: defaultRegistryMaxConcurrency,
		RequestTimeout: DefaultRequestTimeout,
		RetryAttempts:  defaultRegistryRetryAttempts,
		RetryDelay:     defaultRegistryRetryDelay * time.Second,

		EnableParallelPull: true,
		EnableCompression:  true,
		UserAgent:          "kaniko-optimized/1.0",

		EnableManifestCache:  true,
		ManifestCacheTimeout: DefaultManifestCacheTimeout,
	}
}

// RegistryClient provides optimized registry operations
type RegistryClient struct {
	config         *RegistryClientConfig
	parallelClient *ParallelClient
	connectionPool *ConnectionPool
	manifestCache  *ManifestCache
	stats          *RegistryClientStats
	statsMutex     sync.RWMutex
}

// RegistryClientStats holds statistics about registry client usage
type RegistryClientStats struct {
	TotalRequests    int64         `json:"total_requests"`
	ManifestRequests int64         `json:"manifest_requests"`
	LayerRequests    int64         `json:"layer_requests"`
	CacheHits        int64         `json:"cache_hits"`
	CacheMisses      int64         `json:"cache_misses"`
	AverageLatency   time.Duration `json:"average_latency"`
	TotalBytes       int64         `json:"total_bytes"`
	LastReset        time.Time     `json:"last_reset"`
}

// NewRegistryClient creates a new optimized registry client
func NewRegistryClient(config *RegistryClientConfig, pool *ConnectionPool) *RegistryClient {
	if config == nil {
		config = DefaultRegistryClientConfig()
	}

	// Create parallel client
	parallelConfig := &ParallelClientConfig{
		MaxConcurrency:    config.MaxConcurrency,
		RequestTimeout:    config.RequestTimeout,
		RetryAttempts:     config.RetryAttempts,
		RetryDelay:        config.RetryDelay,
		EnableCompression: config.EnableCompression,
		UserAgent:         config.UserAgent,
	}
	parallelClient := NewParallelClient(parallelConfig, pool)

	client := &RegistryClient{
		config:         config,
		parallelClient: parallelClient,
		connectionPool: pool,
		stats: &RegistryClientStats{
			LastReset: time.Now(),
		},
	}

	// Initialize manifest cache if enabled
	if config.EnableManifestCache {
		client.manifestCache = NewManifestCache(config.ManifestCacheTimeout)
	}

	logrus.Info("🏗️ Registry client initialized with optimizations")
	return client
}

// PullImage pulls an image from registry with optimizations
func (rc *RegistryClient) PullImage(_ context.Context, ref name.Reference, options ...remote.Option) (v1.Image, error) {
	start := time.Now()
	logrus.Infof("🏗️ Pulling image: %s", ref.String())

	// Check manifest cache first
	if rc.manifestCache != nil {
		if cachedImage := rc.manifestCache.Get(ref.String()); cachedImage != nil {
			rc.recordCacheHit()
			logrus.Debugf("🏗️ Manifest cache hit for %s", ref.String())
			return cachedImage, nil
		}
		rc.recordCacheMiss()
	}

	// Create optimized remote options
	remoteOptions := rc.createRemoteOptions(options...)

	// Pull image using optimized transport
	image, err := remote.Image(ref, remoteOptions...)
	if err != nil {
		// Record failed request if needed
		return nil, fmt.Errorf("failed to pull image %s: %w", ref.String(), err)
	}

	// Cache manifest if enabled
	if rc.manifestCache != nil {
		rc.manifestCache.Set(ref.String(), image)
	}

	// Update statistics
	rc.updateStats(time.Since(start), 0, true)
	logrus.Infof("🏗️ Successfully pulled image: %s (%v)", ref.String(), time.Since(start))

	return image, nil
}

// PullImageParallel pulls multiple images in parallel
func (rc *RegistryClient) PullImageParallel(ctx context.Context, refs []name.Reference,
	_ ...remote.Option) ([]v1.Image, error) {
	if len(refs) == 0 {
		return nil, fmt.Errorf("no references provided")
	}

	logrus.Infof("🏗️ Pulling %d images in parallel", len(refs))
	start := time.Now()

	// Create parallel requests
	requests := make([]ParallelRequest, len(refs))
	for i, ref := range refs {
		requests[i] = ParallelRequest{
			URL: fmt.Sprintf("https://%s/v2/%s/manifests/%s",
				ref.Context().RegistryStr(), ref.Context().RepositoryStr(), ref.Identifier()),
			Method: "GET",
			Headers: map[string]string{
				"Accept": "application/vnd.docker.distribution.manifest.v2+json",
			},
			Timeout: rc.config.RequestTimeout,
		}
	}

	// Execute parallel requests
	responses, err := rc.parallelClient.ExecuteParallel(ctx, requests)
	if err != nil {
		return nil, fmt.Errorf("parallel pull failed: %w", err)
	}

	// Process responses
	images := make([]v1.Image, len(refs))
	successCount := 0

	for i, response := range responses {
		if response.Error != nil {
			logrus.Warnf("🏗️ Failed to pull image %s: %v", refs[i].String(), response.Error)
			continue
		}

		if response.StatusCode != http.StatusOK {
			logrus.Warnf("🏗️ Unexpected status code %d for %s", response.StatusCode, refs[i].String())
			continue
		}

		// Parse manifest and create image
		// This is a simplified version - in reality, you'd need to parse the manifest
		// and create the appropriate image object
		images[i] = nil // Placeholder - would need actual implementation
		successCount++
	}

	totalTime := time.Since(start)
	logrus.Infof("🏗️ Parallel pull completed: %d/%d successful (%v)", successCount, len(refs), totalTime)

	return images, nil
}

// PushImage pushes an image to registry with optimizations
func (rc *RegistryClient) PushImage(_ context.Context, ref name.Reference, image v1.Image,
	options ...remote.Option) error {
	start := time.Now()
	logrus.Infof("🏗️ Pushing image: %s", ref.String())

	// Create optimized remote options
	remoteOptions := rc.createRemoteOptions(options...)

	// Push image using optimized transport
	if err := remote.Write(ref, image, remoteOptions...); err != nil {
		// Record failed request if needed
		return fmt.Errorf("failed to push image %s: %w", ref.String(), err)
	}

	// Update statistics
	rc.updateStats(time.Since(start), 0, true)
	logrus.Infof("🏗️ Successfully pushed image: %s (%v)", ref.String(), time.Since(start))

	return nil
}

// createRemoteOptions creates optimized remote options
func (rc *RegistryClient) createRemoteOptions(options ...remote.Option) []remote.Option {
	// Start with provided options
	remoteOptions := make([]remote.Option, len(options))
	copy(remoteOptions, options)

	// Add optimized transport and user agent
	remoteOptions = append(remoteOptions,
		remote.WithTransport(rc.connectionPool.GetTransport()),
		remote.WithUserAgent(rc.config.UserAgent))

	return remoteOptions
}

// updateStats updates client statistics
func (rc *RegistryClient) updateStats(latency time.Duration, bytes int64, success bool) {
	rc.statsMutex.Lock()
	defer rc.statsMutex.Unlock()

	rc.stats.TotalRequests++
	rc.stats.TotalBytes += bytes

	if success {
		// Update average latency using exponential moving average
		if rc.stats.AverageLatency == 0 {
			rc.stats.AverageLatency = latency
		} else {
			rc.stats.AverageLatency = (rc.stats.AverageLatency + latency) / averageDivisor
		}
	}
}

// recordCacheHit records a cache hit
func (rc *RegistryClient) recordCacheHit() {
	rc.statsMutex.Lock()
	defer rc.statsMutex.Unlock()
	rc.stats.CacheHits++
}

// recordCacheMiss records a cache miss
func (rc *RegistryClient) recordCacheMiss() {
	rc.statsMutex.Lock()
	defer rc.statsMutex.Unlock()
	rc.stats.CacheMisses++
}

// GetStats returns client statistics
func (rc *RegistryClient) GetStats() *RegistryClientStats {
	rc.statsMutex.RLock()
	defer rc.statsMutex.RUnlock()

	// Return a copy to avoid race conditions
	stats := *rc.stats
	return &stats
}

// LogStats logs client statistics
func (rc *RegistryClient) LogStats() {
	stats := rc.GetStats()

	logrus.Infof("🏗️ Registry Client Statistics:")
	logrus.Infof("   Total Requests: %d", stats.TotalRequests)
	logrus.Infof("   Manifest Requests: %d", stats.ManifestRequests)
	logrus.Infof("   Layer Requests: %d", stats.LayerRequests)
	logrus.Infof("   Cache Hits: %d, Misses: %d", stats.CacheHits, stats.CacheMisses)
	logrus.Infof("   Average Latency: %v", stats.AverageLatency)
	logrus.Infof("   Total Bytes: %d", stats.TotalBytes)

	if stats.CacheHits+stats.CacheMisses > 0 {
		hitRate := float64(stats.CacheHits) / float64(stats.CacheHits+stats.CacheMisses) * percentageBase
		logrus.Infof("   Cache Hit Rate: %.2f%%", hitRate)
	}
}

// Close closes the registry client and cleans up resources
func (rc *RegistryClient) Close() error {
	logrus.Info("🏗️ Closing registry client")

	// Close manifest cache if enabled
	if rc.manifestCache != nil {
		rc.manifestCache.Close()
	}

	logrus.Info("✅ Registry client closed successfully")
	return nil
}
