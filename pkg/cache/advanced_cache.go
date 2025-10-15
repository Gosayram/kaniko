/*
Copyright 2024 Kaniko Contributors

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

// Package cache provides advanced caching capabilities for Kaniko.
package cache

import (
	"context"
	"fmt"
	"sync"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sirupsen/logrus"
)

// Constants for cache operations
const (
	DefaultPreloadTimeout = 5 * time.Minute
)

// AdvancedCache provides enhanced caching capabilities
type AdvancedCache struct {
	layerCache     LayerCacheInterface
	preloadCache   map[string]v1.Image
	preloadMutex   sync.RWMutex
	stats          CacheStats
	statsMutex     sync.RWMutex
	preloadWorkers int
	preloadTimeout time.Duration
}

// CacheStats provides cache performance statistics
type CacheStats struct { //nolint:revive // CacheStats is intentionally named to avoid conflicts
	Hits           int64     `json:"hits"`
	Misses         int64     `json:"misses"`
	PreloadHits    int64     `json:"preload_hits"`
	PreloadMisses  int64     `json:"preload_misses"`
	TotalRequests  int64     `json:"total_requests"`
	HitRate        float64   `json:"hit_rate"`
	PreloadHitRate float64   `json:"preload_hit_rate"`
	LastReset      time.Time `json:"last_reset"`
}

// CacheKey represents a cache key with metadata
type CacheKey struct { //nolint:revive // CacheKey is intentionally named to avoid conflicts
	Key       string            `json:"key"`
	Command   string            `json:"command"`
	Files     []string          `json:"files"`
	Env       map[string]string `json:"env"`
	CreatedAt time.Time         `json:"created_at"`
	Size      int64             `json:"size"`
}

// NewAdvancedCache creates a new advanced cache
func NewAdvancedCache(layerCache LayerCacheInterface, preloadWorkers int, preloadTimeout time.Duration) *AdvancedCache {
	if preloadWorkers <= 0 {
		preloadWorkers = 4 // Default to 4 workers
	}
	if preloadTimeout <= 0 {
		preloadTimeout = DefaultPreloadTimeout // Default timeout
	}

	return &AdvancedCache{
		layerCache:     layerCache,
		preloadCache:   make(map[string]v1.Image),
		preloadWorkers: preloadWorkers,
		preloadTimeout: preloadTimeout,
		stats: CacheStats{
			LastReset: time.Now(),
		},
	}
}

// PreloadCache preloads cache for a set of commands
func (ac *AdvancedCache) PreloadCache(ctx context.Context, commands []CacheKey) error {
	logrus.Infof("Preloading cache for %d commands", len(commands))

	// Create worker pool for preloading
	workerChan := make(chan CacheKey, ac.preloadWorkers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errors []error

	// Start workers
	for i := 0; i < ac.preloadWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for key := range workerChan {
				if err := ac.preloadSingleKey(ctx, &key); err != nil {
					mu.Lock()
					errors = append(errors, fmt.Errorf("failed to preload key %s: %w", key.Key, err))
					mu.Unlock()
				}
			}
		}()
	}

	// Send work to workers
	for _, key := range commands {
		select {
		case workerChan <- key:
		case <-ctx.Done():
			close(workerChan)
			wg.Wait()
			return ctx.Err()
		}
	}

	close(workerChan)
	wg.Wait()

	// Check for errors
	if len(errors) > 0 {
		logrus.Warnf("Preload completed with %d errors: %v", len(errors), errors)
	}

	ac.updateStats(true, len(commands), len(errors) == 0)
	return nil
}

// preloadSingleKey preloads a single cache key
func (ac *AdvancedCache) preloadSingleKey(_ context.Context, key *CacheKey) error {
	// Check if already preloaded
	ac.preloadMutex.RLock()
	if _, exists := ac.preloadCache[key.Key]; exists {
		ac.preloadMutex.RUnlock()
		ac.updatePreloadStats(true)
		return nil
	}
	ac.preloadMutex.RUnlock()

	// Try to retrieve from layer cache
	img, err := ac.layerCache.RetrieveLayer(key.Key)
	if err != nil {
		ac.updatePreloadStats(false)
		return err
	}

	// Store in preload cache
	ac.preloadMutex.Lock()
	ac.preloadCache[key.Key] = img
	ac.preloadMutex.Unlock()

	ac.updatePreloadStats(true)
	return nil
}

// RetrieveLayer retrieves a layer from cache (with preload support)
func (ac *AdvancedCache) RetrieveLayer(key string) (v1.Image, error) {
	ac.statsMutex.Lock()
	ac.stats.TotalRequests++
	ac.statsMutex.Unlock()

	// First check preload cache
	ac.preloadMutex.RLock()
	if img, exists := ac.preloadCache[key]; exists {
		ac.preloadMutex.RUnlock()
		ac.updateStats(true, 1, true)
		ac.updatePreloadStats(true)
		logrus.Debugf("Cache hit (preloaded) for key: %s", key)
		return img, nil
	}
	ac.preloadMutex.RUnlock()

	// Fall back to layer cache
	img, err := ac.layerCache.RetrieveLayer(key)
	if err != nil {
		ac.updateStats(false, 1, false)
		logrus.Debugf("Cache miss for key: %s", key)
		return nil, err
	}

	ac.updateStats(true, 1, true)
	logrus.Debugf("Cache hit for key: %s", key)
	return img, nil
}

// SetLayer stores a layer in cache
func (ac *AdvancedCache) SetLayer(key string, img v1.Image) error {
	// Store in both layer cache and preload cache
	if err := ac.layerCache.SetLayer(key, img); err != nil {
		return err
	}

	ac.preloadMutex.Lock()
	ac.preloadCache[key] = img
	ac.preloadMutex.Unlock()

	return nil
}

// GenerateCacheKeys generates cache keys for a set of commands
func (ac *AdvancedCache) GenerateCacheKeys(commands []interface{}) []CacheKey {
	var keys []CacheKey

	for i, cmd := range commands {
		// This is a simplified implementation
		// In reality, you'd need to extract command-specific information
		key := CacheKey{
			Key:       fmt.Sprintf("cmd_%d_%d", i, time.Now().Unix()),
			Command:   fmt.Sprintf("%T", cmd),
			Files:     []string{}, // Would be populated from command analysis
			Env:       make(map[string]string),
			CreatedAt: time.Now(),
			Size:      0, // Would be calculated from actual layer size
		}
		keys = append(keys, key)
	}

	return keys
}

// updateStats updates cache statistics
func (ac *AdvancedCache) updateStats(hit bool, requests int, _ bool) {
	ac.statsMutex.Lock()
	defer ac.statsMutex.Unlock()

	if hit {
		ac.stats.Hits += int64(requests)
	} else {
		ac.stats.Misses += int64(requests)
	}

	// Calculate hit rate
	total := ac.stats.Hits + ac.stats.Misses
	if total > 0 {
		ac.stats.HitRate = float64(ac.stats.Hits) / float64(total)
	}
}

// updatePreloadStats updates preload statistics
func (ac *AdvancedCache) updatePreloadStats(hit bool) {
	ac.statsMutex.Lock()
	defer ac.statsMutex.Unlock()

	if hit {
		ac.stats.PreloadHits++
	} else {
		ac.stats.PreloadMisses++
	}

	// Calculate preload hit rate
	total := ac.stats.PreloadHits + ac.stats.PreloadMisses
	if total > 0 {
		ac.stats.PreloadHitRate = float64(ac.stats.PreloadHits) / float64(total)
	}
}

// GetStats returns cache statistics
func (ac *AdvancedCache) GetStats() CacheStats {
	ac.statsMutex.RLock()
	defer ac.statsMutex.RUnlock()

	// Return a copy to avoid race conditions
	return CacheStats{
		Hits:           ac.stats.Hits,
		Misses:         ac.stats.Misses,
		PreloadHits:    ac.stats.PreloadHits,
		PreloadMisses:  ac.stats.PreloadMisses,
		TotalRequests:  ac.stats.TotalRequests,
		HitRate:        ac.stats.HitRate,
		PreloadHitRate: ac.stats.PreloadHitRate,
		LastReset:      ac.stats.LastReset,
	}
}

// ResetStats resets cache statistics
func (ac *AdvancedCache) ResetStats() {
	ac.statsMutex.Lock()
	defer ac.statsMutex.Unlock()

	ac.stats = CacheStats{
		LastReset: time.Now(),
	}
}

// ClearPreloadCache clears the preload cache
func (ac *AdvancedCache) ClearPreloadCache() {
	ac.preloadMutex.Lock()
	defer ac.preloadMutex.Unlock()

	ac.preloadCache = make(map[string]v1.Image)
}

// GetPreloadCacheSize returns the size of the preload cache
func (ac *AdvancedCache) GetPreloadCacheSize() int {
	ac.preloadMutex.RLock()
	defer ac.preloadMutex.RUnlock()

	return len(ac.preloadCache)
}

// OptimizeCache performs cache optimization
func (ac *AdvancedCache) OptimizeCache() error {
	logrus.Info("Optimizing cache...")

	// Clear preload cache to free memory
	ac.ClearPreloadCache()

	// Reset statistics
	ac.ResetStats()

	logrus.Info("Cache optimization completed")
	return nil
}

// LayerCacheInterface interface for compatibility
type LayerCacheInterface interface {
	RetrieveLayer(key string) (v1.Image, error)
	SetLayer(key string, img v1.Image) error
}
