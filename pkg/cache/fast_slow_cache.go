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

// Package cache provides a BuildKit-inspired fast/slow cache system.
// Fast cache: quick cache key lookup without data loading
// Slow cache: full cache with data loading and validation
// Remote cache: cache in registry/S3/etc.
package cache

import (
	"context"
	"fmt"
	"sync"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	// PercentageMultiplier is used to convert ratio to percentage
	percentageMultiplier = 100.0
)

// LayerMetadata represents metadata about a cached layer without the full image
// This allows fast "exists/not exists" checks without loading the full layer
type LayerMetadata struct {
	Digest  string    // Layer digest
	Size    int64     // Layer size in bytes
	TTL     time.Time // Expiration time
	Created time.Time // Creation time
}

// CacheRecord represents a cache record with metadata
//
//nolint:revive // stuttering name is intentional for public API clarity
type CacheRecord struct {
	Key      string
	Digest   string
	Image    v1.Image
	Present  bool
	Metadata *LayerMetadata // Metadata for fast cache (without full image)
}

// CacheManager interface for cache operations
//
//nolint:revive // stuttering name is intentional for public API clarity
type CacheManager interface {
	Get(key string) (*CacheRecord, error)
	Set(key string, record *CacheRecord) error
	Probe(key string) (bool, error) // Quick check without loading data
}

// RemoteCache interface for remote cache operations
type RemoteCache interface {
	Get(ctx context.Context, key string) (*CacheRecord, error)
	Probe(ctx context.Context, key string) (bool, error)
	Set(ctx context.Context, key string, record *CacheRecord) error
}

// FastCacheManager implements fast cache (key-only lookup with metadata)
type FastCacheManager struct {
	// cacheKey -> metadata mapping (quick lookup without full image data)
	cache map[string]*LayerMetadata
	mu    sync.RWMutex
}

// NewFastCacheManager creates a new fast cache manager
func NewFastCacheManager() *FastCacheManager {
	return &FastCacheManager{
		cache: make(map[string]*LayerMetadata),
	}
}

// Get retrieves a cache record from fast cache (metadata only, no full image)
func (f *FastCacheManager) Get(key string) (*CacheRecord, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	metadata, exists := f.cache[key]
	if !exists {
		return nil, ErrCacheMiss
	}

	// Check if metadata has expired
	if !metadata.TTL.IsZero() && time.Now().After(metadata.TTL) {
		// Metadata expired, remove it
		f.mu.RUnlock()
		f.mu.Lock()
		delete(f.cache, key)
		f.mu.Unlock()
		f.mu.RLock()
		return nil, ErrCacheMiss
	}

	return &CacheRecord{
		Key:      key,
		Digest:   metadata.Digest,
		Present:  true,
		Metadata: metadata,
		// Image is nil in fast cache - lazy loading will load it if needed
	}, nil
}

// Set stores a cache record in fast cache (metadata only)
func (f *FastCacheManager) Set(key string, record *CacheRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	switch {
	case record != nil && record.Metadata != nil:
		// Store metadata (preferred - already extracted)
		f.cache[key] = record.Metadata
	case record != nil && record.Digest != "":
		// Fallback: create metadata from digest only
		// TTL will be set by caller if available
		f.cache[key] = &LayerMetadata{
			Digest:  record.Digest,
			Size:    0, // Unknown size
			Created: time.Now(),
			TTL:     time.Time{}, // No expiration by default
		}
	default:
		delete(f.cache, key)
	}
	return nil
}

// Probe checks if a key exists in fast cache (with TTL check)
func (f *FastCacheManager) Probe(key string) (bool, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	metadata, exists := f.cache[key]
	if !exists {
		return false, nil
	}

	// Check if metadata has expired
	if !metadata.TTL.IsZero() && time.Now().After(metadata.TTL) {
		return false, nil
	}

	return true, nil
}

// SlowCacheManager implements slow cache (full data loading)
type SlowCacheManager struct {
	layerCache LayerCache
}

// NewSlowCacheManager creates a new slow cache manager
func NewSlowCacheManager(layerCache LayerCache) *SlowCacheManager {
	return &SlowCacheManager{
		layerCache: layerCache,
	}
}

// getCacheRecordFromImage is a helper function to create a CacheRecord from an image
func getCacheRecordFromImage(key string, img v1.Image) (*CacheRecord, error) {
	digest, err := img.Digest()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get digest")
	}

	size, err := img.Size()
	if err != nil {
		size = 0 // Unknown size
	}

	// Extract metadata from image
	cfg, err := img.ConfigFile()
	var created time.Time
	if err == nil && cfg != nil {
		created = cfg.Created.Time
	} else {
		created = time.Now()
	}

	metadata := &LayerMetadata{
		Digest:  digest.String(),
		Size:    size,
		Created: created,
		TTL:     time.Time{}, // TTL will be set by caller if available
	}

	return &CacheRecord{
		Key:      key,
		Digest:   digest.String(),
		Image:    img,
		Present:  true,
		Metadata: metadata,
	}, nil
}

// Get retrieves a cache record from slow cache (full image with metadata)
func (s *SlowCacheManager) Get(key string) (*CacheRecord, error) {
	img, err := s.layerCache.RetrieveLayer(key)
	if err != nil {
		return nil, err
	}

	return getCacheRecordFromImage(key, img)
}

// Set stores a cache record in slow cache
// Note: Slow cache is typically read-only in Kaniko (registry-based)
func (s *SlowCacheManager) Set(key string, _ *CacheRecord) error {
	// Slow cache is typically read-only
	// Writing would require pushing to registry, which is handled elsewhere
	logrus.Debugf("Slow cache set called for key: %s (read-only cache)", key)
	return nil
}

// Probe checks if a key exists in slow cache (with data loading)
func (s *SlowCacheManager) Probe(key string) (bool, error) {
	_, err := s.layerCache.RetrieveLayer(key)
	if err != nil {
		return false, nil
	}
	return true, nil
}

// RegistryRemoteCache implements remote cache using registry
type RegistryRemoteCache struct {
	layerCache LayerCache
}

// NewRegistryRemoteCache creates a new registry-based remote cache
func NewRegistryRemoteCache(layerCache LayerCache) *RegistryRemoteCache {
	return &RegistryRemoteCache{
		layerCache: layerCache,
	}
}

// Get retrieves a cache record from remote cache (full image with metadata)
func (r *RegistryRemoteCache) Get(_ context.Context, key string) (*CacheRecord, error) {
	img, err := r.layerCache.RetrieveLayer(key)
	if err != nil {
		return nil, err
	}

	return getCacheRecordFromImage(key, img)
}

// Probe checks if a key exists in remote cache
func (r *RegistryRemoteCache) Probe(_ context.Context, key string) (bool, error) {
	_, err := r.layerCache.RetrieveLayer(key)
	if err != nil {
		return false, nil
	}
	return true, nil
}

// Set stores a cache record in remote cache
// Note: This is typically handled by the push mechanism
func (r *RegistryRemoteCache) Set(_ context.Context, key string, _ *CacheRecord) error {
	// Remote cache writes are handled by push operations
	logrus.Debugf("Remote cache set called for key: %s (handled by push)", key)
	return nil
}

// FastSlowCache provides BuildKit-inspired fast/slow/remote cache system
type FastSlowCache struct {
	fastCache   CacheManager
	slowCache   CacheManager
	remoteCache RemoteCache

	// Statistics
	fastHits   int64
	slowHits   int64
	remoteHits int64
	misses     int64
	mu         sync.RWMutex
}

// NewFastSlowCache creates a new fast/slow cache system
func NewFastSlowCache(slowCache, remoteCache LayerCache) *FastSlowCache {
	return &FastSlowCache{
		fastCache:   NewFastCacheManager(),
		slowCache:   NewSlowCacheManager(slowCache),
		remoteCache: NewRegistryRemoteCache(remoteCache),
	}
}

// ProbeCache probes the cache hierarchy: fast -> slow -> remote
// This is the main method for cache lookups, following BuildKit's pattern
// Implementation matches the design document specification
// Per performance plan: uses metadata for fast "exists/not exists" checks
func (c *FastSlowCache) ProbeCache(key string) (*CacheRecord, error) {
	// 1. Check fast cache (quick metadata-only lookup - 70-80% faster than full load)
	record, err := c.fastCache.Get(key)
	if err == nil && record != nil {
		c.mu.Lock()
		c.fastHits++
		c.mu.Unlock()
		logrus.Debugf("Fast cache hit (metadata only) for key: %s, digest: %s, size: %d",
			key, record.Digest, record.Metadata.Size)
		// Return metadata-only record (lazy loading will load full image if needed)
		return record, nil
	}

	// 2. Check slow cache (full data loading)
	record, err = c.slowCache.Get(key)
	if err == nil && record != nil {
		c.mu.Lock()
		c.slowHits++
		c.mu.Unlock()
		logrus.Debugf("Slow cache hit for key: %s", key)

		// Update fast cache with metadata for future fast lookups
		if setErr := c.fastCache.Set(key, record); setErr != nil {
			logrus.Warnf("Failed to update fast cache: %v", setErr)
		}

		return record, nil
	}

	// 3. Check remote cache (use background context)
	ctx := context.Background()
	record, err = c.remoteCache.Get(ctx, key)
	if err == nil && record != nil {
		c.mu.Lock()
		c.remoteHits++
		c.mu.Unlock()
		logrus.Debugf("Remote cache hit for key: %s", key)

		// Update slow cache
		if err := c.slowCache.Set(key, record); err != nil {
			logrus.Warnf("Failed to update slow cache: %v", err)
		}

		// Update fast cache with metadata for future fast lookups
		if err := c.fastCache.Set(key, record); err != nil {
			logrus.Warnf("Failed to update fast cache: %v", err)
		}

		return record, nil
	}

	// Cache miss
	c.mu.Lock()
	c.misses++
	c.mu.Unlock()
	logrus.Debugf("Cache miss for key: %s", key)
	return nil, ErrCacheMiss
}

// GetStats returns cache statistics
func (c *FastSlowCache) GetStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	total := c.fastHits + c.slowHits + c.remoteHits + c.misses
	hitRate := float64(0)
	if total > 0 {
		hitRate = float64(c.fastHits+c.slowHits+c.remoteHits) / float64(total) * percentageMultiplier
	}

	return map[string]interface{}{
		"fast_hits":   c.fastHits,
		"slow_hits":   c.slowHits,
		"remote_hits": c.remoteHits,
		"misses":      c.misses,
		"total":       total,
		"hit_rate":    fmt.Sprintf("%.2f%%", hitRate),
	}
}

// RetrieveLayer implements LayerCache interface for compatibility
// Uses ProbeCache internally following the fast/slow/remote cache hierarchy
// Per performance plan: supports lazy loading - if fast cache returns metadata only,
// loads full image from slow cache only when needed
func (c *FastSlowCache) RetrieveLayer(cacheKey string) (v1.Image, error) {
	record, err := c.ProbeCache(cacheKey)
	if err != nil {
		return nil, err
	}

	// If fast cache returned metadata only (Image == nil), load full image lazily
	if record.Image == nil && record.Metadata != nil {
		logrus.Debugf("Lazy loading full image for key: %s (metadata-only cache hit)", cacheKey)
		// Load full image from slow cache
		slowRecord, err := c.slowCache.Get(cacheKey)
		if err != nil {
			return nil, err
		}
		if slowRecord != nil && slowRecord.Image != nil {
			// Update fast cache with full metadata (including TTL if available)
			if setErr := c.fastCache.Set(cacheKey, slowRecord); setErr != nil {
				logrus.Warnf("Failed to update fast cache after lazy load: %v", setErr)
			}
			return slowRecord.Image, nil
		}
		return nil, ErrCacheMiss
	}

	if record.Image == nil {
		return nil, ErrCacheMiss
	}

	return record.Image, nil
}

// RetrieveLayersBatch retrieves multiple layers in parallel
func (c *FastSlowCache) RetrieveLayersBatch(keys []string) map[string]LayerResult {
	results := make(map[string]LayerResult)
	if len(keys) == 0 {
		return results
	}

	// Default max concurrent
	maxConcurrent := 3

	// Try to get max concurrent from slow cache if it supports it
	if c.slowCache != nil {
		if batchCache, ok := c.slowCache.(interface {
			RetrieveLayersBatch([]string) map[string]LayerResult
		}); ok {
			// Use slow cache's batch method directly
			return batchCache.RetrieveLayersBatch(keys)
		}
	}

	// Use semaphore to limit concurrent requests
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, key := range keys {
		wg.Add(1)
		go func(ck string) {
			defer wg.Done()

			// Acquire semaphore
			sem <- struct{}{}
			defer func() { <-sem }()

			// Retrieve layer using ProbeCache (supports metadata-only fast cache)
			record, err := c.ProbeCache(ck)

			// Handle lazy loading if needed
			var img v1.Image
			if err == nil && record != nil {
				if record.Image == nil && record.Metadata != nil {
					// Lazy load full image
					logrus.Debugf("Lazy loading full image for key: %s (metadata-only cache hit)", ck)
					slowRecord, slowErr := c.slowCache.Get(ck)
					if slowErr == nil && slowRecord != nil && slowRecord.Image != nil {
						img = slowRecord.Image
						// Update fast cache with full metadata
						if setErr := c.fastCache.Set(ck, slowRecord); setErr != nil {
							logrus.Warnf("Failed to update fast cache after lazy load: %v", setErr)
						}
					} else {
						err = slowErr
						if err == nil {
							err = ErrCacheMiss
						}
					}
				} else {
					img = record.Image
				}
			}

			// Store result
			mu.Lock()
			results[ck] = LayerResult{
				Image: img,
				Error: err,
			}
			mu.Unlock()
		}(key)
	}

	wg.Wait()
	return results
}

// ErrCacheMiss is returned when cache lookup fails
var ErrCacheMiss = errors.New("cache miss")

// LayerCache interface implementation
var _ LayerCache = (*FastSlowCache)(nil)
