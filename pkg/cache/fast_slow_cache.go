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

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// CacheRecord represents a cache record with metadata
type CacheRecord struct {
	Key     string
	Digest  string
	Image   v1.Image
	Present bool
}

// CacheManager interface for cache operations
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

// FastCacheManager implements fast cache (key-only lookup)
type FastCacheManager struct {
	// cacheKey -> digest mapping (quick lookup without data)
	cache map[string]string
	mu    sync.RWMutex
}

// NewFastCacheManager creates a new fast cache manager
func NewFastCacheManager() *FastCacheManager {
	return &FastCacheManager{
		cache: make(map[string]string),
	}
}

// Get retrieves a cache record from fast cache
func (f *FastCacheManager) Get(key string) (*CacheRecord, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	digest, exists := f.cache[key]
	if !exists {
		return nil, ErrCacheMiss
	}

	return &CacheRecord{
		Key:     key,
		Digest:  digest,
		Present: true,
	}, nil
}

// Set stores a cache record in fast cache
func (f *FastCacheManager) Set(key string, record *CacheRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if record != nil {
		f.cache[key] = record.Digest
	} else {
		delete(f.cache, key)
	}
	return nil
}

// Probe checks if a key exists in fast cache
func (f *FastCacheManager) Probe(key string) (bool, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	_, exists := f.cache[key]
	return exists, nil
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

// Get retrieves a cache record from slow cache
func (s *SlowCacheManager) Get(key string) (*CacheRecord, error) {
	img, err := s.layerCache.RetrieveLayer(key)
	if err != nil {
		return nil, err
	}

	digest, err := img.Digest()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get digest")
	}

	return &CacheRecord{
		Key:     key,
		Digest:  digest.String(),
		Image:   img,
		Present: true,
	}, nil
}

// Set stores a cache record in slow cache
// Note: Slow cache is typically read-only in Kaniko (registry-based)
func (s *SlowCacheManager) Set(key string, record *CacheRecord) error {
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

// Get retrieves a cache record from remote cache
func (r *RegistryRemoteCache) Get(ctx context.Context, key string) (*CacheRecord, error) {
	img, err := r.layerCache.RetrieveLayer(key)
	if err != nil {
		return nil, err
	}

	digest, err := img.Digest()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get digest")
	}

	return &CacheRecord{
		Key:     key,
		Digest:  digest.String(),
		Image:   img,
		Present: true,
	}, nil
}

// Probe checks if a key exists in remote cache
func (r *RegistryRemoteCache) Probe(ctx context.Context, key string) (bool, error) {
	_, err := r.layerCache.RetrieveLayer(key)
	if err != nil {
		return false, nil
	}
	return true, nil
}

// Set stores a cache record in remote cache
// Note: This is typically handled by the push mechanism
func (r *RegistryRemoteCache) Set(ctx context.Context, key string, record *CacheRecord) error {
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
func NewFastSlowCache(slowCache LayerCache, remoteCache LayerCache) *FastSlowCache {
	return &FastSlowCache{
		fastCache:   NewFastCacheManager(),
		slowCache:   NewSlowCacheManager(slowCache),
		remoteCache: NewRegistryRemoteCache(remoteCache),
	}
}

// ProbeCache probes the cache hierarchy: fast -> slow -> remote
// This is the main method for cache lookups, following BuildKit's pattern
// Implementation matches the design document specification
func (c *FastSlowCache) ProbeCache(key string) (*CacheRecord, error) {
	// 1. Check fast cache (quick key-only lookup)
	record, err := c.fastCache.Get(key)
	if err == nil && record != nil {
		c.mu.Lock()
		c.fastHits++
		c.mu.Unlock()
		logrus.Debugf("Fast cache hit for key: %s", key)
		return record, nil
	}

	// 2. Check slow cache (full data loading)
	record, err = c.slowCache.Get(key)
	if err == nil && record != nil {
		c.mu.Lock()
		c.slowHits++
		c.mu.Unlock()
		logrus.Debugf("Slow cache hit for key: %s", key)

		// Update fast cache for future lookups
		if err := c.fastCache.Set(key, record); err != nil {
			logrus.Warnf("Failed to update fast cache: %v", err)
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

		// Update fast cache
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
		hitRate = float64(c.fastHits+c.slowHits+c.remoteHits) / float64(total) * 100
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
func (c *FastSlowCache) RetrieveLayer(cacheKey string) (v1.Image, error) {
	record, err := c.ProbeCache(cacheKey)
	if err != nil {
		return nil, err
	}

	if record.Image == nil {
		return nil, ErrCacheMiss
	}

	return record.Image, nil
}

// ErrCacheMiss is returned when cache lookup fails
var ErrCacheMiss = errors.New("cache miss")

// LayerCache interface implementation
var _ LayerCache = (*FastSlowCache)(nil)
