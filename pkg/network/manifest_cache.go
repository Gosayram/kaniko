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
	"sync"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sirupsen/logrus"
)

// ManifestCacheEntry represents a cached manifest entry
type ManifestCacheEntry struct {
	Image       v1.Image
	ExpiresAt   time.Time
	CreatedAt   time.Time
	AccessCount int64
}

// IsExpired checks if the manifest cache entry is expired
func (entry *ManifestCacheEntry) IsExpired() bool {
	return time.Now().After(entry.ExpiresAt)
}

// ManifestCache provides manifest caching for registry operations
type ManifestCache struct {
	cache      map[string]*ManifestCacheEntry
	mutex      sync.RWMutex
	timeout    time.Duration
	stats      *ManifestCacheStats
	statsMutex sync.RWMutex
	stopChan   chan struct{}
}

// ManifestCacheStats holds manifest cache statistics
type ManifestCacheStats struct {
	Hits      int64     `json:"hits"`
	Misses    int64     `json:"misses"`
	Evictions int64     `json:"evictions"`
	TotalSize int64     `json:"total_size"`
	LastReset time.Time `json:"last_reset"`
}

// NewManifestCache creates a new manifest cache
func NewManifestCache(timeout time.Duration) *ManifestCache {
	cache := &ManifestCache{
		cache:   make(map[string]*ManifestCacheEntry),
		timeout: timeout,
		stats: &ManifestCacheStats{
			LastReset: time.Now(),
		},
		stopChan: make(chan struct{}),
	}

	// Start cleanup goroutine
	go cache.cleanup()

	logrus.Info("Manifest cache initialized")
	return cache
}

// Get retrieves a cached manifest
func (mc *ManifestCache) Get(key string) v1.Image {
	mc.mutex.RLock()
	entry, exists := mc.cache[key]
	mc.mutex.RUnlock()

	if !exists || entry.IsExpired() {
		mc.recordMiss()
		return nil
	}

	// Update access count
	mc.mutex.Lock()
	entry.AccessCount++
	mc.mutex.Unlock()

	mc.recordHit()
	logrus.Debugf("Manifest cache hit for %s", key)
	return entry.Image
}

// Set stores a manifest in the cache
func (mc *ManifestCache) Set(key string, image v1.Image) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	mc.cache[key] = &ManifestCacheEntry{
		Image:       image,
		ExpiresAt:   time.Now().Add(mc.timeout),
		CreatedAt:   time.Now(),
		AccessCount: 1,
	}

	logrus.Debugf("Manifest cached for %s", key)
}

// Invalidate removes a manifest from the cache
func (mc *ManifestCache) Invalidate(key string) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	delete(mc.cache, key)
	logrus.Debugf("Manifest cache invalidated for %s", key)
}

// Clear removes all entries from the cache
func (mc *ManifestCache) Clear() {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	mc.cache = make(map[string]*ManifestCacheEntry)
	logrus.Info("Manifest cache cleared")
}

// GetStats returns manifest cache statistics
func (mc *ManifestCache) GetStats() *ManifestCacheStats {
	mc.statsMutex.RLock()
	defer mc.statsMutex.RUnlock()

	// Return a copy to avoid race conditions
	stats := *mc.stats
	return &stats
}

// recordHit records a cache hit
func (mc *ManifestCache) recordHit() {
	mc.statsMutex.Lock()
	defer mc.statsMutex.Unlock()
	mc.stats.Hits++
}

// recordMiss records a cache miss
func (mc *ManifestCache) recordMiss() {
	mc.statsMutex.Lock()
	defer mc.statsMutex.Unlock()
	mc.stats.Misses++
}

// recordEviction records a cache eviction
func (mc *ManifestCache) recordEviction() {
	mc.statsMutex.Lock()
	defer mc.statsMutex.Unlock()
	mc.stats.Evictions++
}

// cleanup periodically removes expired entries
func (mc *ManifestCache) cleanup() {
	ticker := time.NewTicker(DefaultCleanupInterval) // Cleanup every 5 minutes
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mc.cleanupExpired()
		case <-mc.stopChan:
			return
		}
	}
}

// cleanupExpired removes expired entries from the cache
func (mc *ManifestCache) cleanupExpired() {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	now := time.Now()
	expiredCount := 0

	for key, entry := range mc.cache {
		if now.After(entry.ExpiresAt) {
			delete(mc.cache, key)
			expiredCount++
			mc.recordEviction()
		}
	}

	if expiredCount > 0 {
		logrus.Debugf("Manifest cache cleanup: removed %d expired entries", expiredCount)
	}
}

// Close closes the manifest cache and stops cleanup goroutine
func (mc *ManifestCache) Close() {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	select {
	case <-mc.stopChan:
		// Already closed
		return
	default:
		close(mc.stopChan)
		logrus.Info("Manifest cache closed")
	}
}

// LogStats logs manifest cache statistics
func (mc *ManifestCache) LogStats() {
	stats := mc.GetStats()

	logrus.Infof("Manifest Cache Statistics:")
	logrus.Infof("   Hits: %d, Misses: %d", stats.Hits, stats.Misses)
	logrus.Infof("   Evictions: %d", stats.Evictions)
	logrus.Infof("   Total Size: %d entries", stats.TotalSize)

	if stats.Hits+stats.Misses > 0 {
		hitRate := float64(stats.Hits) / float64(stats.Hits+stats.Misses) * percentageBase
		logrus.Infof("   Hit Rate: %.2f%%", hitRate)
	}
}
