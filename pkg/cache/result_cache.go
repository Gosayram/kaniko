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
	"sync"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sirupsen/logrus"
)

const (
	defaultResultCacheTTL = 5 * time.Minute
	entryMetadataOverhead = 200 // ~200 bytes overhead for entry metadata
	bytesPerKilobyte      = 1024
	bytesPerMegabyte      = bytesPerKilobyte * bytesPerKilobyte
)

// Result represents a cached result of a cache check
type Result struct {
	Key       string
	Image     v1.Image
	Error     error
	Digest    string
	Size      int64
	CachedAt  time.Time
	ExpiresAt time.Time
}

// IsExpired checks if the cache result has expired
func (cr *Result) IsExpired() bool {
	return time.Now().After(cr.ExpiresAt)
}

// ResultCache provides in-memory caching of cache check results
// This avoids duplicate lookups for the same cache keys
type ResultCache struct {
	mu            sync.RWMutex
	results       map[string]*Result
	maxEntries    int
	maxMemoryMB   int
	ttl           time.Duration
	currentMemory int64 // Current memory usage in bytes
}

// NewResultCache creates a new result cache with specified limits
func NewResultCache(maxEntries, maxMemoryMB int, ttl time.Duration) *ResultCache {
	if maxEntries <= 0 {
		maxEntries = 1000 // Default
	}
	if maxMemoryMB <= 0 {
		maxMemoryMB = 100 // Default
	}
	if ttl <= 0 {
		ttl = defaultResultCacheTTL
	}

	return &ResultCache{
		results:     make(map[string]*Result),
		maxEntries:  maxEntries,
		maxMemoryMB: maxMemoryMB,
		ttl:         ttl,
	}
}

// Get retrieves a cached result if available and not expired
func (rc *ResultCache) Get(key string) (*Result, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	result, exists := rc.results[key]
	if !exists {
		return nil, false
	}

	// Check if expired
	if result.IsExpired() {
		// Don't delete here (would need write lock), just return false
		// Expired entries will be cleaned up during eviction
		return nil, false
	}

	return result, true
}

// Set stores a cache result
func (rc *ResultCache) Set(key string, img v1.Image, err error) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	// Estimate memory usage (simplified: use digest + size if available)
	var digest string
	var size int64
	if img != nil {
		if d, digestErr := img.Digest(); digestErr == nil {
			digest = d.String()
		}
		if s, sizeErr := img.Size(); sizeErr == nil {
			size = s
		}
	}

	// Estimate entry size (key + digest + metadata overhead)
	entrySize := int64(len(key) + len(digest) + entryMetadataOverhead)

	// Check if we need to evict entries
	rc.evictIfNeeded(entrySize)

	// Create result
	result := &Result{
		Key:       key,
		Image:     img,
		Error:     err,
		Digest:    digest,
		Size:      size,
		CachedAt:  time.Now(),
		ExpiresAt: time.Now().Add(rc.ttl),
	}

	// Remove old entry if exists (to update memory tracking)
	if oldResult, exists := rc.results[key]; exists {
		oldSize := int64(len(key) + len(oldResult.Digest) + entryMetadataOverhead)
		rc.currentMemory -= oldSize
	}

	// Add new entry
	rc.results[key] = result
	rc.currentMemory += entrySize

	logrus.Debugf("Cached result for key: %s (memory: %d bytes, entries: %d)",
		key, rc.currentMemory, len(rc.results))
}

// evictIfNeeded evicts entries if limits are exceeded
func (rc *ResultCache) evictIfNeeded(newEntrySize int64) {
	maxMemoryBytes := int64(rc.maxMemoryMB) * bytesPerMegabyte

	// Evict expired entries first
	for key, result := range rc.results {
		if result.IsExpired() {
			entrySize := int64(len(key) + len(result.Digest) + entryMetadataOverhead)
			delete(rc.results, key)
			rc.currentMemory -= entrySize
		}
	}

	// Check if we still need to evict (memory limit)
	for rc.currentMemory+newEntrySize > maxMemoryBytes && len(rc.results) > 0 {
		// Evict oldest entry (LRU-like, but simplified: evict first found)
		for key, result := range rc.results {
			entrySize := int64(len(key) + len(result.Digest) + entryMetadataOverhead)
			delete(rc.results, key)
			rc.currentMemory -= entrySize
			break
		}
	}

	// Check if we still need to evict (entry count limit)
	for len(rc.results) >= rc.maxEntries && len(rc.results) > 0 {
		// Evict oldest entry
		for key, result := range rc.results {
			entrySize := int64(len(key) + len(result.Digest) + entryMetadataOverhead)
			delete(rc.results, key)
			rc.currentMemory -= entrySize
			break
		}
	}
}

// Clear removes all cached results
func (rc *ResultCache) Clear() {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	rc.results = make(map[string]*Result)
	rc.currentMemory = 0
}

// GetStats returns cache statistics
func (rc *ResultCache) GetStats() map[string]interface{} {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	// Count expired entries
	expiredCount := 0
	for _, result := range rc.results {
		if result.IsExpired() {
			expiredCount++
		}
	}

	return map[string]interface{}{
		"entries":       len(rc.results),
		"max_entries":   rc.maxEntries,
		"memory_bytes":  rc.currentMemory,
		"max_memory_mb": rc.maxMemoryMB,
		"expired_count": expiredCount,
		"ttl_seconds":   int(rc.ttl.Seconds()),
	}
}
