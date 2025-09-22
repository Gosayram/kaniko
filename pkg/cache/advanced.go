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

package cache

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/debug"
)

// CachePolicy defines the caching policy for a specific cache type
type CachePolicy struct {
	TTL           time.Duration `json:"ttl" yaml:"ttl"`                       // Time to live for cache entries
	MaxSize       int64         `json:"maxSize" yaml:"maxSize"`               // Maximum size in bytes
	EvictionPolicy string       `json:"evictionPolicy" yaml:"evictionPolicy"` // LRU, FIFO, Random
	Compression    string       `json:"compression" yaml:"compression"`       // gzip, zstd, none
}

// CacheEntry represents a single cache entry with metadata
type CacheEntry struct {
	Key          string        `json:"key"`
	Digest       string        `json:"digest"`
	Size         int64         `json:"size"`
	LastAccessed time.Time     `json:"lastAccessed"`
	Created      time.Time     `json:"created"`
	Platform     string        `json:"platform,omitempty"`
	Compression  string        `json:"compression,omitempty"`
	AccessCount  int64         `json:"accessCount"`
	TTL          time.Duration `json:"ttl,omitempty"`
}

// CacheManager manages advanced caching operations for multi-platform builds
type CacheManager struct {
	opts          *config.KanikoOptions
	cachePolicies map[string]CachePolicy
	gcEnabled     bool
	mu            sync.RWMutex
	entries       map[string]*CacheEntry
	stats         *CacheStats
}

// CacheStats provides statistics about cache usage
type CacheStats struct {
	TotalEntries    int64     `json:"totalEntries"`
	TotalSize       int64     `json:"totalSize"`
	LastGC          time.Time `json:"lastGC"`
	HitRate         float64   `json:"hitRate"`
	TotalHits       int64     `json:"totalHits"`
	TotalMisses     int64     `json:"totalMisses"`
	PlatformEntries map[string]int64 `json:"platformEntries"`
}

// NewCacheManager creates a new advanced cache manager
func NewCacheManager(opts *config.KanikoOptions) *CacheManager {
	cm := &CacheManager{
		opts:          opts,
		cachePolicies: make(map[string]CachePolicy),
		gcEnabled:     true,
		entries:       make(map[string]*CacheEntry),
		stats: &CacheStats{
			PlatformEntries: make(map[string]int64),
		},
	}

	// Set default cache policies
	cm.setDefaultPolicies()

	return cm
}

// setDefaultPolicies sets up default cache policies
func (cm *CacheManager) setDefaultPolicies() {
	// Default policy for base image cache
	cm.cachePolicies["base"] = CachePolicy{
		TTL:           24 * time.Hour * 7, // 7 days
		MaxSize:       10 * 1024 * 1024 * 1024, // 10GB
		EvictionPolicy: "LRU",
		Compression:    "gzip",
	}

	// Default policy for build cache
	cm.cachePolicies["build"] = CachePolicy{
		TTL:           24 * time.Hour, // 1 day
		MaxSize:       5 * 1024 * 1024 * 1024, // 5GB
		EvictionPolicy: "LRU",
		Compression:    "gzip",
	}

	// Default policy for multi-platform cache
	cm.cachePolicies["multiplatform"] = CachePolicy{
		TTL:           24 * time.Hour * 3, // 3 days
		MaxSize:       20 * 1024 * 1024 * 1024, // 20GB
		EvictionPolicy: "LRU",
		Compression:    "zstd",
	}
}

// GetCacheEntry retrieves a cache entry by key
func (cm *CacheManager) GetCacheEntry(ctx context.Context, key string) (*CacheEntry, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	debug.LogComponent("cache", "Getting cache entry for key: %s", key)

	entry, exists := cm.entries[key]
	if !exists {
		debug.LogComponent("cache", "Cache miss for key: %s", key)
		cm.stats.TotalMisses++
		return nil, fmt.Errorf("cache entry not found: %s", key)
	}

	// Update access information
	entry.LastAccessed = time.Now()
	entry.AccessCount++
	cm.stats.TotalHits++

	debug.LogComponent("cache", "Cache hit for key: %s, access count: %d", key, entry.AccessCount)

	// Check if entry has expired
	if cm.isEntryExpired(entry) {
		debug.LogComponent("cache", "Cache entry expired for key: %s", key)
		delete(cm.entries, key)
		cm.updatePlatformStats(entry.Platform, -1)
		cm.stats.TotalEntries--
		cm.stats.TotalSize -= entry.Size
		return nil, fmt.Errorf("cache entry expired: %s", key)
	}

	return entry, nil
}

// SetCacheEntry stores a cache entry
func (cm *CacheManager) SetCacheEntry(ctx context.Context, entry *CacheEntry) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	debug.LogComponent("cache", "Setting cache entry for key: %s, size: %d bytes", entry.Key, entry.Size)

	// Check if we need to evict entries based on size policy
	if err := cm.evictIfNeeded(entry.Size); err != nil {
		return fmt.Errorf("failed to evict cache entries: %w", err)
	}

	// Store the entry
	cm.entries[entry.Key] = entry
	cm.stats.TotalEntries++
	cm.stats.TotalSize += entry.Size

	// Update platform statistics
	if entry.Platform != "" {
		cm.updatePlatformStats(entry.Platform, 1)
	}

	debug.LogComponent("cache", "Cache entry stored successfully. Total entries: %d, Total size: %d bytes", 
		cm.stats.TotalEntries, cm.stats.TotalSize)

	return nil
}

// evictIfNeeded evicts cache entries if adding a new entry would exceed size limits
func (cm *CacheManager) evictIfNeeded(newEntrySize int64) error {
	policy := cm.getCachePolicy("build")
	if cm.stats.TotalSize+newEntrySize > policy.MaxSize {
		debug.LogComponent("cache", "Cache size limit reached. Current: %d, New: %d, Limit: %d", 
			cm.stats.TotalSize, newEntrySize, policy.MaxSize)

		neededSpace := cm.stats.TotalSize + newEntrySize - policy.MaxSize
		evicted, err := cm.evictEntries(neededSpace)
		if err != nil {
			return err
		}

		debug.LogComponent("cache", "Evicted %d entries, freed %d bytes", evicted.count, evicted.size)
	}

	return nil
}

// evictEntries evicts cache entries based on the configured eviction policy
func (cm *CacheManager) evictEntries(neededSpace int64) (evictionResult, error) {
	var result evictionResult

	switch cm.getCachePolicy("build").EvictionPolicy {
	case "LRU":
		result = cm.evictLRU(neededSpace)
	case "FIFO":
		result = cm.evictFIFO(neededSpace)
	case "Random":
		result = cm.evictRandom(neededSpace)
	default:
		return result, fmt.Errorf("unknown eviction policy: %s", cm.getCachePolicy("build").EvictionPolicy)
	}

	return result, nil
}

// evictionResult contains the result of an eviction operation
type evictionResult struct {
	count int
	size  int64
}

// evictLRU evicts least recently used entries
func (cm *CacheManager) evictLRU(neededSpace int64) evictionResult {
	var result evictionResult

	// Sort entries by last access time (oldest first)
	entries := make([]*CacheEntry, 0, len(cm.entries))
	for _, entry := range cm.entries {
		entries = append(entries, entry)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].LastAccessed.Before(entries[j].LastAccessed)
	})

	for _, entry := range entries {
		if result.size >= neededSpace {
			break
		}

		delete(cm.entries, entry.Key)
		result.count++
		result.size += entry.Size
		cm.stats.TotalEntries--
		cm.stats.TotalSize -= entry.Size

		// Update platform statistics
		if entry.Platform != "" {
			cm.updatePlatformStats(entry.Platform, -1)
		}

		debug.LogComponent("cache", "LRU eviction: removed entry %s (%d bytes)", entry.Key, entry.Size)
	}

	return result
}

// evictFIFO evicts first-in-first-out entries
func (cm *CacheManager) evictFIFO(neededSpace int64) evictionResult {
	var result evictionResult

	// Sort entries by creation time (oldest first)
	entries := make([]*CacheEntry, 0, len(cm.entries))
	for _, entry := range cm.entries {
		entries = append(entries, entry)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Created.Before(entries[j].Created)
	})

	for _, entry := range entries {
		if result.size >= neededSpace {
			break
		}

		delete(cm.entries, entry.Key)
		result.count++
		result.size += entry.Size
		cm.stats.TotalEntries--
		cm.stats.TotalSize -= entry.Size

		// Update platform statistics
		if entry.Platform != "" {
			cm.updatePlatformStats(entry.Platform, -1)
		}

		debug.LogComponent("cache", "FIFO eviction: removed entry %s (%d bytes)", entry.Key, entry.Size)
	}

	return result
}

// evictRandom evicts random entries
func (cm *CacheManager) evictRandom(neededSpace int64) evictionResult {
	var result evictionResult

	// Convert entries to slice for random access
	entries := make([]*CacheEntry, 0, len(cm.entries))
	for _, entry := range cm.entries {
		entries = append(entries, entry)
	}

	// Simple random eviction (in production, use a better random selection)
	for i := 0; i < len(entries) && result.size < neededSpace; i++ {
		entry := entries[i%len(entries)]
		if _, exists := cm.entries[entry.Key]; !exists {
			continue
		}

		delete(cm.entries, entry.Key)
		result.count++
		result.size += entry.Size
		cm.stats.TotalEntries--
		cm.stats.TotalSize -= entry.Size

		// Update platform statistics
		if entry.Platform != "" {
			cm.updatePlatformStats(entry.Platform, -1)
		}

		debug.LogComponent("cache", "Random eviction: removed entry %s (%d bytes)", entry.Key, entry.Size)
	}

	return result
}

// isEntryExpired checks if a cache entry has expired
func (cm *CacheManager) isEntryExpired(entry *CacheEntry) bool {
	policy := cm.getCachePolicyForEntry(entry)
	if policy.TTL == 0 {
		return false
	}

	return time.Since(entry.Created) > policy.TTL
}

// getCachePolicyForEntry determines the appropriate cache policy for an entry
func (cm *CacheManager) getCachePolicyForEntry(entry *CacheEntry) CachePolicy {
	// Check if entry has platform-specific policy
	if entry.Platform != "" {
		if policy, exists := cm.cachePolicies[entry.Platform]; exists {
			return policy
		}
	}

	// Check if entry has type-specific policy
	if strings.Contains(entry.Key, "base-image") {
		return cm.cachePolicies["base"]
	}

	if strings.Contains(entry.Key, "build-cache") {
		return cm.cachePolicies["build"]
	}

	if strings.Contains(entry.Key, "multiplatform") {
		return cm.cachePolicies["multiplatform"]
	}

	// Default to build policy
	return cm.cachePolicies["build"]
}

// getCachePolicy retrieves a cache policy by name
func (cm *CacheManager) getCachePolicy(name string) CachePolicy {
	if policy, exists := cm.cachePolicies[name]; exists {
		return policy
	}
	return cm.cachePolicies["build"]
}

// updatePlatformStats updates platform-specific cache statistics
func (cm *CacheManager) updatePlatformStats(platform string, delta int64) {
	if platform == "" {
		return
	}

	if cm.stats.PlatformEntries == nil {
		cm.stats.PlatformEntries = make(map[string]int64)
	}

	cm.stats.PlatformEntries[platform] += delta
	if cm.stats.PlatformEntries[platform] < 0 {
		cm.stats.PlatformEntries[platform] = 0
	}
}

// GarbageCollect performs intelligent cache garbage collection
func (cm *CacheManager) GarbageCollect(ctx context.Context) error {
	if !cm.gcEnabled {
		return nil
	}

	debug.LogComponent("cache", "Starting garbage collection")

	cm.mu.Lock()
	defer cm.mu.Unlock()

	var evictedCount int
	var evictedSize int64

	// Remove expired entries
	for key, entry := range cm.entries {
		if cm.isEntryExpired(entry) {
			delete(cm.entries, key)
			evictedCount++
			evictedSize += entry.Size
			cm.stats.TotalEntries--
			cm.stats.TotalSize -= entry.Size

			// Update platform statistics
			if entry.Platform != "" {
				cm.updatePlatformStats(entry.Platform, -1)
			}

			debug.LogComponent("cache", "GC: removed expired entry %s (%d bytes)", entry.Key, entry.Size)
		}
	}

	// Evict entries based on size limits if needed
	policy := cm.getCachePolicy("build")
	if cm.stats.TotalSize > policy.MaxSize {
		neededSpace := cm.stats.TotalSize - policy.MaxSize
		result := cm.evictLRU(neededSpace)
		evictedCount += result.count
		evictedSize += result.size
	}

	// Update statistics
	cm.stats.LastGC = time.Now()
	cm.updateHitRate()

	debug.LogComponent("cache", "Garbage collection completed. Evicted %d entries, freed %d bytes", evictedCount, evictedSize)

	return nil
}

// updateHitRate updates the cache hit rate statistics
func (cm *CacheManager) updateHitRate() {
	total := cm.stats.TotalHits + cm.stats.TotalMisses
	if total > 0 {
		cm.stats.HitRate = float64(cm.stats.TotalHits) / float64(total) * 100
	}
}

// GetStats returns current cache statistics
func (cm *CacheManager) GetStats() *CacheStats {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// Return a copy to avoid race conditions
	stats := *cm.stats
	stats.PlatformEntries = make(map[string]int64)
	for k, v := range cm.stats.PlatformEntries {
		stats.PlatformEntries[k] = v
	}

	return &stats
}

// PrefetchLayers prefetches commonly used layers for multi-platform builds
func (cm *CacheManager) PrefetchLayers(ctx context.Context, platforms []string) error {
	debug.LogComponent("cache", "Starting layer prefetch for platforms: %v", platforms)

	// This is a simplified implementation. In a real scenario, you would:
	// 1. Analyze the build context to identify commonly used layers
	// 2. Check if those layers are already cached
	// 3. If not cached, download them in parallel for all platforms
	// 4. Store them in the cache with appropriate platform metadata

	for _, platform := range platforms {
		debug.LogComponent("cache", "Prefetching layers for platform: %s", platform)
		
		// Create a cache entry for the platform
		entry := &CacheEntry{
			Key:         fmt.Sprintf("platform-prefetch-%s", platform),
			Digest:      fmt.Sprintf("prefetch-%s", platform),
			Size:        0, // Will be updated when actual layers are prefetched
			LastAccessed: time.Now(),
			Created:     time.Now(),
			Platform:    platform,
			AccessCount: 0,
			TTL:         cm.getCachePolicy("multiplatform").TTL,
		}

		if err := cm.SetCacheEntry(ctx, entry); err != nil {
			debug.LogComponent("cache", "Failed to prefetch for platform %s: %v", platform, err)
			continue
		}

		debug.LogComponent("cache", "Successfully prefetched layers for platform: %s", platform)
	}

	debug.LogComponent("cache", "Layer prefetch completed for %d platforms", len(platforms))
	return nil
}

// SetCachePolicy allows setting custom cache policies
func (cm *CacheManager) SetCachePolicy(name string, policy CachePolicy) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.cachePolicies[name] = policy
	debug.LogComponent("cache", "Cache policy set for %s: TTL=%v, MaxSize=%d, EvictionPolicy=%s", 
		name, policy.TTL, policy.MaxSize, policy.EvictionPolicy)
}

// GetCachePolicy retrieves a cache policy by name
func (cm *CacheManager) GetCachePolicy(name string) CachePolicy {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	return cm.getCachePolicy(name)
}

// EnableGC enables or disables garbage collection
func (cm *CacheManager) EnableGC(enabled bool) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.gcEnabled = enabled
	debug.LogComponent("cache", "Garbage collection %s", map[bool]string{true: "enabled", false: "disabled"}[enabled])
}

// Cleanup performs cleanup operations
func (cm *CacheManager) Cleanup() error {
	debug.LogComponent("cache", "Performing cache cleanup")

	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Clear all entries
	entryCount := len(cm.entries)
	cm.entries = make(map[string]*CacheEntry)
	
	// Reset statistics
	cm.stats.TotalEntries = 0
	cm.stats.TotalSize = 0
	cm.stats.TotalHits = 0
	cm.stats.TotalMisses = 0
	cm.stats.HitRate = 0
	cm.stats.PlatformEntries = make(map[string]int64)

	debug.LogComponent("cache", "Cache cleanup completed. Removed %d entries", entryCount)
	return nil
}

// BuildCacheKey constructs a cache key for build operations
func BuildCacheKey(baseImage, dockerfileDigest, platform string) string {
	key := fmt.Sprintf("%s:%s", baseImage, dockerfileDigest)
	if platform != "" {
		key = fmt.Sprintf("%s:%s", key, platform)
	}
	return cleanKey(key)
}

// BuildLayerCacheKey constructs a cache key for layer operations
func BuildLayerCacheKey(digest, platform string) string {
	key := fmt.Sprintf("layer-%s", digest)
	if platform != "" {
		key = fmt.Sprintf("%s:%s", key, platform)
	}
	return cleanKey(key)
}

// cleanKey cleans a cache key by replacing invalid characters
func cleanKey(key string) string {
	// Replace invalid characters with underscores
	invalidChars := "/:@#"
	for _, char := range invalidChars {
		key = strings.ReplaceAll(key, string(char), "_")
	}
	return key
}