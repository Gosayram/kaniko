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

// Cache constants
const (
	sevenDays  = 24 * time.Hour * 7
	tenGB      = 10 * 1024 * 1024 * 1024
	oneDay     = 24 * time.Hour
	fiveGB     = 5 * 1024 * 1024 * 1024
	threeDays  = 24 * time.Hour * 3
	twentyGB   = 20 * 1024 * 1024 * 1024
	hitRateDiv = 100
)

// Policy defines the caching policy for a specific cache type
type Policy struct {
	TTL            time.Duration `json:"ttl" yaml:"ttl"`                       // Time to live for cache entries
	MaxSize        int64         `json:"maxSize" yaml:"maxSize"`               // Maximum size in bytes
	EvictionPolicy string        `json:"evictionPolicy" yaml:"evictionPolicy"` // LRU, FIFO, Random
	Compression    string        `json:"compression" yaml:"compression"`       // gzip, zstd, none
}

// Entry represents a single cache entry with metadata
type Entry struct {
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

// Manager manages advanced caching operations for multi-platform builds
type Manager struct {
	opts          *config.KanikoOptions
	cachePolicies map[string]Policy
	gcEnabled     bool
	mu            sync.RWMutex
	entries       map[string]*Entry
	stats         *Stats
}

// Stats provides statistics about cache usage
type Stats struct {
	TotalEntries    int64            `json:"totalEntries"`
	TotalSize       int64            `json:"totalSize"`
	LastGC          time.Time        `json:"lastGC"`
	HitRate         float64          `json:"hitRate"`
	TotalHits       int64            `json:"totalHits"`
	TotalMisses     int64            `json:"totalMisses"`
	PlatformEntries map[string]int64 `json:"platformEntries"`
}

// NewManager creates a new advanced cache manager
func NewManager(opts *config.KanikoOptions) *Manager {
	cm := &Manager{
		opts:          opts,
		cachePolicies: make(map[string]Policy),
		gcEnabled:     true,
		entries:       make(map[string]*Entry),
		stats: &Stats{
			PlatformEntries: make(map[string]int64),
		},
	}

	// Set default cache policies
	cm.setDefaultPolicies()

	return cm
}

// setDefaultPolicies sets up default cache policies
func (cm *Manager) setDefaultPolicies() {
	// Default policy for base image cache
	cm.cachePolicies["base"] = Policy{
		TTL:            sevenDays, // 7 days
		MaxSize:        tenGB,     // 10GB
		EvictionPolicy: "LRU",
		Compression:    "gzip",
	}

	// Default policy for build cache
	cm.cachePolicies["build"] = Policy{
		TTL:            oneDay, // 1 day
		MaxSize:        fiveGB, // 5GB
		EvictionPolicy: "LRU",
		Compression:    "gzip",
	}

	// Default policy for multi-platform cache
	cm.cachePolicies["multiplatform"] = Policy{
		TTL:            threeDays, // 3 days
		MaxSize:        twentyGB,  // 20GB
		EvictionPolicy: "LRU",
		Compression:    "zstd",
	}
}

// GetEntry retrieves a cache entry by key
func (cm *Manager) GetEntry(_ context.Context, key string) (*Entry, error) {
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

// SetEntry stores a cache entry
func (cm *Manager) SetEntry(_ context.Context, entry *Entry) error {
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
func (cm *Manager) evictIfNeeded(newEntrySize int64) error {
	policy := cm.getPolicy("build")
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
func (cm *Manager) evictEntries(neededSpace int64) (evictionResult, error) {
	var result evictionResult

	switch cm.getPolicy("build").EvictionPolicy {
	case "LRU":
		result = cm.evictLRU(neededSpace)
	case "FIFO":
		result = cm.evictFIFO(neededSpace)
	case "Random":
		result = cm.evictRandom(neededSpace)
	default:
		return result, fmt.Errorf("unknown eviction policy: %s", cm.getPolicy("build").EvictionPolicy)
	}

	return result, nil
}

// evictionResult contains the result of an eviction operation
type evictionResult struct {
	count int
	size  int64
}

// evictEntriesByTime evicts entries based on time comparison with a custom sort function
func (cm *Manager) evictEntriesByTime(neededSpace int64, sortFunc func([]*Entry, int, int) bool) evictionResult {
	var result evictionResult

	// Sort entries using the provided comparison function
	entries := make([]*Entry, 0, len(cm.entries))
	for _, entry := range cm.entries {
		entries = append(entries, entry)
	}

	sort.Slice(entries, func(i, j int) bool {
		return sortFunc(entries, i, j)
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

		debug.LogComponent("cache", "Eviction: removed entry %s (%d bytes)", entry.Key, entry.Size)
	}

	return result
}

// evictLRU evicts least recently used entries
func (cm *Manager) evictLRU(neededSpace int64) evictionResult {
	return cm.evictEntriesByTime(neededSpace, func(entries []*Entry, i, j int) bool {
		return entries[i].LastAccessed.Before(entries[j].LastAccessed)
	})
}

// evictFIFO evicts first-in-first-out entries
func (cm *Manager) evictFIFO(neededSpace int64) evictionResult {
	return cm.evictEntriesByTime(neededSpace, func(entries []*Entry, i, j int) bool {
		return entries[i].Created.Before(entries[j].Created)
	})
}

// evictRandom evicts random entries
func (cm *Manager) evictRandom(neededSpace int64) evictionResult {
	var result evictionResult

	// Convert entries to slice for random access
	entries := make([]*Entry, 0, len(cm.entries))
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
func (cm *Manager) isEntryExpired(entry *Entry) bool {
	policy := cm.getPolicyForEntry(entry)
	if policy.TTL == 0 {
		return false
	}

	return time.Since(entry.Created) > policy.TTL
}

// getPolicyForEntry determines the appropriate cache policy for an entry
func (cm *Manager) getPolicyForEntry(entry *Entry) Policy {
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

// getPolicy retrieves a cache policy by name
func (cm *Manager) getPolicy(name string) Policy {
	if policy, exists := cm.cachePolicies[name]; exists {
		return policy
	}
	return cm.cachePolicies["build"]
}

// updatePlatformStats updates platform-specific cache statistics
func (cm *Manager) updatePlatformStats(platform string, delta int64) {
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
func (cm *Manager) GarbageCollect(_ context.Context) error {
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
		if !cm.isEntryExpired(entry) {
			continue
		}

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

	// Evict entries based on size limits if needed
	policy := cm.getPolicy("build")
	if cm.stats.TotalSize > policy.MaxSize {
		neededSpace := cm.stats.TotalSize - policy.MaxSize
		result := cm.evictLRU(neededSpace)
		evictedCount += result.count
		evictedSize += result.size
	}

	// Update statistics
	cm.stats.LastGC = time.Now()
	cm.updateHitRate()

	debug.LogComponent("cache", "Garbage collection completed. Evicted %d entries, "+
		"freed %d bytes", evictedCount, evictedSize)

	return nil
}

// updateHitRate updates the cache hit rate statistics
func (cm *Manager) updateHitRate() {
	total := cm.stats.TotalHits + cm.stats.TotalMisses
	if total > 0 {
		cm.stats.HitRate = float64(cm.stats.TotalHits) / float64(total) * hitRateDiv
	}
}

// GetStats returns current cache statistics
func (cm *Manager) GetStats() *Stats {
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
func (cm *Manager) PrefetchLayers(ctx context.Context, platforms []string) error {
	debug.LogComponent("cache", "Starting layer prefetch for platforms: %v", platforms)

	// This is a simplified implementation. In a real scenario, you would:
	// 1. Analyze the build context to identify commonly used layers
	// 2. Check if those layers are already cached
	// 3. If not cached, download them in parallel for all platforms
	// 4. Store them in the cache with appropriate platform metadata

	for _, platform := range platforms {
		debug.LogComponent("cache", "Prefetching layers for platform: %s", platform)

		// Create a cache entry for the platform
		entry := &Entry{
			Key:          fmt.Sprintf("platform-prefetch-%s", platform),
			Digest:       fmt.Sprintf("prefetch-%s", platform),
			Size:         0, // Will be updated when actual layers are prefetched
			LastAccessed: time.Now(),
			Created:      time.Now(),
			Platform:     platform,
			AccessCount:  0,
			TTL:          cm.getPolicy("multiplatform").TTL,
		}

		if err := cm.SetEntry(ctx, entry); err != nil {
			debug.LogComponent("cache", "Failed to prefetch for platform %s: %v", platform, err)
			continue
		}

		debug.LogComponent("cache", "Successfully prefetched layers for platform: %s", platform)
	}

	debug.LogComponent("cache", "Layer prefetch completed for %d platforms", len(platforms))
	return nil
}

// SetPolicy allows setting custom cache policies
func (cm *Manager) SetPolicy(name string, policy Policy) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.cachePolicies[name] = policy
	debug.LogComponent("cache", "Cache policy set for %s: TTL=%v, MaxSize=%d, EvictionPolicy=%s",
		name, policy.TTL, policy.MaxSize, policy.EvictionPolicy)
}

// GetPolicy retrieves a cache policy by name
func (cm *Manager) GetPolicy(name string) Policy {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	return cm.getPolicy(name)
}

// EnableGC enables or disables garbage collection
func (cm *Manager) EnableGC(enabled bool) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.gcEnabled = enabled
	debug.LogComponent("cache", "Garbage collection %s", map[bool]string{true: "enabled", false: "disabled"}[enabled])
}

// Cleanup performs cleanup operations
func (cm *Manager) Cleanup() error {
	debug.LogComponent("cache", "Performing cache cleanup")

	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Clear all entries
	entryCount := len(cm.entries)
	cm.entries = make(map[string]*Entry)

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
