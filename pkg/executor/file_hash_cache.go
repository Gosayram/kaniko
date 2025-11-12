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
	"context"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/logging"
	"github.com/Gosayram/kaniko/pkg/util"
)

const (
	fileHashEntryMetadataOverhead = 100 // ~100 bytes for entry metadata
	fileHashBytesPerKilobyte      = 1024
	fileHashBytesPerMegabyte      = fileHashBytesPerKilobyte * fileHashBytesPerKilobyte
	// FNV-1a hash constants
	fnvOffsetBasis = uint32(2166136261) // FNV-1a offset basis
	fnvPrime       = uint32(16777619)   // FNV-1a prime
	// Default file hash size limit (10MB)
	defaultMaxFileHashSizeMB = 10
)

// FileHashCacheEntry represents a cached file hash with metadata for invalidation
type FileHashCacheEntry struct {
	Hash     string
	Mtime    time.Time
	Size     int64
	Inode    uint64
	Mode     os.FileMode
	CachedAt time.Time
}

// FileHashCacheShard represents a single shard of the cache
type FileHashCacheShard struct {
	mu            sync.RWMutex
	cache         map[string]*FileHashCacheEntry
	currentMemory int64 // Current memory usage in bytes for this shard
}

// FileHashCache provides optimized file hash caching with invalidation
// Uses sharding to reduce lock contention (optimized for read-heavy workloads)
type FileHashCache struct {
	shards        []*FileHashCacheShard
	shardCount    int
	maxEntries    int
	maxMemoryMB   int
	totalMemory   int64 // Total memory usage across all shards (approximate)
	totalMemoryMu sync.RWMutex

	// Background cleanup
	cleanupCtx     context.Context
	cleanupCancel  context.CancelFunc
	cleanupOnce    sync.Once
	cleanupRunning int32 // Atomic flag

	// Cache statistics (per performance plan: optimize cache usage)
	hits   int64 // Atomic counter for cache hits
	misses int64 // Atomic counter for cache misses
}

const (
	// Default shard count for file hash cache (reduces lock contention)
	// Using power of 2 for efficient modulo operation
	defaultShardCount = 16
	// Default cleanup interval for background cache cleanup
	defaultCleanupInterval = 30 * time.Second
)

// Global file hash cache instance (initialized on first use)
var (
	globalFileHashCache     *FileHashCache
	globalFileHashCacheMu   sync.Mutex
	globalFileHashCacheOpts *config.KanikoOptions // Store opts for cache initialization
)

// GetGlobalFileHashCache returns the global file hash cache instance
func GetGlobalFileHashCache(opts *config.KanikoOptions) *FileHashCache {
	globalFileHashCacheMu.Lock()
	defer globalFileHashCacheMu.Unlock()

	if globalFileHashCache != nil {
		return globalFileHashCache
	}

	// Get configuration values
	maxEntries := opts.FileHashCacheMaxEntries
	if maxEntries <= 0 {
		maxEntries = 10000 // Default
	}
	maxMemoryMB := opts.FileHashCacheMaxMemoryMB
	if maxMemoryMB <= 0 {
		maxMemoryMB = 200 // Default
	}

	globalFileHashCache = NewFileHashCache(maxEntries, maxMemoryMB)
	logrus.Debugf("Initialized global file hash cache (maxEntries=%d, maxMemoryMB=%d)",
		maxEntries, maxMemoryMB)

	return globalFileHashCache
}

// NewFileHashCache creates a new file hash cache with sharding
func NewFileHashCache(maxEntries, maxMemoryMB int) *FileHashCache {
	if maxEntries <= 0 {
		maxEntries = 10000 // Default
	}
	if maxMemoryMB <= 0 {
		maxMemoryMB = 200 // Default
	}

	shardCount := defaultShardCount
	shards := make([]*FileHashCacheShard, shardCount)
	for i := range shards {
		shards[i] = &FileHashCacheShard{
			cache:         make(map[string]*FileHashCacheEntry),
			currentMemory: 0,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	fhc := &FileHashCache{
		shards:        shards,
		shardCount:    shardCount,
		maxEntries:    maxEntries,
		maxMemoryMB:   maxMemoryMB,
		cleanupCtx:    ctx,
		cleanupCancel: cancel,
	}

	// Start background cleanup goroutine
	fhc.startBackgroundCleanup()

	return fhc
}

// getShard returns the shard for a given key (using hash-based sharding)
func (fhc *FileHashCache) getShard(key string) *FileHashCacheShard {
	// Simple hash function for sharding (FNV-1a style)
	hash := fnvOffsetBasis
	for i := 0; i < len(key); i++ {
		hash ^= uint32(key[i])
		hash *= fnvPrime
	}
	// Use modulo with shardCount (power of 2, so bitwise AND is faster)
	// Safe conversion: shardCount is always positive and small, so uint32 conversion is safe
	shardIndex := int(hash) & (fhc.shardCount - 1)
	return fhc.shards[shardIndex]
}

// Get retrieves a cached hash if available and valid
// Uses sharding to reduce lock contention
func (fhc *FileHashCache) Get(path string) (string, bool) {
	shard := fhc.getShard(path)
	shard.mu.RLock()
	defer shard.mu.RUnlock()

	entry, exists := shard.cache[path]
	if !exists {
		return "", false
	}

	// Check if entry is still valid by comparing file metadata
	valid, err := fhc.isEntryValid(path, entry)
	if err != nil || !valid {
		// Entry is invalid, but don't delete here (would need write lock)
		// It will be cleaned up on next access
		return "", false
	}

	return entry.Hash, true
}

// isEntryValid checks if a cache entry is still valid by comparing file metadata
func (fhc *FileHashCache) isEntryValid(path string, entry *FileHashCacheEntry) (bool, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return false, err
	}

	// Check mtime
	if !fi.ModTime().Equal(entry.Mtime) {
		return false, nil
	}

	// Check size
	if fi.Size() != entry.Size {
		return false, nil
	}

	// Check mode
	if fi.Mode() != entry.Mode {
		return false, nil
	}

	// Check inode (if available)
	if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
		if stat.Ino != entry.Inode {
			return false, nil
		}
	}

	return true, nil
}

// Set stores a file hash with metadata for invalidation
// Uses sharding to reduce lock contention
func (fhc *FileHashCache) Set(path, hash string) error {
	shard := fhc.getShard(path)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	// Get file metadata for invalidation
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}

	var inode uint64
	if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
		inode = stat.Ino
	}

	// Estimate entry size
	entrySize := int64(len(path) + len(hash) + fileHashEntryMetadataOverhead)

	// Check if we need to evict entries (check total memory across all shards)
	fhc.evictIfNeeded(entrySize)

	// Remove old entry if exists (to update memory tracking)
	if oldEntry, exists := shard.cache[path]; exists {
		oldSize := int64(len(path) + len(oldEntry.Hash) + fileHashEntryMetadataOverhead)
		shard.currentMemory -= oldSize
		fhc.updateTotalMemory(-oldSize)
	}

	// Create new entry
	entry := &FileHashCacheEntry{
		Hash:     hash,
		Mtime:    fi.ModTime(),
		Size:     fi.Size(),
		Inode:    inode,
		Mode:     fi.Mode(),
		CachedAt: time.Now(),
	}

	// Store entry
	shard.cache[path] = entry
	shard.currentMemory += entrySize
	fhc.updateTotalMemory(entrySize)

	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		logging.AsyncDebugf("Cached file hash for: %s (shard memory: %d bytes, total entries: %d)",
			path, shard.currentMemory, fhc.getTotalEntries())
	}

	return nil
}

// updateTotalMemory updates the approximate total memory usage
func (fhc *FileHashCache) updateTotalMemory(delta int64) {
	fhc.totalMemoryMu.Lock()
	fhc.totalMemory += delta
	if fhc.totalMemory < 0 {
		fhc.totalMemory = 0 // Safety check
	}
	fhc.totalMemoryMu.Unlock()
}

// getTotalEntries returns the total number of entries across all shards
func (fhc *FileHashCache) getTotalEntries() int {
	total := 0
	for _, shard := range fhc.shards {
		shard.mu.RLock()
		total += len(shard.cache)
		shard.mu.RUnlock()
	}
	return total
}

// evictIfNeeded evicts entries if limits are exceeded
// Works across all shards to maintain global limits
// Note: evictInvalidEntries is called periodically in background, but we still check here
// for immediate cleanup when needed (e.g., when adding new entry)
func (fhc *FileHashCache) evictIfNeeded(newEntrySize int64) {
	// Quick check: only evict invalid entries if we're close to limits
	// Full cleanup happens in background
	fhc.totalMemoryMu.RLock()
	totalMemory := fhc.totalMemory
	fhc.totalMemoryMu.RUnlock()

	maxMemoryBytes := int64(fhc.maxMemoryMB) * fileHashBytesPerMegabyte
	// Only do immediate cleanup if we're at 80% of limit
	if totalMemory+newEntrySize > maxMemoryBytes*80/100 {
		fhc.evictInvalidEntries()
	}

	// Check and evict by memory limit (critical - must be synchronous)
	fhc.evictByMemoryLimit(maxMemoryBytes, newEntrySize)

	// Check and evict by entry count limit (critical - must be synchronous)
	fhc.evictByEntryLimit()
}

// startBackgroundCleanup starts a background goroutine for periodic cache cleanup
func (fhc *FileHashCache) startBackgroundCleanup() {
	fhc.cleanupOnce.Do(func() {
		if atomic.CompareAndSwapInt32(&fhc.cleanupRunning, 0, 1) {
			go fhc.backgroundCleanupWorker()
		}
	})
}

// backgroundCleanupWorker performs periodic cleanup of invalid cache entries
func (fhc *FileHashCache) backgroundCleanupWorker() {
	ticker := time.NewTicker(defaultCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-fhc.cleanupCtx.Done():
			return
		case <-ticker.C:
			// Periodic cleanup of invalid entries (non-blocking for main operations)
			fhc.evictInvalidEntries()
		}
	}
}

// Stop stops the background cleanup goroutine
func (fhc *FileHashCache) Stop() {
	if atomic.LoadInt32(&fhc.cleanupRunning) == 1 {
		fhc.cleanupCancel()
		atomic.StoreInt32(&fhc.cleanupRunning, 0)
	}
}

// evictInvalidEntries removes entries that are too old or have invalid metadata
func (fhc *FileHashCache) evictInvalidEntries() {
	now := time.Now()
	for _, shard := range fhc.shards {
		shard.mu.Lock()
		for path, entry := range shard.cache {
			shouldEvict := false

			// Check if entry is too old (safety check)
			if now.Sub(entry.CachedAt) > 24*time.Hour {
				shouldEvict = true
			} else {
				// Check if file metadata changed (quick check without lock)
				valid, err := fhc.isEntryValidUnlocked(path, entry)
				if err != nil || !valid {
					shouldEvict = true
				}
			}

			if shouldEvict {
				entrySize := int64(len(path) + len(entry.Hash) + fileHashEntryMetadataOverhead)
				delete(shard.cache, path)
				shard.currentMemory -= entrySize
				fhc.updateTotalMemory(-entrySize)
			}
		}
		shard.mu.Unlock()
	}
}

// evictByMemoryLimit evicts entries until memory usage is below limit
func (fhc *FileHashCache) evictByMemoryLimit(maxMemoryBytes, newEntrySize int64) {
	for {
		// Check total memory usage
		fhc.totalMemoryMu.RLock()
		totalMemory := fhc.totalMemory
		fhc.totalMemoryMu.RUnlock()

		if totalMemory+newEntrySize <= maxMemoryBytes {
			break
		}

		// Evict one entry
		if !fhc.evictOneEntry() {
			break // No more entries to evict
		}
	}
}

// evictByEntryLimit evicts entries until entry count is below limit
func (fhc *FileHashCache) evictByEntryLimit() {
	for {
		totalEntries := fhc.getTotalEntries()
		if totalEntries < fhc.maxEntries {
			break
		}

		// Evict one entry
		if !fhc.evictOneEntry() {
			break // No more entries to evict
		}
	}
}

// evictOneEntry evicts a single entry from any shard
// Returns true if an entry was evicted, false otherwise
func (fhc *FileHashCache) evictOneEntry() bool {
	for _, shard := range fhc.shards {
		shard.mu.Lock()
		if len(shard.cache) > 0 {
			for path, entry := range shard.cache {
				entrySize := int64(len(path) + len(entry.Hash) + fileHashEntryMetadataOverhead)
				delete(shard.cache, path)
				shard.currentMemory -= entrySize
				fhc.updateTotalMemory(-entrySize)
				shard.mu.Unlock()
				return true
			}
		}
		shard.mu.Unlock()
	}
	return false
}

// isEntryValidUnlocked checks entry validity without acquiring lock
// Should only be called when already holding write lock
func (fhc *FileHashCache) isEntryValidUnlocked(path string, entry *FileHashCacheEntry) (bool, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return false, err
	}

	if !fi.ModTime().Equal(entry.Mtime) || fi.Size() != entry.Size || fi.Mode() != entry.Mode {
		return false, nil
	}

	if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
		if stat.Ino != entry.Inode {
			return false, nil
		}
	}

	return true, nil
}

// Clear removes all cached entries across all shards
func (fhc *FileHashCache) Clear() {
	for _, shard := range fhc.shards {
		shard.mu.Lock()
		shard.cache = make(map[string]*FileHashCacheEntry)
		shard.currentMemory = 0
		shard.mu.Unlock()
	}
	fhc.totalMemoryMu.Lock()
	fhc.totalMemory = 0
	fhc.totalMemoryMu.Unlock()
}

// GetStats returns cache statistics (per performance plan: optimize cache usage)
func (fhc *FileHashCache) GetStats() map[string]interface{} {
	fhc.totalMemoryMu.RLock()
	totalMemory := fhc.totalMemory
	fhc.totalMemoryMu.RUnlock()

	hits := atomic.LoadInt64(&fhc.hits)
	misses := atomic.LoadInt64(&fhc.misses)
	totalRequests := hits + misses
	var hitRate float64
	if totalRequests > 0 {
		const percentageBase = 100
		hitRate = float64(hits) / float64(totalRequests) * percentageBase
	}

	return map[string]interface{}{
		"entries":        fhc.getTotalEntries(),
		"max_entries":    fhc.maxEntries,
		"memory_bytes":   totalMemory,
		"max_memory_mb":  fhc.maxMemoryMB,
		"shard_count":    fhc.shardCount,
		"cache_hits":     hits,
		"cache_misses":   misses,
		"total_requests": totalRequests,
		"hit_rate_pct":   hitRate,
	}
}

// LogStats logs cache statistics (per performance plan: optimize cache usage)
func (fhc *FileHashCache) LogStats() {
	if fhc == nil {
		return
	}
	stats := fhc.GetStats()
	hits := stats["cache_hits"].(int64)
	misses := stats["cache_misses"].(int64)
	totalRequests := stats["total_requests"].(int64)
	hitRate := stats["hit_rate_pct"].(float64)

	if totalRequests > 0 {
		const percentageBase = 100
		const bytesPerKB = 1024
		memoryMB := float64(stats["memory_bytes"].(int64)) / bytesPerKB / bytesPerKB
		maxMemoryMB := float64(stats["max_memory_mb"].(int))
		logrus.Infof("File hash cache statistics: Total requests: %d, Hits: %d (%.1f%%), "+
			"Misses: %d (%.1f%%), Entries: %d/%d, Memory: %.1fMB/%.1fMB",
			totalRequests, hits, hitRate, misses, percentageBase-hitRate,
			stats["entries"].(int), stats["max_entries"].(int), memoryMB, maxMemoryMB)
	}
}

// SetGlobalFileHashCacheOpts sets the global opts for file hash cache
func SetGlobalFileHashCacheOpts(opts *config.KanikoOptions) {
	globalFileHashCacheMu.Lock()
	defer globalFileHashCacheMu.Unlock()
	globalFileHashCacheOpts = opts
}

// getOptsForHashCache returns the global opts for file hash cache
func getOptsForHashCache() *config.KanikoOptions {
	globalFileHashCacheMu.Lock()
	defer globalFileHashCacheMu.Unlock()
	return globalFileHashCacheOpts
}

// getFileHashWithCache gets file hash using cache with invalidation
func getFileHashWithCache(path string, _ util.FileContext, opts *config.KanikoOptions) (string, error) {
	// Get global cache instance
	cache := GetGlobalFileHashCache(opts)

	// Check cache first
	if cachedHash, found := cache.Get(path); found {
		atomic.AddInt64(&cache.hits, 1)
		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			logging.AsyncDebugf("File hash cache hit for: %s", path)
		}
		return cachedHash, nil
	}

	// Cache miss - compute hash
	atomic.AddInt64(&cache.misses, 1)
	// Use MaxFileHashSize from options for partial hashing of large files
	maxFileHashSize := int64(defaultMaxFileHashSizeMB * fileHashBytesPerMegabyte) // Default: 10MB
	if opts != nil && opts.MaxFileHashSize > 0 {
		maxFileHashSize = opts.MaxFileHashSize
	}

	// Use CacheHasherWithLimit for optimized hashing of large files
	hasher := util.CacheHasherWithLimit(maxFileHashSize)
	hash, err := hasher(path)
	if err != nil {
		return "", err
	}

	// Cache the result
	if err := cache.Set(path, hash); err != nil {
		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			logging.AsyncDebugf("Failed to cache file hash for %s: %v", path, err)
		}
		// Continue even if caching fails
	}

	return hash, nil
}
