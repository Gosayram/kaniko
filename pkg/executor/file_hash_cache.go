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
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/util"
)

const (
	fileHashEntryMetadataOverhead = 100 // ~100 bytes for entry metadata
	fileHashBytesPerKilobyte      = 1024
	fileHashBytesPerMegabyte      = fileHashBytesPerKilobyte * fileHashBytesPerKilobyte
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

// FileHashCache provides optimized file hash caching with invalidation
type FileHashCache struct {
	mu            sync.RWMutex
	cache         map[string]*FileHashCacheEntry
	maxEntries    int
	maxMemoryMB   int
	currentMemory int64 // Current memory usage in bytes
}

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

// NewFileHashCache creates a new file hash cache
func NewFileHashCache(maxEntries, maxMemoryMB int) *FileHashCache {
	if maxEntries <= 0 {
		maxEntries = 10000 // Default
	}
	if maxMemoryMB <= 0 {
		maxMemoryMB = 200 // Default
	}

	return &FileHashCache{
		cache:       make(map[string]*FileHashCacheEntry),
		maxEntries:  maxEntries,
		maxMemoryMB: maxMemoryMB,
	}
}

// Get retrieves a cached hash if available and valid
func (fhc *FileHashCache) Get(path string) (string, bool) {
	fhc.mu.RLock()
	defer fhc.mu.RUnlock()

	entry, exists := fhc.cache[path]
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
func (fhc *FileHashCache) Set(path, hash string) error {
	fhc.mu.Lock()
	defer fhc.mu.Unlock()

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

	// Check if we need to evict entries
	fhc.evictIfNeeded(entrySize)

	// Remove old entry if exists (to update memory tracking)
	if oldEntry, exists := fhc.cache[path]; exists {
		oldSize := int64(len(path) + len(oldEntry.Hash) + fileHashEntryMetadataOverhead)
		fhc.currentMemory -= oldSize
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
	fhc.cache[path] = entry
	fhc.currentMemory += entrySize

	logrus.Debugf("Cached file hash for: %s (memory: %d bytes, entries: %d)",
		path, fhc.currentMemory, len(fhc.cache))

	return nil
}

// evictIfNeeded evicts entries if limits are exceeded
func (fhc *FileHashCache) evictIfNeeded(newEntrySize int64) {
	maxMemoryBytes := int64(fhc.maxMemoryMB) * fileHashBytesPerMegabyte

	// Evict invalid entries first (check file metadata)
	now := time.Now()
	for path, entry := range fhc.cache {
		// Check if entry is too old (safety check)
		if now.Sub(entry.CachedAt) > 24*time.Hour {
			entrySize := int64(len(path) + len(entry.Hash) + fileHashEntryMetadataOverhead)
			delete(fhc.cache, path)
			fhc.currentMemory -= entrySize
			continue
		}

		// Check if file metadata changed (quick check without lock)
		valid, err := fhc.isEntryValidUnlocked(path, entry)
		if err != nil || !valid {
			entrySize := int64(len(path) + len(entry.Hash) + fileHashEntryMetadataOverhead)
			delete(fhc.cache, path)
			fhc.currentMemory -= entrySize
		}
	}

	// Check if we still need to evict (memory limit)
	for fhc.currentMemory+newEntrySize > maxMemoryBytes && len(fhc.cache) > 0 {
		// Evict oldest entry (simplified: evict first found)
		for path, entry := range fhc.cache {
			entrySize := int64(len(path) + len(entry.Hash) + fileHashEntryMetadataOverhead)
			delete(fhc.cache, path)
			fhc.currentMemory -= entrySize
			break
		}
	}

	// Check if we still need to evict (entry count limit)
	for len(fhc.cache) >= fhc.maxEntries && len(fhc.cache) > 0 {
		// Evict oldest entry
		for path, entry := range fhc.cache {
			entrySize := int64(len(path) + len(entry.Hash) + fileHashEntryMetadataOverhead)
			delete(fhc.cache, path)
			fhc.currentMemory -= entrySize
			break
		}
	}
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

// Clear removes all cached entries
func (fhc *FileHashCache) Clear() {
	fhc.mu.Lock()
	defer fhc.mu.Unlock()

	fhc.cache = make(map[string]*FileHashCacheEntry)
	fhc.currentMemory = 0
}

// GetStats returns cache statistics
func (fhc *FileHashCache) GetStats() map[string]interface{} {
	fhc.mu.RLock()
	defer fhc.mu.RUnlock()

	return map[string]interface{}{
		"entries":       len(fhc.cache),
		"max_entries":   fhc.maxEntries,
		"memory_bytes":  fhc.currentMemory,
		"max_memory_mb": fhc.maxMemoryMB,
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
		logrus.Debugf("File hash cache hit for: %s", path)
		return cachedHash, nil
	}

	// Cache miss - compute hash
	hash, err := util.CacheHasher()(path)
	if err != nil {
		return "", err
	}

	// Cache the result
	if err := cache.Set(path, hash); err != nil {
		logrus.Debugf("Failed to cache file hash for %s: %v", path, err)
		// Continue even if caching fails
	}

	return hash, nil
}
